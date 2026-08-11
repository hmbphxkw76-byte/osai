"""多页面 Web 目标发现 — 一次登录，多页面端点嗅探

场景：同一 Web 应用的多个子页面（/, /explore, /labs/PI_01）各自有
提示对话框，可能调用不同的后端 API 端点。本模块：

  1. 首次调用：完整 Playwright 登录 → 端点发现 → Cookie 落盘
  2. 后续调用：复用已保存 Cookie → 无头打开子页面 → 端点发现
  3. 同域会话复用：避免重复登录触发风控

设计约束：
  - 复用 AuthBootstrap + model_probe，不重复造轮子
  - Cookie 过期时自动降级为完整重登录
  - 无头模式用于后续页面（首个页面保留有头模式便于人工配合验证码）
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .bootstrap import AuthBootstrap, UnifiedTargetProfile
from .cookie_session import (
    api_domain_from_endpoint,
    cookie_header_for,
    load_cookies,
    save_cookies,
)
from .model_probe import discover

logger = logging.getLogger(__name__)


class WebTargetDiscovery:
    """多页面 Web 目标发现器 — 一次登录，多页面端点嗅探

    用法:
        wtd = WebTargetDiscovery()
        # 首个页面（有头模式，人工配合验证码）
        profile1 = wtd.login_and_discover("http://192.168.40.198/")
        # 后续页面（无头模式，复用 Cookie）
        profile2 = wtd.discover_subpage("http://192.168.40.198/explore")
        profile3 = wtd.discover_subpage("http://192.168.40.198/labs/PI_01")
    """

    def __init__(
        self,
        sessions_dir: str = "sessions",
        auth_cfg: dict[str, Any] | None = None,
    ) -> None:
        self.sessions_dir = Path(sessions_dir)
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.auth_cfg = auth_cfg or {}
        self._cookie_path: str | None = None
        self._cookie_domain: str | None = None
        self._raw_cookies: list[dict] = []

    # ------------------------------------------------------------------
    # 首次：完整登录 + 端点发现
    # ------------------------------------------------------------------

    def login_and_discover(
        self,
        target_url: str,
        headless: bool = False,
    ) -> UnifiedTargetProfile:
        """完整 Playwright 登录 + 端点发现（首个页面）

        :param target_url: 目标 URL（首页或登录页入口）
        :param headless: True 时无头模式（自动化场景）；False 有头（需人工配合验证码）
        :returns: UnifiedTargetProfile（含 endpoint, model, cookie_header 等）
        """
        logger.info("WebTargetDiscovery: 首次登录 + 端点发现: %s", target_url)

        bootstrap = AuthBootstrap(
            target_url,
            cfg={
                "username_env": self.auth_cfg.get("username_env", "TARGET_USERNAME"),
                "password_env": self.auth_cfg.get("password_env", "TARGET_PASSWORD"),
                "selectors": self.auth_cfg.get("selectors"),
            },
            sessions_dir=str(self.sessions_dir),
        )

        # 有头/无头模式切换
        if headless:
            profile = self._run_bootstrap_headless(bootstrap, target_url)
        else:
            profile = bootstrap.run()

        # 缓存 Cookie 信息供后续页面复用
        self._cookie_domain = profile.api_domain
        self._raw_cookies = profile.raw_cookies
        # 推导 Cookie 文件路径
        safe_name = re.sub(r"\W+", "_", urlparse(target_url).netloc)
        self._cookie_path = str(self.sessions_dir / f"{safe_name}.json")

        logger.info(
            "首次发现完成: endpoint=%s model=%s auth_type=%s cookies=%d",
            profile.endpoint, profile.model, profile.auth_type, len(profile.raw_cookies),
        )
        return profile

    # ------------------------------------------------------------------
    # 后续：复用 Cookie + 子页面端点发现
    # ------------------------------------------------------------------

    def discover_subpage(
        self,
        subpage_url: str,
        headless: bool = True,
    ) -> UnifiedTargetProfile:
        """复用已保存的 Cookie 会话，发现子页面的 API 端点

        :param subpage_url: 子页面 URL（如 http://192.168.40.198/labs/PI_01）
        :param headless: True 时无头模式（默认）
        :returns: UnifiedTargetProfile（该子页面的 endpoint, model + 共享 Cookie）
        """
        if not self._cookie_path or not Path(self._cookie_path).exists():
            logger.warning("Cookie 文件不存在，降级为完整重登录: %s", subpage_url)
            return self.login_and_discover(subpage_url, headless=headless)

        logger.info("WebTargetDiscovery: 子页面端点发现（复用 Cookie）: %s", subpage_url)

        # 加载已保存的 Cookie
        try:
            cookies = load_cookies(self._cookie_path)
        except Exception as exc:
            logger.warning("Cookie 加载失败，降级为完整重登录: %s", exc)
            return self.login_and_discover(subpage_url, headless=headless)

        # 无头浏览器 + 注入 Cookie + 导航到子页面 + 端点发现
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=headless)
            ctx = browser.new_context()

            # 注入已保存的 Cookie 到浏览器上下文
            cookie_list = self._to_playwright_cookies(cookies)
            if cookie_list:
                ctx.add_cookies(cookie_list)

            page = ctx.new_page()
            try:
                page.goto(subpage_url, wait_until="load", timeout=30000)
            except Exception:
                logger.warning("子页面加载超时: %s", subpage_url)

            # 检查是否被重定向到登录页（Cookie 过期）
            if self._is_login_page(page):
                logger.warning("Cookie 已过期（重定向到登录页），触发完整重登录")
                browser.close()
                return self.login_and_discover(subpage_url, headless=headless)

            # 端点发现
            prof = discover(page, subpage_url)
            api_domain = api_domain_from_endpoint(prof["endpoint"])

            # 生成 Cookie 头（复用已有 Cookie）
            cookie_header = cookie_header_for(cookies, api_domain)

            browser.close()

        return UnifiedTargetProfile(
            endpoint=prof["endpoint"],
            model=prof["model"],
            cookie_header=cookie_header,
            auth_type="same_domain",  # 复用同域 Cookie
            api_domain=api_domain,
            cookie_path=self._cookie_path,
            raw_cookies=cookies,
            api_key=prof.get("api_key"),
            key_source=prof.get("key_source"),
        )

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    @staticmethod
    def _to_playwright_cookies(cookies: list[dict]) -> list[dict]:
        """将统一 Cookie 结构转换为 Playwright add_cookies 格式"""
        out = []
        for c in cookies:
            item = {
                "name": c.get("name", ""),
                "value": c.get("value", ""),
                "domain": c.get("domain", ""),
                "path": c.get("path", "/"),
            }
            if c.get("secure"):
                item["secure"] = True
            if c.get("httpOnly"):
                item["httpOnly"] = True
            expiry = c.get("expiry")
            if expiry and isinstance(expiry, (int, float)) and expiry > 0:
                item["expires"] = expiry
            out.append(item)
        return out

    @staticmethod
    def _is_login_page(page: Any) -> bool:
        """检测当前页是否为登录页（Cookie 过期重定向）"""
        import re as _re
        try:
            if page.query_selector("input[type=password]"):
                return True
            return bool(_re.search(
                r"/(login|signin|auth|passport|sso)",
                page.url,
                _re.IGNORECASE,
            ))
        except Exception:
            return False

    def _run_bootstrap_headless(
        self,
        bootstrap: AuthBootstrap,
        target_url: str,
    ) -> UnifiedTargetProfile:
        """无头模式运行 AuthBootstrap（自动化场景，无人工配合）

        复用 AuthBootstrap.run() 但强制 headless=True。
        通过临时 monkey-patch playwright.launch 参数实现。
        """
        # AuthBootstrap.run() 内部硬编码 headless=False，
        # 此处通过包装 _run 方法注入 headless。
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context()
            page = ctx.new_page()

            try:
                page.goto(target_url, wait_until="load", timeout=30000)
            except Exception:
                logger.warning("页面加载超时（headless），继续后续流程")

            # 等待登录表单
            from .selectors import get_selectors
            sel = get_selectors(target_url, self.auth_cfg.get("selectors"))
            _pw_input = sel.get("password", ["input[type=password]"])[0]
            try:
                page.wait_for_selector(_pw_input, state="visible", timeout=15000)
            except Exception:
                logger.debug("15s 内未检测到密码输入框")

            bootstrap.auth_type = "none"
            if not bootstrap._is_login_page(page):
                logger.info("目标无需认证（auth_type=none）")
            else:
                bootstrap.auth_type = bootstrap._detect_sso_type(page)
                logger.info("检测到认证页，类型=%s（headless）", bootstrap.auth_type)
                bootstrap._fill_credentials(page)
                # headless 模式跳过二次验证（无法人工配合）
                bootstrap._wait_back_to_target(page)

            prof = discover(page, target_url)
            api_domain = api_domain_from_endpoint(prof["endpoint"])

            cookie_header = ""
            cookie_path = None
            raw_cookies: list = []
            if bootstrap.auth_type != "none":
                raw_cookies = ctx.cookies()
                cookie_header = cookie_header_for(raw_cookies, api_domain)
                safe_name = re.sub(r"\W+", "_", urlparse(target_url).netloc)
                cookie_path = str(self.sessions_dir / f"{safe_name}.json")
                save_cookies(raw_cookies, cookie_path)

            browser.close()

        return UnifiedTargetProfile(
            endpoint=prof["endpoint"],
            model=prof["model"],
            cookie_header=cookie_header,
            auth_type=bootstrap.auth_type,
            api_domain=api_domain,
            cookie_path=cookie_path,
            raw_cookies=raw_cookies,
            api_key=prof.get("api_key"),
            key_source=prof.get("key_source"),
        )


def discover_multi_page(
    target_url: str,
    sub_pages: list[str],
    auth_cfg: dict[str, Any] | None = None,
    sessions_dir: str = "sessions",
) -> list[UnifiedTargetProfile]:
    """便捷函数：一次登录，发现多个页面的 API 端点

    :param target_url: 首页 URL（用于登录）
    :param sub_pages: 子页面 URL 列表
    :param auth_cfg: 认证配置
    :param sessions_dir: Cookie 保存目录
    :returns: 各页面的 UnifiedTargetProfile 列表（首个为首页）
    """
    wtd = WebTargetDiscovery(sessions_dir=sessions_dir, auth_cfg=auth_cfg)

    profiles = []
    # 首页（有头模式，人工配合验证码）
    profiles.append(wtd.login_and_discover(target_url, headless=False))

    # 子页面（无头模式，复用 Cookie）
    for sub_url in sub_pages:
        try:
            profiles.append(wtd.discover_subpage(sub_url, headless=True))
        except Exception as exc:
            logger.error("子页面 %s 发现失败: %s", sub_url, exc)
            # 降级：返回一个占位 profile
            profiles.append(UnifiedTargetProfile(
                endpoint="",
                model="unknown-model",
                cookie_header="",
                auth_type="failed",
                api_domain=urlparse(sub_url).netloc,
                api_key=None,
                key_source=None,
            ))

    return profiles
