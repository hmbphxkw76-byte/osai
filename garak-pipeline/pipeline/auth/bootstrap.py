"""Playwright 半自动认证引导 — 从目标 URL 到已认证会话

流程：
  1. 打开目标 URL
  2. 判定是否需要认证（同域 / 跨域 SSO / 无认证）
  3. 自动填充用户名 + 密码
  4. 人工配合二次验证：OTP / 图形验证码 / 行为滑窗 / 扫码
  5. 等待跳回目标域（跨域 SSO 场景）
  6. 登录成功后自动侦察模型 endpoint + 模型名
  7. 导出 Cookie 文件 + 生成 UnifiedTargetProfile

设计约束：
  - 用户名/密码自动填（从环境变量读取），不落盘
  - 所有二次验证均为人工配合（input 阻塞），不接打码/OTP 自动求解
  - 跨域场景只在跳回目标域后才抓 Cookie，保证拿到最终认证态
"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .cookie_session import api_domain_from_endpoint, save_cookies
from .model_probe import discover
from .selectors import get_selectors

logger = logging.getLogger(__name__)


class UnifiedTargetProfile:
    """认证引导产出的统一目标画像，供下游流水线消费"""

    def __init__(
        self,
        endpoint: str,
        model: str,
        cookie_header: str,
        auth_type: str,
        api_domain: str,
        cookie_path: str | None = None,
        raw_cookies: list | None = None,
        api_key: str | None = None,
        key_source: str | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.model = model
        self.cookie_header = cookie_header
        self.auth_type = auth_type          # none | same_domain | cross_domain
        self.api_domain = api_domain
        self.cookie_path = cookie_path
        self.raw_cookies = raw_cookies or []
        self.api_key = api_key              # 嗅探到的 API key（可能绕过 Cookie）
        self.key_source = key_source        # 凭据来源（localStorage / 请求头 / JS bundle）

    @property
    def has_api_key(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    def to_target_dict(self) -> dict[str, Any]:
        """转换为流水线 target 段（含 auth 子段）

        优先级：嗅探到的 api_key > Cookie 认证
        若拿到 api_key，auth 段用 static 模式（StaticKeyProvider），
        否则回退 cookie_file。
        """
        if self.has_api_key:
            # 有 API key：直接用 static 认证，绕过 Cookie
            return {
                "endpoint": self.endpoint,
                "model": self.model,
                "api_key": self.api_key,
                "auth": {"type": "static"},
                "_key_source": self.key_source or "unknown",
            }

        # 无 API key：走 Cookie 认证
        auth: dict[str, Any] = {"type": "none" if self.auth_type == "none" else "cookie_file"}
        if self.auth_type != "none":
            auth["cookie_source"] = self.cookie_path or ""
            auth["cookie_domain"] = self.api_domain
        return {
            "endpoint": self.endpoint,
            "model": self.model,
            "api_key": "",
            "auth": auth,
        }


class AuthBootstrap:
    """Playwright 半自动认证引导器"""

    def __init__(
        self,
        target_url: str,
        cfg: dict[str, Any] | None = None,
        sessions_dir: str = "sessions",
    ) -> None:
        self.target_url = target_url
        self.cfg = cfg or {}
        self.sessions_dir = Path(sessions_dir)
        self.username_env = self.cfg.get("username_env", "TARGET_USERNAME")
        self.password_env = self.cfg.get("password_env", "TARGET_PASSWORD")
        self.selector_overrides = self.cfg.get("selectors")
        self.auth_type: str | None = None

    # ------------------------------------------------------------------
    # 入口
    # ------------------------------------------------------------------
    def run(self) -> UnifiedTargetProfile:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            ctx = browser.new_context()
            page = ctx.new_page()

            try:
                page.goto(self.target_url, wait_until="load", timeout=30000)
            except Exception:
                # load 也可能超时（SPA 持续请求），降级继续
                logger.warning("页面加载超时（wait_until=load），继续后续流程")

            # 等待登录表单出现：跨域 SSO 重定向后 SPA 需要时间渲染 DOM
            # 用条件等待替代盲目 sleep，最多等 15s，每 500ms 检查一次
            sel = get_selectors(self.target_url, self.selector_overrides)
            _pw_input = sel.get("password", ["input[type=password]"])[0]
            try:
                page.wait_for_selector(_pw_input, state="visible", timeout=15000)
                logger.debug("检测到密码输入框（%s），登录表单已渲染", _pw_input)
            except Exception:
                logger.debug("15s 内未检测到密码输入框，目标可能无需认证")
                pass

            if not self._is_login_page(page):
                logger.info("目标无需认证（auth_type=none）")
                self.auth_type = "none"
            else:
                self.auth_type = self._detect_sso_type(page)
                logger.info("检测到认证页，类型=%s", self.auth_type)
                self._fill_credentials(page)
                self._handle_second_factor(page)
                # 等待跳离登录域，回到目标域
                self._wait_back_to_target(page)

            # 登录成功后侦察模型信息（已登录 page 携带同源 Cookie）
            # 打印当前页信息便于跨域排查
            current_url = page.url
            current_domain = urlparse(current_url).netloc
            target_domain = urlparse(self.target_url).netloc
            logger.info(
                "开始模型侦察: 当前页=%s (域=%s), 目标域=%s, auth_type=%s",
                current_url[:80], current_domain, target_domain, self.auth_type,
            )
            if current_domain != target_domain and self.auth_type != "none":
                logger.warning(
                    "当前页域(%s)与目标域(%s)不一致，跨域 SSO 可能未完全跳回。"
                    "聊天面板交互可能失败，将尝试在当前页继续探测。",
                    current_domain, target_domain,
                )

            prof = discover(page, self.target_url)
            api_domain = api_domain_from_endpoint(prof["endpoint"])
            logger.info(
                "模型侦察完成: endpoint=%s model=%s method=%s api_key=%s",
                prof["endpoint"], prof["model"],
                prof.get("method", "unknown"),
                "yes" if prof.get("api_key") else "no",
            )

            cookie_header = ""
            cookie_path = None
            raw_cookies: list = []
            if self.auth_type != "none":
                raw_cookies = ctx.cookies()
                from .cookie_session import cookie_header_for
                cookie_header = cookie_header_for(raw_cookies, api_domain)
                # 落盘 Cookie（权限 600）
                safe_name = re.sub(r"\W+", "_", urlparse(self.target_url).netloc)
                cookie_path = str(self.sessions_dir / f"{safe_name}.json")
                save_cookies(raw_cookies, cookie_path)

            browser.close()

        return UnifiedTargetProfile(
            endpoint=prof["endpoint"],
            model=prof["model"],
            cookie_header=cookie_header,
            auth_type=self.auth_type,
            api_domain=api_domain,
            cookie_path=cookie_path,
            raw_cookies=raw_cookies,
            api_key=prof.get("api_key"),
            key_source=prof.get("key_source"),
        )

    # ------------------------------------------------------------------
    # 认证判定
    # ------------------------------------------------------------------
    def _is_login_page(self, page: Any) -> bool:
        if page.query_selector("input[type=password]"):
            return True
        return bool(re.search(r"/(login|signin|auth|passport|sso)", page.url, re.I))

    def _detect_sso_type(self, page: Any) -> str:
        cur = urlparse(page.url).netloc
        tgt = urlparse(self.target_url).netloc
        return "cross_domain" if cur and cur != tgt else "same_domain"

    # ------------------------------------------------------------------
    # 凭证填充（自动）
    # ------------------------------------------------------------------
    def _fill_credentials(self, page: Any) -> None:
        from pipeline.env import get_env

        sel = get_selectors(self.target_url, self.selector_overrides)
        user = get_env(self.username_env, "")
        pwd = get_env(self.password_env, "")
        if not user or not pwd:
            logger.warning(
                "未设置 %s / %s 环境变量，将以交互方式请手动输入",
                self.username_env, self.password_env,
            )
            user = input("请输入用户名: ") or user
            pwd = input("请输入密码: ") or pwd

        self._fill_first_match(page, sel["username"], user, label="用户名")
        self._fill_first_match(page, sel["password"], pwd, label="密码")
        self._click_first_match(page, sel["submit"], label="提交按钮")

    @staticmethod
    def _fill_first_match(page: Any, selectors: list[str], value: str, label: str) -> bool:
        for s in selectors:
            try:
                el = page.query_selector(s)
                if el and el.is_visible():
                    el.fill(value)
                    logger.debug("填充%s: %s", label, s)
                    return True
            except Exception:
                continue
        logger.warning("未找到%s输入框（尝试过的选择器: %s）", label, selectors[:3])
        return False

    @staticmethod
    def _click_first_match(page: Any, selectors: list[str], label: str) -> bool:
        for s in selectors:
            try:
                el = page.query_selector(s)
                if el and el.is_visible():
                    el.click()
                    logger.debug("点击%s: %s", label, s)
                    return True
            except Exception:
                continue
        logger.warning("未找到%s（尝试过的选择器: %s）", label, selectors[:3])
        return False

    # ------------------------------------------------------------------
    # 二次验证（人工配合）
    # ------------------------------------------------------------------
    def _handle_second_factor(self, page: Any) -> None:
        sel = get_selectors(self.target_url, self.selector_overrides)

        # OTP / 动态码
        otp_el = self._first_visible(page, sel["otp"])
        if otp_el:
            code = input("🔢 检测到 OTP/动态码输入框，请输入后回车: ")
            otp_el.fill(code)
            self._click_first_match(page, sel["submit"], "提交按钮")

        # 图形验证码
        cap_img = self._first_visible(page, sel["captcha_img"])
        if cap_img:
            shot = str(self.sessions_dir / "captcha.png")
            self.sessions_dir.mkdir(parents=True, exist_ok=True)
            cap_img.screenshot(path=shot)
            code = input(f"🖼️  已截图 {shot}，请输入验证码后回车: ")
            self._fill_first_match(page, sel["captcha_input"], code, "验证码")
            self._click_first_match(page, sel["submit"], "提交按钮")

        # 行为滑窗
        if self._first_visible(page, sel["slider"]):
            input("🎚️  请手动完成滑窗验证后回车: ")
            self._click_first_match(page, sel["submit"], "提交按钮")

        # 扫码登录
        if self._first_visible(page, sel["scan_qr"]):
            shot = str(self.sessions_dir / "qr.png")
            self.sessions_dir.mkdir(parents=True, exist_ok=True)
            self._first_visible(page, sel["scan_qr"]).screenshot(path=shot)
            input(f"📱 已截图 {shot}，请扫码并在手机确认后回车: ")
            self._click_first_match(page, sel["submit"], "提交按钮")

    @staticmethod
    def _first_visible(page: Any, selectors: list[str]) -> Any:
        for s in selectors:
            try:
                el = page.query_selector(s)
                if el and el.is_visible():
                    return el
            except Exception:
                continue
        return None

    # ------------------------------------------------------------------
    # 等待回到目标域（跨域 SSO 关键）
    # ------------------------------------------------------------------
    def _wait_back_to_target(self, page: Any) -> None:
        tgt = urlparse(self.target_url).netloc
        deadline = time.time() + 60
        while time.time() < deadline:
            cur = urlparse(page.url).netloc
            if cur == tgt:
                # 额外等待可能的客户端跳转/Token 注入
                time.sleep(2)
                logger.info("已跳回目标域 %s，登录完成", tgt)
                return
            time.sleep(1)
        # 超时兜底：主动导航回目标 URL（cookie 已在浏览器上下文中）
        logger.warning(
            "60s 内未自动跳回目标域 %s（当前 %s），主动导航回目标 URL",
            tgt, page.url,
        )
        try:
            page.goto(self.target_url, wait_until="networkidle", timeout=30000)
            cur = urlparse(page.url).netloc
            if cur == tgt:
                time.sleep(2)
                logger.info("主动导航已回到目标域 %s", tgt)
                return
            logger.warning("主动导航后仍在 %s，将以此为当前页继续", cur)
        except Exception as exc:
            logger.warning("主动导航回目标域失败: %s", exc)
