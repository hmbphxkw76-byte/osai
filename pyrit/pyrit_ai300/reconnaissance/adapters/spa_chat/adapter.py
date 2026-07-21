# -*- coding: utf-8 -*-
"""
SPA Chat Recon - 主适配器（编排逻辑）

SPAChatReconAdapter: SPA 智能助手侦察适配器主类

通过 Playwright 浏览器自动化：
1. 登录目标 SPA 应用（SSO / 账号密码 / 手动 / OAuth）
2. 导航到智能助手聊天界面
3. 捕获网络流量识别后端 LLM API
4. 发送探测消息提取模型信息
5. 输出标准化 TargetProfile 数据

设计原则：
  - 薄壳模式：仅做侦察，不执行攻击
  - 零侵入：不修改目标应用状态
  - 可配置：通过 YAML 配置选择器、登录凭证、探测策略
  - 容错：单步失败不影响整体流程
  - 广覆盖：内置多种入口选择器和认证模式

模块化结构（spa_chat/ 包）：
  - constants.py          : 常量定义（选择器/关键词/模式）
  - traffic_capture.py    : 网络流量捕获（NetworkTrafficCapture）
  - auth_mixin.py         : 认证 Mixin（SSO/credentials/preflight/captcha）
  - dom_mixin.py          : DOM 侦测 Mixin（选择器评分/自动检测）
  - chat_entry_mixin.py   : 聊天入口点击 Mixin
  - probe_mixin.py        : 探测消息 + LLM 信息提取 Mixin
  - adapter.py            : 本文件，主类编排逻辑

PyRIT 0.14.0 兼容
"""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from ..base_adapter import AdapterResult, BaseAdapter
from .traffic_capture import NetworkTrafficCapture
from .auth_mixin import AuthMixin
from .dom_mixin import DOMMixin
from .chat_entry_mixin import ChatEntryMixin
from .probe_mixin import ProbeMixin
from .constants import (
    DEFAULT_CHAT_ENTRY_SELECTORS,
    OIDC_CALLBACK_WHITELIST,
    PROBE_MESSAGES,
    STEALTH_LAUNCH_ARGS,
    HUMAN_BEHAVIOR_SIM,
)

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

logger = logging.getLogger(__name__)


class SPAChatReconAdapter(BaseAdapter, AuthMixin, DOMMixin, ChatEntryMixin, ProbeMixin):
    """
    SPA 智能助手侦察适配器

    通过 Playwright 浏览器自动化：
    1. 登录目标 SPA 应用
    2. 导航到智能助手聊天界面
    3. 捕获网络流量识别后端 LLM API
    4. 发送探测消息提取模型信息
    5. 输出标准化 TargetProfile 数据

    配置示例（config/targets/spa_target.yaml）：
        target:
          type: playwright
          connection:
            url: "https://example.com/#/home"
            browser: chromium
            headless: false
          login:
            mode: credentials          # credentials / header_file / storage_state / manual / oauth / cookies / raw_headers
            url: "https://example.com/#/login"
            username: "student001"
            password: "password123"
            selectors:
              username_input: "#username, input[name='username']"
              password_input: "#password, input[name='password']"
              submit_button: "button[type='submit'], .login-btn"
          chat_entry:
            mode: selector             # selector / auto / none
            selector: ""               # 留空则使用内置 DEFAULT_CHAT_ENTRY_SELECTORS
            wait_after_click: 3000
          selectors:
            input: "textarea, input[type='text']"
            send_button: "button[type='submit'], .send-btn"
            response: ".response, .ai-message"
          probe:
            enabled: true
            messages:
              - "你好"
              - "你是什么模型？"
    
    chat_entry.mode 说明：
        - selector  : 通过 selector 定位并点击入口按钮（默认）
        - auto      : 自动检测 - 先检查 URL 是否为聊天页，再检查 DOM 是否已含聊天元素，
                      若是则跳过点击；否则使用 selector 或 DEFAULT_CHAT_ENTRY_SELECTORS
        - none      : 跳过入口点击（适用于页面本身即是聊天页，如 qianwen.com/chat）
    
    login.mode 说明：
        - credentials  : 账号密码自动登录（含验证码检测）
        - sso          : SSO/OIDC 单点登录（跨域认证 + 验证码 + 回调等待）
        - header_file  : 从 F12 复制的 Headers 文件注入（Cookie/Bearer）
        - storage_state: 使用之前保存的浏览器状态 JSON
        - manual       : 用户手动登录后按 Enter 继续
        - oauth        : 第三方 OAuth 登录（支付宝/微信等），手动完成后按 Enter
        - cookies      : 直接在 YAML 中内联 Cookie 字符串
        - raw_headers  : 直接在 YAML 中内联原始 Headers 文本
    """

    @property
    def name(self) -> str:
        return "spa_chat_recon"

    def check_available(self) -> bool:
        """检查 Playwright 是否可用"""
        try:
            import playwright  # noqa: F401
            return True
        except ImportError:
            return False

    @staticmethod
    async def _goto_resilient(page: Any, url: str, timeout: int = 30000) -> None:
        """弹性导航：先尝试 networkidle，超时后降级到 domcontentloaded。

        解决问题：千问、京东等高流量站点持续有后台请求（心跳/统计/WebSocket），
        networkidle 永远不会触发，导致 30s 超时。
        策略：先试 networkidle（理想情况），超时则降级 domcontentloaded（保证 DOM 可用）。
        """
        try:
            await page.goto(url, wait_until="networkidle", timeout=timeout)
        except Exception as e:
            err_str = str(e)
            # 仅对超时降级，其他错误（如导航中断）直接抛出
            if "Timeout" in err_str or "timeout" in err_str.lower():
                logger.warning(
                    "Navigation timeout with networkidle, falling back to domcontentloaded: %s",
                    err_str[:100],
                )
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=min(timeout, 15000))
                except Exception as e2:
                    logger.warning("Fallback navigation also failed: %s", str(e2)[:100])
                    # 不抛出，让调用方继续（页面可能已部分加载）
            else:
                logger.warning("Navigation error (non-timeout): %s", err_str[:100])

    def run(self, target: str, config: dict) -> AdapterResult:
        """
        执行 SPA 智能助手侦察

        Args:
            target: 目标 URL（如 https://student.syxy.ouchn.cn/#/home）
            config: 配置字典，包含 login / chat_entry / selectors / probe 等

        Returns:
            AdapterResult，data 包含 model_name / entry_points / surfaces 等
        """
        start_time = time.time()

        if not self.check_available():
            return AdapterResult(
                tool=self.name,
                success=False,
                errors=["Playwright not installed. Install with: pip install playwright && playwright install chromium"],
            )

        # 合并配置
        full_config = self._merge_config(target, config)

        data: Dict[str, Any] = {
            "target": target,
            "detected_protocols": [],
            "surfaces": ["prompt"],
            "entry_points": [],
            "provider": None,
            "model_name": None,
            "model_family": None,
            "capabilities": [],
            "auth_required": True,
            "auth_type": None,
            "auth_details": {},
            "system_prompt_leaked": False,
            "system_prompt": None,
            "rag_endpoints": [],
            "agent_frameworks": [],
            "model_capabilities": {},
            "traffic_summary": {},
            "probe_responses": [],
        }

        findings: List[Dict[str, Any]] = []
        errors: List[str] = []

        try:
            # 通过 run_async 桥接异步 Playwright API
            from ....utils.async_helper import run_async
            result = run_async(self._execute_recon(full_config, data, findings, errors))

            if result:
                data.update(result)

            duration = time.time() - start_time
            return AdapterResult(
                tool=self.name,
                success=True,
                data=data,
                findings=findings,
                errors=errors,
                duration=duration,
            )

        except Exception as e:
            duration = time.time() - start_time
            logger.error("SPA chat recon failed: %s", str(e), exc_info=True)
            errors.append(str(e))
            return AdapterResult(
                tool=self.name,
                success=False,
                data=data,
                findings=findings,
                errors=errors,
                duration=duration,
            )

    def _merge_config(self, target: str, config: dict) -> dict:
        """合并目标 URL 和配置"""
        merged = dict(config)
        connection = merged.get("connection", {})
        if not connection.get("url"):
            connection["url"] = target
        merged["connection"] = connection
        return merged

    async def _execute_recon(
        self,
        config: dict,
        data: Dict[str, Any],
        findings: List[Dict[str, Any]],
        errors: List[str],
    ) -> Dict[str, Any]:
        """
        执行侦察的核心异步逻辑

        流程：
        1. 启动浏览器
        2. 登录认证
        3. 导航到智能助手
        4. 捕获网络流量
        5. 发送探测消息
        6. 分析结果
        """
        from playwright.async_api import async_playwright

        connection = config.get("connection", {})
        # ── 兼容新旧配置格式 ──
        # 新格式 (spa_target.yaml): target.auth + target.spa.chat_entry + target.spa.selectors
        # 旧格式 (spa_target.yaml v1): target.login + target.chat_entry + target.selectors
        spa_config = config.get("spa", {})
        login_config = config.get("login", {})
        auth_config = config.get("auth", {})
        # 合并 login 和 auth（auth 优先，新格式覆盖旧格式）
        login_config = {**login_config, **auth_config}
        chat_entry = spa_config.get("chat_entry") or config.get("chat_entry", {})
        probe_config = config.get("probe", {})
        selectors = spa_config.get("selectors") or config.get("selectors", {})

        browser_type = connection.get("browser", "chromium")
        headless = connection.get("headless", True)
        ignore_https = connection.get("ignore_https_errors", True)
        target_url = connection.get("url", "")

        # 网络流量捕获器
        traffic = NetworkTrafficCapture()

        result_data: Dict[str, Any] = {}

        # 初始化聊天入口选择器跟踪变量
        self._chat_entry_hit_selector: str = ""

        async with async_playwright() as p:
            # ── 0. 认证预检（HTTP 请求验证，在浏览器启动前执行） ──
            # 读取 credentials 文件 → 用 HTTP 请求携带认证头访问目标 URL → 显示认证状态
            preflight = await self._preflight_auth_check(
                p, config, target_url, findings, errors
            )
            result_data["preflight_auth_check"] = preflight

            # ── 1. 启动浏览器（问题④修复：stealth 模式 + 反检测参数） ──
            #
            # 使用 playwright-stealth 开源框架 + Chromium 反检测启动参数，
            # 确保不被京东等反爬网站检测为自动化工具。
            # 参考：playwright-stealth v2.0.3 + OWasp WSTG-07 (Bot Protection)
            logger.info("Launching browser: %s (headless=%s, stealth=enabled)", browser_type, headless)
            launch_kwargs: Dict[str, Any] = {"headless": headless}

            # Chromium 专属：添加反检测启动参数
            if browser_type in ("chromium", "chrome", ""):
                launch_kwargs["args"] = STEALTH_LAUNCH_ARGS

            if browser_type == "firefox":
                browser = await p.firefox.launch(**launch_kwargs)
            elif browser_type == "webkit":
                browser = await p.webkit.launch(**launch_kwargs)
            else:
                browser = await p.chromium.launch(**launch_kwargs)

            # ── 上下文创建：设置真实浏览器指纹（问题④修复） ──
            context_kwargs: Dict[str, Any] = {
                "ignore_https_errors": ignore_https,
                # 视口大小通过 new_context 参数设置（Playwright 不支持 set_default_viewport_size）
                "viewport": {"width": 1280, "height": 800},
                # 真实 User-Agent（避免 HeadlessChrome 标志被检测）
                "user_agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/131.0.0.0 Safari/537.36"
                ),
                # 真实 locale 和 timezone
                "locale": "zh-CN",
                "timezone_id": "Asia/Shanghai",
                # 权限设置（避免权限拒绝被检测）
                "permissions": ["geolocation"],
                # 额外 HTTP 头
                "extra_http_headers": {
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                },
            }

            # 加载 storage_state（如有）
            storage_state = login_config.get("storage_state")
            if storage_state and os.path.exists(storage_state):
                context_kwargs["storage_state"] = storage_state
                logger.info("Loaded storage_state from: %s", storage_state)

            context = await browser.new_context(**context_kwargs)

            page = await context.new_page()

            # ── 应用 playwright-stealth（问题④修复） ──
            # playwright-stealth v2.0.3 会注入多个反检测脚本：
            # - navigator.webdriver = false
            # - chrome.runtime / chrome.app 模拟
            # - navigator.plugins / languages 模拟
            # - WebGL renderer / vendor 模拟
            # - iframe.contentWindow 修补
            try:
                from playwright_stealth import Stealth
                stealth = Stealth()
                await stealth.apply_stealth_async(page)
                logger.info("playwright-stealth applied successfully")
            except ImportError:
                logger.warning("playwright-stealth not installed, running without stealth")
            except Exception as e:
                logger.warning("playwright-stealth apply failed: %s, continuing without", str(e)[:100])

            # ── 人类行为模拟：页面加载后随机鼠标移动（问题④修复） ──
            # 模拟真实用户行为：页面加载后移动鼠标、滚动页面，
            # 避免被行为分析系统检测为机器人。
            try:
                import random as _random
                # 随机鼠标移动（3-5次）
                for _ in range(_random.randint(3, 5)):
                    x = _random.randint(100, 1180)
                    y = _random.randint(100, 700)
                    await page.mouse.move(x, y, steps=_random.randint(3, 8))
                    await page.wait_for_timeout(_random.randint(50, 200))
                logger.debug("Human behavior simulation: mouse movements injected")
            except Exception:
                pass

            # ── 2. 注册网络流量捕获 ──
            page.on("request", traffic.on_request)
            page.on("response", traffic.on_response)
            # ── 2b. WebSocket 流量捕获（v3 新增） ──
            # 某些 AI 平台（如千问）使用 WebSocket 进行实时聊天通信，
            # 需要单独监听 WebSocket 事件
            page.on("websocket", traffic.on_websocket)

            # ── 3. 认证流程（注入即继续策略 v1.6） ──
            #
            # 设计原则（Best Practice）：
            #   1. 预检有效 → 信任预检结果 → 注入凭据 → 导航 → 直接进入侦察
            #      不做浏览器级硬验证（_verify_auth_valid），因为 SPA 客户端重定向
            #      不代表 HTTP 级认证无效。预检 HTTP 200 已证明凭据在传输层有效。
            #   2. SPA 重定向到登录页 → 软检查记录 finding，但不阻塞流程
            #      仍尝试侦察（可能捕获 API 流量、公开内容等）
            #   3. headless=true 时，绝不使用 manual/oauth 等需人工干预的模式
            #      headless 浏览器无可见窗口，人工干预不可能完成
            #   4. 减少用户参与：有凭据就用，无凭据才考虑登录流程

            from ....orchestrators.auth import normalize_domain
            login_mode = login_config.get("mode", "manual")
            login_url = login_config.get("url", target_url)
            auth_errors_before = len(errors)
            target_domain = normalize_domain(target_url)

            print("\n" + "═" * 60)
            print("  🔐 认证阶段（注入即继续策略）")
            print("  目标: %s" % target_url)
            print("  模式: %s" % login_mode)
            print("  浏览器: %s (headless=%s)" % (browser_type, headless))
            print("═" * 60)

            auth_succeeded = False
            auth_level = "none"  # none / partial / full

            # ── 3a. 预检有效 → 注入即继续（信任预检，不阻塞） ──
            # 但如果用户显式配置了主动登录模式（sso/credentials/manual/oauth），
            # 预检的 HTTP 200 可能是 WAF/CDN 层 Cookie 导致的假阳性（SPA 静态壳
            # 不校验应用会话），此时应优先走用户配置的登录流程，不被预检拦截。
            # 参见：OIDC 隐式流场景，真正的 token 在 localStorage 而非 Cookie 中。
            active_login_modes = ("sso", "credentials", "manual", "oauth")
            preflight_bypassed = (
                login_mode in active_login_modes
                and preflight.get("auth_valid")
                and preflight.get("auth_profile")
                and preflight.get("auth_type", "") == "cookie"  # 仅 Cookie 类预检可能假阳性
            )

            if preflight_bypassed:
                logger.info(
                    "Preflight auth_valid but login_mode='%s' with cookie-only auth — "
                    "likely WAF-level cookies, deferring to active login flow",
                    login_mode,
                )
                print("\n  [1/3] 预检通过但仅有 Cookie（可能 WAF 级别），走 %s 登录流程..." % login_mode)
                # 不走 3a 注入分支，直接进入 3b/3c 的登录流程
            elif preflight.get("auth_valid") and preflight.get("auth_profile"):
                print("\n  [1/3] 预检认证有效，注入凭据并继续...")
                try:
                    from ....orchestrators.auth import inject_auth
                    await inject_auth(context, page, preflight["auth_profile"])

                    # 导航到目标页面（弹性导航：networkidle → domcontentloaded 降级）
                    try:
                        await self._goto_resilient(page, target_url, timeout=30000)
                    except Exception as e:
                        logger.warning("Navigation after preflight auth failed: %s", str(e))

                    # 等待 SPA 渲染完成（SPA 可能需要 JS 执行后才重定向）
                    await page.wait_for_timeout(3000)

                    # ── 软检查：SPA 是否重定向到登录页（不阻塞，仅记录） ──
                    current_url = page.url.lower()
                    login_indicators = [
                        "/login", "/signin", "/account/login", "/auth",
                        "#/login", "#/signin", "#login",
                        "passport.", "/connect/authorize",
                    ]
                    # 排除 OIDC 回调路由（#/signin-oidc 是回调，不是登录页）
                    oidc_callback = any(p in current_url for p in OIDC_CALLBACK_WHITELIST)
                    spa_redirect_detected = (
                        any(ind in current_url for ind in login_indicators)
                        and not oidc_callback
                    )

                    if spa_redirect_detected:
                        # SPA 重定向到登录页 — Cookie 可能是 WAF/传输层级别，非应用会话级别
                        # 如果用户配置了主动登录模式，降级到登录流程（3c）
                        if login_mode in active_login_modes:
                            logger.info(
                                "SPA redirected to login page after preflight injection, "
                                "falling back to %s login flow", login_mode
                            )
                            print("  ⚠️  SPA 重定向到登录页，降级到 %s 登录流程..." % login_mode)
                            # 不标记 auth_succeeded，让代码进入 3c 登录流程
                        else:
                            auth_level = "partial"
                            auth_succeeded = True  # 标记成功，让侦察继续
                            print("  ⚠️  SPA 重定向到登录页（Cookie 可能是 WAF 级别，非应用会话级别）")
                            print("     当前 URL: %s" % page.url[:80])
                            print("  ℹ️  将以部分认证状态继续侦察（不要求人工干预）")
                            print("     后端 API 调用可能仍携带注入的 Cookie，有望捕获流量")
                            findings.append({
                                "category": "preflight_auth_partial",
                                "severity": "medium",
                                "description": "Preflight HTTP auth valid but SPA redirected to login. Cookies may be WAF-level only.",
                                "evidence": f"HTTP {preflight.get('http_status')}, SPA URL: {page.url[:100]}",
                                "owasp_mapping": "LLM02",
                                "confidence": 0.7,
                            })
                    else:
                        # SPA 未重定向 — 认证完全有效
                        auth_level = "full"
                        auth_succeeded = True
                        print("  ✅ 预检凭据注入成功，页面未重定向到登录页")
                        print("     当前 URL: %s" % page.url[:80])

                    # 导出凭据（仅在 SPA 未重定向时，说明 Cookie 有效）
                    if not spa_redirect_detected:
                        print("\n  [3/3] 导出凭据...")
                        cred_path = await self._export_credentials(page, context, target_url)
                        if cred_path:
                            result_data["credential_file"] = cred_path
                    else:
                        print("\n  [3/3] 跳过凭据导出（SPA 重定向，Cookie 可能不完整）")
                        print("     建议：从 F12 → Network → 复制包含应用会话的完整 Headers")
                        print("     保存到 credentials/%s.txt 后重新侦察" % target_domain)

                except Exception as e:
                    logger.warning("Preflight auth injection failed: %s", str(e))
                    auth_succeeded = False
                    print("  ⚠️  预检凭据注入异常: %s" % str(e))

            # ── 3b. 预检无效/无预检 → 尝试凭据缓存 → 走认证流程 ──
            #
            # SSO 模式跳过缓存复用：SSO 认证的核心是在 SSO 认证中心（如 passport.xxx.cn）
            # 完成登录，缓存的应用 Cookie/JWT 无法绕过 SSO 登录流程。重复导航到 target_url
            # 只会导致 SPA 多次重定向到 SSO 登录页，触发多次验证码弹出（根因分析 v1.6.1）。
            if not auth_succeeded:
                # 尝试从 credentials/ 目录复用已有凭据（兼容旧流程）
                cached_auth_ok = False
                if login_mode not in ("manual", "oauth", "sso"):
                    print("\n  [1/3] 检查本地凭据缓存...")
                    cached_auth_ok = await self._try_cached_credentials(
                        page, context, target_url, errors
                    )
                    if cached_auth_ok:
                        print("  ✅ 凭据复用成功！跳过登录流程")
                        auth_level = "full"
                    else:
                        print("  ⚠️  本地无可用凭据或凭据已失效")

                if cached_auth_ok:
                    auth_succeeded = True
                    print("\n  [2/3] 跳过（凭据已复用）")
                    print("  [3/3] 导出凭据...")
                    cred_path = await self._export_credentials(page, context, target_url)
                    if cred_path:
                        result_data["credential_file"] = cred_path
                else:
                    # ── 3c. 走完整认证流程 ──
                    # headless 感知：headless=true 时跳过需人工干预的模式
                    interactive_modes = ("manual", "oauth")
                    if headless and login_mode in interactive_modes:
                        print("\n  [2/3] ⏭️  跳过 %s 模式（headless=true，无法人工干预）" % login_mode)
                        print("  [3/3] 跳过凭据导出")
                        print("")
                        print("  💡 建议：")
                        if login_mode == "manual":
                            print("     - 设置 headless: false 后重新运行（可手动登录）")
                        else:
                            print("     - 设置 headless: false 后重新运行（可完成 OAuth）")
                        print("     - 或从 F12 复制 Headers 到 credentials/%s.txt" % target_domain)
                        print("     - 或配置 username/password 走 credentials 模式")
                    else:
                        print("\n  [2/3] 执行认证流程 (%s)..." % login_mode)
                        errors_before_login = len(errors)

                        # 导航到登录页/目标页（复用当前页面，避免重复导航）
                        #
                        # 根因分析 v1.6.1：SSO 模式下，3a 预检降级可能已经导航到
                        # target_url 并重定向到 SSO 登录页。此时 3c 再 page.goto
                        # 会导致 SPA 再次重定向，触发验证码重置。
                        # 修复：检测当前 URL 是否已在登录页，是则跳过导航。
                        current_url_before_login = page.url or ""
                        url_lower = current_url_before_login.lower()
                        already_on_login_page = any(ind in url_lower for ind in (
                            "/account/login", "/login", "/signin",
                            "/connect/authorize", "passport.",
                        ))

                        if already_on_login_page and login_mode == "sso":
                            logger.info(
                                "Already on login page (from 3a fallback), "
                                "skipping navigation: %s",
                                current_url_before_login,
                            )
                            print("  ✅ 当前已在登录页，跳过导航（避免重复触发验证码）")
                        else:
                            try:
                                _wait = connection.get("wait_until", "networkidle")
                                if _wait == "networkidle":
                                    await self._goto_resilient(page, login_url, timeout=30000)
                                else:
                                    await page.goto(login_url, wait_until=_wait)
                            except Exception as e:
                                logger.warning("Initial navigation failed: %s", str(e))

                        if login_mode == "credentials":
                            await self._login_with_credentials(page, login_config, errors)
                        elif login_mode == "sso":
                            await self._login_with_sso(page, login_config, target_url, errors)
                        elif login_mode == "header_file":
                            await self._login_with_header_file(page, context, login_config, errors)
                        elif login_mode == "storage_state":
                            logger.info("Using storage_state authentication")
                            await page.wait_for_timeout(2000)
                        elif login_mode == "oauth":
                            await self._login_with_oauth(page, login_config, errors)
                        elif login_mode == "cookies":
                            await self._login_with_inline_cookies(page, context, login_config, errors)
                        elif login_mode == "raw_headers":
                            await self._login_with_raw_headers(page, context, login_config, errors)
                        elif login_mode == "manual":
                            await self._login_manual(page, login_config, target_url, errors)
                        else:
                            logger.warning("Unknown login mode: %s, skipping", login_mode)

                        # 判断认证是否成功（无新增错误）
                        new_errors = len(errors) - errors_before_login
                        if new_errors == 0:
                            auth_succeeded = True
                            auth_level = "full"
                            print("  ✅ 认证流程完成")

                            # 3c. 认证成功后自动导出凭据（供下次复用）
                            print("\n  [3/3] 导出凭据...")
                            cred_path = await self._export_credentials(page, context, target_url)
                            if cred_path:
                                result_data["credential_file"] = cred_path
                            else:
                                print("  ℹ️  无可导出的 Cookie（可能使用 Token 认证）")
                                print("     如需复用，请从 F12 手动复制 Headers 到 credentials/%s.txt" % target_domain)
                        else:
                            auth_succeeded = False
                            print("  ❌ 认证失败（%d 个错误）" % new_errors)
                            for e in errors[errors_before_login:]:
                                print("     - %s" % e)

            # ── 3d. 认证状态总结 + 降级模式处理 ──
            result_data["auth_succeeded"] = auth_succeeded
            result_data["auth_level"] = auth_level

            if auth_succeeded:
                # 确保在目标页面（认证后可能还在登录页或中间页）
                if target_domain and target_domain not in page.url.lower():
                    logger.info("Post-auth redirect to target: %s", target_url)
                    try:
                        await self._goto_resilient(page, target_url, timeout=30000)
                        await page.wait_for_timeout(2000)
                    except Exception as e:
                        logger.warning("Post-auth navigation failed: %s", str(e))

                level_label = {"full": "完全认证", "partial": "部分认证（SPA 重定向）"}.get(auth_level, "已认证")
                print("\n" + "─" * 60)
                print("  ✅ 认证完成 [%s]，当前页面: %s" % (level_label, page.url[:80]))
                if auth_level == "partial":
                    print("  ℹ️  部分认证模式：Cookie 在 HTTP 层有效但 SPA 可能重定向")
                    print("     后端 API 调用仍携带注入的 Cookie，侦察将正常进行")
                print("─" * 60 + "\n")
            else:
                # 无认证降级模式：不终止流程，继续有限侦察
                print("\n" + "!" * 60)
                print("  ⚠️  无认证降级模式")
                print("!" * 60)
                print("  认证失败，将以未认证状态继续侦察。")
                print("  局限性说明：")
                print("    - 无法访问需认证的 AI 聊天界面")
                print("    - 可能无法捕获 LLM API 端点")
                print("    - 仅能检测公开页面和未保护的接口")
                print("    - 攻击阶段需要认证才能发送 payload")
                print("")
                if headless:
                    print("  当前为 headless 模式，已跳过人工干预步骤。")
                    print("  建议：")
                    print("    1. 从 F12 复制 Request Headers 到 credentials/%s.txt" % target_domain)
                    print("    2. 重新运行侦察（系统将自动复用凭据）")
                    print("    3. 或设置 headless: false + 配置 username/password 走自动认证")
                else:
                    print("  建议：")
                    print("    1. 检查 credentials/%s.txt 是否存在且有效" % target_domain)
                    print("    2. 从 F12 复制 Request Headers 到 credentials/ 目录")
                    print("    3. 或配置 username/password 走 credentials 模式")
                    print("    4. 或使用 manual 模式手动登录后按 Enter")
                print("!" * 60 + "\n")

                # 尝试导航到目标页面（即使未认证，也可能有公开内容）
                try:
                    await self._goto_resilient(page, target_url, timeout=15000)
                    await page.wait_for_timeout(2000)
                except Exception as e:
                    logger.warning("Degraded navigation failed: %s", str(e))

                result_data["auth_degraded"] = True
                findings.append({
                    "category": "auth_failure_degraded_mode",
                    "severity": "high",
                    "description": "Authentication failed, running in degraded mode with limited recon capability",
                    "evidence": "Auth errors: " + "; ".join(errors[auth_errors_before:]) if errors else "Unknown",
                    "owasp_mapping": "LLM02",
                    "confidence": 0.9,
                })

            # ── 3.5 登录页检测（认证有效性验证） ──
            # 即使 HTTP 预检通过（WAF/CDN 层 Cookie 有效），
            # SPA 仍可能因应用层 Session/JWT 过期而重定向到登录页
            is_on_login_page = await self._detect_login_page(page)
            if is_on_login_page:
                print("\n" + "!" * 60)
                print("  ⚠️  应用层认证无效 — 页面已重定向到登录页")
                print("!" * 60)
                print("  当前 URL: %s" % page.url[:100])
                print("  HTTP 预检通过（WAF/CDN Cookie 有效），但应用层 Session/JWT 无效")
                print("  影响: 聊天界面探测将被跳过（无聊天入口可点击）")
                print("  建议:")
                print("    1. 在浏览器手动登录 → F12 → Network → 复制完整 Request Headers")
                print("    2. 保存到 config/targets/credentials/%s.txt" % target_domain or "target")
                print("    3. 重新运行侦察")
                print("!" * 60 + "\n")
                logger.warning("Login page detected after auth injection: %s", page.url)
                findings.append({
                    "category": "login_page_redirect",
                    "severity": "high",
                    "description": "Application-layer authentication invalid: page redirected to login page despite HTTP preflight success",
                    "evidence": "Current URL: %s | Auth level: %s" % (page.url, auth_level),
                    "owasp_mapping": "LLM02",
                    "confidence": 0.95,
                })
                result_data["login_page_detected"] = True
                result_data["login_page_url"] = page.url

                # ── 3.6 交互式询问：认证部分失效后是否继续 ──
                # 部分认证信息失效（应用层 Session/JWT 过期）后，将控制权
                # 交还用户：y = 继续后续侦察步骤（降级模式），n = 中止本次侦察。
                print("\n  ❓ 认证部分失效，是否继续后续侦察步骤？")
                print("     y = 继续尝试（降级模式，可能无法获取聊天界面信息）")
                print("     n = 中止本次侦察（建议更新凭据后重新运行）")
                user_continue = await self._prompt_user_continue(
                    "  请选择", default=False
                )
                if not user_continue:
                    print("\n  ⏹️  用户选择中止侦察。")
                    print("  ──────────────────────────────────────────")
                    print("  建议: 更新 config/targets/credentials/ 下的凭据后重新运行")
                    result_data["auth_aborted_by_user"] = True
                    logger.info(
                        "User chose to abort recon due to login page detection"
                    )
                    return result_data
                else:
                    print("  ▶️  继续执行（降级模式）...\n")
                    result_data["auth_user_acknowledged"] = True
                    logger.info(
                        "User chose to continue despite login page detection"
                    )

            # ── 3.7 多步导航支持（问题⑤修复） ──
            #
            # 某些平台（如京东）登录后不会自动跳转到 AI 聊天页面，
            # 需要手动导航到特定的聊天页面 URL。
            # 支持两种配置方式：
            #   1. chat_page_url: 单个 URL（导航到指定聊天页）
            #   2. nav_steps: URL 列表（多步导航，依次访问每个 URL）
            #
            # 配置示例：
            #   spa:
            #     chat_entry:
            #       chat_page_url: "https://www.jd.com/..."
            #   或：
            #   spa:
            #     chat_entry:
            #       nav_steps:
            #         - "https://www.jd.com/"
            #         - "https://www.jd.com/ai-chat"
            chat_page_url = chat_entry.get("chat_page_url", "")
            nav_steps = chat_entry.get("nav_steps", [])

            if nav_steps and isinstance(nav_steps, list):
                # 多步导航：依次访问每个 URL
                print("\n  🧭 多步导航 (%d 步)" % len(nav_steps))
                print("  ──────────────────────────────────────────")
                for i, nav_url in enumerate(nav_steps):
                    if not isinstance(nav_url, str) or not nav_url:
                        continue
                    print("  [%d/%d] 导航到: %s" % (i + 1, len(nav_steps), nav_url[:80]))
                    logger.info("Multi-step nav [%d/%d]: %s", i + 1, len(nav_steps), nav_url)
                    try:
                        await self._goto_resilient(page, nav_url, timeout=30000)
                        await page.wait_for_timeout(2000)
                        # 人类行为模拟：每次导航后随机鼠标移动
                        try:
                            import random as _r
                            for _ in range(_r.randint(2, 4)):
                                await page.mouse.move(
                                    _r.randint(100, 1180),
                                    _r.randint(100, 700),
                                    steps=_r.randint(3, 6),
                                )
                                await page.wait_for_timeout(_r.randint(100, 300))
                        except Exception:
                            pass
                    except Exception as e:
                        logger.warning("Nav step %d failed: %s", i + 1, str(e))
                        print("  ⚠️ 导航失败: %s" % str(e)[:60])
                print("  ──────────────────────────────────────────\n")
                result_data["multi_step_nav"] = len(nav_steps)

            elif chat_page_url:
                # 单 URL 导航
                print("\n  🧭 导航到聊天页面: %s" % chat_page_url[:80])
                logger.info("Navigating to chat_page_url: %s", chat_page_url)
                    try:
                        await self._goto_resilient(page, chat_page_url, timeout=30000)
                    await page.wait_for_timeout(2000)
                    # 人类行为模拟
                    try:
                        import random as _r
                        for _ in range(_r.randint(2, 4)):
                            await page.mouse.move(
                                _r.randint(100, 1180),
                                _r.randint(100, 700),
                                steps=_r.randint(3, 6),
                            )
                            await page.wait_for_timeout(_r.randint(100, 300))
                    except Exception:
                        pass
                except Exception as e:
                    logger.warning("chat_page_url navigation failed: %s", str(e))
                    print("  ⚠️ 导航失败: %s" % str(e)[:60])
                result_data["chat_page_url_navigated"] = chat_page_url

            # ── 4. 导航到智能助手 ──
            chat_mode = chat_entry.get("mode", "selector")
            chat_selector = chat_entry.get("selector", "")
            wait_after_click = chat_entry.get("wait_after_click", 3000)

            # 如果未配置 selector，使用内置默认选择器
            if not chat_selector and chat_mode in ("selector", "auto"):
                chat_selector = DEFAULT_CHAT_ENTRY_SELECTORS
                logger.info("Using built-in DEFAULT_CHAT_ENTRY_SELECTORS (%d patterns)",
                            chat_selector.count(",") + 1)

            chat_entry_skipped = False

            if chat_mode == "none":
                # 模式 none：跳过入口点击（页面本身即是聊天页）
                logger.info("chat_entry.mode=none, assuming already on chat page")
                await page.wait_for_timeout(2000)
                chat_entry_skipped = True

            elif chat_mode == "auto":
                # 模式 auto：自动检测页面是否已是聊天页
                is_chat_page = await self._detect_chat_page(page, target_url)
                if is_chat_page:
                    logger.info("chat_entry.mode=auto: detected chat page, skipping entry click")
                    await page.wait_for_timeout(2000)
                    chat_entry_skipped = True
                    findings.append({
                        "category": "chat_page_auto_detected",
                        "severity": "low",
                        "description": "Page auto-detected as chat interface (URL pattern or DOM features matched)",
                        "evidence": f"URL: {page.url}",
                        "owasp_mapping": "",
                        "confidence": 0.85,
                    })
                else:
                    # 不是聊天页，尝试点击入口
                    logger.info("chat_entry.mode=auto: not a chat page, trying entry selector")
                    clicked = await self._try_click_chat_entry(page, chat_selector, wait_after_click, errors, findings, url=target_url)
                    if not clicked:
                        # 入口点击失败，再检测一次是否已是聊天页
                        is_chat_page = await self._detect_chat_page(page, page.url)
                        if is_chat_page:
                            logger.info("After entry click failure, page appears to be chat page")
                            chat_entry_skipped = True
                        else:
                            # ── 交互式：引导用户手工输入聊天入口选择器 ──
                            print("\n  💡 auto 模式未找到聊天入口，扫描页面可交互元素...")
                            entry_snapshot = await self._extract_dom_snapshot(page)
                            entry_candidates = self._score_elements(entry_snapshot, "send_button", target_url)
                            result_data["selector_probe_before"] = {
                                "snapshot": entry_snapshot,
                                "candidates": entry_candidates[:10],
                            }
                            manual_clicked = await self._interactive_chat_entry_retry(
                                page, entry_candidates[:10], wait_after_click,
                                errors, findings, headless=headless,
                            )
                            if manual_clicked:
                                clicked = True

            elif chat_mode == "selector":
                # 模式 selector：通过选择器定位并点击入口
                if chat_selector:
                    clicked = await self._try_click_chat_entry(page, chat_selector, wait_after_click, errors, findings, url=target_url)
                    if not clicked:
                        # 入口点击失败，自动探测页面元素辅助调试
                        print("\n  💡 入口点击失败，扫描页面可交互元素...")
                        entry_snapshot = await self._extract_dom_snapshot(page)
                        entry_candidates = self._score_elements(entry_snapshot, "send_button", target_url)
                        result_data["selector_probe_before"] = {
                            "snapshot": entry_snapshot,
                            "candidates": entry_candidates[:10],
                        }
                        # ── 交互式：引导用户手工输入聊天入口选择器 ──
                        manual_clicked = await self._interactive_chat_entry_retry(
                            page, entry_candidates[:10], wait_after_click,
                            errors, findings, headless=headless,
                        )
                        if manual_clicked:
                            clicked = True
                else:
                    logger.info("No chat_entry selector configured, assuming already on chat page")
                    await page.wait_for_timeout(2000)
                    chat_entry_skipped = True

            # 记录入口是否跳过
            if chat_entry_skipped:
                result_data["chat_entry_skipped"] = True
                result_data["chat_entry_mode"] = chat_mode

            # ── 4.6 记录聊天入口选择器（用于黄金信息报告） ──
            # 优先使用 _try_click_chat_entry 中记录的实际匹配选择器
            hit_selector = getattr(self, "_chat_entry_hit_selector", "")
            if hit_selector:
                result_data["chat_entry_clicked"] = hit_selector
            elif chat_mode == "selector" and chat_selector:
                result_data["chat_entry_clicked"] = chat_selector[:200] if isinstance(chat_selector, str) else ""
            elif chat_mode == "auto":
                result_data["chat_entry_clicked"] = "auto"
            elif chat_mode == "none":
                result_data["chat_entry_clicked"] = "none (已是聊天页)"

            # ── 4.5 自动发现聊天 DOM 选择器（v1.4 新增）──
            # 入口点击后或聊天页确认后，自动发现 input/send_button/response 选择器
            # 降级链：自动发现 > YAML 配置 > 硬编码默认值
            auto_selectors = await self._auto_detect_selectors(page, target_url, selectors)
            selectors = auto_selectors
            result_data["auto_detected_selectors"] = auto_selectors

            # ── 5. 发送探测消息 ──
            probe_enabled = probe_config.get("enabled", True)
            probe_messages = probe_config.get("messages")
            probe_responses: List[Dict[str, str]] = []
            if probe_enabled:
                if probe_messages and isinstance(probe_messages, list):
                    # 使用自定义探测消息
                    probe_list = [{"text": m, "purpose": "custom"} for m in probe_messages if isinstance(m, str)]
                else:
                    probe_list = PROBE_MESSAGES

                probe_responses = await self._send_probe_messages(
                    page, selectors, probe_list, errors, traffic=traffic
                )
                result_data["probe_responses"] = probe_responses

                # 从探测响应中提取模型信息
                model_from_probe = self._extract_model_from_responses(probe_responses)
                if model_from_probe:
                    result_data["model_name_from_probe"] = model_from_probe

            # ── 6. 等待所有网络请求完成 ──
            await page.wait_for_timeout(3000)

            # ── 7. 分析捕获的流量 ──
            traffic_summary = traffic.get_summary()
            result_data["traffic_summary"] = traffic_summary

            # 面向用户的流量摘要
            print("\n  📡 网络流量分析")
            print("  ──────────────────────────────────────────")
            print("     总请求数: %d | LLM API: %d | RAG API: %d" % (
                traffic_summary["total_requests"],
                traffic_summary["llm_api_calls"],
                traffic_summary["rag_api_calls"],
            ))
            # WebSocket 统计（v3 新增）
            ws_count = traffic_summary.get("websocket_connections", 0)
            ws_msgs = traffic_summary.get("websocket_messages", 0)
            if ws_count > 0:
                ws_llm = len(traffic_summary.get("websocket_llm_endpoints", []))
                print("     WebSocket: %d 连接 | %d 消息 | LLM WS: %d" % (ws_count, ws_msgs, ws_llm))
            logger.info(
                "Traffic captured: %d requests, %d LLM API calls, %d RAG calls, "
                "%d WebSocket connections (%d messages)",
                traffic_summary["total_requests"],
                traffic_summary["llm_api_calls"],
                traffic_summary["rag_api_calls"],
                ws_count, ws_msgs,
            )

            # ── 8. 提取 LLM API 信息 ──
            primary_endpoint = traffic.get_primary_llm_endpoint()
            if primary_endpoint:
                result_data.update(self._extract_llm_info(primary_endpoint, findings))
                result_data["entry_points"] = [{
                    "url": primary_endpoint["url"],
                    "method": primary_endpoint["method"],
                    "protocol": "spa_chat_api",
                }]
                # 重点展示 LLM API 端点
                print("\n  🤖 AI 应用端点 (LLM API)")
                print("     ✅ 主端点: %s" % primary_endpoint["url"][:80])
                print("        方法: %s | 状态: %s | 流式: %s" % (
                    primary_endpoint.get("method", ""),
                    primary_endpoint.get("status", ""),
                    "是" if primary_endpoint.get("is_streaming") else "否",
                ))
                if primary_endpoint.get("model_extracted"):
                    print("        模型: %s" % primary_endpoint["model_extracted"])
                if primary_endpoint.get("provider_inferred"):
                    print("        提供商: %s" % primary_endpoint["provider_inferred"])
                if primary_endpoint.get("model_parameters"):
                    params = primary_endpoint["model_parameters"]
                    param_str = ", ".join(f"{k}={v}" for k, v in params.items())
                    print("        参数: %s" % param_str)
                # 显示所有 LLM 端点
                all_llm_urls = traffic_summary.get("llm_endpoints", [])
                if len(all_llm_urls) > 1:
                    print("     📋 其他 LLM 端点:")
                    for ep_url in all_llm_urls[1:5]:
                        print("        • %s" % ep_url[:80])
            else:
                # 没有捕获到 LLM API 调用
                print("\n  🤖 AI 应用端点: ❌ 未检测到 LLM API 调用")
                ws_count = traffic_summary.get("websocket_connections", 0)
                if ws_count > 0:
                    print("     可能原因: API 通过 WebSocket 调用（检测到 %d 个 WS 连接）" % ws_count)
                    ws_llm_urls = traffic_summary.get("websocket_llm_endpoints", [])
                    if ws_llm_urls:
                        print("     📋 LLM WebSocket 端点:")
                        for ws_url in ws_llm_urls[:3]:
                            print("        • %s" % ws_url[:80])
                else:
                    print("     可能原因: 聊天窗口未打开 / 消息未发送 / API 通过 WebSocket 调用")
                findings.append({
                    "category": "no_llm_api_detected",
                    "severity": "low",
                    "description": "未检测到 LLM API 调用。请调整聊天入口选择器或探测消息。",
                    "evidence": "总请求数: %d" % traffic_summary['total_requests'],
                    "owasp_mapping": "",
                    "confidence": 0.5,
                })

            # ── 8.5 直接 API 探测（当流量捕获未提取到模型名时） ──
            # 根因：Playwright 对 SSE 流式 POST 请求的 post_data 和 response.text()
            # 可能返回 None/空，导致模型名和参数无法从流量中提取。
            # 解决方案：通过浏览器 fetch() 直接调用 LLM API，从响应中提取模型信息。
            if primary_endpoint and not primary_endpoint.get("model_extracted"):
                probe_result = await self._direct_api_probe(page, primary_endpoint)
                if probe_result:
                    model_name, provider, model_params = probe_result
                    if model_name:
                        # 更新 primary_endpoint 中的模型信息
                        primary_endpoint["model_extracted"] = model_name
                        primary_endpoint["model_source"] = "direct_probe"
                        primary_endpoint["provider_inferred"] = provider
                        if model_params:
                            primary_endpoint["model_parameters"] = model_params
                        # 同步更新 traffic 中的 llm_api_calls
                        for call in traffic.llm_api_calls:
                            if call.get("url") == primary_endpoint.get("url"):
                                call["model_extracted"] = model_name
                                call["model_source"] = "direct_probe"
                                call["provider_inferred"] = provider
                                if model_params:
                                    call["model_parameters"] = model_params
                                break
                        # 重新提取 LLM 信息（更新 findings）
                        result_data.update(self._extract_llm_info(primary_endpoint, findings))
                        logger.info("Direct API probe extracted model: %s, provider: %s", model_name, provider)

            # ── 8.6 扫描响应容器（探测后页面已有 AI 回复） ──
            response_containers = await self._scan_response_containers(page)
            if response_containers:
                result_data["response_containers"] = response_containers
                # 更新 response 选择器为实际发现的最优选择器
                best_rc = response_containers[0]
                if best_rc.get("class"):
                    cls = best_rc["class"].split()[0]
                    if cls:
                        result_data.setdefault("auto_detected_selectors", {})["response"] = ".%s" % cls
                        result_data["auto_detected_selectors"]["response_source"] = "post_probe"
                        result_data["auto_detected_selectors"]["response_score"] = best_rc.get("textLength", 0)

            # ── 8.6 提取应用名称（从 DOM） ──
            app_name = await self._extract_app_name(page)
            if app_name:
                result_data["app_name"] = app_name

            # ── 8.7 提取 localStorage 认证信息 ──
            local_storage_info = await self._extract_auth_info(page, login_mode)
            if local_storage_info:
                result_data["auth_info"] = local_storage_info

            # ── 9. RAG 端点分析 ──
            if traffic.rag_api_calls:
                rag_endpoints = []
                print("\n  📚 RAG 端点")
                for rag_call in traffic.rag_api_calls:
                    rag_endpoints.append({
                        "name": "spa_rag_endpoint",
                        "path": rag_call["path"],
                        "url": rag_call["url"],
                        "status": rag_call["status"],
                        "surface": "rag",
                        "owasp": "LLM04",
                        "description": "RAG 端点: %s" % rag_call['path'],
                    })
                    print("     • %s (状态: %s)" % (rag_call["path"][:60], rag_call["status"]))
                result_data["rag_endpoints"] = rag_endpoints
                surfaces = result_data.get("surfaces", ["prompt"])
                if "rag" not in surfaces:
                    surfaces.append("rag")
                result_data["surfaces"] = surfaces

                for ep in rag_endpoints:
                    findings.append({
                        "category": "rag_endpoint_exposed",
                        "severity": "medium",
                        "description": ep["description"],
                        "evidence": "端点 %s 返回 %s" % (ep['path'], ep['status']),
                        "owasp_mapping": "LLM04",
                        "confidence": 0.8,
                    })
            print("  ──────────────────────────────────────────\n")

            # ── 10. 从探测响应中检测系统提示泄露 ──
            probe_responses = result_data.get("probe_responses", [])
            for resp in probe_responses:
                if resp.get("purpose") == "system_prompt_leak":
                    text = resp.get("response", "").lower()
                    leak_indicators = [
                        "you are", "system prompt", "instructions",
                        "你的指令", "系统提示", "你是一个",
                    ]
                    if any(ind in text for ind in leak_indicators) and len(resp.get("response", "")) > 50:
                        result_data["system_prompt_leaked"] = True
                        result_data["system_prompt"] = resp.get("response", "")[:2000]
                        findings.append({
                            "category": "system_prompt_leak",
                            "severity": "high",
                            "description": "System prompt may have leaked via probe message",
                            "evidence": resp.get("response", "")[:200],
                            "owasp_mapping": "LLM07",
                            "confidence": 0.75,
                        })
                        break

            # ── 11. 检测到的协议 ──
            if primary_endpoint:
                result_data["detected_protocols"] = ["spa_chat_api"]
                # 推断 API 格式
                req_body = primary_endpoint.get("request_body")
                if req_body and isinstance(req_body, dict):
                    if "messages" in req_body and "model" in req_body:
                        result_data["provider"] = "openai_compatible"
                        result_data["detected_protocols"].append("openai_compatible")
                    elif "messages" in req_body:
                        result_data["provider"] = "custom_chat_api"
                    elif "prompt" in req_body:
                        result_data["provider"] = "custom_completion_api"

            # ── 12. 合并模型信息（流量 + 探测） ──
            model_from_traffic = result_data.get("model_name_from_traffic")
            model_from_probe = result_data.get("model_name_from_probe")
            final_model = model_from_traffic or model_from_probe
            if final_model:
                result_data["model_name"] = final_model
                result_data["model_family"] = self._extract_model_family(final_model)

            # 合并提供商信息
            provider = result_data.get("provider_inferred")
            if provider:
                result_data["provider"] = provider

            # 合并模型参数
            if result_data.get("model_parameters"):
                result_data.setdefault("model_capabilities", {})["parameters"] = result_data["model_parameters"]

            # ── 12.5 确定应用类型（必须在黄金信息报告之前）──
            result_data["app_type"] = self._determine_app_type(
                target_url, traffic, result_data,
            )

            # ── 12.6 生成黄金信息汇总报告 ──
            self._generate_golden_summary(
                page, target_url, result_data, traffic, traffic_summary,
                primary_endpoint, selectors, probe_responses,
            )

            # ── 13. 能力汇总 ──
            capabilities: List[str] = []
            if primary_endpoint:
                if primary_endpoint.get("is_streaming"):
                    capabilities.append("streaming")
                if primary_endpoint.get("has_tools"):
                    capabilities.append("function_calling")
                if primary_endpoint.get("has_vision"):
                    capabilities.append("vision")
            result_data["capabilities"] = capabilities

            # 能力 findings
            if "streaming" in capabilities:
                findings.append({
                    "category": "streaming_supported",
                    "severity": "low",
                    "description": "Target LLM API supports streaming (SSE)",
                    "evidence": "Response content-type: text/event-stream",
                    "owasp_mapping": "",
                    "confidence": 0.9,
                })
            if "function_calling" in capabilities:
                findings.append({
                    "category": "function_calling_enabled",
                    "severity": "medium",
                    "description": "Target supports function calling (ASI03 attack surface)",
                    "evidence": "tools/functions parameter in request body",
                    "owasp_mapping": "ASI03",
                    "confidence": 0.85,
                })

            # ── 14. 认证信息 ──
            if primary_endpoint:
                result_data["auth_type"] = primary_endpoint.get("auth_type", "none")
                result_data["auth_details"] = {
                    "type": primary_endpoint.get("auth_type"),
                    "has_authorization_header": "authorization" in primary_endpoint.get("request_headers", {}),
                    "has_cookie": bool(primary_endpoint.get("request_headers", {}).get("cookie")),
                }

            # ── 14.5 应用类型已在 12.5 设置（提前到黄金信息报告之前）──

            # ── 15. 截图保存（调试用） ──
            screenshot_dir = config.get("screenshot_dir", "results/recon/screenshots")
            try:
                os.makedirs(screenshot_dir, exist_ok=True)
                screenshot_path = os.path.join(
                    screenshot_dir,
                    f"spa_recon_{int(time.time())}.png"
                )
                await page.screenshot(path=screenshot_path, full_page=True)
                result_data["screenshot_path"] = screenshot_path
                logger.info("Screenshot saved: %s", screenshot_path)
            except Exception as e:
                logger.debug("Screenshot failed: %s", str(e))

            # ── 16. 可选：保存 storage_state 供后续复用 ──
            save_storage = config.get("save_storage_state", True)
            if save_storage:
                try:
                    storage_dir = "results/recon/storage_states"
                    os.makedirs(storage_dir, exist_ok=True)
                    storage_path = os.path.join(storage_dir, f"spa_state_{int(time.time())}.json")
                    await context.storage_state(path=storage_path)
                    result_data["storage_state_path"] = storage_path
                    logger.info("Storage state saved: %s", storage_path)
                except Exception as e:
                    logger.debug("Storage state save failed: %s", str(e))

            await browser.close()

        return result_data

    # ── 黄金信息提取方法 ──

    async def _extract_app_name(self, page: Any) -> Optional[str]:
        """
        从 DOM 提取应用名称

        提取策略（按优先级）：
        1. 页面 <title> 标签
        2. 聊天面板标题文本（class 含 chat-title/header/title/name）
        3. 页面主标题（h1/h2）

        Returns:
            应用名称字符串，或 None
        """
        try:
            app_name = await page.evaluate("""() => {
                // 1. 聊天面板标题
                const titleSelectors = [
                    '[class*="chat-title"]', '[class*="chat-header"]',
                    '[class*="chat-name"]', '[class*="assistant-title"]',
                    '[class*="panel-title"]', '[class*="dialog-title"]',
                    '[class*="sidebar-title"]', '[class*="header-title"]',
                ];
                for (const sel of titleSelectors) {
                    const el = document.querySelector(sel);
                    if (el && el.innerText && el.innerText.trim().length > 0) {
                        return el.innerText.trim().substring(0, 100);
                    }
                }
                // 2. 页面标题
                if (document.title && document.title.trim().length > 0) {
                    return document.title.trim().substring(0, 100);
                }
                // 3. h1/h2
                const h1 = document.querySelector('h1');
                if (h1 && h1.innerText && h1.innerText.trim().length > 0) {
                    return h1.innerText.trim().substring(0, 100);
                }
                const h2 = document.querySelector('h2');
                if (h2 && h2.innerText && h2.innerText.trim().length > 0) {
                    return h2.innerText.trim().substring(0, 100);
                }
                return null;
            }""")
            if app_name:
                logger.info("App name extracted: %s", app_name)
            return app_name
        except Exception as e:
            logger.debug("App name extraction failed: %s", str(e))
            return None

    async def _extract_auth_info(self, page: Any, login_mode: str = "") -> Optional[Dict[str, Any]]:
        """
        从 localStorage 提取认证信息

        识别 OIDC 隐式流 token、JWT、Access Token 等。

        OIDC 隐式流特征：
        - localStorage 中存在 id_token / access_token
        - token 为 JWT 格式（以 eyJ 开头，3 段以 . 分隔）
        - 可能存在 userid / user_info 等用户标识
        - 当 login_mode="sso" 时，userid 等用户标识也暗示 OIDC 流

        Args:
            page: Playwright 页面
            login_mode: 登录模式（sso/credentials/manual 等），用于辅助判断

        Returns:
            {"type": "oidc/jwt/token", "key": "...", "preview": "...",
             "storage": "localStorage", "flow": "implicit/..."}
        """
        try:
            auth_info = await page.evaluate("""(loginMode) => {
                const tokenKeywords = [
                    'token', 'access', 'id_token', 'bearer', 'auth', 'jwt', 'userid',
                    'user_id', 'session', 'oidc', 'openid',
                ];
                const items = {};
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    items[key] = localStorage.getItem(key);
                }
                // 优先查找 OIDC 相关 key
                const oidcKeys = ['id_token', 'access_token', 'oidc.user', 'openid'];
                for (const [key, value] of Object.entries(items)) {
                    const keyLower = key.toLowerCase();
                    if (oidcKeys.some(ok => keyLower.includes(ok))) {
                        const isJwt = typeof value === 'string' && value.startsWith('eyJ') && value.split('.').length === 3;
                        return {
                            type: isJwt ? 'oidc' : 'token',
                            key: key,
                            preview: typeof value === 'string' ? value.substring(0, 80) : '',
                            storage: 'localStorage',
                            flow: isJwt ? 'implicit' : 'unknown',
                        };
                    }
                }
                // SSO 模式下，userid / user_id 等也暗示 OIDC 隐式流
                if (loginMode === 'sso') {
                    const ssoUserKeys = ['userid', 'user_id', 'user_info', 'profile', 'session_state'];
                    for (const [key, value] of Object.entries(items)) {
                        const keyLower = key.toLowerCase();
                        if (ssoUserKeys.some(sk => keyLower === sk || keyLower.includes(sk))) {
                            const isJwt = typeof value === 'string' && value.startsWith('eyJ') && value.split('.').length === 3;
                            return {
                                type: 'oidc',
                                key: key,
                                preview: typeof value === 'string' ? value.substring(0, 80) : '',
                                storage: 'localStorage',
                                flow: 'implicit',
                            };
                        }
                    }
                }
                // 通用 token 检测
                for (const [key, value] of Object.entries(items)) {
                    const keyLower = key.toLowerCase();
                    if (tokenKeywords.some(kw => keyLower.includes(kw))) {
                        const isJwt = typeof value === 'string' && value.startsWith('eyJ') && value.split('.').length === 3;
                        return {
                            type: isJwt ? 'jwt' : 'token',
                            key: key,
                            preview: typeof value === 'string' ? value.substring(0, 80) : '',
                            storage: 'localStorage',
                            flow: isJwt ? 'likely_oidc_implicit' : 'unknown',
                        };
                    }
                }
                return null;
            }""", login_mode)
            return auth_info
        except Exception as e:
            logger.debug("Auth info extraction failed: %s", str(e))
            return None

    async def _direct_api_probe(
        self,
        page: Any,
        primary_endpoint: Dict[str, Any],
    ) -> Optional[Tuple]:
        """
        直接 API 探测：通过浏览器 fetch() 直接调用 LLM API 提取模型信息（v2 三重策略）

        根因：某些自定义 API 平台（如 Go 风格封装）在 SSE 响应中不返回 model 字段。
        Playwright 对流式 POST 请求的 post_data 也可能返回 None。

        三重策略（依次尝试）：
        1. 非流式请求 (stream=false)：完整 JSON 响应更可能包含 model 字段
        2. 流式请求 (stream=true) + 增强解析：解析所有 SSE 块 + 正则搜索
        3. 从已捕获的请求体/原始 post_data 中提取（含 Go 风格大写字段名）

        Returns:
            (model_name, provider, model_params) 元组，或 None
        """
        url = primary_endpoint.get("url", "")
        if not url:
            return None

        req_headers = primary_endpoint.get("request_headers") or {}
        req_body = primary_endpoint.get("request_body")

        # 提取 Authorization 头
        auth_header = (
            req_headers.get("authorization")
            or req_headers.get("Authorization")
            or ""
        )

        print("\n  🔬 直接 API 探测（提取模型信息）...")
        print("     端点: %s" % url[:80])
        logger.info("Direct API probe to: %s", url)

        # ── 策略 0: 先从已捕获的请求体中提取 ──
        if req_body and isinstance(req_body, dict):
            model_from_req = self._extract_model_from_request_body(req_body)
            if model_from_req:
                provider = NetworkTrafficCapture._infer_provider(model_from_req, url)
                family = self._extract_model_family(model_from_req)
                model_desc = self._format_model_desc(model_from_req, family)
                print("  ✅ 模型提取成功（来源: 请求体）: %s" % model_desc)
                if provider:
                    print("     提供商: %s" % provider)
                logger.info("Model extracted from request body: %s", model_from_req)
                # 仍尝试获取参数
                params = self._extract_params_from_body(req_body)
                return (model_from_req, provider, params)

        # 也尝试从原始 post_data 字符串中正则提取
        raw_post_data = primary_endpoint.get("post_data") or ""
        if raw_post_data and isinstance(raw_post_data, str):
            model_from_raw = self._regex_extract_model(raw_post_data)
            if model_from_raw:
                provider = NetworkTrafficCapture._infer_provider(model_from_raw, url)
                family = self._extract_model_family(model_from_raw)
                model_desc = self._format_model_desc(model_from_raw, family)
                print("  ✅ 模型提取成功（来源: 原始请求）: %s" % model_desc)
                if provider:
                    print("     提供商: %s" % provider)
                logger.info("Model extracted from raw post_data: %s", model_from_raw)
                return (model_from_raw, provider, None)

        # ── 策略 1: 非流式请求 ──
        body_non_stream = dict(req_body) if req_body and isinstance(req_body, dict) else {}
        body_non_stream["messages"] = [{"role": "user", "content": "1+1=?"}]
        body_non_stream["stream"] = False

        # 从原始请求头中提取 Content-Type（京东等自研 API 使用 form-urlencoded）
        original_ct = (
            req_headers.get("content-type")
            or req_headers.get("Content-Type")
            or "application/json"
        )
        # raw_post_data 用于检测 JD 风格 body=<JSON> 格式
        raw_pd = raw_post_data or ""

        model_name, model_params, body_text = await self._fetch_and_extract(
            page, url, auth_header, body_non_stream, "非流式",
            content_type=original_ct, raw_post_data=raw_pd,
        )

        # ── 策略 1b: 如果 JSON 被 Content-Type 拒绝，用 form-urlencoded 重试 ──
        # 京东等 API 返回 {"code":"1","echo":"request Content-Type is not compatible with application/x-www-form-urlencoded"}
        if not model_name and body_text and "not compatible with application/x-www-form-urlencoded" in body_text:
            logger.info("Original Content-Type rejected, retrying with form-urlencoded")
            print("  🔄 切换到 form-urlencoded 格式重试...")
            model_name, model_params, body_text = await self._fetch_and_extract(
                page, url, auth_header, body_non_stream, "非流式(form)",
                content_type="application/x-www-form-urlencoded", raw_post_data=raw_pd,
            )

        # ── 策略 2: 流式请求（如果非流式未提取到） ──
        if not model_name:
            body_stream = dict(req_body) if req_body and isinstance(req_body, dict) else {}
            body_stream["messages"] = [{"role": "user", "content": "1+1=?"}]
            body_stream["stream"] = True

            model_name, model_params, body_text = await self._fetch_and_extract(
                page, url, auth_header, body_stream, "流式",
                content_type=original_ct, raw_post_data=raw_pd,
            )

            # 流式也尝试 form-urlencoded 降级
            if not model_name and body_text and "not compatible with application/x-www-form-urlencoded" in body_text:
                model_name, model_params, body_text = await self._fetch_and_extract(
                    page, url, auth_header, body_stream, "流式(form)",
                    content_type="application/x-www-form-urlencoded", raw_post_data=raw_pd,
                )

        # ── 策略 3: 从 SPA JavaScript 全局变量中提取 ──
        if not model_name:
            model_name = await self._extract_model_from_js_globals(page)
            if model_name:
                logger.info("Model extracted from JS globals: %s", model_name)

        if model_name:
            provider = NetworkTrafficCapture._infer_provider(model_name, url)
            family = self._extract_model_family(model_name)
            model_desc = self._format_model_desc(model_name, family)
            print("  ✅ 模型提取成功: %s" % model_desc)
            if provider:
                print("     提供商: %s" % provider)
            if model_params:
                param_str = ", ".join(f"{k}={v}" for k, v in model_params.items())
                print("     参数: %s" % param_str)
            return (model_name, provider, model_params if model_params else None)
        else:
            print("  ❌ 所有策略均未提取到模型名")
            if body_text:
                preview = body_text[:300].replace("\n", " ")
                print("     响应预览: %s..." % preview)
                logger.warning("All strategies failed. Response preview: %s", preview)

            # ── 针对 functionId 风格 API（京东等）的提示 ──
            # 京东 API 使用 functionId 参数指定功能，模型名在服务端选择，
            # 不暴露给客户端。这是自研 RPC 框架的特征，不是安全防护。
            if "functionId" in url:
                print("  ℹ️  检测到 functionId 参数（自研 RPC 框架，如京东 api-ai.jd.com）")
                print("     此类 API 的模型选择在服务端完成，请求/响应中不包含 model 字段")
                print("     这是 API 设计特征，不是安全防护措施")

            return None

    async def _fetch_and_extract(
        self,
        page: Any,
        url: str,
        auth_header: str,
        body: dict,
        strategy_label: str,
        content_type: str = "application/json",
        raw_post_data: str = "",
    ) -> Tuple[Optional[str], Dict[str, Any], str]:
        """
        执行 fetch 请求并从响应中提取模型信息

        支持两种 Content-Type：
        - application/json（默认，OpenAI 兼容 API）
        - application/x-www-form-urlencoded（京东等自研 RPC 框架）

        当 Content-Type 为 form-urlencoded 时，支持两种 body 格式：
        1. 直接表单字段（key=value&key=value）
        2. JD 风格 body=<JSON 字符串>（京东 api-ai.jd.com 标准 RPC 格式）

        Args:
            content_type: 请求的 Content-Type（从原始请求头继承）
            raw_post_data: 原始请求体字符串（用于检测 JD 风格 body=<JSON> 格式）

        Returns:
            (model_name, model_params, body_text) 元组
        """
        logger.info("Direct API probe [%s]: %s (Content-Type: %s)", strategy_label, url, content_type)
        try:
            result = await page.evaluate("""async (params) => {
                const { url, authHeader, body, contentType, rawPostData } = params;
                const headers = { "Content-Type": contentType };
                if (authHeader) headers["Authorization"] = authHeader;

                // 根据 Content-Type 构造请求体
                let requestBody;
                if (contentType.includes("x-www-form-urlencoded")) {
                    // ── form-urlencoded 格式 ──
                    // 检测是否是 JD 风格：原始 body 是 body=<JSON> 格式
                    if (rawPostData && rawPostData.startsWith("body=")) {
                        // JD 风格：body=<JSON 字符串>
                        // 替换 JSON 内容但保持外层结构
                        const innerJson = JSON.stringify(body);
                        requestBody = "body=" + encodeURIComponent(innerJson);
                    } else {
                        // 标准表单格式：直接 URL 编码每个字段
                        const formBody = [];
                        for (const key in body) {
                            const val = typeof body[key] === 'object' ? JSON.stringify(body[key]) : String(body[key]);
                            formBody.push(encodeURIComponent(key) + "=" + encodeURIComponent(val));
                        }
                        requestBody = formBody.join("&");
                    }
                } else {
                    // ── JSON 格式（默认） ──
                    requestBody = JSON.stringify(body);
                }

                try {
                    const response = await fetch(url, {
                        method: "POST",
                        headers: headers,
                        body: requestBody,
                    });

                    const contentType = response.headers.get("content-type") || "";
                    const text = await response.text();

                    return {
                        status: response.status,
                        contentType: contentType,
                        body: text.substring(0, 15000),
                        success: true,
                    };
                } catch (e) {
                    return { success: false, error: e.message };
                }
            }""", {"url": url, "authHeader": auth_header, "body": body, "contentType": content_type, "rawPostData": raw_post_data})

            if not result or not result.get("success"):
                error = result.get("error", "unknown") if result else "no result"
                logger.warning("Direct API probe [%s] failed: %s", strategy_label, error)
                return (None, {}, "")

            body_text = result.get("body", "")
            resp_status = result.get("status", 0)
            resp_ct = result.get("contentType", "")

            if not body_text:
                logger.warning("Direct API probe [%s]: empty body (status=%s, ct=%s)",
                               strategy_label, resp_status, resp_ct)
                return (None, {}, "")

            logger.info(
                "Direct API probe [%s] response: status=%s, ct=%s, body_len=%d",
                strategy_label, resp_status, resp_ct, len(body_text),
            )

            # 从响应体提取模型名（增强版 v2）
            model_name = NetworkTrafficCapture._extract_model_from_response_body(body_text)

            # 提取模型参数
            model_params = self._extract_params_from_response(body_text)

            return (model_name, model_params, body_text)

        except Exception as e:
            logger.warning("Direct API probe [%s] exception: %s", strategy_label, str(e)[:200])
            return (None, {}, "")

    @staticmethod
    def _extract_model_from_request_body(req_body: dict) -> Optional[str]:
        """从请求体中提取模型名（兼容标准 + Go 风格字段名）"""
        model_fields = [
            "model", "Model", "MODEL",
            "model_name", "ModelName", "modelName",
            "model_id", "ModelId", "modelId",
        ]
        for field in model_fields:
            val = req_body.get(field)
            if val and isinstance(val, str) and len(val) > 1:
                return val
        # 嵌套字段
        for nested_key in ("extra_body", "ExtraBody", "config", "Config", "options", "Options"):
            nested = req_body.get(nested_key)
            if isinstance(nested, dict):
                for field in model_fields:
                    val = nested.get(field)
                    if val and isinstance(val, str) and len(val) > 1:
                        return val
        return None

    @staticmethod
    def _regex_extract_model(text: str) -> Optional[str]:
        """从原始文本中正则提取模型名"""
        import re as _re
        pattern = r'["\']?(?:model|Model|model_name|ModelName)["\']?\s*:\s*["\']([\w\-.:/]+)["\']'
        matches = _re.findall(pattern, text)
        for match in matches:
            if match.lower() not in ("chat", "completion", "text", "stream", "json"):
                return match
        return None

    @staticmethod
    def _extract_params_from_response(body_text: str) -> Dict[str, Any]:
        """从响应体中提取模型参数"""
        import json as _json
        params: Dict[str, Any] = {}
        param_keys = ("top_p", "temperature", "max_tokens", "stream", "top_k",
                      "frequency_penalty", "presence_penalty")

        try:
            if "data:" in body_text:
                for line in body_text.split("\n"):
                    if line.startswith("data:"):
                        data = line[5:].strip()
                        if data and data != "[DONE]":
                            chunk = _json.loads(data)
                            for k in param_keys:
                                if k in chunk:
                                    params[k] = chunk[k]
                            # 也检查 Go 风格大写
                            go_map = {"TopP": "top_p", "Temperature": "temperature",
                                      "MaxTokens": "max_tokens", "Stream": "stream"}
                            for go_key, py_key in go_map.items():
                                if go_key in chunk:
                                    params[py_key] = chunk[go_key]
                            if params:
                                break
            else:
                parsed = _json.loads(body_text)
                for k in param_keys:
                    if k in parsed:
                        params[k] = parsed[k]
        except Exception:
            pass
        return params

    @staticmethod
    def _extract_params_from_body(req_body: dict) -> Dict[str, Any]:
        """从请求体中提取模型参数"""
        params: Dict[str, Any] = {}
        param_keys = ("top_p", "temperature", "max_tokens", "stream", "top_k",
                      "frequency_penalty", "presence_penalty", "stop", "n", "seed")
        for k in param_keys:
            val = req_body.get(k)
            if val is not None:
                params[k] = val
        return params

    async def _extract_model_from_js_globals(self, page: Any) -> Optional[str]:
        """
        从 SPA 页面的 JavaScript 全局变量中提取模型名

        某些 SPA 应用会在 window 对象或 Vue/React 状态中存储模型配置。
        """
        try:
            result = await page.evaluate("""() => {
                // 搜索 window 对象上的模型相关属性
                const modelKeys = ['model', 'Model', 'modelName', 'model_name',
                                   'modelId', 'model_id', 'currentModel', 'llmModel'];
                const found = [];

                // 1. 直接搜索 window 属性
                for (const key of modelKeys) {
                    if (window[key] && typeof window[key] === 'string') {
                        found.push({source: 'window.' + key, value: window[key]});
                    }
                }

                // 2. 搜索 Vue 实例（如果存在）
                const app = document.querySelector('#app');
                if (app && app.__vue_app__) {
                    const config = app.__vue_app__.config;
                    if (config && config.globalProperties) {
                        const gp = config.globalProperties;
                        for (const key of modelKeys) {
                            if (gp[key] && typeof gp[key] === 'string') {
                                found.push({source: 'vue.' + key, value: gp[key]});
                            }
                        }
                    }
                }

                // 3. 搜索 localStorage 中的模型配置
                for (let i = 0; i < localStorage.length; i++) {
                    const k = localStorage.key(i);
                    if (k && k.toLowerCase().includes('model')) {
                        const v = localStorage.getItem(k);
                        if (v && v.length > 1 && v.length < 100) {
                            found.push({source: 'localStorage.' + k, value: v});
                        }
                    }
                }

                // 4. 搜索 sessionStorage
                for (let i = 0; i < sessionStorage.length; i++) {
                    const k = sessionStorage.key(i);
                    if (k && k.toLowerCase().includes('model')) {
                        const v = sessionStorage.getItem(k);
                        if (v && v.length > 1 && v.length < 100) {
                            found.push({source: 'sessionStorage.' + k, value: v});
                        }
                    }
                }

                return found.length > 0 ? found : null;
            }""")

            if result and isinstance(result, list):
                for item in result:
                    value = item.get("value", "")
                    # 排除明显的非模型名值
                    if value.lower() not in ("chat", "completion", "text", "stream", "json", "true", "false"):
                        logger.info("JS global model candidate: %s (from %s)",
                                    value, item.get("source"))
                        return value
            return None
        except Exception as e:
            logger.debug("JS global extraction failed: %s", str(e)[:100])
            return None

    @staticmethod
    def _extract_model_family(model_name: str) -> str:
        """从模型名称提取家族标识（用于描述和日志）"""
        name_lower = model_name.lower()
        families = [
            ("deepseek", "deepseek"),
            ("gpt", "gpt"),
            ("claude", "claude"),
            ("qwen", "qwen"),
            ("glm", "glm"),
            ("llama", "llama"),
            ("gemini", "gemini"),
            ("moonshot", "moonshot"),
            ("ernie", "ernie"),
            ("spark", "spark"),
            ("hunyuan", "hunyuan"),
            ("baichuan", "baichuan"),
            ("mistral", "mistral"),
            ("yi", "yi"),
            ("phi", "phi"),
            ("gemma", "gemma"),
        ]
        for keyword, family in families:
            if keyword in name_lower:
                return family
        return "unknown"

    @staticmethod
    def _format_model_desc(model_name: str, family: str) -> str:
        """
        生成模型描述字符串（包含家族中文名和版本信息）

        示例：
            deepseek-r1-250120 → "deepseek-r1-250120（DeepSeek R1，250120 版本）"
            gpt-4o → "gpt-4o（OpenAI GPT）"
            qwen-72b → "qwen-72b（通义千问）"
        """
        family_cn = {
            "deepseek": "DeepSeek",
            "gpt": "OpenAI GPT",
            "claude": "Anthropic Claude",
            "qwen": "通义千问",
            "glm": "智谱 GLM",
            "llama": "Meta Llama",
            "gemini": "Google Gemini",
            "moonshot": "月之暗面 Kimi",
            "ernie": "百度文心",
            "spark": "科大讯飞星火",
            "hunyuan": "腾讯混元",
            "baichuan": "百川",
            "mistral": "Mistral",
            "yi": "零一万物",
            "phi": "微软 Phi",
            "gemma": "Google Gemma",
        }.get(family, family)

        # 尝试提取版本号后缀
        import re as _re
        version_match = _re.search(r'-(\d{4,})$', model_name)
        if version_match:
            version = version_match.group(1)
            # deepseek-r1-250120 → "DeepSeek R1，250120 版本"
            if family == "deepseek" and "r1" in model_name.lower():
                return "%s（DeepSeek R1，%s 版本）" % (model_name, version)
            return "%s（%s，%s 版本）" % (model_name, family_cn, version)

        # 特殊处理 deepseek-r1（无版本号）
        if family == "deepseek" and "r1" in model_name.lower():
            return "%s（DeepSeek R1）" % model_name

        return "%s（%s）" % (model_name, family_cn)

    @staticmethod
    def _determine_app_type(
        target_url: str,
        traffic: NetworkTrafficCapture,
        result_data: Dict[str, Any],
    ) -> str:
        """
        确定应用类型

        基于流量特征和 URL 模式判断：
        - Chat（RAG 增强问答）：LLM API 路径含 knowledge/rag/with-knowledge
        - Chat（普通对话）：LLM API 路径含 chat/completions/message
        - Agent：LLM API 请求含 tools/functions
        - Playground：URL 含 playground/studio
        """
        llm_calls = traffic.llm_api_calls
        if llm_calls:
            primary = llm_calls[0]
            path = (primary.get("path") or "").lower()
            req_body = primary.get("request_body") or {}

            if primary.get("has_tools") or req_body.get("tools") or req_body.get("functions"):
                return "Agent（工具调用）"
            if any(kw in path for kw in ("with-knowledge", "rag", "knowledge", "kb")):
                return "Chat（RAG 增强问答）"
            if any(kw in path for kw in ("chat", "completions", "message", "conversation")):
                return "Chat（普通对话）"

        # URL 模式判断
        url_lower = target_url.lower()
        if "playground" in url_lower or "studio" in url_lower:
            return "Playground / Studio"
        if "agent" in url_lower:
            return "Agent"

        return "Chat"

    def _generate_golden_summary(
        self,
        page: Any,
        target_url: str,
        result_data: Dict[str, Any],
        traffic: NetworkTrafficCapture,
        traffic_summary: Dict[str, Any],
        primary_endpoint: Optional[Dict[str, Any]],
        selectors: Dict[str, Any],
        probe_responses: List[Dict[str, str]],
    ) -> None:
        """
        生成黄金信息汇总报告（对标 auto_spa_recon.py 的侦察总结）

        将所有侦察发现整合为一个结构化的终端输出，包括：
        - LLM 端点 / 模型 / 提供商 / 参数
        - 应用类型 / 应用名
        - 聊天入口 / 输入框 / 发送方式 / 响应容器
        - 知识库 / 认证方式
        """
        print("\n" + "═" * 60)
        print("  🏆 侦察成功！关键发现汇总")
        print("═" * 60)

        # ── LLM 端点 ──
        if primary_endpoint:
            method = primary_endpoint.get("method", "")
            url = primary_endpoint.get("url", "")
            print("\n  📌 LLM 端点")
            print("     %s %s" % (method, url))

            # 模型
            model = primary_endpoint.get("model_extracted")
            if model:
                family = self._extract_model_family(model)
                # 生成模型描述（包含版本信息）
                model_desc = self._format_model_desc(model, family)
                print("     模型: %s" % model_desc)
            else:
                print("     模型: (未从请求体提取到 model 字段)")

            # 提供商
            provider = primary_endpoint.get("provider_inferred")
            provider_cn = {
                "volcengine": "火山引擎/字节跳动",
                "deepseek": "DeepSeek",
                "openai": "OpenAI",
                "anthropic": "Anthropic",
                "alibaba": "阿里云",
                "zhipu": "智谱",
                "baidu": "百度",
                "moonshot": "月之暗面",
                "minimax": "MiniMax",
                "custom": "自建平台",
            }.get(provider, provider or "未知")
            print("     提供商: %s" % provider_cn)

            # 参数
            params = primary_endpoint.get("model_parameters")
            if params:
                param_parts = []
                for k in ("top_p", "temperature", "max_tokens", "max_new_tokens", "stream"):
                    if k in params:
                        param_parts.append(f"{k}={params[k]}")
                if param_parts:
                    print("     参数: %s" % ", ".join(param_parts))
        else:
            print("\n  📌 LLM 端点: ❌ 未检测到")

        # ── 应用类型 / 应用名 ──
        app_type = result_data.get("app_type", "Chat")
        print("\n  📌 应用类型: %s" % app_type)
        app_name = result_data.get("app_name")
        if app_name:
            print("     应用名: \"%s\"" % app_name)

        # ── 聊天入口 ──
        print("\n  📌 聊天入口")
        chat_entry_sel = result_data.get("chat_entry_clicked", "")
        if chat_entry_sel:
            print("     选择器: %s" % chat_entry_sel)
        else:
            print("     选择器: (自动检测模式)")

        # ── 输入框 ──
        input_sel = selectors.get("input", "")
        input_src = selectors.get("input_source", "")
        print("     输入框: %s [%s]" % (input_sel[:60], input_src))

        # ── 发送方式 ──
        send_methods = []
        for resp in probe_responses:
            sm = resp.get("send_method", "")
            if sm and sm not in send_methods:
                send_methods.append(sm)
        if send_methods:
            method_cn = {
                "button": "发送按钮",
                "enter": "Enter 键（无独立发送按钮）",
                "container": "父容器点击",
                "failed": "发送失败",
            }
            method_labels = [method_cn.get(m, m) for m in send_methods]
            print("     发送方式: %s" % " / ".join(method_labels))

        # ── 响应容器 ──
        response_containers = result_data.get("response_containers", [])
        if response_containers:
            print("     响应容器:", end="")
            for rc in response_containers[:3]:
                cls = rc.get("class", "")
                if cls:
                    first_cls = cls.split()[0]
                    print(" .%s" % first_cls, end="")
            print()
        else:
            resp_sel = selectors.get("response", "")
            print("     响应容器: %s [%s]" % (resp_sel[:60], selectors.get("response_source", "")))

        # ── 知识库 ──
        rag_endpoints = result_data.get("rag_endpoints", [])
        has_rag = bool(traffic.rag_api_calls) or any(
            "knowledge" in ep.get("url", "").lower() or "rag" in ep.get("url", "").lower()
            for ep in rag_endpoints
        )
        if has_rag:
            print("\n  📌 知识库: 有 RAG")
            # 尝试从响应中提取引用文档名
            for call in traffic.llm_api_calls:
                body = call.get("response_body", "")
                if body and (".xlsx" in body or ".doc" in body or ".pdf" in body):
                    import re
                    docs = re.findall(r'[\u4e00-\u9fa5\w]+\.(?:xlsx|docx?|pdf|csv|txt)', body)
                    if docs:
                        print("     引用文档: %s" % ", ".join(docs[:5]))
                        break
        else:
            print("\n  📌 知识库: 无")

        # ── 认证 ──
        print("\n  📌 认证")
        auth_type = result_data.get("auth_type", "none")
        auth_info = result_data.get("auth_info", {})
        if auth_info:
            flow = auth_info.get("flow", "")
            if flow == "implicit" or auth_info.get("type") == "oidc":
                print("     OIDC 隐式流, token 在 localStorage %s" % auth_info.get("key", ""))
            elif flow == "likely_oidc_implicit":
                print("     JWT token（疑似 OIDC 隐式流）, 在 localStorage %s" % auth_info.get("key", ""))
            else:
                print("     类型: %s, token 在 localStorage %s" % (
                    auth_info.get("type", ""), auth_info.get("key", ""),
                ))
        elif auth_type != "none":
            auth_type_cn = {"bearer": "Bearer Token", "cookie": "Cookie", "basic": "Basic Auth", "api_key": "API Key"}.get(auth_type, auth_type)
            print("     类型: %s" % auth_type_cn)
        else:
            print("     类型: (未检测到)")

        print("\n" + "═" * 60 + "\n")

    # ── 登录方法 ──

