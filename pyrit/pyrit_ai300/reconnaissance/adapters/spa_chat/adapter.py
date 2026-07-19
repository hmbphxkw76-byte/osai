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

        async with async_playwright() as p:
            # ── 0. 认证预检（HTTP 请求验证，在浏览器启动前执行） ──
            # 读取 credentials 文件 → 用 HTTP 请求携带认证头访问目标 URL → 显示认证状态
            preflight = await self._preflight_auth_check(
                p, config, target_url, findings, errors
            )
            result_data["preflight_auth_check"] = preflight

            # ── 1. 启动浏览器 ──
            logger.info("Launching browser: %s (headless=%s)", browser_type, headless)
            launch_kwargs: Dict[str, Any] = {"headless": headless}
            if browser_type == "firefox":
                browser = await p.firefox.launch(**launch_kwargs)
            elif browser_type == "webkit":
                browser = await p.webkit.launch(**launch_kwargs)
            else:
                browser = await p.chromium.launch(**launch_kwargs)

            context_kwargs: Dict[str, Any] = {
                "ignore_https_errors": ignore_https,
                # 视口大小通过 new_context 参数设置（Playwright 不支持 set_default_viewport_size）
                "viewport": {"width": 1280, "height": 800},
            }

            # 加载 storage_state（如有）
            storage_state = login_config.get("storage_state")
            if storage_state and os.path.exists(storage_state):
                context_kwargs["storage_state"] = storage_state
                logger.info("Loaded storage_state from: %s", storage_state)

            context = await browser.new_context(**context_kwargs)

            page = await context.new_page()

            # ── 2. 注册网络流量捕获 ──
            page.on("request", traffic.on_request)
            page.on("response", traffic.on_response)

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

                    # 导航到目标页面
                    try:
                        await page.goto(target_url, wait_until="networkidle", timeout=30000)
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
            if not auth_succeeded:
                # 尝试从 credentials/ 目录复用已有凭据（兼容旧流程）
                cached_auth_ok = False
                if login_mode not in ("manual", "oauth"):
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

                        # 导航到登录页/目标页
                        try:
                            await page.goto(login_url, wait_until=connection.get("wait_until", "networkidle"))
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
                            await self._login_manual(page, login_config, errors)
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
                        await page.goto(target_url, wait_until="networkidle", timeout=30000)
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
                    await page.goto(target_url, wait_until="networkidle", timeout=15000)
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

            # ── 4.5 自动发现聊天 DOM 选择器（v1.4 新增）──
            # 入口点击后或聊天页确认后，自动发现 input/send_button/response 选择器
            # 降级链：自动发现 > YAML 配置 > 硬编码默认值
            auto_selectors = await self._auto_detect_selectors(page, target_url, selectors)
            selectors = auto_selectors
            result_data["auto_detected_selectors"] = auto_selectors

            # ── 5. 发送探测消息 ──
            probe_enabled = probe_config.get("enabled", True)
            probe_messages = probe_config.get("messages")
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
            logger.info(
                "Traffic captured: %d requests, %d LLM API calls, %d RAG calls",
                traffic_summary["total_requests"],
                traffic_summary["llm_api_calls"],
                traffic_summary["rag_api_calls"],
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
                # 显示所有 LLM 端点
                all_llm_urls = traffic_summary.get("llm_endpoints", [])
                if len(all_llm_urls) > 1:
                    print("     📋 其他 LLM 端点:")
                    for ep_url in all_llm_urls[1:5]:
                        print("        • %s" % ep_url[:80])
            else:
                # 没有捕获到 LLM API 调用
                print("\n  🤖 AI 应用端点: ❌ 未检测到 LLM API 调用")
                print("     可能原因: 聊天窗口未打开 / 消息未发送 / API 通过 WebSocket 调用")
                findings.append({
                    "category": "no_llm_api_detected",
                    "severity": "low",
                    "description": "未检测到 LLM API 调用。请调整聊天入口选择器或探测消息。",
                    "evidence": "总请求数: %d" % traffic_summary['total_requests'],
                    "owasp_mapping": "",
                    "confidence": 0.5,
                })

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

    # ── 登录方法 ──

