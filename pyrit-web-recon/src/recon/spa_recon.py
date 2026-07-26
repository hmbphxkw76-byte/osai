# -*- coding: utf-8 -*-
"""
SPA Recon
=========

单页应用（SPA）AI 聊天界面侦察引擎。

执行流程：
  1. 登录页检测
  2. 聊天入口发现与点击
  3. DOM 输入框 / 发送按钮 / 响应区检测
  4. 网络流量拦截与 LLM API 识别
  5. 探测消息发送（Enter / 按钮 / 父容器）
  6. 生成 TargetProfile
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from src.auth import CredentialExtractor
from src.dom import DOMDetector
from src.network import HTTPInterceptor
from src.utils import wait_for_manual_login

from .target_profile import TargetProfile

logger = logging.getLogger(__name__)


class SPARecon:
    """SPA AI 聊天界面侦察器"""

    DEFAULT_CONFIG = {
        # 选择器查找超时（毫秒）
        "selector_timeout_ms": 5000,
        # 探测消息文本
        "send_probe_text": "你好，请介绍一下你自己。",
        # 显式聊天入口选择器（若已知）
        "entry_selector": "",
        # 是否启用聊天入口自动发现
        "enable_entry_discovery": True,
        # 是否自动尝试发送探测消息
        "enable_probe_send": True,
        # 发送后等待响应时间（毫秒）
        "post_send_wait_ms": 3000,
        # 最大重试次数
        "max_retries": 2,
        # 是否在检测到登录页时等待人工完成登录
        "manual_login": False,
        # 人工登录最大等待时间（毫秒），默认 5 分钟
        "manual_login_timeout_ms": 300000,
        # 登录完成轮询间隔（毫秒）
        "manual_login_poll_ms": 2000,
        # 自动检测成功后是否仍需用户按 Enter 确认
        "manual_login_require_enter": True,
        # 显式指定登录页 URL（如 https://passport.jd.com/...）
        # 用于起始页与登录页跨域的场景：www.jd.com -> passport.jd.com -> www.jd.com
        "login_url": "",
    }

    def __init__(
        self,
        browser_manager: Any,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.browser = browser_manager
        self.config = {**self.DEFAULT_CONFIG, **(config or {})}
        self.page = None

    async def run(self, url: str) -> TargetProfile:
        """
        执行完整 SPA 侦察流程。

        支持两种登录场景：
          A. 起始页即登录页：直接在该页等待人工登录
          B. 起始页需要跳转到登录页：www.jd.com -> passport.jd.com -> www.jd.com
             通过 --login-url 指定登录页，登录完成后自动回到起始页

        步骤：
          1. 登录页检测 / 跳转登录页 / 人工登录等待
          2. 确保回到目标域
          3. 聊天入口发现（如需要）
          4. DOM 元素检测
          5. 网络流量拦截
          6. 探测消息发送
          7. 保存 storage_state / 截图
          8. 生成 TargetProfile
        """
        profile = TargetProfile(target=url, target_type="spa")
        self.page = self.browser.page
        if not self.page:
            raise RuntimeError("Browser not started")

        # 基础指纹
        profile.fingerprint.url = self.page.url
        profile.fingerprint.title = await self.page.title()
        from src.auth import extract_domain_from_url

        profile.fingerprint.domain = extract_domain_from_url(self.page.url)

        detector = DOMDetector(self.page, self.config)

        # 1. 处理登录流程
        login_handled = await self._handle_login_flow(url, detector, profile)
        if not login_handled:
            return profile

        # 确保当前在目标域（跨域登录后可能仍留在登录页，需要导航回目标页）
        await self._ensure_target_page(url)

        # 重新初始化 detector 与基础指纹（页面可能已变化）
        detector = DOMDetector(self.page, self.config)
        profile.fingerprint.url = self.page.url
        profile.fingerprint.title = await self.page.title()
        profile.fingerprint.domain = extract_domain_from_url(self.page.url)

        # 2. 网络拦截
        interceptor = HTTPInterceptor(self.page, self.config)
        await interceptor.start()

        # 3. 聊天入口发现（如果需要）
        chat_entry = {"selector": "", "source": "none", "score": 0.0}
        if self.config.get("enable_entry_discovery", True):
            from src.dom import discover_chat_entry

            chat_entry = await discover_chat_entry(
                self.page,
                yaml_selector=self.config.get("entry_selector", ""),
                timeout_ms=self.config.get("selector_timeout_ms", 5000),
            )
            if chat_entry["selector"]:
                try:
                    el = await self.page.query_selector(chat_entry["selector"])
                    if el:
                        await el.scroll_into_view_if_needed()
                        await el.click(timeout=5000)
                        await self.page.wait_for_timeout(1500)
                        logger.info("Chat entry clicked: %s", chat_entry["selector"])
                except Exception as e:
                    logger.warning("Failed to click chat entry: %s", str(e)[:120])

        # 4. DOM 检测
        detection = await detector.detect_all()
        profile.fingerprint.detected_selectors = detection
        profile.add_entry_point(
            entry_type="web_ui",
            selector=detection["input_selector"],
            score=detection["input_score"],
            extra={
                "send_selector": detection["send_selector"],
                "send_score": detection["send_score"],
                "response_selector": detection["response_selector"],
                "response_score": detection["response_score"],
                "chat_entry": chat_entry,
            },
        )

        # 5. 发送探测消息
        send_result = None
        if self.config.get("enable_probe_send", True) and detection["input_selector"]:
            send_result = await detector.type_and_send()
            if send_result["success"]:
                await self.page.wait_for_timeout(self.config.get("post_send_wait_ms", 3000))
                profile.add_entry_point(
                    entry_type="probe_success",
                    selector=detection["input_selector"],
                    score=1.0,
                    extra={
                        "send_strategy": send_result["send_strategy"],
                        "response_preview": send_result.get("response", {}).get("response_text", "")[:200],
                    },
                )
            else:
                profile.add_vulnerability(
                    owasp_category="LLM07:2025 - Denial of Service",
                    description="Could not successfully send a probe message to the LLM chat interface.",
                    evidence={"error": send_result.get("error", "")},
                    risk_level="low",
                    remediation="Check selector accuracy or manual authentication.",
                )

        # 6. 再次捕获网络流量中的响应文本
        await interceptor.stop()
        llm_endpoints = interceptor.get_llm_endpoints()
        profile.fingerprint.llm_api_endpoints = llm_endpoints
        profile.fingerprint.model_name = interceptor.get_model_name()
        profile.fingerprint.protocols = interceptor.get_protocols()
        profile.fingerprint.rag_features = interceptor.get_rag_features()
        profile.fingerprint.agent_features = interceptor.get_agent_features()
        profile.fingerprint.extracted_credentials = interceptor.get_extracted_credentials()

        # 如果拦截流量中提取到 Authorization，追加保存凭据
        if profile.fingerprint.extracted_credentials:
            try:
                extractor = CredentialExtractor()
                await extractor.extract_from_browser(
                    self.browser.context,
                    url,
                    captured_entries=interceptor.captured,
                )
            except Exception as e:
                logger.warning("Failed to save credentials from intercepted traffic: %s", str(e)[:120])

        # WebSocket 帧记录
        ws_frames = interceptor.get_websocket_frames()
        if ws_frames:
            profile.raw_results["websocket_frames"] = ws_frames

        for ep in llm_endpoints:
            profile.add_entry_point(
                entry_type="api",
                url=ep.get("url", ""),
                api_type=ep.get("api_type", ""),
                model_name=ep.get("model_name", ""),
                score=0.95,
                extra={
                    "method": ep.get("method"),
                    "status": ep.get("response_status"),
                    "protocol": ep.get("protocol"),
                    "rag_features": ep.get("rag_features", []),
                    "agent_features": ep.get("agent_features", []),
                    "api_keys": ep.get("api_keys", []),
                },
            )

        # 7. 攻击面推断
        surfaces = self._infer_surfaces(profile, chat_entry, detection)
        profile.surfaces = surfaces

        # 8. 保存状态
        try:
            storage_path = await self.browser.save_storage_state()
            profile.raw_results["storage_state_path"] = storage_path
            screenshot_path = await self.browser.screenshot()
            profile.raw_results["screenshot_path"] = screenshot_path
        except Exception as e:
            logger.warning("Failed to save state/screenshot: %s", str(e)[:120])

        # 9. 风险定级
        profile.risk_level = profile.classify_risk()
        return profile

    async def _handle_login_flow(
        self,
        url: str,
        detector: DOMDetector,
        profile: TargetProfile,
    ) -> bool:
        """
        处理登录流程。

        返回 True 表示可以继续侦察，False 表示应终止。
        """
        is_login = await detector.is_login_page()

        # 场景 A：起始页就是登录页
        if is_login:
            return await self._wait_for_login_on_current_page(url, detector, profile)

        # 如果已经发现聊天输入框，不需要登录
        detection = await detector.detect_all()
        if detection.get("input_selector"):
            logger.info("Chat input detected on initial page, skipping login flow")
            return True

        # 场景 B：提供了显式 login_url，直接导航到登录页
        login_url = self.config.get("login_url", "")
        if login_url:
            print(f"\n  🔗 导航到登录页: {login_url}")
            await self.page.goto(login_url, wait_until="networkidle", timeout=60000)
            await self.page.wait_for_timeout(1500)
            detector = DOMDetector(self.page, self.config)
            return await self._wait_for_login_on_current_page(url, detector, profile)

        # 场景 C：尝试在起始页发现登录入口并点击
        login_entry = await self._find_login_entry()
        if login_entry:
            try:
                print(f"\n  🔗 点击登录入口: {login_entry}")
                el = await self.page.query_selector(login_entry)
                if el:
                    await el.scroll_into_view_if_needed()
                    await el.click(timeout=5000)
                    await self.page.wait_for_timeout(3000)
                    detector = DOMDetector(self.page, self.config)
                    if await detector.is_login_page():
                        return await self._wait_for_login_on_current_page(url, detector, profile)
            except Exception as e:
                logger.warning("Failed to click login entry: %s", str(e)[:120])

        # 没有登录页也没有登录入口，继续常规侦察
        return True

    async def _wait_for_login_on_current_page(
        self,
        url: str,
        detector: DOMDetector,
        profile: TargetProfile,
    ) -> bool:
        """在当前页面等待人工完成登录"""
        profile.add_vulnerability(
            owasp_category="LLM01:2025 - Prompt Injection",
            description="Target presents a login page before exposing LLM interface. Credentials may be required.",
            evidence={"login_page": True, "current_url": self.page.url},
            risk_level="medium",
            remediation="Provide valid credentials or use --manual-login to complete authentication interactively.",
        )
        profile.fingerprint.notes = "login_page_detected"

        if not self.config.get("manual_login", False):
            logger.info("Login page detected but manual_login is disabled")
            return False

        wait_result = await wait_for_manual_login(
            self.page,
            detector,
            timeout_ms=self.config.get("manual_login_timeout_ms", 300000),
            poll_interval_ms=self.config.get("manual_login_poll_ms", 2000),
            require_enter=self.config.get("manual_login_require_enter", True),
            target_url=url,
        )
        profile.raw_results["manual_login_wait"] = wait_result

        if not wait_result["login_resolved"]:
            print("  ❌ 登录未完成或超时，侦察终止。")
            return False

        # 登录完成后保存 storage_state
        try:
            storage_path = await self.browser.save_storage_state()
            profile.raw_results["storage_state_path_after_login"] = storage_path
            print(f"  💾 登录后状态已保存: {storage_path}")
        except Exception as e:
            logger.warning("Failed to save storage state after login: %s", str(e)[:120])

        # 自动提取并保存凭据到 credentials/{domain}.txt，供后续复用
        try:
            extractor = CredentialExtractor()
            cred_path = await extractor.extract_from_browser(self.browser.context, url)
            if cred_path:
                profile.raw_results["extracted_credentials_path"] = cred_path
                profile.fingerprint.auth_mode = "cookie"
                print(f"  🔑 凭据已自动提取并保存: {cred_path}")
        except Exception as e:
            logger.warning("Failed to extract credentials after login: %s", str(e)[:120])

        print("  🚀 登录完成，继续侦察流程...")
        return True

    async def _ensure_target_page(self, url: str) -> None:
        """确保当前页面回到目标 URL，用于跨域登录后返回"""
        from src.auth import extract_domain_from_url

        target_domain = extract_domain_from_url(url)
        current_domain = extract_domain_from_url(self.page.url)

        if not target_domain or current_domain == target_domain:
            return

        print(f"\n  ↩️  当前在 {current_domain}，准备返回目标域 {target_domain}")
        try:
            await self.page.goto(url, wait_until="networkidle", timeout=60000)
            await self.page.wait_for_timeout(2000)
            print(f"  ✅ 已回到目标页: {self.page.url}")
        except Exception as e:
            logger.warning("Failed to navigate back to target page: %s", str(e)[:120])

    async def _find_login_entry(self) -> Optional[str]:
        """在起始页发现登录入口选择器"""
        login_selectors = [
            "a[href*='login']",
            "a[href*='passport']",
            "a[href*='signin']",
            "a[href*='auth']",
            "button:has-text('登录')",
            "button:has-text('登陆')",
            "button:has-text('Sign in')",
            "button:has-text('Login')",
            "a:has-text('登录')",
            "a:has-text('登陆')",
            "a:has-text('Sign in')",
            "a:has-text('Login')",
            "[class*='login']",
            "[class*='signin']",
            "[class*='user-login']",
        ]
        for selector in login_selectors:
            try:
                el = await self.page.query_selector(selector)
                if el and await el.is_visible():
                    return selector
            except Exception:
                continue
        return None

    def _infer_surfaces(
        self,
        profile: TargetProfile,
        chat_entry: Dict[str, Any],
        detection: Dict[str, Any],
    ) -> List[str]:
        """根据侦察结果推断攻击面"""
        surfaces: List[str] = []
        has_chat = bool(detection.get("input_selector"))
        has_api = bool(profile.fingerprint.llm_api_endpoints)
        has_rag = bool(profile.fingerprint.rag_features)
        has_agent = bool(profile.fingerprint.agent_features)

        if has_chat:
            surfaces.append("prompt_injection")
            surfaces.append("jailbreak")
        if has_api:
            surfaces.append("api_prompt_injection")
            surfaces.append("model_extraction")
        if has_rag:
            surfaces.append("rag_poisoning")
            surfaces.append("knowledge_base_extraction")
        if has_agent:
            surfaces.append("agent_tool_misuse")
            surfaces.append("mcp_hijacking")
        if chat_entry.get("selector"):
            entry_signals = str(chat_entry.get("signals", "")).lower()
            if any(kw in entry_signals for kw in ["knowledge", "rag", "知识库", "doc"]):
                surfaces.append("rag_poisoning")
            if any(kw in entry_signals for kw in ["agent", "智能体", "copilot"]):
                surfaces.append("agent_tool_misuse")

        # 去重保持顺序
        seen = set()
        unique = []
        for s in surfaces:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        return unique
