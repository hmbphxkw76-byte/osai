# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""阶段2: 认证决策 + 执行。

职责 (对应需求):
  根据阶段1的分类结果 (llm_webapp / model_platform, 认证拓扑, 二次验证),
  自动决定使用哪种认证策略并执行认证:

    - model_platform + 有 API Key  → APIKeyAuth (Bearer)
    - model_platform + 无 Key       → NoneAuth (匿名探测)
    - llm_webapp + none             → NoneAuth
    - llm_webapp + same_domain      → PlaywrightAuth (同域登录页)
    - llm_webapp + cross_domain     → PlaywrightAuth (跨域 IdP) + Cookie 回填
    - 含二次验证信号 (otp/sliding/sms/qr) → HumanAssisted 流程 (needs_human=True)

本阶段复用 core.auth.auth_strategy.AuthStrategy 的策略选择逻辑,
并实际执行认证, 将 AuthState 写入 context 供 ReconStage 使用。
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from pipeline.models import AuthDecision, TargetCategory
from pipeline.stages.base import PipelineStage

logger = logging.getLogger(__name__)


class AuthStage(PipelineStage):
    name = "auth"

    async def run(self, context: object) -> AuthDecision:
        ctx = context  # type: ignore[assignment]
        classification = ctx.classification
        if classification is None:
            raise RuntimeError("AuthStage requires classification from ClassifyStage")

        # ── 阶段A: 产生决策 ──
        decision = self._make_decision(classification, ctx)

        # ── 阶段B: 执行认证 ──
        await self._execute_auth(ctx, decision, classification)

        return decision

    def _make_decision(self, classification, ctx) -> AuthDecision:
        """产生认证决策 (原逻辑)。"""
        decision = AuthDecision()

        # 模型平台: 优先 API Key
        if classification.category == TargetCategory.MODEL_PLATFORM:
            if ctx.api_key:
                decision.strategy_name = "APIKeyAuth"
                decision.api_key_env = "API_KEY"
                decision.reason = "Model platform with API key present → Bearer auth"
            else:
                decision.strategy_name = "NoneAuth"
                decision.reason = "Model platform without API key → anonymous probe"
            return decision

        # LLM Web App (或未知)
        if classification.auth_topology == "none":
            decision.strategy_name = "NoneAuth"
            decision.reason = "No auth required (directly accessible)"
            return decision

        if classification.auth_topology == "same_domain":
            decision.strategy_name = "PlaywrightAuth"
            decision.needs_browser = True
            decision.login_url = classification.detection_signals and _extract_login_url(
                classification.detection_signals
            ) or ctx.target_url
            decision.reason = "Same-domain login detected → Playwright auth flow"
            if classification.second_factor != "none":
                decision.needs_human = True
                decision.reason += f" (second factor: {classification.second_factor})"
            return decision

        if classification.auth_topology == "cross_domain":
            decision.strategy_name = "PlaywrightAuth"
            decision.needs_browser = True
            decision.idp_url = _extract_login_url(classification.detection_signals) or ""
            decision.reason = "Cross-domain SSO/IdP detected → Playwright + cookie replay"
            if classification.second_factor != "none":
                decision.needs_human = True
            return decision

        # 兜底: 用户显式 auth_type_hint
        if ctx.auth_type_hint and ctx.auth_type_hint not in ("auto",):
            hint = ctx.auth_type_hint
            if hint in ("otp", "sliding", "sms", "qr"):
                decision.strategy_name = "PlaywrightAuth"
                decision.needs_browser = True
                decision.needs_human = True
                decision.reason = f"User hint second-factor auth ({hint})"
            elif hint == "same_domain":
                decision.strategy_name = "PlaywrightAuth"
                decision.needs_browser = True
                decision.login_url = ctx.target_url
                decision.reason = "User hint same_domain auth"
            elif hint == "cross_domain":
                decision.strategy_name = "PlaywrightAuth"
                decision.needs_browser = True
                decision.idp_url = ctx.target_url
                decision.reason = "User hint cross_domain auth"
            elif hint == "none":
                decision.strategy_name = "NoneAuth"
                decision.reason = "User hint no auth"
            return decision

        decision.strategy_name = "NoneAuth"
        decision.reason = "Fallback: no clear auth requirement"
        return decision

    async def _execute_auth(self, ctx: Any, decision: AuthDecision, classification: Any) -> None:
        """根据决策实际执行认证, 将 AuthState 写入 ctx。"""
        from core.auth.platform_auth import PlatformAuthStrategy
        from core.auth.provider import APIKeyAuthProvider, NoAuthProvider
        from core.models.auth_state import AuthState

        if decision.strategy_name == "APIKeyAuth" and ctx.api_key:
            # G14: 厂商级认证 — 根据 platform_vendor 选择认证方式
            vendor = classification.platform_vendor.value if classification.platform_vendor else "generic"
            if vendor not in ("unknown", "generic"):
                provider = PlatformAuthStrategy(
                    vendor=vendor,
                    api_key=ctx.api_key,
                )
                logger.info(f"[auth] PlatformAuthStrategy for vendor={vendor}")
            else:
                provider = APIKeyAuthProvider(api_key=ctx.api_key, use_bearer=True)
            ctx.auth_state = await provider.authenticate(ctx.target_url)
            logger.info(f"[auth] APIKeyAuth executed, authenticated={ctx.auth_state.is_authenticated()}")

        elif decision.strategy_name == "PlaywrightAuth" and ctx.browser_page is not None:
            # 使用 ClassifyStage 保留的浏览器会话执行认证
            ctx.auth_state = await self._execute_playwright_auth(ctx, decision, classification)
            logger.info(f"[auth] PlaywrightAuth executed, authenticated={ctx.auth_state.is_authenticated()}")

        elif decision.strategy_name == "PlaywrightAuth" and ctx.browser_page is None:
            # 浏览器不可用, 降级为无认证
            logger.warning(
                "[auth] PlaywrightAuth requires browser but none available; "
                "falling back to NoAuth"
            )
            provider = NoAuthProvider()
            ctx.auth_state = await provider.authenticate(ctx.target_url)

        else:
            provider = NoAuthProvider()
            ctx.auth_state = await provider.authenticate(ctx.target_url)
            logger.info("[auth] NoAuth executed")

    async def _execute_playwright_auth(
        self, ctx: Any, decision: AuthDecision, classification: Any,
    ) -> Any:
        """执行浏览器认证, 含二次验证自动感知。

        复用 ClassifyStage 保留的 browser_page, 动态生成检测配置,
        调用 AuthStrategy 执行认证, 返回 AuthState。
        """
        from core.auth.auth_detector import AuthDetector, URLPatternStrategy, DOMElementStrategy
        from core.auth.auth_strategy import AuthStrategyFactory
        from core.auth.human_assisted_auth import HumanAssistedAuth
        from core.auth.models import DetectionConfig
        from core.models.auth_state import AuthState

        page = ctx.browser_page
        target_url = ctx.target_url
        target_domain = urlparse(target_url).netloc
        target_path = urlparse(target_url).path

        # 动态生成检测配置 — G12: 根据 platform_vendor 调整选择器
        vendor = classification.platform_vendor.value if classification.platform_vendor else "unknown"
        vendor_selectors = self._get_vendor_detection_selectors(vendor)
        pattern = target_domain + (target_path if target_path and target_path != "/" else "")
        detector = AuthDetector(
            strategies=[
                URLPatternStrategy(pattern=pattern),
                DOMElementStrategy(selector=vendor_selectors[0], timeout_seconds=300),
                DOMElementStrategy(selector=vendor_selectors[1], timeout_seconds=300),
                DOMElementStrategy(selector='[class*="chat"]', timeout_seconds=300),
                DOMElementStrategy(selector='textarea', timeout_seconds=300),
            ],
            timeout_seconds=300,
        )

        # 构建 auth 配置
        auth_type = classification.auth_topology
        if auth_type == "none":
            auth_type = "same_domain"  # 降级

        login_url = decision.login_url or target_url
        human_steps = []
        if classification.second_factor != "none":
            sf = classification.second_factor
            if sf in ("otp", "2fa"):
                human_steps.append("otp")
            elif sf == "sliding":
                human_steps.append("slider")
            elif sf == "sms":
                human_steps.append("otp")
            elif sf == "qr":
                human_steps.append("qr_scan")

        class _AuthConfig:
            type: str = auth_type
            target_url: str = target_url
            login_url: str = login_url
            auto_fill: dict[str, str] | None = None
            human_assisted_steps: list[str] | None = human_steps or None

        class _Profile:
            auth = _AuthConfig()

            def get_detection_configs(self) -> list[DetectionConfig]:
                return [
                    DetectionConfig(strategy="url_pattern", pattern=pattern),
                    DetectionConfig(strategy="dom_element", selector='[class*="chat"]'),
                ]

        # 执行认证
        human_auth = HumanAssistedAuth()

        # 导航到登录页
        logger.info(f"[auth] navigating to login URL: {login_url}")
        await page.goto(login_url, wait_until="domcontentloaded")

        # 提示人工
        if human_steps:
            human_auth._print_human_instructions(human_steps)

        # 轮询检测认证完成
        logger.info("[auth] waiting for authentication completion (incl. second factor)...")
        is_complete = await detector.wait_for_completion(page)
        if not is_complete:
            logger.warning("[auth] authentication did not complete within timeout")
        else:
            logger.info("[auth] authentication completed, navigating to target URL")
            await page.goto(target_url, wait_until="domcontentloaded")

        # 提取 AuthState
        cookies: list[dict[str, Any]] = []
        storage_state: dict[str, Any] = {}
        browser_session = ctx.browser_session

        if browser_session and browser_session.context:
            context = browser_session.context
            try:
                raw_cookies = await context.cookies()
                cookies = [
                    {
                        "name": c.get("name", ""),
                        "value": c.get("value", ""),
                        "domain": c.get("domain", ""),
                        "path": c.get("path", "/"),
                    }
                    for c in raw_cookies
                ]
            except Exception as e:
                logger.debug(f"[auth] error extracting cookies: {e}")

            try:
                import tempfile, json, os
                with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
                    tmp_path = f.name
                await context.storage_state(path=tmp_path)
                with open(tmp_path, encoding="utf-8") as f:
                    storage_state = json.load(f)
                os.unlink(tmp_path)
            except Exception as e:
                logger.debug(f"[auth] error extracting storage state: {e}")

        return AuthState(
            auth_type=f"playwright:{auth_type}",
            cookies=cookies,
            headers={},
            tokens={},
            storage_state=storage_state,
            browser_context=browser_session.context if browser_session else None,
        )

    # G12: 厂商级认证完成检测选择器
    _VENDOR_DETECTION_SELECTORS: dict[str, tuple[str, str]] = {
        "openai": ('textarea[data-id="root"]', 'nav[aria-label="Chat history"]'),
        "zhipu": ('textarea[placeholder*="输入"]', 'div[class*="chat-container"]'),
        "deepseek": ('textarea[placeholder*="发送"]', 'div[class*="chat-input"]'),
        "moonshot": ('textarea[class*="chat"]', 'div[class*="conversation"]'),
        "qwen": ('textarea[placeholder*="输入"]', 'div[class*="chat-window"]'),
        "doubao": ('textarea[class*="chat-input"]', 'div[class*="chat-content"]'),
        "baichuan": ('textarea[placeholder*="消息"]', 'div[class*="chat-box"]'),
        "spark": ('textarea[class*="chat"]', 'div[class*="dialogue"]'),
        "minimax": ('textarea[placeholder*="发送"]', 'div[class*="chat-container"]'),
        "ollama": ('textarea[placeholder*="Send"]', 'div[class*="chat"]'),
        "lm_studio": ('textarea[placeholder*="Message"]', 'div[class*="chat"]'),
    }

    def _get_vendor_detection_selectors(self, vendor: str) -> tuple[str, str]:
        """G12: 根据厂商返回认证完成检测选择器。

        Args:
            vendor: PlatformVendor 的 value 字符串

        Returns:
            (primary_selector, secondary_selector) 元组
        """
        return self._VENDOR_DETECTION_SELECTORS.get(
            vendor,
            ('[class*="chat-input"]', '[class*="message-input"]'),
        )


def _extract_login_url(signals: list[str]) -> str:
    """从 detection_signals 中提取登录/IdP URL。"""
    for sig in signals:
        if sig.startswith("login_url_detected="):
            return sig.split("=", 1)[1]
        if "http" in sig and ("login" in sig or "idp" in sig or "sso" in sig or "authorize" in sig):
            # 取第一个 http(s) URL
            import re
            m = re.search(r"https?://[^\s'\"]+", sig)
            if m:
                return m.group(0)
    return ""
