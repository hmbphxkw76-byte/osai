# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""阶段2: 认证决策。

职责 (对应需求):
  根据阶段1的分类结果 (llm_webapp / model_platform, 认证拓扑, 二次验证),
  自动决定使用哪种认证策略:

    - model_platform + 有 API Key  → APIKeyAuth (Bearer)
    - model_platform + 无 Key       → NoneAuth (匿名探测)
    - llm_webapp + none             → NoneAuth
    - llm_webapp + same_domain      → PlaywrightAuth (同域登录页)
    - llm_webapp + cross_domain     → PlaywrightAuth (跨域 IdP) + Cookie 回填
    - 含二次验证信号 (otp/sliding/sms/qr) → HumanAssisted 流程 (needs_human=True)

本阶段复用 core.auth.auth_strategy.AuthStrategy 的策略选择逻辑,
但本身不执行认证 (认证在 ReconSession 内由 orchestrator 调用),
只产出决策供下游使用, 保持阶段解耦。
"""

from __future__ import annotations

import logging

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
