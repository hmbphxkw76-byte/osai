# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""阶段3: 端到端侦察编排。

职责 (对应需求):
  基于阶段1/2 的分类与认证决策, 自动完成后续所有的侦察:
    - LLM 模型探测 (chat-shape / model-list / OpenAPI)
    - RAG 探测 (vector DB / retrieval)
    - Agent 探测 (tool panel)
    - MCP 探测 (tools/resources/prompts)
    - Embedding 探测
    - DOM / JS / Network / 安全头 / 错误泄露 / 一致性 / WAF / 端口 / 对话态 / Token 估算 / 子域
    - 聊天页面导航 (自动发现聊天入口, 进入 LLM 交互页)

全部探针根据目标类别自动选用, 通过 ReconOrchestrator + ReconSession 统一执行,
产物写入 ReconReport (供下游 Export 阶段消费)。

★ 复用 ClassifyStage / AuthStage 保留的浏览器会话和认证态,
  侦察完成后关闭浏览器 (流水线最后一步)。
"""

from __future__ import annotations

import logging

from pipeline.models import TargetCategory
from pipeline.stages.base import PipelineStage

logger = logging.getLogger(__name__)


def session_report_skip(ctx: object) -> object:
    """Return an empty report when RoE gates the run (P1-2-C)."""
    from core.models.recon_report import ReconReport
    report = ReconReport(target_url=getattr(ctx, "target_url", ""))
    report.auth_flow_state = "roe_skip"
    return report


# 不同目标类别默认关注的探针子集 (端到端全覆盖, 此处用于优先级与可选裁剪)
_PROBE_BY_CATEGORY = {
    TargetCategory.MODEL_PLATFORM: [
        "LLMProbe", "OpenAICompatProbe", "EmbeddingProbe", "RAGProbe",
        "MCPProbe", "ErrorAnalyzerProbe", "SecurityHeaderProbe",
        "ResponseConsistencyProbe", "PortScanProbe", "TokenEstimatorProbe",
        "ProbePackProbe", "GraphQLProbe", "CachePoisoningProbe", "AIWAFClassifierProbe",
    ],
    TargetCategory.LLM_WEBAPP: [
        "ChatNavigationProbe",
        "LLMProbe", "RAGProbe", "AgentProbe", "MCPProbe", "EmbeddingProbe",
        "DOMProbe", "JSReconProbe", "NetworkProbe", "OpenAICompatProbe",
        "ErrorAnalyzerProbe", "SecurityHeaderProbe", "ResponseConsistencyProbe",
        "ConversationStateProbe", "TokenEstimatorProbe", "WAFDetectorProbe",
        "SubdomainProbe", "ProbePackProbe", "GraphQLProbe", "CachePoisoningProbe",
        "AIWAFClassifierProbe",
    ],
}


class ReconStage(PipelineStage):
    name = "recon"

    def __init__(self, probe_order: list[str] | None = None) -> None:
        # probe_order 为 None 时按分类自动选择子集 (端到端)
        self._probe_order = probe_order

    async def run(self, context: object) -> object:
        from core.orchestration import ReconOrchestrator
        from core.session import ReconSession
        from core.task_runtime import GuardrailPolicy
        from core.probes import (
            AgentProbe, ChatNavigationProbe, ConversationStateProbe, DOMProbe, EmbeddingProbe,
            ErrorAnalyzerProbe, JSReconProbe, LLMProbe, MCPProbe,
            NetworkProbe, OpenAICompatProbe, PortScanProbe, RAGProbe,
            ResponseConsistencyProbe, SecurityHeaderProbe, SubdomainProbe,
            TokenEstimatorProbe, WAFDetectorProbe,
        )
        from core.probes.probe_pack_probe import ProbePackProbe
        from core.probes.cache_poisoning_probe import CachePoisoningProbe
        from core.probes.graphql_probe import GraphQLProbe
        from core.probes.ai_waf_classifier import AIWAFClassifierProbe

        ctx = context  # type: ignore[assignment]
        classification = ctx.classification
        auth_decision = ctx.auth_decision

        if classification is None:
            raise RuntimeError("ReconStage requires classification from ClassifyStage")

        # P1-2-C: RoE time-window gate (best-effort, warn + skip if outside window)
        roe = getattr(ctx, "roe", None)
        if roe is not None:
            from core.safety import RoE
            r = roe if isinstance(roe, RoE) else RoE(**(roe if isinstance(roe, dict) else {}))
            if not r.in_time_window():
                logger.warning(
                    "[recon] RoE time window not satisfied; skipping active recon. "
                    "Window=%s", r.time_window,
                )
                return session_report_skip(ctx)

        # 选择探针列表
        if self._probe_order:
            wanted = set(self._probe_order)
            available = {
                "AgentProbe": AgentProbe, "ChatNavigationProbe": ChatNavigationProbe,
                "ConversationStateProbe": ConversationStateProbe,
                "DOMProbe": DOMProbe, "EmbeddingProbe": EmbeddingProbe,
                "ErrorAnalyzerProbe": ErrorAnalyzerProbe, "JSReconProbe": JSReconProbe,
                "LLMProbe": LLMProbe, "MCPProbe": MCPProbe, "NetworkProbe": NetworkProbe,
                "OpenAICompatProbe": OpenAICompatProbe, "PortScanProbe": PortScanProbe,
                "RAGProbe": RAGProbe, "ResponseConsistencyProbe": ResponseConsistencyProbe,
                "SecurityHeaderProbe": SecurityHeaderProbe, "SubdomainProbe": SubdomainProbe,
                "TokenEstimatorProbe": TokenEstimatorProbe, "WAFDetectorProbe": WAFDetectorProbe,
                "ProbePackProbe": ProbePackProbe, "CachePoisoningProbe": CachePoisoningProbe,
                "GraphQLProbe": GraphQLProbe, "AIWAFClassifierProbe": AIWAFClassifierProbe,
            }
            selected = [available[n] for n in self._probe_order if n in available]
        else:
            cat = classification.category
            names = _PROBE_BY_CATEGORY.get(cat, _PROBE_BY_CATEGORY[TargetCategory.LLM_WEBAPP])
            all_map = {
                "AgentProbe": AgentProbe, "ChatNavigationProbe": ChatNavigationProbe,
                "ConversationStateProbe": ConversationStateProbe,
                "DOMProbe": DOMProbe, "EmbeddingProbe": EmbeddingProbe,
                "ErrorAnalyzerProbe": ErrorAnalyzerProbe, "JSReconProbe": JSReconProbe,
                "LLMProbe": LLMProbe, "MCPProbe": MCPProbe, "NetworkProbe": NetworkProbe,
                "OpenAICompatProbe": OpenAICompatProbe, "PortScanProbe": PortScanProbe,
                "RAGProbe": RAGProbe, "ResponseConsistencyProbe": ResponseConsistencyProbe,
                "SecurityHeaderProbe": SecurityHeaderProbe, "SubdomainProbe": SubdomainProbe,
                "TokenEstimatorProbe": TokenEstimatorProbe, "WAFDetectorProbe": WAFDetectorProbe,
                "ProbePackProbe": ProbePackProbe, "CachePoisoningProbe": CachePoisoningProbe,
                "GraphQLProbe": GraphQLProbe, "AIWAFClassifierProbe": AIWAFClassifierProbe,
            }
            selected = [all_map[n] for n in names if n in all_map]

        logger.info(f"[recon] selected {len(selected)} probes: {[c.__name__ for c in selected]}")

        # 构建 Guardrail (组织边界)
        # P1-2-B: RoE excluded_hosts 注入 guardrail 边界
        roe_excluded = []
        if roe is not None:
            roe_excluded = list(roe.excluded_hosts) if hasattr(roe, "excluded_hosts") else []
        guardrail = GuardrailPolicy(
            allowed_hosts=set(ctx.allowed_hosts or []),
            organizational_domains=set(ctx.org_domains or []),
            disallow_patterns=tuple(list(ctx.disallow_patterns or []) + roe_excluded),
        )

        # 构建 Session — ★复用 context 中的浏览器会话和认证态
        session = ReconSession(target_url=ctx.target_url)

        # 注入已有认证态 (来自 AuthStage 执行)
        if ctx.auth_state is not None:
            session.auth_state = ctx.auth_state
            session.report.auth_type = session.auth_state.auth_type
            session.report.target_url = ctx.target_url
            logger.info(f"[recon] reusing auth_state from AuthStage (type={session.auth_state.auth_type})")
        elif auth_decision and auth_decision.strategy_name == "APIKeyAuth" and ctx.api_key:
            from core.auth.provider import APIKeyAuthProvider
            await session.authenticate(APIKeyAuthProvider(api_key=ctx.api_key, use_bearer=True))
        else:
            from core.auth.provider import NoAuthProvider
            await session.authenticate(NoAuthProvider())

        # 注入已有浏览器页面 (来自 ClassifyStage 保留)
        if ctx.browser_page is not None:
            # G15: 浏览器会话健康检查 — 页面可能已崩溃/关闭
            is_healthy = await self._check_browser_health(ctx.browser_page)
            if is_healthy:
                session.browser_page = ctx.browser_page
                logger.info("[recon] reusing browser_page from ClassifyStage (health check passed)")
            else:
                logger.warning("[recon] browser_page health check failed, attempting recovery")
                recovered_page = await self._recover_browser_session(ctx)
                if recovered_page is not None:
                    session.browser_page = recovered_page
                    ctx.browser_page = recovered_page
                    logger.info("[recon] browser session recovered successfully")
                else:
                    logger.warning("[recon] browser session recovery failed; browser-dependent probes will be skipped")
        elif auth_decision and auth_decision.needs_browser:
            logger.warning(
                "[recon] auth decision requires browser but none available; "
                "browser-dependent probes will be skipped"
            )

        # 执行编排
        orchestrator = ReconOrchestrator(
            probes=selected,
            guardrail_policy=guardrail,
        )
        result = await orchestrator.run(session)

        report = session.report
        report.target_url = ctx.target_url
        report.auth_type = session.auth_state.auth_type if session.auth_state else "none"
        report.auth_flow_state = (
            classification.second_factor if (auth_decision and auth_decision.needs_human)
            else (classification.auth_topology if classification else "none")
        )

        # ★ 侦察完成, 关闭浏览器 (流水线最后一步)
        if ctx.browser_session is not None:
            try:
                await ctx.browser_session.close()
                logger.info("[recon] browser session closed (pipeline complete)")
                ctx.browser_session = None
                ctx.browser_page = None
            except Exception as e:  # noqa: BLE001
                logger.debug(f"[recon] error closing browser: {e}")

        return report

    # ── G15: 浏览器会话健康检查与恢复 ──

    @staticmethod
    async def _check_browser_health(page: Any) -> bool:
        """检查浏览器页面是否仍然可用。"""
        try:
            # 最轻量的操作: 获取当前 URL
            _ = page.url
            # 尝试执行一个简单的 evaluate
            await page.evaluate("() => document.readyState")
            return True
        except Exception as e:
            logger.debug(f"[recon] browser health check failed: {e}")
            return False

    @staticmethod
    async def _recover_browser_session(ctx: Any) -> Any:
        """尝试从 BrowserSession 恢复浏览器页面。

        策略:
        1. 检查 browser_session 是否仍然有活跃的 context
        2. 尝试新建一个页面
        3. 导航到目标 URL
        """
        browser_session = getattr(ctx, "browser_session", None)
        if browser_session is None:
            return None

        try:
            context = getattr(browser_session, "context", None)
            if context is None:
                return None

            # 尝试新建页面
            new_page = await context.new_page()
            target_url = getattr(ctx, "target_url", "")
            if target_url:
                await new_page.goto(target_url, wait_until="domcontentloaded")
            logger.info("[recon] recovered browser page via context.new_page()")
            return new_page
        except Exception as e:
            logger.debug(f"[recon] browser session recovery failed: {e}")
            return None
