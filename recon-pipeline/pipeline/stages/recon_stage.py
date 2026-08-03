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

全部探针根据目标类别自动选用, 通过 ReconOrchestrator + ReconSession 统一执行,
产物写入 ReconReport (供下游 Export 阶段消费)。
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
            AgentProbe, ConversationStateProbe, DOMProbe, EmbeddingProbe,
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
                "AgentProbe": AgentProbe, "ConversationStateProbe": ConversationStateProbe,
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
                "AgentProbe": AgentProbe, "ConversationStateProbe": ConversationStateProbe,
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

        # 构建 Session
        session = ReconSession(target_url=ctx.target_url)

        # 认证: 根据决策注入 AuthProvider (若需要)
        if auth_decision and auth_decision.strategy_name == "APIKeyAuth" and ctx.api_key:
            from core.auth.provider import APIKeyAuthProvider
            await session.authenticate(APIKeyAuthProvider(api_key=ctx.api_key, use_bearer=True))
        elif auth_decision and auth_decision.strategy_name == "PlaywrightAuth":
            # 需要浏览器交互 (可能含人工二次验证); 此处仅记录, 由调用方在交互环境执行
            logger.info(
                "[recon] Playwright auth required (needs_browser=%s, needs_human=%s); "
                "running unauthenticated probes, auth-dependent probes will yield no results",
                auth_decision.needs_browser, auth_decision.needs_human,
            )
        else:
            from core.auth.provider import NoAuthProvider
            await session.authenticate(NoAuthProvider())

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
            auth_decision.second_factor if (auth_decision and auth_decision.needs_human)
            else (classification.auth_topology if classification else "none")
        )
        return report
