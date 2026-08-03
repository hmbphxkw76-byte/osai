# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Recon 自动触发器 — Stage 0.5 认证后自动调用 recon-pipeline。.

当流水线通过 ``--target-url`` 指定目标并完成认证后, 本模块:
  1. 从已认证的 Playwright Page 构建 ReconSession
  2. 根据目标类型自动选择合适的 ReconProbe 组合
  3. 运行 ReconPipeline 收集侦察结果
  4. 将 ReconReport 注入 PipelineContext.metadata, 供 Stage 2 场景选择
  5. 持久化 ReconReport 到 outputs/evidence/recon_*.json

设计原则 (R-010: PyRIT 原生优先):
  - ReconPipeline / ReconSession / ReconProbe 全部来自 recon-pipeline (core.*)
  - 本模块仅做编排和适配, 不修改 recon-pipeline 任何代码
  - 侦察失败不阻断主流水线 (降级为无侦察模式)

学术依据:
  - MITRE ATT&CK: Reconnaissance → Initial Access → Execution
  - Greshake et al. (arXiv:2302.12173): 间接注入需发现 Agent 工具调用端点
  - OWASP Top 10 for LLMs 2025: LLM01 Prompt Injection 需识别注入面

> **日期**: 2026-8-3
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pipeline.integrations.target_classifier import TargetClassification

if TYPE_CHECKING:
    from pipeline.context import PipelineContext

logger = logging.getLogger(__name__)


@dataclass
class ReconTriggerResult:
    """Recon 触发结果。.

    Attributes:
        success: 侦察是否成功完成。
        report: ReconReport 实例 (成功时), None (失败时)。
        probe_count: 运行的探针数。
        duration_seconds: 侦察耗时 (秒)。
        error: 失败时的错误信息。
        skipped_reason: 跳过原因 (如 recon-pipeline 未安装)。
    """

    success: bool = False
    report: Any | None = None
    probe_count: int = 0
    duration_seconds: float = 0.0
    error: str = ""
    skipped_reason: str = ""


async def trigger_recon(
    ctx: PipelineContext,
    target_url: str,
    classification: TargetClassification,
    *,
    page: Any | None = None,
) -> ReconTriggerResult:
    """在 Stage 0.5 认证后自动触发 recon-pipeline 侦察。.

    流程:
      1. 检查 --recon 标志 (或 Web App 目标自动启用)
      2. 从已认证的 Playwright Page 构建 ReconSession
      3. 根据目标类型选择探针组合
      4. 运行 ReconPipeline
      5. 将 ReconReport 注入 ctx.metadata

    降级策略:
      - recon-pipeline 未安装 → 跳过 (skipped_reason)
      - 侦察探针失败 → 记录错误, 不阻断主流水线
      - 无浏览器 Page → 仅运行不需要浏览器的探针

    Args:
        ctx: PipelineContext 实例。
        target_url: 目标 URL。
        classification: Stage 0.5 的目标类型判别结果。
        page: 已认证的 Playwright Page (可选, Web App 模式提供)。

    Returns:
        ReconTriggerResult 侦察触发结果。
    """
    # 检查是否启用 recon
    recon_enabled = getattr(ctx.args, "recon", False)
    if not recon_enabled and classification.target_type != "llm_web_app":
        return ReconTriggerResult(
            success=False,
            skipped_reason="--recon 未启用且目标非 Web App, 跳过侦察",
        )

    # 尝试导入 recon-pipeline (仅检查可用性, 探针在 _select_probes 中按需导入)
    try:
        from core.pipeline import ReconPipeline  # noqa: F401
        from core.session import ReconSession  # noqa: F401
    except ImportError:
        return ReconTriggerResult(
            success=False,
            skipped_reason="recon-pipeline (core.*) 未安装, 跳过侦察",
        )

    print("\n  --- [Recon] 自动侦察 ---")

    # 1. 构建 ReconSession
    session = ReconSession(target_url=target_url)

    # 如果有已认证的 Page, 注入到 session
    if page is not None:
        session.browser_page = page
        # 标记为已认证 (复用 Playwright 认证态)
        from core.models.auth_state import AuthState

        session.auth_state = AuthState(
            auth_type="browser",
            cookies=[],
            headers={},
            tokens={},
        )
        print("  [Recon] 复用已认证的浏览器会话")
    else:
        print("  [Recon] 无浏览器会话, 仅运行 HTTP 探针")

    # 2. 根据目标类型选择探针
    probes = _select_probes(classification, has_page=page is not None)

    if not probes:
        return ReconTriggerResult(
            success=False,
            skipped_reason="无可用探针 (目标类型不支持)",
        )

    probe_names = [type(p).__name__ for p in probes]
    print(f"  [Recon] 选择 {len(probes)} 个探针: {probe_names}")

    # 3. 运行 ReconPipeline
    pipeline = ReconPipeline(probes=probes, probe_timeout=60)

    import time

    start = time.time()

    try:
        pipeline_result = await pipeline.run(session, raise_on_error=False)
    except (RuntimeError, OSError, ValueError) as e:
        elapsed = round(time.time() - start, 2)
        logger.error(f"Recon pipeline failed: {e}", exc_info=True)
        print(f"  [Recon] 侦察失败: {e}")
        return ReconTriggerResult(
            success=False,
            probe_count=len(probes),
            duration_seconds=elapsed,
            error=str(e),
        )

    elapsed = round(time.time() - start, 2)

    print(
        f"  [Recon] 完成: {pipeline_result.executed} executed, "
        f"{pipeline_result.skipped} skipped, {pipeline_result.failed} failed "
        f"({elapsed}s)"
    )

    if pipeline_result.failed > 0 and pipeline_result.executed == 0:
        return ReconTriggerResult(
            success=False,
            probe_count=len(probes),
            duration_seconds=elapsed,
            error=f"All probes failed: {pipeline_result.errors}",
        )

    # 4. 注入 ReconReport 到 PipelineContext
    report = session.report
    if report is None:
        return ReconTriggerResult(
            success=False,
            probe_count=len(probes),
            duration_seconds=elapsed,
            error="ReconReport is None after pipeline run",
        )

    # 生成攻击推荐
    try:
        from core.probes import AttackRecommender

        recommender = AttackRecommender()
        report.recommendations = recommender.recommend(report)
        print(f"  [Recon] 攻击推荐: {len(report.recommendations)} 条")
    except (ImportError, RuntimeError, ValueError) as e:
        logger.warning(f"AttackRecommender failed: {e}")

    # 注入到 ctx.metadata
    ctx.metadata["recon_result"] = report
    ctx.metadata["recon_summary"] = _build_recon_summary(report, target_url)

    # P4: 持久化 ReconReport 到 JSON (可审计 + 跨运行对比)
    _persist_recon_report(ctx, report)

    # 打印侦察摘要
    _print_recon_summary(report)

    return ReconTriggerResult(
        success=True,
        report=report,
        probe_count=len(probes),
        duration_seconds=elapsed,
    )


def _select_probes(
    classification: TargetClassification,
    *,
    has_page: bool,
) -> list[Any]:
    """根据目标类型和可用资源选择探针组合。.

    探针选择策略:
      - LLM Web App + 浏览器 → 全套探针 (DOM + Network + LLM + RAG + Agent + MCP + Embedding + Endpoint)
      - LLM Web App 无浏览器 → HTTP 探针 (Endpoint + LLM)
      - LLM API Platform → API 探针 (Endpoint + LLM + Embedding)
      - unknown → 基础探针 (Endpoint)

    Args:
        classification: 目标类型判别结果。
        has_page: 是否有可用的浏览器 Page。

    Returns:
        探针实例列表。
    """
    from core.probes import (
        AgentProbe,
        DOMProbe,
        EmbeddingProbe,
        EndpointClassifier,
        LLMProbe,
        MCPProbe,
        NetworkInterceptor,
        RAGProbe,
    )

    probes: list[Any] = []

    if classification.target_type == "llm_web_app":
        # Web App: 浏览器探针优先
        if has_page:
            probes.append(DOMProbe())
            probes.append(NetworkInterceptor())
        # HTTP 探针 (不需要浏览器)
        probes.append(EndpointClassifier())
        probes.append(LLMProbe())
        probes.append(RAGProbe())
        probes.append(AgentProbe())
        probes.append(MCPProbe())
        probes.append(EmbeddingProbe())

    elif classification.target_type == "llm_api_platform":
        # API Platform: HTTP 探针
        probes.append(EndpointClassifier())
        probes.append(LLMProbe())
        probes.append(EmbeddingProbe())

    else:
        # unknown: 基础探针
        probes.append(EndpointClassifier())

    return probes


def _build_recon_summary(report: Any, target_url: str) -> dict[str, Any]:
    """构建 ReconReport 摘要字典, 供 Stage 2 快速读取。."""
    return {
        "target_url": target_url,
        "auth_type": getattr(report, "auth_type", ""),
        "has_agent_tools": getattr(report, "has_agent_tools", False),
        "has_rag_endpoints": getattr(report, "has_rag_endpoints", False),
        "has_file_upload": getattr(report, "has_file_upload", False),
        "has_multimodal_input": getattr(report, "has_multimodal_input", False),
        "endpoint_count": len(getattr(report, "endpoints", [])),
        "surface_count": len(getattr(report, "injection_surfaces", [])),
        "recommendation_count": len(getattr(report, "recommendations", [])),
        "recommendations": [
            r.to_dict() if hasattr(r, "to_dict") else str(r)
            for r in getattr(report, "recommendations", [])
        ],
    }


def _persist_recon_report(ctx: PipelineContext, report: Any) -> None:
    """P4: 将 ReconReport 持久化到 JSON 文件。.

    保存路径: outputs/evidence/recon_{timestamp}.json
    失败不阻断主流水线。
    """
    try:
        import json
        from datetime import datetime

        output_mgr = getattr(ctx, "output_manager", None)
        if output_mgr is not None:
            evidence_dir = output_mgr.evidence_dir
            timestamp = output_mgr.timestamp
        else:
            evidence_dir = Path("outputs/evidence")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        evidence_dir.mkdir(parents=True, exist_ok=True)
        recon_path = evidence_dir / f"recon_{timestamp}.json"

        # 序列化: 优先用 to_dict(), 否则用 __dict__
        if hasattr(report, "to_dict"):
            data = report.to_dict()
        elif hasattr(report, "__dict__"):
            data = report.__dict__
        else:
            data = {"repr": str(report)}

        with open(recon_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)

        print(f"  [Recon] 报告已保存: {recon_path}")
        logger.info(f"ReconReport persisted to {recon_path}")
    except (OSError, ValueError, TypeError) as e:
        logger.warning(f"Failed to persist ReconReport: {e}")


def _print_recon_summary(report: Any) -> None:
    """打印侦察结果摘要。."""
    endpoints = getattr(report, "endpoints", [])
    surfaces = getattr(report, "injection_surfaces", [])
    recommendations = getattr(report, "recommendations", [])

    print(f"  [Recon] 端点发现: {len(endpoints)} 个")
    for ep in endpoints[:5]:
        print(f"    [E] {ep}")
    if len(endpoints) > 5:
        print(f"    ... 及其他 {len(endpoints) - 5} 个")

    print(f"  [Recon] 注入面: {len(surfaces)} 个")
    for sf in surfaces[:3]:
        print(f"    [S] {sf}")
    if len(surfaces) > 3:
        print(f"    ... 及其他 {len(surfaces) - 3} 个")

    if recommendations:
        print("  [Recon] 攻击推荐 (前 3 条):")
        for rec in recommendations[:3]:
            priority = getattr(rec, "priority", 0)
            owasp_id = getattr(rec, "owasp_id", "")
            strategy = getattr(rec, "attack_strategy", "")
            rationale = getattr(rec, "rationale", "")[:80]
            print(f"    [P{priority}] {strategy} ({owasp_id}) — {rationale}")
