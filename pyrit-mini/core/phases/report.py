"""REPORT .

Academic basis:
    - OWASP LLM 2025 - Top 10

"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)


def _attach_combo_artifacts(ctx: "PipelineContext", evidence: Any) -> None:
    """把组件图 / 攻击链 / 影响链 / 预算 / 评分清单投影到证据集（plan Wave 6）。

    影响链在此**从真实证据构建**：每个 ImpactNode 的 evidence_ids 取自对应步骤
    实际产生的 EVD-* 编号，因此 `validate_causality()` 的缺口是真实的举证缺口，
    而非形式化填空。

    IA-6：任一环节失败只降级该字段，不影响报告生成。
    """
    # 1) 组件拓扑
    graph = getattr(ctx, "component_graph", None)
    if graph is not None:
        try:
            evidence.component_graph = graph.to_dict()
        except Exception as e:
            logger.warning("[Report] 组件图序列化失败（降级）: %s", e)

    # 2) 有状态攻击链
    chain = getattr(ctx, "attack_chain", None)
    evidence_by_step: dict[str, list[str]] = {}
    if chain is not None:
        try:
            evidence.attack_chain = chain.to_dict()
        except Exception as e:
            logger.warning("[Report] 攻击链序列化失败（降级）: %s", e)
        # 步骤 → EVD-* 映射：按组件键匹配证据（CB-2 元数据）
        try:
            state = chain.state
            for step in chain.steps:
                if state.status.get(step.id) != "succeeded":
                    continue
                ids = [
                    ev.evidence_id
                    for ev in evidence.evidence
                    if ((getattr(ev, "metadata", None) or {}).get("component_type")) == step.component_key
                ]
                if ids:
                    evidence_by_step[step.id] = ids
        except Exception as e:
            logger.debug("[Report] 步骤→证据映射失败（降级）: %s", e)

    # 3) 影响链举证
    try:
        from report.impact_chain import ImpactChainBuilder, build_impact_chains_from_components

        builder = ImpactChainBuilder()
        chains: list[Any] = []

        if chain is not None:
            built = builder.build(
                chain_result=None,
                attack_chain=chain,
                evidence_by_step=evidence_by_step,
            )
            if built.nodes:
                chains.append(built)

        if graph is not None:
            # 组件级证据映射（用于枚举多条路径）
            by_component: dict[str, list[str]] = {}
            for ev in evidence.evidence:
                comp = (getattr(ev, "metadata", None) or {}).get("component_type")
                if comp:
                    by_component.setdefault(comp, []).append(ev.evidence_id)
            chains.extend(build_impact_chains_from_components(graph, evidence_by_component=by_component))

        evidence.impact_chains = [c.to_dict() for c in chains]
        gaps: list[dict[str, Any]] = []
        for c in chains:
            gaps.extend(g.model_dump(mode="json") for g in c.validate_causality())
        evidence.impact_gaps = gaps
        if gaps:
            logger.warning(
                "[Report] 影响链举证不完整：%d 个缺口（节点缺 EVD-* 证据或因果断裂），报告中将显式标注",
                len(gaps),
            )
    except Exception as e:
        logger.warning("[Report] 影响链构建失败（降级）: %s", e)

    # 4) 预算（含裁剪原因 —— DoD 要求出现在报告中）
    budget = getattr(ctx, "budget", None)
    if budget is not None:
        try:
            evidence.budget_report = {
                "snapshot": budget.remaining().to_dict(),
                "trims": budget.trim_report(),
            }
        except Exception as e:
            logger.debug("[Report] 预算报告序列化失败（降级）: %s", e)

    # 5) 评分运行清单（可复现指纹）
    manifest = getattr(ctx, "score_manifest", None)
    if manifest is not None:
        try:
            evidence.score_manifest = manifest.to_dict()
        except Exception as e:
            logger.debug("[Report] 评分清单序列化失败（降级）: %s", e)


async def _run_report_phase(ctx: "PipelineContext", output_dir: Path) -> None:
    """(6) REPORT : +"""
    from utils.display import print_phase, print_report_card, print_status

    print_phase("REPORT", " & ...")
    from core.phases._helpers import _extract_auth_recovery_log
    from report.evidence import EvidenceCollector
    from report.generator import generate_report

    target_fingerprint = {}
    if ctx.parsed_request:
        target_fingerprint = ctx.parsed_request.target_fingerprint

    collector = EvidenceCollector(
        target_model=ctx.model_name,
        target_fingerprint=target_fingerprint,
    )
    evidence = collector.collect(
        attack_results=ctx.attack_results,
        scenario_result_id=ctx.scenario_result_id,
        asr_per_technique=ctx.asr_per_technique,
        overall_asr=ctx.overall_asr,
        memory_labels=ctx.memory_labels,
        orchestration_log=ctx.orchestration_log,
    )

    # evidence
    if hasattr(ctx, "dual_judge_stats") and ctx.dual_judge_stats:
        evidence.dual_judge_stats = ctx.dual_judge_stats
        evidence.wilson_ci = getattr(ctx, "wilson_ci", (0.0, 0.0))
        evidence.cohens_kappa = ctx.dual_judge_stats.get("cohens_kappa", 0.0) if ctx.dual_judge_stats else 0.0
        evidence.orchestration_log = ctx.orchestration_log

    #
    auth_recovery_log = _extract_auth_recovery_log(ctx)
    if auth_recovery_log:
        if hasattr(evidence, "attack_surface") and evidence.attack_surface:
            evidence.attack_surface["auth_recovery_attempts"] = len(auth_recovery_log)
            evidence.attack_surface["auth_recovery_log"] = auth_recovery_log

    # == plan Wave 6：组合体 / 攻击链 / 影响链 / 预算 → 报告 ==
    # 交付物必须承载「入口组件 → 业务影响」的因果举证，而不只是 ASR 数字。
    _attach_combo_artifacts(ctx, evidence)

    # ( generate_report )
    _native_dir = output_dir / "native_output"
    _report_index_path = str(output_dir / "report.md")
    ctx.orchestration_log.append(
        {
            "phase": "report",
            "decision": "report_generation",
            "input": {
                "evidence_count": evidence.total_attacks,
                "overall_asr": ctx.overall_asr,
            },
            "output": {
                "report_index": _report_index_path,
                "report_executive": str(output_dir / "report_executive.md"),
                "report_findings": str(output_dir / "report_findings.md"),
                "report_technical": str(output_dir / "report_technical.md"),
                "report_success": str(output_dir / "report_success.md") if evidence.successful_evidence else "",
                "native_output": str(_native_dir) if _native_dir.exists() else "",
            },
            "reasoning": f"Layer (ASR={ctx.overall_asr:.1f}%, {evidence.total_attacks} , 4 Layer)",
        }
    )

    report_path = await generate_report(ctx, evidence, output_dir)
    print_report_card(
        total_attacks=evidence.total_attacks,
        successful_attacks=evidence.successful_attacks,
        overall_asr=ctx.overall_asr,
        report_path=str(report_path),
        evidence_count=evidence.total_attacks,
        wilson_ci=getattr(ctx, "wilson_ci", (0.0, 0.0)),
        native_output_dir=str(_native_dir) if _native_dir.exists() else "",
    )
    print_status("REPORT", "DONE", "", ok=True)

    # === 数据流完整性快照: post_report ===
    try:
        from tools.dataflow.hooks import snapshot_hook

        snapshot_hook(ctx, "post_report")
    except Exception as e:
        logger.debug("[Report] Data flow snapshot skipped: %s", e)
