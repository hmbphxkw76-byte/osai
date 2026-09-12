"""ASSESS  + ASR .

Academic basis:
    - arXiv:2308.07920 (Judge )
    - Wilson Score CI ()
    - Cohen's Kappa ()
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)


def _build_score_manifest(ctx: "PipelineContext") -> None:
    """构建评分运行清单（plan Wave 5 / C7）。

    `adaptive_random_seed` 长期只写在 defaults.yaml 而无消费者（C7 断链）。
    本函数把它接入唯一链路：defaults.yaml → parse_args → ctx.args → Manifest。

    IA-6：任何一步失败都只降级，不中断评分。
    """
    try:
        from core.contracts.manifest import ScoreRunManifest

        args = ctx.args
        manifest = ScoreRunManifest(
            run_id=str(getattr(ctx, "scenario_result_id", "") or ""),
            random_seed=getattr(args, "adaptive_random_seed", None),
            temperature=getattr(args, "temperature", None),
            aggregation=str(getattr(args, "dual_judge_disagreement_strategy", "or") or "or"),
            t0_enabled=bool(getattr(args, "dual_judge_enabled", True)),
            adaptive_threshold=getattr(args, "dual_judge_high_confidence_threshold", None),
            target_model=getattr(ctx, "model_name", "") or "",
        )

        # judge 模型（可能缺失，缺失即留空，不伪造）
        for attr in ("scoring_model", "judge_model", "adversarial_model"):
            val = getattr(args, attr, None)
            if val:
                manifest.judge_models.append(str(val))

        # rubric：来自已识别组件的 ComponentSpec（无组件时留空）
        graph = getattr(ctx, "component_graph", None)
        if graph is not None:
            try:
                from core.registry import get_registry

                reg = get_registry()
                for key in graph.keys():
                    spec = reg.spec(key)
                    if spec is None:
                        continue
                    manifest.component_keys.append(key)
                    if spec.rubric:
                        manifest.add_rubric(spec.rubric)
            except Exception as e:
                logger.debug("[Assess] rubric 清单收集失败（降级）: %s", e)

        ctx.score_manifest = manifest
        logger.info(
            "[Assess] ScoreRunManifest: seed=%s, rubrics=%d, fingerprint=%s",
            manifest.random_seed,
            len(manifest.rubric_hashes),
            manifest.fingerprint(),
        )
    except Exception as e:
        logger.warning("[Assess] ScoreRunManifest 构建失败（不影响评分）: %s", e)
        ctx.score_manifest = None


def _attach_success_levels(ctx: "PipelineContext") -> None:
    """REQ-164：计算 L1–L4 分层并写入 `ctx.attack_success_levels`（附加维度）。

    不改变 `overall_asr` / `asr_per_technique` 的分子分母（NFR-13 口径稳定）——
    仅补充"成功证据强度"，供报告分列与后续 ImpactChain（REQ-152）消费。
    失败只降级，不中断评分（IA-6）。
    """
    try:
        from assess.success_levels import compute_success_levels

        summary = compute_success_levels(
            getattr(ctx, "attack_results", None),
            impact_verdicts=getattr(ctx, "impact_verdicts", None),
        )
        ctx.attack_success_levels = summary
        logger.info(
            "[Assess] Success levels histogram=%s, highest=%s",
            summary.get("histogram"),
            summary.get("highest"),
        )
    except Exception as e:
        logger.debug("[Assess] success-level computation skipped: %s", e)


def _attach_impact_verdicts(ctx: "PipelineContext") -> None:
    """REQ-152 / ADR-008：为每条攻击结果判定四态并写入 `ctx.impact_verdicts`。

    **只记录非 `content_only` 的判定**——避免把"无任何影响信号"也写成 verdict 从而
    让 `confirmed_asr` 从 `n/a` 突变为 0.0（口径突变）。有信号时才登记（IC-5/IC-6）。
    失败只降级，不中断评分。
    """
    try:
        from assess.impact.exfil import extract_canaries, get_receipt_log
        from assess.impact.verdict import CONTENT_ONLY, decide_verdict

        receipt_log = get_receipt_log()
        verdicts: list[dict[str, object]] = []
        for technique, results in (getattr(ctx, "attack_results", None) or {}).items():
            for idx, result in enumerate(results):
                text = getattr(result, "converted_value", "") or ""
                canaries = extract_canaries(text)
                outcome = decide_verdict(response_text=text, canaries=canaries, receipt_log=receipt_log)
                if outcome.get("verdict") == CONTENT_ONLY:
                    continue
                verdicts.append(
                    {
                        "attack_id": f"{technique}#{idx}",
                        "verdict": outcome["verdict"],
                        "confirmed": outcome["confirmed"],
                        "evidence": outcome["evidence"],
                    }
                )
        ctx.impact_verdicts = verdicts
        if verdicts:
            logger.info("[Assess] impact verdicts recorded: %d", len(verdicts))
    except Exception as e:
        logger.debug("[Assess] impact-verdict computation skipped: %s", e)


def _persist_verdicts(ctx: "PipelineContext") -> None:
    """REQ-152 / NFR-13 ④：持久化 verdict 记录并计算双口径 ASR。

    产物：`<output_dir>/verdicts.json` + `verdicts.jsonl`（含 schema_version +
    content_hash，幂等去重）。报告阶段可经 `assess.persistence.load_verdicts` 读取
    `reported_asr` / `confirmed_asr` 分列（NFR-13 ④）。
    """
    try:
        from assess.persistence import build_verdict_records, persist_verdicts

        records = build_verdict_records(
            getattr(ctx, "attack_results", None),
            impact_verdicts=getattr(ctx, "impact_verdicts", None),
            success_levels=getattr(ctx, "attack_success_levels", None),
        )
        output_dir = getattr(ctx, "output_dir", None)
        if output_dir:
            persist_verdicts(output_dir, records)
    except Exception as e:
        logger.warning("[Assess] verdict persistence failed (non-fatal): %s", e)


async def _run_assess_phase(ctx: "PipelineContext") -> None:
    """(5) ASSESS : + ASR"""
    from utils.display import print_assess_card, print_phase, print_status

    args = ctx.args
    print_phase("ASSESS", " Judge  & ASR ...")

    from assess.asr_manager import (
        collect_dual_judge_stats,
        compute_asr,
        compute_overall_asr,
        compute_wilson_score_interval,
        save_asr_history,
    )
    from assess.asr_stats import (
        compute_cohens_kappa,
    )
    from assess.score_pipeline import precompute_outcomes_async
    from core.phases._helpers import _log_dual_judge_stats

    _assess_reset_stats = not getattr(ctx.args, "escalation", True)
    try:
        await precompute_outcomes_async(ctx.attack_results, score_all=False, reset_stats=_assess_reset_stats, ctx=ctx)
    except Exception as e:
        logger.error(": %s - ", e)

    ctx.asr_per_technique = compute_asr(ctx.attack_results)
    ctx.overall_asr = compute_overall_asr(ctx.asr_per_technique)
    save_asr_history(ctx.asr_per_technique, attack_results=ctx.attack_results)

    # asr_priors.yaml
    if ctx.parsed_request:
        model_family = ctx.parsed_request.target_fingerprint.get("model_family")
        if model_family:
            from arm.seed_ranker import update_asr_priors

            update_asr_priors(model_family, ctx.asr_per_technique)

    # Wilson
    # Score
    # CI
    from assess.asr_stats import _get_outcome as _get_attack_outcome

    total_successes = sum(
        1 for results in ctx.attack_results.values() for r in results if _get_attack_outcome(r) == "success"
    )
    total_decided = sum(
        1
        for results in ctx.attack_results.values()
        for r in results
        if _get_attack_outcome(r) in ("success", "failure")
    )
    wilson_lower, wilson_upper = compute_wilson_score_interval(total_successes, total_decided)
    logging.info(
        "ASR Wilson Score 95%% CI: [%.1f%%, %.1f%%] (: %.1f%%)",
        wilson_lower,
        wilson_upper,
        ctx.overall_asr,
    )
    ctx.wilson_ci = (wilson_lower, wilson_upper)

    # == REQ-152：影响链四态判定（仅记录非 content_only 信号，避免口径突变）==
    _attach_impact_verdicts(ctx)

    # == REQ-164：L1–L4 成功分层（附加维度，不改变 ASR 分子/分母）==
    _attach_success_levels(ctx)

    # == REQ-152 / NFR-13 ④：verdict 持久化（幂等）+ 双口径 ASR ==
    _persist_verdicts(ctx)

    # == plan Wave 5：评分运行清单（消费 adaptive_random_seed，修 C7 断链）==
    # `config/defaults.yaml:82 adaptive_random_seed` 此前无人读取 —— 配置写了却不生效。
    # Manifest 把它连同 judge 模型 / rubric 哈希 / temperature 一起固化，
    # 使"同输入 + 同 seed → 同结果"成为可验证命题。
    _build_score_manifest(ctx)

    # Judge
    ctx.dual_judge_stats = collect_dual_judge_stats(ctx)
    if ctx.dual_judge_stats:
        # == plan Wave 5 / A.2：κ 口径唯一化 ==
        # 旧代码在此用**两参数**（agreements, disagreements）重算 κ，并直接覆盖
        # `DualJudgeState.to_dict()` 用**四参数**（含 judge1/judge2_successes，
        # 即 P_e 按边际分布计算）算出的值 —— 同一指标两套口径，后者静默胜出。
        # 修正：以 DualJudgeState 的四参数结果为唯一事实源；仅在其缺席时，
        # 才用完整的四参数补全（绝不退化成两参数）。
        if "cohens_kappa" not in ctx.dual_judge_stats:
            ctx.dual_judge_stats["cohens_kappa"] = compute_cohens_kappa(
                ctx.dual_judge_stats.get("agreements", 0),
                ctx.dual_judge_stats.get("disagreements", 0),
                ctx.dual_judge_stats.get("judge1_successes", 0),
                ctx.dual_judge_stats.get("judge2_successes", 0),
            )
        _log_dual_judge_stats(ctx.dual_judge_stats)

    #
    print_assess_card(ctx)

    # --stage assess
    if getattr(args, "stage", None) == "assess":
        print_status("ASSESS", "DONE", "", ok=True)
        return

    # ASSESS
    _dual_judge_enabled = getattr(ctx.args, "dual_judge_enabled", True)
    _wilson_level = getattr(ctx.args, "wilson_confidence_level", 0.95)
    ctx.orchestration_log.append(
        {
            "phase": "assess",
            "decision": "scoring_assessment",
            "input": {
                "total_attacks": sum(len(v) for v in ctx.attack_results.values()),
                "scoring_model": "T0->J1->J2 OR  ( 2-LLM)" if _dual_judge_enabled else "T0->J1 (single judge)",
                "dual_judge_enabled": _dual_judge_enabled,
                "wilson_confidence_level": _wilson_level,
            },
            "output": {
                "overall_asr": ctx.overall_asr,
                "wilson_ci": list(ctx.wilson_ci),
                "asr_per_technique": ctx.asr_per_technique,
                "dual_judge_invoked": ctx.dual_judge_stats.get("dual_judge_invoked", 0),
                "cohens_kappa": ctx.dual_judge_stats.get("cohens_kappa", 0.0),
            },
            "reasoning": ("arXiv:2308.07920  Judge  + T0  (0 token) + Wilson Score 95% CI + Cohen's Kappa "),
        }
    )

    # === 数据流完整性快照: post_assess ===
    try:
        from tools.dataflow.hooks import snapshot_hook

        snapshot_hook(ctx, "post_assess")
    except Exception as e:
        logger.debug("[Assess] Data flow snapshot skipped: %s", e)
