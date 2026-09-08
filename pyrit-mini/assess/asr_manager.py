# arXiv:2308.07920 - Zhang et al., Dual Judge cross-validation
# arXiv:2406.12609 - Lattner et al., Parallel scoring throughput
# arXiv:2402.04249 - Mazeika et al., HarmBench scoring baseline
# arXiv:2306.05685 - Zheng et al., LLM-as-a-Judge robustness
# arXiv:2307.08673 - Zou et al., GCG
# arXiv:2302.12173 - Greshake et al., Indirect Prompt Injection
# arXiv:2310.08419 - Chao et al., PAIR (Joint ASR)
"""ASR - asr_stats/asr_history/asr_compute/joint_asr

:
    - ASR  (compute_asr, compute_overall_asr, compute_wilson_score_interval)
    - ASR  (save_asr_history, converter/gcg ASR history)
    -  Judge  (Cohen's Kappa, dual judge stats)
    -  ASR  (multi-endpoint joint ASR)
"""

from __future__ import annotations

import json
import logging
import math
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ===============================================================================
# SSOT imports - Judge asr_stats.py
# ===============================================================================

from assess.asr_stats import (  # noqa: E402 - from
    _get_outcome,
    compute_overall_asr,  # noqa: F401 - SSOT in asr_stats, re-exported via __init__.py
    get_dual_judge_stats,
)

# SSOT :
# _get_outcome() SSOT asr_stats.py - asr_manager
# compute_overall_asr() SSOT asr_stats.py - __init__.py

# ===============================================================================
# ASR
# ===============================================================================

def compute_asr(attack_results: dict[str, list[Any]]) -> dict[str, float]:
    """ ASR

    Args:
        attack_results: {technique_name: [AttackResult, ...]}

    Returns:
        {technique_name: asr_percentage}
    """
    asr_per_technique: dict[str, float] = {}

    for technique_name, results in attack_results.items():
        if not results:
            asr_per_technique[technique_name] = 0.0
            continue

        successes = 0
        total_decided = 0

        for result in results:
            outcome = _get_outcome(result)
            if outcome == "success":
                successes += 1
                total_decided += 1
            elif outcome == "failure":
                total_decided += 1

        if total_decided > 0:
            asr = (successes / total_decided) * 100
        else:
            asr = 0.0

        asr_per_technique[technique_name] = round(asr, 1)
        logger.info(
            "ASR [%s]: %.1f%% (%d/%d)",
            technique_name,
            asr,
            successes,
            total_decided,
        )

    return asr_per_technique

def compute_wilson_score_interval(
    successes: int,
    total: int,
    confidence: float = 0.95,
) -> tuple[float, float]:
    """ Wilson Score

    Academic basis: Wilson (1927) -
     ASR

    Args:
        successes:
        total:
        confidence:  (0.95 = 95% CI)

    Returns:
        (lower, upper)  [0, 100]
    """
    if total == 0:
        return (0.0, 0.0)

    z_scores = {0.90: 1.645, 0.95: 1.96, 0.99: 2.576}
    z = z_scores.get(confidence, 1.96)

    p = successes / total
    n = total

    denominator = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denominator
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator

    lower = max(0.0, (centre - margin) * 100)
    upper = min(100.0, (centre + margin) * 100)

    return (round(lower, 1), round(upper, 1))

# ===============================================================================
# Judge
# ===============================================================================

def _post_hoc_judge_success(result: Any) -> bool:
    """L5 v44: post-hoc LLM Judge - OR

     failure/undecided ,  Judge:
        Judge 1: SelfAskTrueFalseScorer (calibrated_task_achieved, lenient)
        Judge 2: TrueFalseInverterScorer(SelfAskRefusalScorer, OBJECTIVE_STRICT)

    Academic basis:
        - Zhang et al. (arXiv:2308.07920) -  Judge
        - Chao et al. (arXiv:2402.01135) - OR
        - Mazeika et al. (arXiv:2402.04249) - HarmBench
    """
 # LLM Judge
    from assess.judge_manager import _heuristic_second_judge_success, _init_judges, _run_llm_dual_judge_sync

    if _init_judges():
        try:
            return _run_llm_dual_judge_sync(result)
        except Exception as e:
            logger.debug("L5 v25: LLM dual judge failed: %s, falling back to heuristic", e)

 # Fallback:
    return _heuristic_second_judge_success(result)

def collect_dual_judge_stats(ctx: Any) -> dict[str, Any]:
    """ Judge - asr_stats.SSOT

    Academic basis: Zhang et al. (arXiv:2308.07920) -  Judge
    , imports

    Args:
        ctx: PipelineContext ( scorer )

    Returns:
         Judge
    """
    stats = get_dual_judge_stats()

    if stats.get("total_scored", 0) > 0:
        logger.info(
            "L5 v30: Dual Judge stats (from post-hoc global counter): "
            "total=%d, agreed=%d, disagreed=%d",
            stats.get("total_scored", 0),
            stats.get("agreements", 0),
            stats.get("disagreements", 0),
        )
        return stats

 # Fallback: ctx.scorer
    scorer = getattr(ctx, "scorer", None)
    if scorer and hasattr(scorer, "get_stats"):
        stats = scorer.get_stats()
        logger.info("Dual Judge stats (from ctx.scorer): %s", stats)
        return stats

    return stats

# ===============================================================================
# ASR
# ===============================================================================

def _get_asr_history_path():
    """ ASR """
    from arm import seed_ranker
    return seed_ranker._ASR_HISTORY_PATH

def save_asr_history(
    asr_per_technique: dict[str, float],
    *,
    attack_results: dict[str, list[Any]] | None = None,
) -> None:
    """ ASR data/seeds/asr_history.json

    Academic basis: Auer et al. (arXiv:cs/0207052) - UCB1
     ASR
    """
    from arm.seed_ranker import update_asr_history

    seed_asr: dict[str, float] = {}
    seed_attempts: dict[str, int] = {}
    converter_asr: dict[str, float] = {}
    converter_attempts: dict[str, int] = {}
    gcg_suffix_asr: dict[str, float] = {}
    gcg_suffix_attempts: dict[str, int] = {}

    if attack_results:
        seed_stats: dict[str, dict[str, int]] = {}
        for results in attack_results.values():
            for result in results:
                objective = getattr(result, "objective", "") or ""
                if not objective:
                    continue
                from arm.seed_ranking import _make_seed_key
                prefix = _make_seed_key(objective)
                if prefix not in seed_stats:
                    seed_stats[prefix] = {"success": 0, "total": 0}
                seed_stats[prefix]["total"] += 1
                outcome = _get_outcome(result)
                if outcome == "success":
                    seed_stats[prefix]["success"] += 1

                meta = getattr(result, "metadata", {}) or {}
                converter_name = ""
                if isinstance(meta, dict):
                    converter_name = str(meta.get("converter_name", "") or meta.get("converter", ""))
                if converter_name:
                    if converter_name not in converter_attempts:
                        converter_attempts[converter_name] = 0
                        converter_asr[converter_name] = 0.0
                    converter_attempts[converter_name] += 1
                    if outcome == "success":
                        converter_asr[converter_name] = (
                            converter_asr.get(converter_name, 0.0) + 1
                        )

                gcg_suffix = ""
                if isinstance(meta, dict):
                    gcg_suffix = str(meta.get("gcg_suffix", ""))
                if gcg_suffix:
                    gcg_key = _make_seed_key(gcg_suffix)
                    if gcg_key not in gcg_suffix_attempts:
                        gcg_suffix_attempts[gcg_key] = 0
                        gcg_suffix_asr[gcg_key] = 0.0
                    gcg_suffix_attempts[gcg_key] += 1
                    if outcome == "success":
                        gcg_suffix_asr[gcg_key] = (
                            gcg_suffix_asr.get(gcg_key, 0.0) + 1
                        )

        for prefix, stats in seed_stats.items():
            if stats["total"] > 0:
                seed_asr[prefix] = round(stats["success"] / stats["total"] * 100, 1)
                seed_attempts[prefix] = stats["total"]

        for conv_name in converter_asr:
            total = converter_attempts.get(conv_name, 1)
            converter_asr[conv_name] = round(
                converter_asr[conv_name] / total * 100, 1
            )

        for gcg_key in gcg_suffix_asr:
            total = gcg_suffix_attempts.get(gcg_key, 1)
            gcg_suffix_asr[gcg_key] = round(
                gcg_suffix_asr[gcg_key] / total * 100, 1
            )

    update_asr_history(
        asr_per_technique,
        seed_asr=seed_asr if seed_asr else None,
        seed_attempts=seed_attempts if seed_attempts else None,
    )

    if converter_asr:
        _save_converter_asr_history(converter_asr, converter_attempts)

    if gcg_suffix_asr:
        _save_gcg_suffix_asr_history(gcg_suffix_asr, gcg_suffix_attempts)

def _save_converter_asr_history(
    converter_asr: dict[str, float],
    converter_attempts: dict[str, int],
) -> None:
    """ converter ASR """
    asr_history_path = _get_asr_history_path()
    if not asr_history_path.exists():
        return

    try:
        data = json.loads(asr_history_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning("Failed to read ASR history for converter ASR: %s", e)
        return

    existing = data.get("converter_asr", {})
    alpha = 0.3

    for conv_name, new_asr in converter_asr.items():
        if conv_name in existing:
            existing[conv_name] = round(
                alpha * new_asr + (1 - alpha) * existing[conv_name], 1
            )
        else:
            existing[conv_name] = new_asr

    data["converter_asr"] = existing

    try:
        asr_history_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info(
            "Converter ASR history saved: %d converters tracked",
            len(existing),
        )
    except Exception as e:
        logger.warning("Failed to save converter ASR history: %s", e)

def _save_gcg_suffix_asr_history(
    gcg_suffix_asr: dict[str, float],
    gcg_suffix_attempts: dict[str, int],
) -> None:
    """ GCG ASR """
    asr_history_path = _get_asr_history_path()
    if not asr_history_path.exists():
        return

    try:
        data = json.loads(asr_history_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning("Failed to read ASR history for GCG suffix ASR: %s", e)
        return

    existing = data.get("gcg_suffix_asr", {})
    alpha = 0.3

    for gcg_key, new_asr in gcg_suffix_asr.items():
        if gcg_key in existing:
            existing[gcg_key] = round(
                alpha * new_asr + (1 - alpha) * existing[gcg_key], 1
            )
        else:
            existing[gcg_key] = new_asr

    data["gcg_suffix_asr"] = existing

    try:
        asr_history_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info(
            "GCG suffix ASR history saved: %d suffixes tracked",
            len(existing),
        )
    except Exception as e:
        logger.warning("Failed to save GCG suffix ASR history: %s", e)

# ===============================================================================
# ASR ( endpoint)
# ===============================================================================

def compute_joint_asr(endpoint_asrs: list[float]) -> float:
    """ ASR - endpoint

    Academic basis: Chao et al. (arXiv:2310.08419) - / endpoint  ASR
         ASR = 1 - Prod(1 - ASRi)
        : converter(s) endpoint ,

    Args:
        endpoint_asrs:  endpoint  ASR

    Returns:
         ASR  (0.0-100.0)
    """
    if not endpoint_asrs:
        return 0.0

    prob = 1.0
    for asr in endpoint_asrs:
        p = max(0.0, min(100.0, asr)) / 100.0
        prob *= (1.0 - p)

    joint = (1.0 - prob) * 100.0
    return round(joint, 1)

def build_joint_summary(
    multi_endpoint_results: list[dict[str, Any]],
) -> dict[str, Any]:
    """ endpoint ASR

    Args:
        multi_endpoint_results: converter(s) endpoint

    Returns:
         ASR
    """
    endpoint_summaries: list[dict[str, Any]] = []
    endpoint_asrs: list[float] = []
    total_attacks = 0
    total_successes = 0

    for result in multi_endpoint_results:
        asr = result.get("overall_asr", 0.0)
        attacks = result.get("total_attacks", 0)
        successes = result.get("successful_attacks", 0)
        endpoint_asrs.append(asr)
        total_attacks += attacks
        total_successes += successes

        endpoint_summaries.append({
            "burp_name": result.get("burp_name", "unknown"),
            "endpoint": result.get("endpoint", ""),
            "overall_asr": asr,
            "total_attacks": attacks,
            "successful_attacks": successes,
            "wilson_ci": result.get("wilson_ci", (0.0, 0.0)),
            "capabilities": result.get("capabilities", ""),
            "model_family": result.get("model_family", ""),
        })

    joint_asr = compute_joint_asr(endpoint_asrs)

    return {
        "joint_asr": joint_asr,
        "total_endpoints": len(multi_endpoint_results),
        "total_attacks": total_attacks,
        "total_successes": total_successes,
        "endpoint_summaries": endpoint_summaries,
    }

def save_joint_report(
    joint_summary: dict[str, Any],
    output_dir: Path,
) -> Path:
    """ ASR JSON

    Args:
        joint_summary: build_joint_summary
        output_dir: Output directory

    Returns:
        JSON
    """
    report_path = output_dir / "joint_asr_report.json"
    report_path.write_text(
        json.dumps(joint_summary, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    logger.info("Joint ASR report saved to %s", report_path)
    return report_path
