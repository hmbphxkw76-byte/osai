"""display.py - Unified display facade + progress orchestration.

Architecture: single entry point, delegates to:
    - display_primitives: ANSI colors + Banner/Phase/Status
    - display_stages: RECON/ARM/STRIKE/ESCALATE/ASSESS/REPORT phase cards
    - display_native: PyRIT native output adapters (output_attack/scenario/technique_trail)
    - display.py: unified facade + progress orchestration

Responsibilities:
    1. Unified facade: backward-compatible re-exports
    2. Log suppression: PyRIT/Alembic INFO noise filtering
    3. Progress orchestration: seed -> converter -> ASR -> payload -> success
    4. Summary cards: converter(s) attack summary
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

# == PyRIT (display_native) ==
from utils.display_native import (
    print_native_attack_result,
    print_native_scenario_result,
    print_technique_trail,
)

# == (display_params SSOT) ==
# == (display_primitives) ==
# == (display_stages) ==
# : _get_converter_chain_names display_primitives ( 289)
from utils.display_primitives import (
    _C_CYAN,
    _C_DIM,
    _C_GREEN,
    _C_RED,
    _C_RESET,
    _C_YELLOW,
    _asr_bar,
    _asr_color,
    _format_asr,
    print_card,
    print_status,
)
from utils.display_stages import (
    _extract_success_info,
    _get_outcome_label,
    _is_success,
    print_arm_card,
    print_assess_card,
    print_escalate_card,
    print_success_breakthrough,
    print_success_payload_snapshot,
)

if TYPE_CHECKING:
    from core.context import PipelineContext


logger = logging.getLogger(__name__)

# ====================================================================
#
# ====================================================================

# (, print_status)
print_status_card = print_status

# ====================================================================
#
# ====================================================================

def print_summary(
    *,
    total_attacks: int,
    successful_attacks: int,
    overall_asr: float,
    report_path: str,
) -> None:
    """ ()."""
    print()
    print_card(
        "Attack Summary",
        [
            ("Total Attacks", str(total_attacks)),
            ("Successful", f"{_C_GREEN}{successful_attacks}{_C_RESET}"),
            ("Overall ASR", _format_asr(overall_asr)),
            ("Report", report_path),
        ],
        color=_C_CYAN,
    )
    print()

# ====================================================================
# PyRIT AttackResult ()
# ====================================================================

def _print_failure_summary(result: Any, tech_name: str, idx: int) -> None:
    """T-03: 1 ."""
    objective = getattr(result, "objective", "") or ""
    outcome = _get_outcome_label(result)

    seed_label = ""
    if hasattr(result, "metadata") and isinstance(result.metadata, dict):
        seed_label = result.metadata.get("seed_label", "") or result.metadata.get("seed_category", "")
    if not seed_label:
        seed_label = objective[:30].strip() + ("..." if len(objective) > 30 else "")

    converter_info = ""
    if hasattr(result, "converters") and result.converters:
        conv_names = [type(c).__name__ for c in result.converters[:2]]
        converter_info = f" [{', '.join(conv_names)}]" if conv_names else ""

    print(
        f"  {_C_DIM}[FAIL] [{tech_name}#{idx}]{_C_RESET} "
        f"{_C_DIM}{seed_label[:50]:<50}{_C_RESET} "
        f"{_C_RED}{outcome}{_C_RESET}"
        f"{_C_DIM}{converter_info}{_C_RESET}"
    )

def _print_result_fallback(result: Any) -> None:
    """ output ."""
    objective = getattr(result, "objective", "") or ""
    outcome = _get_outcome_label(result)
    print(f"    Objective: {objective[:100]}")
    print(f"    Outcome: {outcome}")

async def print_attack_results_native(
    attack_results: dict[str, list[Any]],
    *,
    phase_label: str = "STRIKE",
    max_per_tech: int = 3,
    verbose_failures: bool = False,
) -> None:
    """: PyRIT output_attack_async .

    R2 Sec2.1 :  pyrit.output  AttackResult,
    Layer ( ASR )
    """
    total_results = sum(len(r) for r in attack_results.values())
    if total_results == 0:
        print(f"\n  {_C_RED}[FAIL]  - {_C_RESET}")
        return

 # ASR
    sorted_techs = sorted(
        attack_results.items(),
        key=lambda kv: -(sum(1 for r in kv[1] if _is_success(r)) / max(1, len(kv[1]))),
    )

    for tech_name, results in sorted_techs:
        if not results:
            continue

        success_results = [r for r in results if _is_success(r)]
        fail_results = [r for r in results if not _is_success(r)]
        display_results = success_results[:max_per_tech]
        remaining_slots = max_per_tech - len(display_results)
        if remaining_slots > 0:
            display_results.extend(fail_results[:remaining_slots])

        if not display_results:
            continue

        for idx, result in enumerate(display_results):
            is_successful = _is_success(result)
            if is_successful:
                info = _extract_success_info(result, tech_name)
                print_success_breakthrough(
                    seed=info["seed"],
                    converter=info["converter"],
                    technique=info["technique"],
                    result_index=idx,
                    asr_prior=info.get("asr_prior", ""),
                    response=info.get("response", ""),
                )
                ok = await print_native_attack_result(result)
                if not ok:
                    _print_result_fallback(result)
            else:
                if verbose_failures:
                    ok = await print_native_attack_result(result)
                    if not ok:
                        _print_result_fallback(result)
                else:
                    _print_failure_summary(result, tech_name, idx)

    print_success_payload_snapshot(attack_results, phase_label=phase_label)

    print()
    print_card(
        f"{phase_label} - Per-Technique Summary (enhancement)",
        [
            ("Techniques", str(len(attack_results))),
            ("Total Results", str(total_results)),
            ("Native Output", f"output_attack_async (max {max_per_tech}/tech) shown above"),
        ],
        color=_C_YELLOW,
    )

    for tech_name, results in sorted_techs:
        if not results:
            continue
        tech_success = sum(1 for r in results if _is_success(r))
        tech_total = len(results)
        tech_asr = (tech_success / tech_total * 100) if tech_total > 0 else 0
        color = _asr_color(tech_asr)
        print(f"  {color}{tech_name:<28}{_C_RESET} "
              f"{tech_success:>3}/{tech_total:<3} {_asr_bar(tech_asr, width=20)}")

async def print_strike_results_native(ctx: "PipelineContext", *, max_per_tech: int = 3) -> None:
    """Print STRIKE results (native output)."""
    await print_attack_results_native(ctx.attack_results, phase_label="STRIKE", max_per_tech=max_per_tech)

def print_strike_card(ctx: "PipelineContext") -> None:
    """Print STRIKE card (summary only)."""
    total = sum(len(results) for results in ctx.attack_results.values())
    success_count = sum(
        1 for results in ctx.attack_results.values()
        for r in results if _is_success(r)
    )

    overall_asr = (success_count / total * 100) if total > 0 else 0

    print()
    print_card(
        "STRIKE - Execution Summary",
        [
            ("Techniques", str(len(ctx.attack_results))),
            ("Total Attacks", str(total)),
            ("Successful", f"{_C_GREEN if success_count == 0 else _asr_color(overall_asr)}{success_count}{_C_RESET}"),
            ("Failed", str(total - success_count)),
            ("Overall ASR", _format_asr(overall_asr)),
            ("Native Output", "see per-attack results above (pyrit.output)"),
        ],
        color=_C_YELLOW,
    )

    if total == 0:
        print(f"\n  {_C_RED}[FAIL]  - {_C_RESET}")

# ====================================================================
# (--stage , )
# ====================================================================

async def print_strike_report_async(ctx: "PipelineContext") -> None:
    """ (--stage strike) ."""
    scenario_result = getattr(ctx, "scenario_result", None)

    if scenario_result is not None:
        await print_native_scenario_result(scenario_result)

    await print_strike_results_native(ctx)

    if scenario_result is not None:
        await print_technique_trail(scenario_result)

    print_strike_card(ctx)

def print_strike_report(ctx: "PipelineContext") -> None:
    """Sync wrapper: print STRIKE report."""
    print_strike_card(ctx)

def print_arm_report(ctx: "PipelineContext") -> None:
    """ (--stage arm) ."""
    print_arm_card(ctx)

async def print_escalate_report_async(ctx: "PipelineContext") -> None:
    """Print ESCALATE report (R2 section 2.1 compliant)."""
    escalation_techs = [
        k for k in ctx.attack_results
        if any(
            x in k.lower()
            for x in [
                "crescendo", "tap", "pair", "gcg", "best_of_n",
                "skeleton", "native", "rogue", "mcp", "embedding",
                "many_shot", "cair", "encoded",
                "red_teaming", "multi_prompt", "chunked",
            ]
        )
    ]

    if escalation_techs:
        escalate_results = {k: ctx.attack_results[k] for k in escalation_techs}
        await print_attack_results_native(
            escalate_results,
            phase_label="ESCALATE",
            max_per_tech=3,
        )

    print_escalate_card(ctx)

def print_escalate_report(ctx: "PipelineContext") -> None:
    """: ()."""
    print_escalate_card(ctx)

def print_assess_report(ctx: "PipelineContext") -> None:
    """ (--stage assess) ."""
    print_assess_card(ctx)


# NOTE: Strike/Escalation helpers moved to utils/_display_helpers.py:
#   _get_endpoint_name, _load_tech_asr_data, _rank_techniques_for_display,
#   _partition_into_display_batches, _get_seed_summary, _print_priority_batch_card,
#   print_strike_start_banner, print_escalation_decision_card, print_escalation_level_banner,
#   print_batch_exit_card, _get_current_technique, _get_seed_category_for_idx,
#   print_converter_path_start, print_converter_path_done, print_seed_batch_progress,
#   print_native_sequential_progress, print_escalation_tech_start, print_escalation_tech_done,
#   print_strike_phase_summary
