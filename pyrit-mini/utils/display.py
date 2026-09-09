"""display.py - unified display facade (consolidated post-redteam).

Architecture: single flat file replaces 5 fragmented display modules.
Removed: decorative banners, progress bars, ASCII art, unused helpers.

Preserved: only symbols with actual consumers in the attack pipeline.
"""
from __future__ import annotations

import logging
import re as _re
import sys as _sys
from typing import TYPE_CHECKING, Any

from utils.attack_utils import _is_success  # P0-3: SSOT import

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)

# == ANSI color codes ==
_C_RESET = "\033[0m"
_C_BOLD = "\033[1m"
_C_DIM = "\033[2m"
_C_RED = "\033[91m"
_C_GREEN = "\033[92m"
_C_YELLOW = "\033[93m"
_C_BLUE = "\033[94m"
_C_CYAN = "\033[96m"
_C_MAGENTA = "\033[95m"

# Windows terminal setup
for _stream in (_sys.stdout, _sys.stderr):
    try:
        if hasattr(_stream, "reconfigure"):
            _stream.reconfigure(encoding="utf-8")
    except Exception:
        pass

if _sys.platform == "win32":
    try:
        import ctypes
        _kernel32 = ctypes.windll.kernel32
        _kernel32.SetConsoleMode(_kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

# == Internal: ANSI regex for visual width ==
_ANSI_RE = _re.compile(r"\033\[[0-9;]*m")


def _asr_color(asr: float) -> str:
    if asr >= 70:
        return _C_RED
    if asr >= 40:
        return _C_YELLOW
    if asr >= 15:
        return _C_CYAN
    return _C_GREEN


def _format_asr(asr: float) -> str:
    c = _asr_color(asr)
    return f"{c}{asr:.1f}%{_C_RESET}"


def _asr_bar(asr: float, width: int = 20) -> str:
    c = _asr_color(asr)
    filled = int(asr / 100 * width)
    bar = "#" * filled + "-" * (width - filled)
    return f"{c}{bar} {asr:>5.1f}%{_C_RESET}"


def _visual_width(text: str) -> int:
    import unicodedata
    clean = _ANSI_RE.sub("", text)
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in clean)


def _pad_line(text: str, width: int = 68) -> str:
    vw = _visual_width(text)
    if vw > width:
        return text
    return text + " " * max(0, width - vw)


def _card_line(text: str, color: str = "") -> str:
    padded = _pad_line(text)
    if color:
        return f"{color}|| {padded} ||{_C_RESET}"
    return f"|| {padded} []"


def _print_card_top(color: str = "") -> None:
    line = "+" + "=" * 68 + "+"
    print(f"{color}{line}{_C_RESET}" if color else line)


def _print_card_bottom(color: str = "") -> None:
    line = "+" + "=" * 68 + "+"
    print(f"{color}{line}{_C_RESET}" if color else line)


def _print_card_sep() -> None:
    print("|| " + "=" * 68 + " ||")


# ====================================================================
# Phase display primitives (consumed by: main.py, core/phases/*)
# ====================================================================

def print_banner() -> None:
    print()
    print(f"{_C_CYAN}{_C_BOLD}+{'=' * 68}+")
    print(f"||{'PyRIT-Strike v2.0.0':^68}||")
    print(f"||{'Burp -> Attack -> Report - One-Click Pipeline':^68}||")
    print(f"+{'=' * 68}+{_C_RESET}")
    print()


def print_phase(phase: str, description: str) -> None:
    phase_colors = {
        "RECON": _C_CYAN, "ARM": _C_BLUE, "STRIKE": _C_YELLOW,
        "ESCALATE": _C_MAGENTA, "ASSESS": _C_GREEN, "REPORT": _C_CYAN, "INIT": _C_DIM,
    }
    color = phase_colors.get(phase, _C_BOLD)
    sep = "=" * 60
    print()
    print(f"  {color}{sep}{_C_RESET}")
    print(f"  {color}> [{phase}] {_C_RESET}{_C_BOLD}{description}{_C_RESET}")
    print(f"  {color}{sep}{_C_RESET}")


def print_status(phase: str, status: str, message: str, *, ok: bool | None = None) -> None:
    if ok is True:
        tag = f"{_C_GREEN}[OK]{_C_RESET}"
        sc = _C_GREEN
    elif ok is False:
        tag = f"{_C_RED}[FAIL]{_C_RESET}"
        sc = _C_RED
    else:
        tag = f"{_C_CYAN}[*]{_C_RESET}"
        sc = _C_CYAN
    print(f"  {tag} {_C_BOLD}[{phase}]{_C_RESET} {sc}{status}{_C_RESET}  {_C_DIM}{message}{_C_RESET}")


def print_card(title: str, rows: list[tuple[str, str]], *, color: str = "", title_color: str = "") -> None:
    border_color = color or title_color
    _print_card_top(border_color)
    tc = title_color or color or _C_BOLD
    print(_card_line(title, tc))
    _print_card_sep()
    for label, value in rows:
        print(_card_line(f"{label}: {value}"))
    _print_card_bottom(border_color)


def print_error(message: str) -> None:
    print()
    _print_card_top(_C_RED)
    print(_card_line(f"{_C_RED}{_C_BOLD}[FAIL] ERROR{_C_RESET}", _C_RED))
    _print_card_sep()
    print(_card_line(message, _C_RED))
    _print_card_bottom(_C_RED)
    print()


# ====================================================================
# Phase-specific cards (consumed by: core/phases/*)
# ====================================================================

def print_recon_card(
    entry_point: str,
    attack_surface: list[str],
    confidence: float,
    capabilities: list[str],
    seeds: list[str],
    converters: list[str],
) -> None:
    rows = [
        ("Entry", entry_point),
        ("Attack Surface", ", ".join(attack_surface[:3]) if attack_surface else "N/A"),
        ("Confidence", f"{_C_CYAN}{confidence:.1%}{_C_RESET}"),
        ("Capabilities", ", ".join(capabilities[:4]) if capabilities else "N/A"),
    ]
    if seeds:
        rows.append(("Seeds", f"{len(seeds)} seeds loaded"))
    if converters:
        rows.append(("Converters", ", ".join(converters[:3])))
    print_card("RECON: Target Reconnaissance", rows, color=_C_CYAN)


def print_arm_card(tech: str, seeds_count: int, converters: list[str], max_seeds: int, ctx: Any = None) -> None:
    rows = [
        ("Technology", f"{_C_BOLD}{tech}{_C_RESET}"),
        ("Seeds", f"{seeds_count} (max={max_seeds})"),
        ("Converters", ", ".join(converters[:4]) if converters else "raw"),
    ]
    if ctx:
        budget = getattr(ctx, "probe_budget", None)
        if budget:
            rows.append(("Budget", str(budget)))
    print_card("ARM: Weapon Assembly", rows, color=_C_BLUE)


def print_arm_highlights(*, seed_count: int, technique_count: int, converter_count: int) -> None:
    """Print ARM phase highlights (consumed by: core/phases/arm.py)."""
    print(f"  {_C_DIM}[ARM]{_C_RESET} {_C_GREEN}Seed={seed_count}{_C_RESET}, "
          f"{_C_MAGENTA}Technique={technique_count}{_C_RESET}, "
          f"{_C_CYAN}Converter={converter_count}{_C_RESET}")


def print_assess_card(tech: str, judge_scores: list[float], avg_score: float, confidence: float) -> None:
    score_color = _C_GREEN if avg_score >= 7 else _C_YELLOW if avg_score >= 4 else _C_RED
    rows = [
        ("Technology", f"{_C_BOLD}{tech}{_C_RESET}"),
        ("Avg Score", f"{score_color}{avg_score:.1f}/10{_C_RESET}"),
        ("Confidence", f"{_C_CYAN}{confidence:.1%}{_C_RESET}"),
        ("Samples", f"{len(judge_scores)}"),
    ]
    print_card("ASSESS: Scoring", rows, color=_C_GREEN)


def print_report_card(report_path: str, report_type: str = "HTML") -> None:
    rows = [
        ("Type", report_type),
        ("Path", report_path),
        ("Status", f"{_C_GREEN}Generated{_C_RESET}"),
    ]
    print_card("REPORT: Generated", rows, color=_C_CYAN)


def print_joint_asr_card(per_endpoint: dict[str, float], joint_asr: float) -> None:
    rows = []
    for endpoint, asr in per_endpoint.items():
        rows.append((endpoint, _format_asr(asr)))
    rows.append(("Joint ASR", f"{_C_BOLD}{_format_asr(joint_asr)}{_C_RESET}"))
    print_card("Joint ASR Summary", rows, color=_C_MAGENTA)


def print_summary(*, total_attacks: int, successful_attacks: int, overall_asr: float, report_path: str) -> None:
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
# Strike helpers (consumed by: strike/executor.py, core/phases/strike.py)
# ====================================================================

def _get_endpoint_name(ctx: Any) -> str:
    import pathlib
    burp_val = getattr(ctx.args, "burp", None)
    if burp_val:
        try:
            return pathlib.Path(burp_val).stem
        except Exception:
            return str(burp_val)
    out_dir = getattr(ctx, "output_dir", None)
    if out_dir:
        try:
            name = pathlib.Path(str(out_dir)).name
            parts = name.split("_", 2)
            if len(parts) >= 3 and parts[0] == "endpoint":
                return parts[2]
            return name
        except Exception:
            pass
    return "unknown"


def print_strike_start_banner(ctx: Any, *, total_endpoints: int | None = None, current_endpoint_idx: int | None = None) -> None:
    ep_name = _get_endpoint_name(ctx)
    total_seeds = len(ctx.seeds)
    total_converters = sum(len(v) for v in ctx.converter_map.values()) if ctx.converter_map else 0
    ep_idx_str = ""
    if total_endpoints and current_endpoint_idx is not None:
        ep_idx_str = f" {_C_DIM}(endpoint {current_endpoint_idx + 1}/{total_endpoints}){_C_RESET}"
    from core.context import get_effective_concurrency
    concurrency = get_effective_concurrency(ctx)
    print()
    print(f"{_C_BOLD}{'=' * 60}{_C_RESET}")
    print(f"{_C_BOLD}  > STRIKE: Baseline Attack ( PromptSending){_C_RESET}{ep_idx_str}")
    print(f"{_C_BOLD}{'=' * 60}{_C_RESET}")
    print(f"  {_C_CYAN}Endpoint{_C_RESET}      {ep_name}")
    print(f"  {_C_CYAN}Seeds{_C_RESET}         {total_seeds}")
    print(f"  {_C_CYAN}Conv. Paths{_C_RESET}   {total_converters}")
    print(f"  {_C_CYAN}Concurrency{_C_RESET}   {concurrency}")


def print_strike_phase_summary(ctx: Any, *, total_results: int, total_success: int, elapsed_seconds: float) -> None:
    ep_name = _get_endpoint_name(ctx)
    asr = (total_success / max(1, total_results) * 100) if total_results > 0 else 0.0
    asr_str = _format_asr(asr)
    print()
    print(f"  {_C_BOLD}{'=' * 60}{_C_RESET}")
    print(f"  {_C_BOLD}STRIKE DONE:{_C_RESET} {_C_CYAN}{ep_name}{_C_RESET} "
          f"| {total_results} attacks, {_C_GREEN}{total_success} success{_C_RESET} ({asr_str}) "
          f"| {elapsed_seconds:.1f}s")
    print(f"  {_C_BOLD}{'=' * 60}{_C_RESET}")


def print_converter_path_start(ctx: Any, *, converter_name: str, path_idx: int, total_paths: int, seeds_remaining: int) -> None:
    ep_name = _get_endpoint_name(ctx)
    print(f"\n  {_C_BOLD}> [STRIKE]{_C_RESET} {_C_CYAN}{ep_name}{_C_RESET} "
          f"{_C_DIM}|{_C_RESET} Path {_C_YELLOW}{path_idx + 1}/{total_paths}{_C_RESET}: "
          f"{_C_MAGENTA}{converter_name}{_C_RESET} "
          f"| {seeds_remaining} seeds {_C_DIM}[WAIT]{_C_RESET}")


def print_converter_path_done(ctx: Any, *, converter_name: str, path_idx: int, total_paths: int,
                               seeds_attempted: int, seeds_succeeded: int, seeds_remaining: int, elapsed_seconds: float) -> None:
    ep_name = _get_endpoint_name(ctx)
    success_rate = (seeds_succeeded / seeds_attempted * 100) if seeds_attempted > 0 else 0.0
    rate_color = _asr_color(success_rate)
    if seeds_remaining == 0:
        status = f"{_C_GREEN}[OK] ALL DONE{_C_RESET}"
    elif seeds_succeeded > 0:
        status = f"{_C_GREEN}[OK] partial{_C_RESET}"
    else:
        status = f"{_C_YELLOW}o no success{_C_RESET}"
    print(f"  {status} {_C_DIM}[STRIKE]{_C_RESET} {_C_CYAN}{ep_name}{_C_RESET} "
          f"{_C_DIM}|{_C_RESET} Path {_C_YELLOW}{path_idx + 1}/{total_paths}{_C_RESET}: "
          f"{_C_MAGENTA}{converter_name}{_C_RESET} "
          f"| {rate_color}{seeds_succeeded}/{seeds_attempted} ({success_rate:.0f}%) success{_C_RESET}, "
          f"{seeds_remaining} remaining {_C_DIM}({elapsed_seconds:.1f}s){_C_RESET}")


def print_seed_batch_progress(ctx: Any, *, converter_name: str, path_idx: int, total_paths: int,
                               completed: int, total: int, succeeded: int) -> None:
    ep_name = _get_endpoint_name(ctx)
    bar_width = 20
    filled = int(completed / max(1, total) * bar_width)
    bar = "#" * filled + "-" * (bar_width - filled)
    succ_str = f"{_C_GREEN}{succeeded} success{_C_RESET}" if succeeded > 0 else f"{_C_DIM}0 success{_C_RESET}"
    line = (f"\r  {_C_DIM}[STRIKE]{_C_RESET} {_C_CYAN}{ep_name}{_C_RESET} "
            f"{_C_DIM}|{_C_RESET} Path {_C_YELLOW}{path_idx + 1}/{total_paths}{_C_RESET}: "
            f"{_C_MAGENTA}{converter_name}{_C_RESET} "
            f"{_C_DIM}|{_C_RESET} {bar} {completed}/{total} ({succ_str})")
    if completed < total:
        print(f"{line}{' ' * 10}", end="", flush=True)
    else:
        print(f"{line}{' ' * 10}")


def print_native_sequential_progress(ctx: Any, *, seed_idx: int, total_seeds: int,
                                      converter_count: int, objective_preview: str) -> None:
    ep_name = _get_endpoint_name(ctx)
    bar_width = 20
    filled = int((seed_idx + 1) / max(1, total_seeds) * bar_width)
    bar = "#" * filled + "-" * (bar_width - filled)
    obj_short = objective_preview[:50] + ("..." if len(objective_preview) > 50 else "")
    line = (f"\r  {_C_DIM}[STRIKE]{_C_RESET} {_C_CYAN}{ep_name}{_C_RESET} "
            f"{_C_DIM}| Sequential{_C_RESET} {bar} {seed_idx + 1}/{total_seeds} "
            f"{_C_DIM}| {converter_count} paths{_C_DIM} | obj: \"{obj_short}\"")
    if seed_idx + 1 < total_seeds:
        print(f"{line}{' ' * 10}", end="", flush=True)
    else:
        print(f"{line}{' ' * 10}")


# ====================================================================
# PyRIT native output (consumed by: this module's own orchestrators)
# ====================================================================

async def print_native_attack_result(result: Any, *, include_auxiliary: bool = True,
                                      include_adversarial: bool = True, include_pruned: bool = True) -> bool:
    """Dispatch PyRIT output_attack_async for a single result."""
    if result is None:
        return False
    try:
        from pyrit.output import OutputFormat, StdoutSink, output_attack_async
        await output_attack_async(
            result, format=OutputFormat.PRETTY, sink=StdoutSink(),
            include_auxiliary_metadata=include_auxiliary,
            include_adversarial_conversation=include_adversarial,
            include_pruned_conversations=include_pruned,
        )
        return True
    except Exception as e:
        logger.debug("Native attack output failed: %s", e)
        return False


async def print_native_scenario_result(scenario_result: Any) -> bool:
    """Dispatch PyRIT output_scenario_async."""
    if scenario_result is None:
        return False
    try:
        from pyrit.output import OutputFormat, StdoutSink, output_scenario_async
        await output_scenario_async(scenario_result, format=OutputFormat.PRETTY, sink=StdoutSink(),
                                     sort_groups_by_success_rate=True)
        return True
    except Exception as e:
        logger.debug("Native scenario output failed: %s", e)
        return False


async def print_technique_trail(scenario_result: Any) -> None:
    """Display per-objective per-attempt technique trail."""
    if scenario_result is None:
        return
    try:
        from pyrit.models import AttackOutcome
    except ImportError:
        return
    display_groups = scenario_result.get_display_groups()
    if not display_groups:
        return
    for group_name, group_results in display_groups.items():
        if not group_results:
            continue
        print(f"\n{_C_BOLD}=== Group: {group_name} ==={_C_RESET}")
        objectives_order: list[str] = []
        objectives_map: dict[str, list[Any]] = {}
        for r in group_results:
            obj = getattr(r, "objective", "") or ""
            if obj not in objectives_map:
                objectives_map[obj] = []
                objectives_order.append(obj)
            objectives_map[obj].append(r)
        for objective in objectives_order:
            attempts = objectives_map[objective]
            final_outcome = getattr(attempts[-1], "outcome", None) if attempts else None
            is_success = final_outcome == AttackOutcome.SUCCESS if final_outcome else False
            outcome_str = f"{_C_GREEN}success{_C_RESET}" if is_success else f"{_C_RED}failure{_C_RESET}"
            obj_display = objective[:80] if len(objective) > 80 else objective
            print(f"  [{outcome_str}] '{obj_display}': ", end="")
            trail_parts: list[str] = []
            for attempt in attempts:
                tech = getattr(attempt, "attack_technique", None) or getattr(attempt, "technique", None)
                if tech:
                    name = tech if isinstance(tech, str) else type(tech).__name__
                    attempt_ok = getattr(attempt, "outcome", None) == AttackOutcome.SUCCESS
                    trail_parts.append(f"{name}({'ok' if attempt_ok else 'fail'})")
            print(" -> ".join(trail_parts) if trail_parts else "(no trail)")


# ====================================================================
# Attack result orchestration (consumed by: strike/__init__.py)
# ====================================================================

def _print_failure_summary(result: Any, tech_name: str, idx: int) -> None:
    objective = getattr(result, "objective", "") or ""
    outcome = getattr(result, "outcome", "")
    outcome_str = str(outcome)
    tag = f"{_C_GREEN}SCORE{_C_RESET}" if "score" in outcome_str.lower() else (
        f"{_C_RED}FAIL{_C_RESET}" if "fail" in outcome_str.lower() else outcome_str[:10]
    )
    seed_label = objective[:30].strip() + ("..." if len(objective) > 30 else "")
    print(f"  {_C_DIM}[FAIL] [{tech_name}#{idx}]{_C_RESET} "
          f"{_C_DIM}{seed_label[:50]:<50}{_C_RESET} {_C_RED}{tag}{_C_RESET}")


async def print_attack_results_native(
    attack_results: dict[str, list[Any]], *, phase_label: str = "STRIKE",
    max_per_tech: int = 3, verbose_failures: bool = False,
) -> None:
    total_results = sum(len(r) for r in attack_results.values())
    if total_results == 0:
        print(f"\n  {_C_RED}[FAIL]  - no results{_C_RESET}")
        return
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
            if _is_success(result):
                obj = getattr(result, "objective", "") or ""
                conv_names = [type(c).__name__ for c in getattr(result, "converters", [])[:2]]
                resp = getattr(result, "response", "") or "N/A"
                print(f"\n  {_C_BOLD}{_C_GREEN}[BREAKTHROUGH] [{tech_name}]{_C_RESET}")
                print(f"  {_C_DIM}Objective: {obj[:80]}{_C_RESET}")
                print(f"  {_C_DIM}Converters: {', '.join(conv_names)}{_C_RESET}")
                print(f"  {_C_DIM}Response: {str(resp)[:120]}{_C_RESET}")
                ok = await print_native_attack_result(result)
                if not ok:
                    print(f"  {_C_DIM}payload={getattr(result, 'converted_prompt', '')[:100]}{_C_RESET}")
            else:
                if verbose_failures:
                    await print_native_attack_result(result)
                else:
                    _print_failure_summary(result, tech_name, idx)
    print()
    print_card(
        f"{phase_label} - Per-Technique Summary",
        [
            ("Techniques", str(len(attack_results))),
            ("Total Results", str(total_results)),
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
    await print_attack_results_native(ctx.attack_results, phase_label="STRIKE", max_per_tech=max_per_tech)


def print_strike_card(ctx: "PipelineContext") -> None:
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
        ],
        color=_C_YELLOW,
    )


async def print_strike_report_async(ctx: "PipelineContext") -> None:
    scenario_result = getattr(ctx, "scenario_result", None)
    if scenario_result is not None:
        await print_native_scenario_result(scenario_result)
    await print_strike_results_native(ctx)
    if scenario_result is not None:
        await print_technique_trail(scenario_result)
    print_strike_card(ctx)


def print_strike_report(ctx: "PipelineContext") -> None:
    print_strike_card(ctx)


async def print_escalate_report_async(ctx: "PipelineContext") -> None:
    escalation_techs = [
        k for k in ctx.attack_results
        if any(x in k.lower() for x in [
            "crescendo", "tap", "pair", "gcg", "best_of_n",
            "skeleton", "native", "rogue", "mcp", "embedding",
            "many_shot", "cair", "encoded", "red_teaming", "multi_prompt", "chunked",
        ])
    ]
    if escalation_techs:
        escalate_results = {k: ctx.attack_results[k] for k in escalation_techs}
        await print_attack_results_native(escalate_results, phase_label="ESCALATE", max_per_tech=3)
    print_strike_card(ctx)


def print_escalate_report(ctx: "PipelineContext") -> None:
    print_strike_card(ctx)


def print_assess_report(ctx: "PipelineContext") -> None:
    print_assess_card(ctx)
