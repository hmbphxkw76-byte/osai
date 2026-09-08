# -*- coding: utf-8 -*-
"""display: Strike/Escalation helpers.

Striped from utils/display.py (R-SIZE , 926 -> <800).
All print_ functions for strike progress, escalation level and batch judgment.

Dependencies: utils.display_primitives (color + card), utils.display_params (),
             utils.display_stages (_get_technique_category / _get_technique_params / _get_converter_summary).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from utils.display_params import _get_converter_summary, _get_technique_category, _get_technique_params
from utils.display_primitives import (
    _C_BLUE,
    _C_BOLD,
    _C_CYAN,
    _C_DIM,
    _C_GREEN,
    _C_MAGENTA,
    _C_RED,
    _C_RESET,
    _C_YELLOW,
    _asr_color,
    _card_line,
    _format_asr,
    _print_card_bottom,
    _print_card_sep,
    _print_card_top,
)

if TYPE_CHECKING:
    from core.context import PipelineContext


# ---------------------------------------------------------------------------
# ctx
# ---------------------------------------------------------------------------

def _get_endpoint_name(ctx: "PipelineContext") -> str:
    """ctx (burp stem / output_dir name / 'unknown')."""
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


def _get_current_technique(ctx: "PipelineContext") -> str:
    """ctx._current_escalation_tech  'prompt_sending'."""
    _esc_tech = getattr(ctx, "_current_escalation_tech", None)
    if _esc_tech:
        return _esc_tech
    techniques = getattr(ctx, "techniques", None) or []
    if techniques:
        return "prompt_sending"
    return "unknown"


def _get_seed_category_for_idx(ctx: "PipelineContext", seed_idx: int) -> str:
    """owasp_id / severity / category  ' [A03, high]'."""
    if seed_idx < 0 or seed_idx >= len(ctx.seeds):
        return ""
    group = ctx.seeds[seed_idx]
    for seed in getattr(group, "seeds", []):
        meta = getattr(seed, "metadata", {}) or {}
        tags = [v for v in (str(meta.get("owasp_id", "")).strip(),
                            str(meta.get("severity", "")).strip(),
                            str(meta.get("category", "")).strip()) if v]
        return f" [{', '.join(tags)}]" if tags else ""
    return ""


def _get_seed_summary(ctx: "PipelineContext") -> str:
    """:  + category + severity + UCB ."""
    total = len(ctx.seeds)
    if total == 0:
        return "0 seeds"

    categories: set[str] = set()
    severities: set[str] = set()
    for group in ctx.seeds[:20]:
        for seed in getattr(group, "seeds", []):
            meta = getattr(seed, "metadata", {}) or {}
            cats = str(meta.get("category", "")).strip()
            sevs = str(meta.get("severity", "")).strip()
            if cats:
                categories.add(cats)
            if sevs:
                severities.add(sevs)

    parts: list[str] = [f"{total} seeds"]
    if categories:
        parts.append(f"{len(categories)} cats")
    if severities:
        parts.append(f"{len(severities)} sev")
    parts.append("UCB-ranked")

    return ", ".join(parts)


# ---------------------------------------------------------------------------
# ASR prior  batch
# ---------------------------------------------------------------------------

def _load_tech_asr_data(
    techniques: list[str],
    ctx: "PipelineContext",
) -> tuple[dict[str, float], dict[str, float]]:
    """ASR prior ()."""
    tech_asr_history: dict[str, float] = {}
    try:
        from arm.seed_ranking import _ASR_HISTORY_PATH
        if _ASR_HISTORY_PATH.exists():
            import json
            data = json.loads(_ASR_HISTORY_PATH.read_text(encoding="utf-8"))
            tech_asr_history = data.get("asr", {})
    except Exception:
        pass

    tech_asr_priors: dict[str, float] = {}
    if techniques:
        try:
            from arm.seed_ranking import get_technique_asr_prior
            _model_name = ctx.model_name or ""
            if ctx.parsed_request:
                _fp = ctx.parsed_request.target_fingerprint
                _model_name = _fp.get("model_family", "") or _fp.get("burp_model_name", "") or _model_name
            for tech in techniques:
                prior_key = tech.split("_")[0] if "_" in tech and tech not in ("prompt_sending",) else tech
                prior_val = get_technique_asr_prior(tech, _model_name)
                if prior_val == 0.0:
                    prior_val = get_technique_asr_prior(prior_key, _model_name)
                if prior_val > 0:
                    tech_asr_priors[tech] = prior_val
        except Exception:
            pass

    return tech_asr_history, tech_asr_priors


def _rank_techniques_for_display(
    techniques: list[str],
    tech_asr_priors: dict[str, float],
) -> list[tuple[str, float]]:
    """ prior ."""
    ranked: list[tuple[str, float]] = []
    for tech in techniques:
        prior = tech_asr_priors.get(tech, 0.0)
        ranked.append((tech, prior))
    ranked.sort(key=lambda x: x[1], reverse=True)
    return ranked


def _partition_into_display_batches(
    ranked: list[tuple[str, float]],
    *,
    high_threshold: float = 60.0,
    low_threshold: float = 40.0,
) -> list[tuple[str, list[tuple[str, float]]]]:
    """ prior (high //)."""
    if len(ranked) <= 2:
        return [("all", ranked)]

    batch_high: list[tuple[str, float]] = []
    batch_mid: list[tuple[str, float]] = []
    batch_low: list[tuple[str, float]] = []

    for tech, prior in ranked:
        if prior >= high_threshold:
            batch_high.append((tech, prior))
        elif prior >= low_threshold:
            batch_mid.append((tech, prior))
        else:
            batch_low.append((tech, prior))

    batches: list[tuple[str, list[tuple[str, float]]]] = []
    if batch_high:
        batches.append(("1 (high prior >= 60%)", batch_high))
    if batch_mid:
        batches.append(("2 (mid prior 40-59%)", batch_mid))
    if batch_low:
        batches.append(("3 (low prior < 40%)", batch_low))

    return batches


# ---------------------------------------------------------------------------
# Banner / Card
# ---------------------------------------------------------------------------

def print_strike_start_banner(
    ctx: "PipelineContext",
    *,
    total_endpoints: int | None = None,
    current_endpoint_idx: int | None = None,
) -> None:
    """STRIKE baseline ."""
    ep_name = _get_endpoint_name(ctx)
    total_seeds = len(ctx.seeds)
    total_converters = sum(len(v) for v in ctx.converter_map.values()) if ctx.converter_map else 0

    ep_idx_str = ""
    if total_endpoints and current_endpoint_idx is not None:
        ep_idx_str = f" {_C_DIM}(endpoint {current_endpoint_idx + 1}/{total_endpoints}){_C_RESET}"

    timeout_val = getattr(ctx.args, "timeout", None) or 1200
    from core.context import get_effective_concurrency
    concurrency = get_effective_concurrency(ctx)

    model_family = ""
    if ctx.parsed_request:
        _fp = ctx.parsed_request.target_fingerprint
        model_family = _fp.get("model_family", "") or _fp.get("burp_model_name", "") or ""
    if not model_family:
        model_family = ctx.model_name or "unknown"

    print()
    print(f"{_C_BOLD}{'=' * 60}{_C_RESET}")
    print(f"{_C_BOLD}  > STRIKE: Baseline Attack ( PromptSending){_C_RESET}{ep_idx_str}")
    print(f"{_C_BOLD}{'=' * 60}{_C_RESET}")
    print(f"  {_C_CYAN}Endpoint{_C_RESET}      {ep_name}")
    print(f"  {_C_CYAN}Model Family{_C_RESET}  {model_family}")
    print(f"  {_C_CYAN}Technique{_C_RESET}    prompt_sending (PromptSendingAttack)")
    print(f"  {_C_CYAN}Seeds{_C_RESET}         {total_seeds}")
    print(f"  {_C_CYAN}Conv. Paths{_C_RESET}   {total_converters}")
    print(f"  {_C_CYAN}Concurrency{_C_RESET}   {concurrency}")
    print(f"  {_C_CYAN}Timeout{_C_RESET}       {timeout_val}s ({timeout_val // 60}m {(timeout_val % 60)}s)")
    print(f"  {_C_CYAN}Pre-inject{_C_RESET}    SkeletonKey (native)")
    print(f"  {_C_CYAN}Scorer{_C_RESET}        MultiKeywordRefusal (0 token, FIRST_SUCCESS)")
    print(f"{_C_BOLD}{'=' * 60}{_C_RESET}")


def print_escalation_decision_card(
    ctx: "PipelineContext",
    *,
    baseline_asr: float,
    failed_count: int,
) -> None:
    """."""
    _esc_threshold = float(getattr(ctx.args, "escalation_asr_threshold", 90) or 90)
    _l1_exit = float(getattr(ctx.args, "post_l1_exit_threshold", 70) or 70)
    _l2_exit = float(getattr(ctx.args, "post_l2_exit_threshold", 80) or 80)
    _esc_levels = getattr(ctx.args, "escalation_levels_parsed", None)
    if _esc_levels is not None:
        chain_str = ", ".join(f"L{i}" for i in sorted(_esc_levels))
    else:
        chain_str = "L1->L2->L3->L4 (full chain)"

    decision = "ESCALATE" if baseline_asr < _esc_threshold else "SKIP"
    decision_color = _C_RED if decision == "ESCALATE" else _C_GREEN

    print()
    _print_card_top(_C_MAGENTA)
    print(_card_line("ESCALATION DECISION", _C_MAGENTA + _C_BOLD))
    _print_card_sep()
    print(_card_line(f"Baseline ASR:        {baseline_asr:.1f}%", _C_MAGENTA))
    print(_card_line(f"Escalation Threshold: {_esc_threshold:.0f}%", _C_MAGENTA))
    print(_card_line(
        f"Decision:            {decision_color}{decision}{_C_RESET}"
        + (f" (ASR < threshold, {failed_count} failed targets)" if decision == "ESCALATE" else " (ASR >= threshold)"),
        _C_MAGENTA,
    ))
    print(_card_line(f"Escalation Chain:    {chain_str}", _C_MAGENTA))
    print(_card_line(f"L1 Exit Threshold:   ASR >= {_l1_exit:.0f}% -> skip L2-L4", _C_MAGENTA))
    print(_card_line(f"L2 Exit Threshold:   ASR >= {_l2_exit:.0f}% -> skip L3-L4", _C_MAGENTA))
    _print_card_bottom(_C_MAGENTA)


def print_escalation_level_banner(
    ctx: "PipelineContext",
    *,
    level: int,
    techniques: list[str],
    failed_count: int,
    batch_mode: bool = False,
) -> None:
    """."""
    level_names = {
        1: "Multi-Turn Priority Batches",
        2: "GCG + CAIR + Best-of-N + Encoded Injection",
        3: "Multi-Model + SkeletonKey + Many-Shot+CoT",
        4: "Rogue Agent + Embedding Inversion + MCP/RAG",
    }
    level_colors = {1: _C_RED, 2: _C_YELLOW, 3: _C_CYAN, 4: _C_MAGENTA}
    color = level_colors.get(level, _C_BOLD)
    name = level_names.get(level, f"Level {level}")

    sep = "=" * 60
    print()
    print(f"  {color}{sep}{_C_RESET}")
    print(f"  {color}> ESCALATE L{level}: {name}{_C_RESET}")
    print(f"  {color}{sep}{_C_RESET}")
    print(f"  {_C_CYAN}Seeds{_C_RESET}     {failed_count} failed objectives from baseline")
    if batch_mode:
        _l1_exit = float(getattr(ctx.args, "post_l1_exit_threshold", 70) or 70)
        _ps_epsilon = float(getattr(ctx.args, "priority_scheduler_epsilon", 0.1) or 0.1)
        print(f"  {_C_CYAN}Scheduler{_C_RESET}  priority-batch (exit={_l1_exit:.0f}%, e={_ps_epsilon:.2f})")
    else:
        print(f"  {_C_CYAN}Strategy{_C_RESET}   full parallel ({len(techniques)} techniques)")
    print(f"  {_C_CYAN}Scorer{_C_RESET}    MultiKeywordRefusal (0-token) -> TFInverter -> LLM Dual Judge")
    print(f"  {color}{sep}{_C_RESET}")


def print_batch_exit_card(
    *,
    batch_idx: int,
    total_batches: int,
    cumulative_asr: float,
    exit_threshold: float,
    remaining_failed: int,
) -> None:
    """batch /."""
    is_exit = cumulative_asr >= exit_threshold
    decision = "EXIT" if is_exit else "CONTINUE"
    decision_color = _C_GREEN if is_exit else _C_YELLOW

    _card_color = _C_BLUE
    print()
    _print_card_top(_card_color)
    print(_card_line(f"Batch {batch_idx + 1} Result", _card_color + _C_BOLD))
    _print_card_sep()
    print(_card_line(f"Cumulative ASR: {cumulative_asr:.1f}%", _card_color))
    print(_card_line(f"Exit Threshold:  {exit_threshold:.0f}%", _card_color))
    if is_exit:
        saved = total_batches - batch_idx - 1
        print(
            _card_line(
                f"Decision:       {decision_color}{decision}{_C_RESET} - ASR >= threshold, skipping {saved} remaining batch(es)",
                _card_color,
            ))
        print(_card_line(f"Saved:           ~{saved} batches (est. 40-50% token/time)", _card_color))
    else:
        print(_card_line(
            f"Decision:       {decision_color}{decision}{_C_RESET} - proceeding to Batch {batch_idx + 2}",
            _card_color,
        ))
        print(_card_line(f"Remaining:       {remaining_failed} failed objectives", _card_color))
    _print_card_bottom(_card_color)


# ---------------------------------------------------------------------------
# Converter path / seed batch
# ---------------------------------------------------------------------------

def print_converter_path_start(
    ctx: "PipelineContext",
    *,
    converter_name: str,
    path_idx: int,
    total_paths: int,
    seeds_remaining: int,
) -> None:
    """ converter ."""
    ep_name = _get_endpoint_name(ctx)
    tech = _get_current_technique(ctx)
    cat = _get_technique_category(tech)

    print(
        f"\n  {_C_BOLD}> [STRIKE]{_C_RESET} {_C_CYAN}{ep_name}{_C_RESET} "
        f"{_C_DIM}|{_C_RESET} {_C_MAGENTA}{tech}{_C_RESET} {_C_DIM}({cat}){_C_RESET} "
        f"{_C_DIM}|{_C_RESET} Path {_C_YELLOW}{path_idx + 1}/{total_paths}{_C_RESET}: "
        f"{_C_MAGENTA}{converter_name}{_C_RESET} "
        f"| {seeds_remaining} seeds {_C_DIM}[WAIT]{_C_RESET}"
    )
    seed_summary = _get_seed_summary(ctx)
    print(
        f"  {_C_DIM}== Seeds: {_C_CYAN}{seed_summary}{_C_RESET}  "
        f"{_C_DIM}== Scorer: MultiKeywordRefusal (0-token) -> TFInverter{_C_RESET}"
    )


def print_converter_path_done(
    ctx: "PipelineContext",
    *,
    converter_name: str,
    path_idx: int,
    total_paths: int,
    seeds_attempted: int,
    seeds_succeeded: int,
    seeds_remaining: int,
    elapsed_seconds: float,
) -> None:
    """ converter ."""
    ep_name = _get_endpoint_name(ctx)
    tech = _get_current_technique(ctx)

    success_rate = (seeds_succeeded / seeds_attempted * 100) if seeds_attempted > 0 else 0.0
    rate_color = _asr_color(success_rate)

    if seeds_remaining == 0:
        status = f"{_C_GREEN}[OK] ALL DONE{_C_RESET}"
    elif seeds_succeeded > 0:
        status = f"{_C_GREEN}[OK] partial{_C_RESET}"
    else:
        status = f"{_C_YELLOW}o no success{_C_RESET}"

    print(
        f"  {status} {_C_DIM}[STRIKE]{_C_RESET} {_C_CYAN}{ep_name}{_C_RESET} "
        f"{_C_DIM}|{_C_RESET} {_C_MAGENTA}{tech}{_C_RESET} "
        f"{_C_DIM}|{_C_RESET} Path {_C_YELLOW}{path_idx + 1}/{total_paths}{_C_RESET}: "
        f"{_C_MAGENTA}{converter_name}{_C_RESET} "
        f"| {rate_color}{seeds_succeeded}/{seeds_attempted} ({success_rate:.0f}%) success{_C_RESET}, "
        f"{seeds_remaining} remaining "
        f"{_C_DIM}({elapsed_seconds:.1f}s){_C_RESET}"
    )


def print_seed_batch_progress(
    ctx: "PipelineContext",
    *,
    converter_name: str,
    path_idx: int,
    total_paths: int,
    completed: int,
    total: int,
    succeeded: int,
) -> None:
    """ ()."""
    ep_name = _get_endpoint_name(ctx)
    tech = _get_current_technique(ctx)

    bar_width = 20
    filled = int(completed / max(1, total) * bar_width)
    bar = "#" * filled + "#" * (bar_width - filled)

    succ_str = f"{_C_GREEN}{succeeded} success{_C_RESET}" if succeeded > 0 else f"{_C_DIM}0 success{_C_RESET}"

    line = (
        f"\r  {_C_DIM}[STRIKE]{_C_RESET} {_C_CYAN}{ep_name}{_C_RESET} "
        f"{_C_DIM}|{_C_RESET} {_C_MAGENTA}{tech}{_C_RESET} "
        f"{_C_DIM}|{_C_RESET} Path {_C_YELLOW}{path_idx + 1}/{total_paths}{_C_RESET}: "
        f"{_C_MAGENTA}{converter_name}{_C_RESET} "
        f"{_C_DIM}|{_C_RESET} {bar} {completed}/{total} ({succ_str})"
    )

    if completed < total:
        print(f"{line}{' ' * 10}", end="", flush=True)
    else:
        print(f"{line}{' ' * 10}")


def print_native_sequential_progress(
    ctx: "PipelineContext",
    *,
    seed_idx: int,
    total_seeds: int,
    converter_count: int,
    objective_preview: str,
) -> None:
    """ SequentialAttack ."""
    ep_name = _get_endpoint_name(ctx)
    tech = _get_current_technique(ctx)

    bar_width = 20
    filled = int((seed_idx + 1) / max(1, total_seeds) * bar_width)
    bar = "#" * filled + "#" * (bar_width - filled)

    obj_short = objective_preview[:50] + ("..." if len(objective_preview) > 50 else "")
    seed_cat = _get_seed_category_for_idx(ctx, seed_idx)

    line = (
        f"\r  {_C_DIM}[STRIKE]{_C_RESET} {_C_CYAN}{ep_name}{_C_RESET} "
        f"{_C_DIM}|{_C_RESET} {_C_MAGENTA}{tech}{_C_RESET} "
        f"{_C_DIM}| Sequential{_C_RESET} {bar} {seed_idx + 1}/{total_seeds} "
        f"{_C_DIM}| {converter_count} paths{_C_DIM}{seed_cat}{_C_RESET} "
        f"{_C_DIM}| obj: \"{obj_short}\""
    )

    if seed_idx + 1 < total_seeds:
        print(f"{line}{' ' * 10}", end="", flush=True)
    else:
        print(f"{line}{' ' * 10}")


# ---------------------------------------------------------------------------
# ESCALATE  L1-L4
# ---------------------------------------------------------------------------

def print_escalation_tech_start(
    ctx: "PipelineContext",
    *,
    level: int,
    technique: str,
    batch_idx: int | None = None,
    total_batches: int | None = None,
    objectives_count: int,
) -> None:
    """ escalation ."""
    setattr(ctx, "_current_escalation_tech", technique)

    ep_name = _get_endpoint_name(ctx)
    cat = _get_technique_category(technique)
    params_str = _get_technique_params(technique, ctx)

    batch_str = ""
    if batch_idx is not None and total_batches is not None:
        batch_str = f" {_C_DIM}| Batch {_C_YELLOW}{batch_idx + 1}/{total_batches}{_C_RESET}"

    if level == 1 and batch_idx is not None and batch_idx > 0:
        seed_source = f"failed objectives from Batch {batch_idx} ({objectives_count} targets)"
    else:
        seed_source = f"failed objectives from single-turn ({objectives_count} targets)"

    converter_str = _get_converter_summary(technique, ctx)
    scorer_str = "MultiKeywordRefusal (0-token) -> TFInverter -> LLM Dual Judge"

    level_colors = {1: _C_RED, 2: _C_YELLOW, 3: _C_CYAN, 4: _C_MAGENTA}
    level_color = level_colors.get(level, _C_BOLD)

    print()
    print(
        f"  {_C_BOLD}> [ESCALATE L{level}]{_C_RESET} {level_color}{ep_name}{_C_RESET} "
        f"{_C_DIM}|{_C_RESET} {_C_MAGENTA}{_C_BOLD}{technique}{_C_RESET} "
        f"{_C_DIM}({cat}){_C_RESET}{batch_str} "
        f"{_C_DIM}| {objectives_count} objectives{_C_RESET}"
    )
    print(f"  {_C_DIM}== Seeds: {_C_CYAN}{seed_source}{_C_RESET}")
    print(f"  {_C_DIM}== Converters: {_C_DIM}{converter_str}{_C_RESET}")
    if params_str:
        print(f"  {_C_DIM}== Params: {_C_DIM}{params_str}{_C_RESET}")
    print(f"  {_C_DIM}== Scorer: {_C_DIM}{scorer_str}{_C_RESET}")


def print_escalation_tech_done(
    ctx: "PipelineContext",
    *,
    level: int,
    technique: str,
    results_count: int,
    success_count: int,
    elapsed_seconds: float,
) -> None:
    """ escalation ."""
    setattr(ctx, "_current_escalation_tech", None)

    ep_name = _get_endpoint_name(ctx)

    asr = (success_count / results_count * 100) if results_count > 0 else 0.0
    rate_color = _asr_color(asr)

    level_colors = {1: _C_RED, 2: _C_YELLOW, 3: _C_CYAN, 4: _C_MAGENTA}
    level_color = level_colors.get(level, _C_BOLD)

    status = f"{_C_GREEN}[OK]{_C_RESET}" if success_count > 0 else f"{_C_YELLOW}o{_C_RESET}"

    print(
        f"  {status} {_C_DIM}[ESCALATE L{level}]{_C_RESET} {level_color}{ep_name}{_C_RESET} "
        f"{_C_DIM}|{_C_RESET} {_C_MAGENTA}{technique}{_C_RESET} "
        f"| {rate_color}{success_count}/{results_count} ({asr:.1f}%) success{_C_RESET} "
        f"{_C_DIM}({elapsed_seconds:.1f}s){_C_RESET}"
    )


def print_strike_phase_summary(
    ctx: "PipelineContext",
    *,
    total_results: int,
    total_success: int,
    elapsed_seconds: float,
) -> None:
    """ STRIKE ."""
    ep_name = _get_endpoint_name(ctx)
    asr = (total_success / max(1, total_results) * 100) if total_results > 0 else 0.0
    asr_str = _format_asr(asr)

    print()
    print(f"  {_C_BOLD}{'=' * 60}{_C_RESET}")
    print(
        f"  {_C_BOLD}STRIKE DONE:{_C_RESET} {_C_CYAN}{ep_name}{_C_RESET} "
        f"| {total_results} attacks, {_C_GREEN}{total_success} success{_C_RESET} ({asr_str}) "
        f"| {elapsed_seconds:.1f}s"
    )
    print(f"  {_C_BOLD}{'=' * 60}{_C_RESET}")


# ---------------------------------------------------------------------------
# priority batch ()
# ---------------------------------------------------------------------------

def _print_priority_batch_card(
    batch_label: str,
    batch_techs: list[tuple[str, float]],
    ctx: "PipelineContext",
    tech_asr_history: dict[str, float],
    *,
    batch_idx: int,
    total_batches: int,
    exit_threshold: float,
) -> None:
    """card converter(s)."""
    batch_colors = [_C_RED, _C_YELLOW, _C_CYAN]
    batch_color = batch_colors[batch_idx] if batch_idx < len(batch_colors) else _C_CYAN

    print()
    _print_card_top(batch_color)
    print(_card_line(f"Batch {batch_label}", batch_color))
    _print_card_sep()

    for i, (tech, prior) in enumerate(batch_techs):
        cat = _get_technique_category(tech)
        hist = tech_asr_history.get(tech)

        asr_parts: list[str] = []
        if hist is not None:
            asr_parts.append(f"hist={hist:.0f}%")
        if prior > 0:
            asr_parts.append(f"prior={prior:.0f}%")
        asr_str = f" [{', '.join(asr_parts)}]" if asr_parts else ""

        params_str = _get_technique_params(tech, ctx)

        if batch_idx == 0:
            seed_source = _get_seed_summary(ctx)
        else:
            seed_source = f"failed objectives from Batch {batch_idx}"

        converter_str = _get_converter_summary(tech, ctx)
        scorer_str = "MultiKeywordRefusal (0-token) -> TrueFalseInverter -> LLM Dual Judge"

        if batch_idx < total_batches - 1:
            exit_str = f"ASR >= {exit_threshold:.0f}% -> skip remaining batches"
        else:
            exit_str = "final batch (no early exit)"

        print(_card_line(
            f"{_C_BOLD}{_C_MAGENTA}{tech}{_C_RESET} "
            f"{_C_DIM}({cat}){_C_RESET}{_C_DIM}{asr_str}{_C_RESET}"
        ))
        if params_str:
            print(_card_line(f"  Params:    {_C_DIM}{params_str}{_C_RESET}"))
        print(_card_line(f"  Seeds:     {_C_CYAN}{seed_source}{_C_RESET}"))
        print(_card_line(f"  Converters: {_C_DIM}{converter_str}{_C_RESET}"))
        print(_card_line(f"  Scorer:    {_C_DIM}{scorer_str}{_C_RESET}"))
        print(_card_line(f"  Exit:      {_C_DIM}{exit_str}{_C_RESET}"))

        if i < len(batch_techs) - 1:
            _print_card_sep()

    _print_card_bottom(batch_color)
