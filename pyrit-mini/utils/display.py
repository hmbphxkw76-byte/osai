"""display.py — 终端输出格式化 + 分阶段报告输出 (统一门面)。

架构: 拆分后的统一入口, 提供向后兼容的完整符号集。
    - display_primitives: 基础卡片工具 + Banner/Phase/Status
    - display_stages: RECON/ARM/STRIKE/ESCALATE/ASSESS/REPORT 阶段卡片
    - display_native: PyRIT 原生 output 适配器 (output_attack/scenario/technique_trail)
    - display.py: 编排进度展示 + 兼容导出

设计原则:
    1. 卡片式: 阶段级摘要以边框卡片突出
    2. 高信噪比: PyRIT/Alembic 等第三方 INFO 日志压制
    3. 攻击者关注: 目标指纹→种子→Converter→攻击进度→ASR→成功payload→报告
    4. 阶段传递一致性: 每个阶段结束后输出 "传递给下一阶段" 的关键数据卡片
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

# ── 导入基础工具 (display_primitives) ──
from utils.display_primitives import (
    _C_BOLD, _C_BLUE, _C_CYAN, _C_DIM, _C_GREEN, _C_MAGENTA, _C_RED, _C_RESET, _C_YELLOW,
    _asr_bar, _asr_color, _card_line, _format_asr,
    _print_card_bottom, _print_card_sep, _print_card_top,
    print_banner, print_card, print_error, print_phase, print_section, print_status,
)

# ── 导入阶段卡片 (display_stages) ──
from utils.display_stages import (
    _CAPABILITY_STRATEGY,
    _extract_success_info,
    _get_converter_chain_names,
    _get_outcome_label,
    _is_success,
    print_arm_card, print_arm_highlights,
    print_assess_card,
    print_escalate_card,
    print_joint_asr_card,
    print_recon_card,
    print_report_card,
    print_success_breakthrough, print_success_payload_snapshot,
)

# ── 导入 PyRIT 原生输出适配器 (display_native) ──
from utils.display_native import (
    print_native_attack_result,
    print_native_scenario_result,
    print_technique_trail,
)

# ── 导入技术参数展示逻辑 (display_params SSOT) ──
from utils.display_params import (
    _get_converter_summary,
    _get_technique_category,
    _get_technique_params,
)

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════
# 兼容旧接口
# ════════════════════════════════════════════════════════════════════

# 旧函数名兼容 (已弃用, 新代码请用 print_status)
print_status_card = print_status


# ════════════════════════════════════════════════════════════════════
# 全局摘要
# ════════════════════════════════════════════════════════════════════

def print_summary(
    *,
    total_attacks: int,
    successful_attacks: int,
    overall_asr: float,
    report_path: str,
) -> None:
    """打印最终摘要 (卡片式)."""
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


# ════════════════════════════════════════════════════════════════════
# PyRIT AttackResult 过程性输出 (通用)
# ════════════════════════════════════════════════════════════════════

def _print_failure_summary(result: Any, tech_name: str, idx: int) -> None:
    """T-03: 失败结果 1 行精简摘要."""
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
        f"  {_C_DIM}❌ [{tech_name}#{idx}]{_C_RESET} "
        f"{_C_DIM}{seed_label[:50]:<50}{_C_RESET} "
        f"{_C_RED}{outcome}{_C_RESET}"
        f"{_C_DIM}{converter_info}{_C_RESET}"
    )


def _print_result_fallback(result: Any) -> None:
    """原生 output 失败时的最小摘要."""
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
    """通用过程性输出: 使用 PyRIT 原生 output_attack_async 展示攻击结果.

    R2 §2.1 原生优先: 先调用 pyrit.output 官方模块渲染 AttackResult,
    再输出增强层卡片 (技术 ASR 统计)。
    """
    total_results = sum(len(r) for r in attack_results.values())
    if total_results == 0:
        print(f"\n  {_C_RED}✗ 无攻击结果 — 检查目标是否可用{_C_RESET}")
        return

    # 按 ASR 降序排
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
        f"{phase_label} — Per-Technique Summary (enhancement)",
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
    """STRIKE 阶段过程性输出的向后兼容包装."""
    await print_attack_results_native(ctx.attack_results, phase_label="STRIKE", max_per_tech=max_per_tech)


def print_strike_card(ctx: "PipelineContext") -> None:
    """打印攻击执行结果摘要卡片 (进度/统计)."""
    total = sum(len(results) for results in ctx.attack_results.values())
    success_count = sum(
        1 for results in ctx.attack_results.values()
        for r in results if _is_success(r)
    )

    overall_asr = (success_count / total * 100) if total > 0 else 0

    print()
    print_card(
        "STRIKE — Execution Summary",
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
        print(f"\n  {_C_RED}✗ 无攻击结果 — 检查目标是否可用{_C_RESET}")


# ════════════════════════════════════════════════════════════════════
# 分阶段报告 (--stage 模式, 调用对应卡片函数)
# ════════════════════════════════════════════════════════════════════

async def print_strike_report_async(ctx: "PipelineContext") -> None:
    """输出单轮攻击阶段 (--stage strike) 的完整结果."""
    scenario_result = getattr(ctx, "scenario_result", None)

    if scenario_result is not None:
        await print_native_scenario_result(scenario_result)

    await print_strike_results_native(ctx)

    if scenario_result is not None:
        await print_technique_trail(scenario_result)

    print_strike_card(ctx)


def print_strike_report(ctx: "PipelineContext") -> None:
    """同步包装: 输出单轮攻击阶段结果 (仅摘要卡片)."""
    print_strike_card(ctx)


def print_arm_report(ctx: "PipelineContext") -> None:
    """输出武器化阶段 (--stage arm) 的结果摘要."""
    print_arm_card(ctx)


async def print_escalate_report_async(ctx: "PipelineContext") -> None:
    """输出升级链阶段的完整结果 (R2 §2.1 原生优先)."""
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
    """同步包装: 输出升级链阶段结果 (仅摘要卡片)."""
    print_escalate_card(ctx)


def print_assess_report(ctx: "PipelineContext") -> None:
    """输出评分阶段 (--stage assess) 的结果摘要."""
    print_assess_card(ctx)


# ════════════════════════════════════════════════════════════════════
# STRIKE 进度展示 (攻击者实时感知)
# ════════════════════════════════════════════════════════════════════

def _get_endpoint_name(ctx: "PipelineContext") -> str:
    """从 ctx 提取当前 endpoint 名称 (用于进度日志)."""
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






def _load_tech_asr_data(
    techniques: list[str],
    ctx: "PipelineContext",
) -> tuple[dict[str, float], dict[str, float]]:
    """加载技术级历史 ASR 和先验 ASR."""
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
    """按 ASR 先验降序排序技术."""
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
    """将排序后的技术按 prior 阈值分为高/中/低三批."""
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
        batches.append(("1 (high prior ≥ 60%)", batch_high))
    if batch_mid:
        batches.append(("2 (mid prior 40-59%)", batch_mid))
    if batch_low:
        batches.append(("3 (low prior < 40%)", batch_low))

    return batches


def _get_seed_summary(ctx: "PipelineContext") -> str:
    """种子摘要: 数量 + UCB 排序 + 类别多样性."""
    total = len(ctx.seeds)
    if total == 0:
        return "0 seeds"

    categories: set[str] = set()
    severities: set[str] = set()
    for group in ctx.seeds[:20]:
        for seed in getattr(group, "seeds", []):
            meta = getattr(seed, "metadata", {}) or {}
            cat = str(meta.get("category", "")).strip()
            sev = str(meta.get("severity", "")).strip()
            if cat:
                categories.add(cat)
            if sev:
                severities.add(sev)

    parts: list[str] = [f"{total} seeds"]
    if categories:
        parts.append(f"{len(categories)} cats")
    if severities:
        parts.append(f"{len(severities)} sev")
    parts.append("UCB-ranked")

    return ", ".join(parts)




# ── 卡片绘制函数 (用于进度展示) ──

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
    """打印单个优先级批次卡片."""
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
        scorer_str = "MultiKeywordRefusal (0-token) → TrueFalseInverter → LLM Dual Judge"

        if batch_idx < total_batches - 1:
            exit_str = f"ASR ≥ {exit_threshold:.0f}% → skip remaining batches"
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


# ── STRIKE 阶段横幅 + 进度 ──

def print_strike_start_banner(
    ctx: "PipelineContext",
    *,
    total_endpoints: int | None = None,
    current_endpoint_idx: int | None = None,
) -> None:
    """STRIKE 阶段开始时输出 baseline 攻击概览横幅."""
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
    print(f"{_C_BOLD}{'─' * 60}{_C_RESET}")
    print(f"{_C_BOLD}  ► STRIKE: Baseline Attack (单轮 PromptSending){_C_RESET}{ep_idx_str}")
    print(f"{_C_BOLD}{'─' * 60}{_C_RESET}")
    print(f"  {_C_CYAN}Endpoint{_C_RESET}      {ep_name}")
    print(f"  {_C_CYAN}Model Family{_C_RESET}  {model_family}")
    print(f"  {_C_CYAN}Technique{_C_RESET}    prompt_sending (PromptSendingAttack)")
    print(f"  {_C_CYAN}Seeds{_C_RESET}         {total_seeds}")
    print(f"  {_C_CYAN}Conv. Paths{_C_RESET}   {total_converters}")
    print(f"  {_C_CYAN}Concurrency{_C_RESET}   {concurrency}")
    print(f"  {_C_CYAN}Timeout{_C_RESET}       {timeout_val}s ({timeout_val // 60}m {(timeout_val % 60)}s)")
    print(f"  {_C_CYAN}Pre-inject{_C_RESET}    SkeletonKey (native)")
    print(f"  {_C_CYAN}Scorer{_C_RESET}        MultiKeywordRefusal (0 token, FIRST_SUCCESS)")
    print(f"{_C_BOLD}{'─' * 60}{_C_RESET}")


def print_escalation_decision_card(
    ctx: "PipelineContext",
    *,
    baseline_asr: float,
    failed_count: int,
) -> None:
    """输出升级决策卡片."""
    _esc_threshold = float(getattr(ctx.args, "escalation_asr_threshold", 90) or 90)
    _l1_exit = float(getattr(ctx.args, "post_l1_exit_threshold", 70) or 70)
    _l2_exit = float(getattr(ctx.args, "post_l2_exit_threshold", 80) or 80)
    _esc_levels = getattr(ctx.args, "escalation_levels_parsed", None)
    if _esc_levels is not None:
        chain_str = ", ".join(f"L{i}" for i in sorted(_esc_levels))
    else:
        chain_str = "L1→L2→L3→L4 (full chain)"

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
        + (f" (ASR < threshold, {failed_count} failed targets)" if decision == "ESCALATE" else " (ASR ≥ threshold)"),
        _C_MAGENTA,
    ))
    print(_card_line(f"Escalation Chain:    {chain_str}", _C_MAGENTA))
    print(_card_line(f"L1 Exit Threshold:   ASR ≥ {_l1_exit:.0f}% → skip L2-L4", _C_MAGENTA))
    print(_card_line(f"L2 Exit Threshold:   ASR ≥ {_l2_exit:.0f}% → skip L3-L4", _C_MAGENTA))
    _print_card_bottom(_C_MAGENTA)


def print_escalation_level_banner(
    ctx: "PipelineContext",
    *,
    level: int,
    techniques: list[str],
    failed_count: int,
    batch_mode: bool = False,
) -> None:
    """输出升级链 Level 横幅."""
    level_names = {
        1: "Multi-Turn Priority Batches",
        2: "GCG + CAIR + Best-of-N + Encoded Injection",
        3: "Multi-Model + SkeletonKey + Many-Shot+CoT",
        4: "Rogue Agent + Embedding Inversion + MCP/RAG",
    }
    level_colors = {1: _C_RED, 2: _C_YELLOW, 3: _C_CYAN, 4: _C_MAGENTA}
    color = level_colors.get(level, _C_BOLD)
    name = level_names.get(level, f"Level {level}")

    sep = "═" * 60
    print()
    print(f"  {color}{sep}{_C_RESET}")
    print(f"  {color}► ESCALATE L{level}: {name}{_C_RESET}")
    print(f"  {color}{sep}{_C_RESET}")
    print(f"  {_C_CYAN}Seeds{_C_RESET}     {failed_count} failed objectives from baseline")
    if batch_mode:
        _l1_exit = float(getattr(ctx.args, "post_l1_exit_threshold", 70) or 70)
        _ps_epsilon = float(getattr(ctx.args, "priority_scheduler_epsilon", 0.1) or 0.1)
        print(f"  {_C_CYAN}Scheduler{_C_RESET}  priority-batch (exit={_l1_exit:.0f}%, ε={_ps_epsilon:.2f})")
    else:
        print(f"  {_C_CYAN}Strategy{_C_RESET}   full parallel ({len(techniques)} techniques)")
    print(f"  {_C_CYAN}Scorer{_C_RESET}    MultiKeywordRefusal (0-token) → TFInverter → LLM Dual Judge")
    print(f"  {color}{sep}{_C_RESET}")


def print_batch_exit_card(
    *,
    batch_idx: int,
    total_batches: int,
    cumulative_asr: float,
    exit_threshold: float,
    remaining_failed: int,
) -> None:
    """输出批次退出决策卡片."""
    is_exit = cumulative_asr >= exit_threshold
    decision = "EXIT" if is_exit else "CONTINUE"
    decision_color = _C_GREEN if is_exit else _C_YELLOW

    print()
    _print_card_top(_C_BLUE)
    print(_card_line(f"Batch {batch_idx + 1} Result", _C_BLUE + _C_BOLD))
    _print_card_sep()
    print(_card_line(f"Cumulative ASR: {cumulative_asr:.1f}%", _C_BLUE))
    print(_card_line(f"Exit Threshold:  {exit_threshold:.0f}%", _C_BLUE))
    if is_exit:
        saved = total_batches - batch_idx - 1
        print(_card_line(
            f"Decision:       {decision_color}{decision}{_C_RESET} — ASR ≥ threshold, skipping {saved} remaining batch(es)",
            _C_BLUE,
        ))
        print(_card_line(f"Saved:           ~{saved} batches (est. 40-50% token/time)", _C_BLUE))
    else:
        print(_card_line(
            f"Decision:       {decision_color}{decision}{_C_RESET} — proceeding to Batch {batch_idx + 2}",
            _C_BLUE,
        ))
        print(_card_line(f"Remaining:       {remaining_failed} failed objectives", _C_BLUE))
    _print_card_bottom(_C_BLUE)


# ── 辅助函数 ──

def _get_current_technique(ctx: "PipelineContext") -> str:
    """推断当前正在执行的技术名称."""
    _esc_tech = getattr(ctx, "_current_escalation_tech", None)
    if _esc_tech:
        return _esc_tech
    techniques = getattr(ctx, "techniques", None) or []
    if techniques:
        return "prompt_sending"
    return "unknown"


def _get_seed_category_for_idx(ctx: "PipelineContext", seed_idx: int) -> str:
    """获取指定索引种子的 category 标签."""
    if seed_idx < 0 or seed_idx >= len(ctx.seeds):
        return ""
    group = ctx.seeds[seed_idx]
    for seed in getattr(group, "seeds", []):
        meta = getattr(seed, "metadata", {}) or {}
        owasp = str(meta.get("owasp_id", "")).strip()
        sev = str(meta.get("severity", "")).strip()
        cat = str(meta.get("category", "")).strip()
        tags: list[str] = []
        if owasp:
            tags.append(owasp)
        if sev:
            tags.append(sev)
        if cat:
            tags.append(cat)
        return f" [{', '.join(tags)}]" if tags else ""
    return ""


# ── Converter 路径进度 ──

def print_converter_path_start(
    ctx: "PipelineContext",
    *,
    converter_name: str,
    path_idx: int,
    total_paths: int,
    seeds_remaining: int,
) -> None:
    """单条 converter 路径开始执行时输出进度行."""
    ep_name = _get_endpoint_name(ctx)
    tech = _get_current_technique(ctx)
    cat = _get_technique_category(tech)

    print(
        f"\n  {_C_BOLD}► [STRIKE]{_C_RESET} {_C_CYAN}{ep_name}{_C_RESET} "
        f"{_C_DIM}|{_C_RESET} {_C_MAGENTA}{tech}{_C_RESET} {_C_DIM}({cat}){_C_RESET} "
        f"{_C_DIM}|{_C_RESET} Path {_C_YELLOW}{path_idx + 1}/{total_paths}{_C_RESET}: "
        f"{_C_MAGENTA}{converter_name}{_C_RESET} "
        f"| {seeds_remaining} seeds {_C_DIM}⏳{_C_RESET}"
    )
    seed_summary = _get_seed_summary(ctx)
    print(
        f"  {_C_DIM}└─ Seeds: {_C_CYAN}{seed_summary}{_C_RESET}  "
        f"{_C_DIM}└─ Scorer: MultiKeywordRefusal (0-token) → TFInverter{_C_RESET}"
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
    """单条 converter 路径执行完成后输出结果行."""
    ep_name = _get_endpoint_name(ctx)
    tech = _get_current_technique(ctx)

    if seeds_attempted > 0:
        success_rate = seeds_succeeded / seeds_attempted * 100
    else:
        success_rate = 0.0
    rate_color = _asr_color(success_rate)

    if seeds_remaining == 0:
        status = f"{_C_GREEN}✓ ALL DONE{_C_RESET}"
    elif seeds_succeeded > 0:
        status = f"{_C_GREEN}✓ partial{_C_RESET}"
    else:
        status = f"{_C_YELLOW}○ no success{_C_RESET}"

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
    """批量执行中输出种子级进度."""
    ep_name = _get_endpoint_name(ctx)
    tech = _get_current_technique(ctx)

    bar_width = 20
    filled = int(completed / max(1, total) * bar_width)
    bar = "▓" * filled + "░" * (bar_width - filled)

    if succeeded > 0:
        succ_str = f"{_C_GREEN}{succeeded} success{_C_RESET}"
    else:
        succ_str = f"{_C_DIM}0 success{_C_RESET}"

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
    """SequentialAttack 逐种子执行时输出进度."""
    ep_name = _get_endpoint_name(ctx)
    tech = _get_current_technique(ctx)

    bar_width = 20
    filled = int((seed_idx + 1) / max(1, total_seeds) * bar_width)
    bar = "▓" * filled + "░" * (bar_width - filled)

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


# ── ESCALATE 阶段进度 ──

def print_escalation_tech_start(
    ctx: "PipelineContext",
    *,
    level: int,
    technique: str,
    batch_idx: int | None = None,
    total_batches: int | None = None,
    objectives_count: int,
) -> None:
    """升级阶段技术开始执行时输出完整路径卡片."""
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
    scorer_str = "MultiKeywordRefusal (0-token) → TFInverter → LLM Dual Judge"

    level_colors = {1: _C_RED, 2: _C_YELLOW, 3: _C_CYAN, 4: _C_MAGENTA}
    level_color = level_colors.get(level, _C_BOLD)

    print()
    print(
        f"  {_C_BOLD}► [ESCALATE L{level}]{_C_RESET} {level_color}{ep_name}{_C_RESET} "
        f"{_C_DIM}|{_C_RESET} {_C_MAGENTA}{_C_BOLD}{technique}{_C_RESET} "
        f"{_C_DIM}({cat}){_C_RESET}{batch_str} "
        f"{_C_DIM}| {objectives_count} objectives{_C_RESET}"
    )
    print(f"  {_C_DIM}└─ Seeds: {_C_CYAN}{seed_source}{_C_RESET}")
    print(f"  {_C_DIM}└─ Converters: {_C_DIM}{converter_str}{_C_RESET}")
    if params_str:
        print(f"  {_C_DIM}└─ Params: {_C_DIM}{params_str}{_C_RESET}")
    print(f"  {_C_DIM}└─ Scorer: {_C_DIM}{scorer_str}{_C_RESET}")


def print_escalation_tech_done(
    ctx: "PipelineContext",
    *,
    level: int,
    technique: str,
    results_count: int,
    success_count: int,
    elapsed_seconds: float,
) -> None:
    """升级阶段技术执行完成后输出结果行."""
    setattr(ctx, "_current_escalation_tech", None)

    ep_name = _get_endpoint_name(ctx)

    if results_count > 0:
        asr = success_count / results_count * 100
    else:
        asr = 0.0
    rate_color = _asr_color(asr)

    level_colors = {1: _C_RED, 2: _C_YELLOW, 3: _C_CYAN, 4: _C_MAGENTA}
    level_color = level_colors.get(level, _C_BOLD)

    if success_count > 0:
        status = f"{_C_GREEN}✓{_C_RESET}"
    else:
        status = f"{_C_YELLOW}○{_C_RESET}"

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
    """STRIKE 整体执行完毕后的精简摘要行."""
    ep_name = _get_endpoint_name(ctx)
    asr = (total_success / max(1, total_results) * 100) if total_results > 0 else 0.0
    asr_str = _format_asr(asr)

    print()
    print(f"  {_C_BOLD}{'═' * 60}{_C_RESET}")
    print(
        f"  {_C_BOLD}STRIKE DONE:{_C_RESET} {_C_CYAN}{ep_name}{_C_RESET} "
        f"| {total_results} attacks, {_C_GREEN}{total_success} success{_C_RESET} ({asr_str}) "
        f"| {elapsed_seconds:.1f}s"
    )
    print(f"  {_C_BOLD}{'═' * 60}{_C_RESET}")
