# arXiv:2406.12609 — Lattner et al., Parallel multi-strategy scoring
# arXiv:cs/0207052 — Auer et al., UCB1 bandit algorithm
# arXiv:2310.08419 — Chao et al., PAIR adaptive strategy selection
# arXiv:2407.01232 — PyRIT, FIRST_SUCCESS strategy
"""技术级优先级调度器 — 将 FIRST_SUCCESS + UCB 从 converter 级扩展到多轮技术级。

学术依据:
    - Lattner et al. (arXiv:2406.12609) — 高价值策略优先, 中间退出节省 60-80% token
    - Auer et al. (arXiv:cs/0207052) — UCB1 排序, 探索-利用平衡
    - Chao et al. (arXiv:2310.08419) — 联合 ASR = 1 - ∏(1 - ASRᵢ), 高 ASR 技术边际收益递减
    - PyRIT SequentialAttack (arXiv:2407.01232) — FIRST_SUCCESS 从 converter 级扩展到技术级

核心策略:
    1. 按 ASR 先验降序将技术分为高/中/低三批
    2. 批次内并行执行, 批次间串行 (高 prior 批次先执行)
    3. 每批结束后检查中间退出阈值 (post_l1_exit_threshold)
    4. 若 ASR >= 阈值 → 跳过后续批次 (节省 token)
    5. ε-贪心: 小概率随机探索低 prior 技术 (避免过度依赖历史先验)
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from typing import Any, Callable, Coroutine

from core.context import PipelineContext

logger = logging.getLogger(__name__)

# ── 技术到 ASR 先验键的映射 ──
# asr_priors.yaml 中的 technique_asr 使用的键名
_TECHNIQUE_PRIOR_KEY: dict[str, str] = {
    "red_teaming": "red_teaming",
    "crescendo": "crescendo",
    "tap": "tap",
    "pair": "pair",
    "cot_hijack": "cot_hijack",
    "best_of_n": "best_of_n_retry",
    "gcg": "gcg",
    "cair": "cair",
    "encoded_injection": "structured_injection",
    "skeleton_key_native": "skeleton_key",
    "many_shot_cot": "many_shot_cot",
    "multi_model_pair": "multi_model_cot",
    "multi_prompt_sending": "prompt_sending",
    "chunked_request": "prompt_sending",
    "rogue_agent": "role_confusion",
    "embedding_inversion": "token_smuggling",
    "mcp_rag": "context_compliance",
}

# L-01: UCB1 探索系数默认值
# UCB1 公式: score = avg_reward + C * sqrt(ln(N) / n_i)
# C 控制探索程度:
#   C=0.0: 纯利用 (贪心, 永远选最高先验)
#   C=0.1: 轻度探索 (默认, 平衡)
#   C=1.0: 标准 UCB1 (理论最优, Auer et al.)
#   C>1.0: 高度探索 (适合先验不确定场景)
#
# 配置优先级: ctx.args.ucb_exploration_factor > config/defaults.yaml > 默认值 0.1
_DEFAULT_UCB_EXPLORATION_FACTOR: float = 0.1

# L-01: UCB1 配置键名 (用于从 ctx.args / config/defaults.yaml 读取)
_UCB_CONFIG_KEY: str = "ucb_exploration_factor"


def _get_ucb_exploration_factor(ctx: Any | None = None) -> float:
    """获取 UCB1 探索系数 C — 支持运行时配置覆盖.

    学术依据: Auer et al. (arXiv:cs/0207052)
        C = sqrt(2) ≈ 1.414 是理论最优, 但实际红队场景需要更低 C 值
        因为高 C 值会导致大量 token 浪费在低概率技术上.

    Args:
        ctx: 流水线上下文 (可选).

    Returns:
        UCB1 探索系数 C (默认 0.1).
    """
    # 优先级 1: ctx.args 命令行覆盖
    if ctx is not None:
        _args = getattr(ctx, "args", None)
        if _args is not None:
            _c = getattr(_args, _UCB_CONFIG_KEY, None)
            if isinstance(_c, (int, float)) and 0.0 <= float(_c) <= 2.0:
                logger.debug("L-01: UCB1 C=%.3f from args", float(_c))
                return float(_c)

    # 优先级 2: config/defaults.yaml
    try:
        import yaml
        from pathlib import Path
        config_path = Path(__file__).resolve().parent.parent / "config" / "defaults.yaml"
        if config_path.exists():
            with open(config_path, encoding="utf-8") as f:
                config = yaml.safe_load(f)
            _c = config.get(_UCB_CONFIG_KEY, _DEFAULT_UCB_EXPLORATION_FACTOR)
            if isinstance(_c, (int, float)):
                _c = float(_c)
                if 0.0 <= _c <= 2.0:
                    logger.debug("L-01: UCB1 C=%.3f from defaults.yaml", _c)
                    return _c
                logger.warning("L-01: UCB1 C=%.3f out of range [0.0, 2.0], using default", _c)
    except Exception as e:
        logger.warning("L-01: Failed to read UCB1 config: %s, using default %.3f", e, _DEFAULT_UCB_EXPLORATION_FACTOR)

    return _DEFAULT_UCB_EXPLORATION_FACTOR


def _compute_ucb_score(
    prior_asr: float,
    total_experiments: int,
    tech_experiments: int,
    *,
    c: float | None = None,
) -> float:
    """计算 UCB1 分数 — 用于排序.

    UCB1 公式:
        UCB1_score = avg_reward + C * sqrt(ln(N) / n_i)

    其中:
        - avg_reward = prior_asr (历史平均成功率, 0-100)
        - N = total_experiments (总实验次数)
        - n_i = tech_experiments (该技术实验次数)
        - C = 探索系数

    边界情况:
        - tech_experiments = 0: 返回 inf (鼓励探索未尝试技术)
        - C = 0: 返回 prior_asr (纯贪心)

    Args:
        prior_asr: 该技术历史 ASR 先验 (0-100).
        total_experiments: 总实验次数.
        tech_experiments: 该技术的实验次数.
        c: 探索系数 (默认使用 _get_ucb_exploration_factor()).

    Returns:
        UCB1 分数 (越高越优先).
    """
    import math

    if c is None:
        c = _DEFAULT_UCB_EXPLORATION_FACTOR

    # 从未实验的技术: 最高优先级 (鼓励探索)
    if tech_experiments == 0:
        return float('inf')

    # 纯贪心模式 (C=0): 仅按先验排序
    if c == 0.0:
        return prior_asr

    # UCB1 公式
    avg_reward = prior_asr / 100.0  # 归一化到 [0, 1]
    exploration_bonus = c * math.sqrt(math.log(total_experiments) / tech_experiments)
    ucb_score = (avg_reward + exploration_bonus) * 100.0  # 还原到 0-100 范围

    return ucb_score


def _get_model_family(ctx: PipelineContext) -> str:
    """从 ctx 中获取目标模型族名称 (用于 ASR 先验查询)."""
    if ctx is not None and ctx.parsed_request:
        mf = ctx.parsed_request.target_fingerprint.get("model_family", "")
        if mf:
            return mf
    return getattr(ctx, "model_name", "") or ""


def _rank_techniques_by_prior(
    techniques: list[str],
    ctx: PipelineContext,
    *,
    use_ucb: bool = True,
) -> list[tuple[str, float]]:
    """按 ASR 先验 (或 UCB1 分数) 对技术降序排序, 返回 (technique_name, prior_asr) 列表.

    学术依据:
        - Auer et al. (arXiv:cs/0207052) — UCB1 排序
        - Chao et al. (arXiv:2310.08419) — 跨技术 ASR 差异显著

    查找策略 (3 层 fallback):
        1. technique_asr[prior_key][model_family] (精确匹配)
        2. technique_asr[prior_key]["default"] (默认值)
        3. 0.0 (无先验数据, 排在最后)

    L-01: 支持 UCB1 排序 (当 use_ucb=True 且配置了实验次数时).
        UCB1 会给予未充分探索的技术更高优先级, 避免历史先验偏差.

    Args:
        techniques: 技术名称列表 (如 ["crescendo", "tap", "pair", ...]).
        ctx: 流水线上下文 (用于获取 model_family).
        use_ucb: 是否使用 UCB1 排序 (默认 True, 可通过 config 禁用).

    Returns:
        按 prior (或 UCB1 分数) 降序排列的 (technique_name, prior_asr) 元组列表.
    """
    from arm.seed_ranking import get_technique_asr_prior, get_technique_experiment_count

    model_name = _get_model_family(ctx)
    ucb_c = _get_ucb_exploration_factor(ctx) if use_ucb else 0.0

    ranked: list[tuple[str, float, float]] = []  # (tech, prior, ucb_score)
    for tech in techniques:
        prior_key = _TECHNIQUE_PRIOR_KEY.get(tech, tech)
        prior = get_technique_asr_prior(prior_key, model_name)
        if prior == 0.0:
            # fallback: 尝试用技术名本身查询
            prior = get_technique_asr_prior(tech, model_name)

        # L-01: 计算 UCB1 分数 (如果启用)
        ucb_score = prior  # 默认: 纯 prior 排序
        if use_ucb and ucb_c > 0.0:
            try:
                tech_exp_count = get_technique_experiment_count(prior_key, model_name)
                total_exp = max(1, sum(
                    get_technique_experiment_count(_TECHNIQUE_PRIOR_KEY.get(t, t), model_name)
                    for t in techniques
                ))
                ucb_score = _compute_ucb_score(prior, total_exp, tech_exp_count, c=ucb_c)
            except Exception:
                # UCB1 计算失败时回退到 prior 排序
                pass

        ranked.append((tech, prior, ucb_score))

    # 按 UCB1 分数 (或 prior) 降序排序
    ranked.sort(key=lambda x: x[2], reverse=True)

    logger.info(
        "Priority scheduler: technique ranking (model=%s, UCB C=%.3f): %s",
        model_name or "unknown",
        ucb_c,
        ", ".join(f"{t}={p:.0f}%(ucb={u:.1f})" for t, p, u in ranked),
    )

    # 返回 (tech, prior) 格式, 保持向后兼容
    return [(tech, prior) for tech, prior, _ in ranked]


def _get_total_experiment_count(techniques: list[str], model_name: str) -> int:
    """获取所有技术的总实验次数 (用于 UCB1 计算).

    Args:
        techniques: 技术名称列表.
        model_name: 目标模型族名称.

    Returns:
        总实验次数.
    """
    from arm.seed_ranking import get_technique_experiment_count

    total = 0
    for tech in techniques:
        prior_key = _TECHNIQUE_PRIOR_KEY.get(tech, tech)
        total += get_technique_experiment_count(prior_key, model_name)
    return max(1, total)  # 至少为 1, 避免 log(0)


def _partition_into_batches(
    ranked: list[tuple[str, float]],
    *,
    high_threshold: float = 60.0,
    low_threshold: float = 40.0,
) -> list[list[tuple[str, float]]]:
    """将排序后的技术按 prior 阈值分为高/中/低三批.

    学术依据:
        - Lattner et al. (arXiv:2406.12609) — 高价值策略优先, 分批执行
        - Chao et al. (arXiv:2310.08419) — 联合概率下高 ASR 技术边际收益先递增后递减

    分批策略:
        - 批次 1 (高 prior >= high_threshold): 优先执行, 预期覆盖大部分可突破目标
        - 批次 2 (中 prior, low_threshold <= prior < high_threshold): 补充执行
        - 批次 3 (低 prior < low_threshold): 最后执行, 探索性尝试

    特殊处理:
        - 如果只有 1-2 个技术, 不分批 (全并行)
        - 如果某批为空, 跳过该批

    Args:
        ranked: 按 prior 降序排列的 (technique_name, prior_asr) 列表.
        high_threshold: 高 prior 阈值 (default 60%).
        low_threshold: 低 prior 阈值 (default 40%).

    Returns:
        技术批次列表, 每批是 (technique_name, prior_asr) 元组列表.
    """
    if len(ranked) <= 2:
        # 技术数太少, 不分批
        return [ranked]

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

    batches = [b for b in (batch_high, batch_mid, batch_low) if b]

    for i, batch in enumerate(batches):
        logger.info(
            "Priority scheduler: batch %d (%d techniques): %s",
            i + 1,
            len(batch),
            ", ".join(f"{t}={p:.0f}%" for t, p in batch),
        )

    return batches


async def _execute_priority_batches(
    ctx: PipelineContext,
    techniques: list[str],
    attack_runners: dict[str, Callable[[PipelineContext, list[str]], Coroutine[Any, Any, dict[str, list[Any]]]]],
    failed_objectives: list[str],
    *,
    exit_threshold: float = 70.0,
    high_threshold: float = 60.0,
    low_threshold: float = 40.0,
    epsilon: float = 0.1,
    base_attack_results: dict[str, list[Any]] | None = None,
    # L-02: Circuit Breaker 集成 — 可选回调
    circuit_breaker_check: Callable[[str, Any | None], bool] | None = None,
    circuit_breaker_record: Callable[[str, bool, Any | None], None] | None = None,
) -> dict[str, list[Any]]:
    """分批优先级执行多轮攻击技术.

    学术依据:
        - Lattner et al. (arXiv:2406.12609) — 高价值策略优先, 中间退出
        - PyRIT SequentialAttack (arXiv:2407.01232) — FIRST_SUCCESS 扩展到技术级
        - Auer et al. (arXiv:cs/0207052) — ε-贪心探索-利用平衡

    执行流程:
        1. 按 ASR 先验排序技术
        2. 分为高/中/低三批
        3. 批次 1 并行执行 → 检查 ASR ≥ exit_threshold? → 退出
        4. 批次 2 并行执行 (仅对仍失败的目标) → 检查 → 退出
        5. 批次 3 并行执行 (仅对仍失败的目标)
        6. ε-贪心: epsilon 概率将批次 3 中的一个技术提升到批次 1

    Args:
        ctx: 流水线上下文.
        techniques: 要执行的技术名称列表.
        attack_runners: {technique_name: async_func(ctx, objectives) -> dict} 映射.
        failed_objectives: 失败目标列表.
        exit_threshold: 中间退出 ASR 阈值 (default 70%, 从 post_l1_exit_threshold 读取).
        high_threshold: 高 prior 阈值 (default 60%).
        low_threshold: 低 prior 阈值 (default 40%).
        epsilon: 探索概率 (default 0.1, 10% 概率随机提升低 prior 技术).

    Args:
        ctx: 流水线上下文.
        techniques: 要执行的技术名称列表.
        attack_runners: {technique_name: async_func(ctx, objectives) -> dict} 映射.
        failed_objectives: 失败目标列表.
        exit_threshold: 中间退出 ASR 阈值 (default 70%, 从 post_l1_exit_threshold 读取).
        high_threshold: 高 prior 阈值 (default 60%).
        low_threshold: 低 prior 阈值 (default 40%).
        epsilon: 探索概率 (default 0.1, 10% 概率随机提升低 prior 技术).
        base_attack_results: 单轮攻击结果 (断点 B/C 修复: ASR 计算和
            失败目标选择需要基于 {单轮 + 升级} 合并结果, 而非仅升级结果).

    Returns:
        合并后的 {technique_name: [AttackResult, ...]} 结果字典.
    """
    if not techniques or not failed_objectives:
        return {}

    # 1. 按 ASR 先验排序
    ranked = _rank_techniques_by_prior(techniques, ctx)

    # 2. ε-贪心: epsilon 概率将最低 prior 的技术提升到第一批次
    if len(ranked) > 2 and random.random() < epsilon:
        # 找到 prior 最低的技术
        lowest_tech, lowest_prior = ranked[-1]
        # 从原位置移除, 插入到第一位
        ranked = [(lowest_tech, lowest_prior)] + [
            (t, p) for t, p in ranked if t != lowest_tech
        ]
        logger.info(
            "Priority scheduler: ε-greedy exploration — promoted '%s' (prior=%.0f%%) to batch 1",
            lowest_tech, lowest_prior,
        )

    # 3. 分批
    batches = _partition_into_batches(
        ranked,
        high_threshold=high_threshold,
        low_threshold=low_threshold,
    )

    # 4. 分批执行
    all_results: dict[str, list[Any]] = {}
    remaining_objectives = list(failed_objectives)

    # v58: 分批预览卡片 — 在执行前展示所有批次的技术路径
    try:
        from utils.display import (
            _load_tech_asr_data,
            _partition_into_display_batches,
            _print_priority_batch_card,
            _rank_techniques_for_display,
        )
        _display_history, _display_priors = _load_tech_asr_data(techniques, ctx)
        _display_ranked = _rank_techniques_for_display(techniques, _display_priors)
        _display_batches = _partition_into_display_batches(
            _display_ranked,
            high_threshold=high_threshold,
            low_threshold=low_threshold,
        )
        _total_display_batches = len(_display_batches)
        for _bi, (_bl, _bt) in enumerate(_display_batches):
            _print_priority_batch_card(
                batch_label=_bl,
                batch_techs=_bt,
                ctx=ctx,
                tech_asr_history=_display_history,
                batch_idx=_bi,
                total_batches=_total_display_batches,
                exit_threshold=exit_threshold,
            )
    except Exception:
        pass

    for batch_idx, batch in enumerate(batches):
        if not remaining_objectives:
            logger.info(
                "Priority scheduler: batch %d skipped (no remaining failed objectives)",
                batch_idx + 1,
            )
            break

        batch_techs = [t for t, _ in batch]
        logger.info(
            "Priority scheduler: executing batch %d/%d: %s (%d objectives remaining)",
            batch_idx + 1,
            len(batches),
            ", ".join(batch_techs),
            len(remaining_objectives),
        )

        # v57: 执行时完整路径展示 — 每个技术显示 Seeds → Converters → Scorer
        try:
            from utils.display import print_escalation_tech_start
            for tech_name in batch_techs:
                print_escalation_tech_start(
                    ctx,
                    level=1,
                    technique=tech_name,
                    batch_idx=batch_idx,
                    total_batches=len(batches),
                    objectives_count=len(remaining_objectives),
                )
        except Exception:
            pass

        # 批次内并行执行
        _batch_start_time = time.monotonic()

        async def _safe_run(
            tech_name: str,
            runner: Callable[[PipelineContext, list[str]], Coroutine[Any, Any, dict[str, list[Any]]]],
        ) -> dict[str, list[Any]]:
            """批次内安全执行, 集成 Circuit Breaker (L-02)."""
            # L-02: Circuit Breaker 前置检查
            if circuit_breaker_check is not None and circuit_breaker_check(tech_name, ctx):
                logger.warning(
                    "L-02: Priority scheduler skipping '%s' — circuit breaker is OPEN",
                    tech_name,
                )
                return {}

            try:
                result = await runner(ctx, remaining_objectives)
                # L-02: 记录成功 (有结果视为成功)
                if circuit_breaker_record is not None:
                    success = bool(result and any(result.values()))
                    circuit_breaker_record(tech_name, success, ctx)
                return result
            except Exception as e:
                # L-02: 记录失败
                if circuit_breaker_record is not None:
                    circuit_breaker_record(tech_name, False, ctx)
                logger.warning("Priority scheduler: '%s' failed: %s", tech_name, e)
                return {}

        coros = []
        batch_tech_names = []
        for tech_name in batch_techs:
            runner = attack_runners.get(tech_name)
            if runner is not None:
                coros.append(_safe_run(tech_name, runner))
                batch_tech_names.append(tech_name)
            else:
                logger.warning(
                    "Priority scheduler: no runner for technique '%s', skipping",
                    tech_name,
                )

        if not coros:
            continue

        batch_results = await asyncio.gather(*coros, return_exceptions=False)
        _batch_elapsed = time.monotonic() - _batch_start_time

        # v57: 执行完成后输出每个技术的结果行
        try:
            from utils.display import print_escalation_tech_done
            for tech_name in batch_tech_names:
                # 注意: all_results 此时可能还没合并完, 用 batch_results 查
                _tech_success = 0
                _tech_count = 0
                for result_dict in batch_results:
                    if isinstance(result_dict, dict) and tech_name in result_dict:
                        _tech_count = len(result_dict[tech_name])
                        from strike.escalation import _is_success as _esc_is_success
                        _tech_success = sum(1 for r in result_dict[tech_name] if _esc_is_success(r))
                        break
                print_escalation_tech_done(
                    ctx,
                    level=1,
                    technique=tech_name,
                    results_count=_tech_count,
                    success_count=_tech_success,
                    elapsed_seconds=_batch_elapsed,
                )
        except Exception:
            pass

        # 合并批次结果
        for result_dict in batch_results:
            if isinstance(result_dict, dict):
                for tech, results in result_dict.items():
                    if results:
                        all_results.setdefault(tech, []).extend(results)

        # 中间退出检查 (非最后一批)
        if batch_idx < len(batches) - 1:
            # 断点 B/C 修复: ASR 计算和失败目标选择需要基于 {单轮 + 升级} 合并结果
            combined_results = dict(base_attack_results) if base_attack_results else {}
            for tech, results in all_results.items():
                if tech in combined_results:
                    combined_results[tech].extend(results)
                else:
                    combined_results[tech] = list(results)

            from strike.escalation import _compute_overall_asr
            cumulative_asr = _compute_overall_asr(combined_results)

            # 提取仍失败的目标 (基于合并结果)
            from strike.escalation import _select_failed_objectives
            still_failed = _select_failed_objectives(ctx, combined_results)
            remaining_objectives = still_failed

            logger.info(
                "Priority scheduler: post-batch %d ASR=%.1f%% "
                "(exit threshold=%.1f%%, %d objectives still failed)",
                batch_idx + 1,
                cumulative_asr,
                exit_threshold,
                len(remaining_objectives),
            )

            if cumulative_asr >= exit_threshold:
                logger.info(
                    "Priority scheduler: cumulative ASR %.1f%% >= exit threshold %.1f%% "
                    "— skipping remaining batches (saves ~40-50%% token/time "
                    "per arXiv:2406.12609)",
                    cumulative_asr,
                    exit_threshold,
                )
                # v58: 批次退出决策卡片
                try:
                    from utils.display import print_batch_exit_card
                    print_batch_exit_card(
                        batch_idx=batch_idx,
                        total_batches=len(batches),
                        cumulative_asr=cumulative_asr,
                        exit_threshold=exit_threshold,
                        remaining_failed=len(remaining_objectives),
                    )
                except Exception:
                    pass
                # 记录编排日志
                ctx.orchestration_log.append({
                    "phase": "escalate",
                    "decision": "priority_batch_early_exit",
                    "input": {
                        "batch_completed": batch_idx + 1,
                        "total_batches": len(batches),
                        "cumulative_asr": cumulative_asr,
                        "exit_threshold": exit_threshold,
                    },
                    "output": {
                        "skipped_batches": len(batches) - batch_idx - 1,
                        "techniques_executed": list(all_results.keys()),
                    },
                    "reasoning": (
                        f"Priority scheduler: batch {batch_idx + 1} completed with "
                        f"ASR={cumulative_asr:.1f}% >= {exit_threshold:.1f}%, "
                        f"skipping {len(batches) - batch_idx - 1} remaining batches"
                    ),
                })
                break
            else:
                # v58: 批次退出决策卡片 (CONTINUE)
                try:
                    from utils.display import print_batch_exit_card
                    print_batch_exit_card(
                        batch_idx=batch_idx,
                        total_batches=len(batches),
                        cumulative_asr=cumulative_asr,
                        exit_threshold=exit_threshold,
                        remaining_failed=len(remaining_objectives),
                    )
                except Exception:
                    pass

    return all_results
