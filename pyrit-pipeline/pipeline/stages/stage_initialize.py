# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Stage 3: 场景初始化 + ASR 驱动的智能调度 + 同次运行 ASR 反馈闭环。.

职责:
  - 调用 ``scenario.initialize_async()`` 构建 AtomicAttack + SequentialAttack
  - **P1-闭环: 同次运行 ASR 反馈** — 查询当前运行中已完成的 AttackResult ASR,
    写入 ``ctx.metadata["current_run_asr"]`` 供后续阶段使用
    (实现 Stage 3 → Stage 2/4 的动态调参闭环)
  - P4: 初始化后, 按 ASR 优先级重排 AtomicAttack 执行顺序
    (高 ASR 的攻击优先执行, 快速获取结果信号)

产出 (写入 PipelineContext):
  - ctx.metadata["current_run_asr"] = 当前运行 ASR 统计 (dict)
  - 无新字段 (scenario 内部状态已更新)

依赖的原生 API:
  - TextAdaptive.initialize_async() (间接调用 _build_atomic_attacks_async)
  - pipeline.asr.optimizer (ASR 驱动排序 + 同次运行反馈)

修改此文件不影响 Stage 1–2, 4–6。

> **日期**: 2026-8-1
> **更新记录**:
>   2026-8-1 15:25 — 添加同次运行 ASR 反馈闭环 (query_current_run_asr_by_technique)
>   2026-8-1 22:00 — P0-1: 修复 _feedback_current_run_asr() 死代码, 在 run() 中调用
>   2026-8-1 22:00 — P1-5: 消除直接访问 scenario._atomic_attacks, 使用 getattr/setattr
"""

import logging
from typing import Any

from pipeline.asr.optimizer import (  # noqa: F401 — re-exported for test patching
    get_current_run_asr_summary,
    query_current_run_asr_by_technique,
    query_historical_asr_by_technique,
)
from pipeline.context import PipelineContext

logger = logging.getLogger(__name__)


async def run(ctx: PipelineContext) -> None:
    """执行 Stage 3/6: 场景初始化 + ASR 智能调度。."""
    print("\n" + "=" * 70)
    print("阶段 3/6: 场景初始化 — ASR 智能调度 + AtomicAttack 构建")
    print("=" * 70)

    # ── 原生: 场景初始化 ──
    await ctx.scenario.initialize_async()

    atomic_attacks = getattr(ctx.scenario, "_atomic_attacks", [])
    sequential_count = sum(1 for a in atomic_attacks if hasattr(a, "child_attacks") or hasattr(a, "attack_sequence"))
    standalone_count = len(atomic_attacks) - sequential_count
    strategy = "EXHAUSTIVE" if ctx.max_attempts_per_objective >= 999 else "FIRST_SUCCESS"

    print("\n  ┌─ AtomicAttack 构建 ──────────────────────────────────────┄")
    print(f"  │ AtomicAttack 总数: {len(atomic_attacks)}")
    print(f"  │ SequentialAttack (复合): {sequential_count}")
    print(f"  │ 独立 AtomicAttack: {standalone_count}")
    print(f"  │ 停止策略: {strategy} (max_attempts={ctx.max_attempts_per_objective})")
    print(f"  │ 并发控制: {ctx.args.max_concurrency if ctx.args else 'N/A'}")
    print("  └───────────────────────────────────────────────────────────────┄")

    # ── P0: 同次运行 ASR 反馈闭环 (必须在重排序之前执行, 提供动态反馈数据) ──
    _feedback_current_run_asr(ctx)

    # ── ASR 智能调度 ──
    _reorder_attacks_by_asr(ctx)

    # ── 衔接块 ──
    print(
        f"\n  → 传递到 Stage 4/6: {len(atomic_attacks)} AtomicAttack 已就绪 | "
        f"策略={strategy} | 并发={ctx.args.max_concurrency if ctx.args else 5}"
    )


def _feedback_current_run_asr(ctx: PipelineContext) -> None:
    """同次运行 ASR 反馈闭环。.

    查询当前运行中已完成的 AttackResult ASR, 写入 ctx.metadata:
      - ``ctx.metadata["current_run_asr"]``: 当前运行 ASR (by technique)

    在 resume 场景下, 已有部分 AttackResult 完成, 这部分 ASR 数据:
      1. 供 Stage 4 做动态展示
      2. 供 EpsilonGreedyTechniqueSelector (current_run scope) 做动态调参
      3. 供用户了解当前运行的进度和 ASR 趋势

    冷启动 (首次运行) 时无已完成结果, 返回空字典, 不影响后续流程。

    参考:
      - arXiv:2310.04451 (PAIR) — 自适应策略选择
      - arXiv:2406.16241 (TAP) — 基于搜索的攻击优化
    """
    scenario_result_id = ctx.args.resume or getattr(ctx.scenario, "scenario_result_id", None)
    if not scenario_result_id:
        print("  同次运行 ASR 反馈: (首次运行, 无 resume ID)")
        ctx.metadata["current_run_asr"] = {}
        return

    asr_by_tech = query_current_run_asr_by_technique(scenario_result_id)
    ctx.metadata["current_run_asr"] = asr_by_tech

    if asr_by_tech:
        print(get_current_run_asr_summary(asr_by_tech))
        # 趋势分析: 当前运行 ASR vs 历史 ASR
        historical = query_historical_asr_by_technique()
        if historical:
            print("\n  ASR 趋势分析 (当前运行 vs 历史):")
            for tech, current_stats in sorted(
                asr_by_tech.items(),
                key=lambda x: x[1].success_rate or 0,
                reverse=True,
            ):
                if current_stats.total_decided > 0:
                    hist_stats = historical.get(tech)
                    current_sr = current_stats.success_rate or 0
                    if hist_stats and hist_stats.total_decided > 0:
                        hist_sr = hist_stats.success_rate or 0
                        trend = "↑" if current_sr > hist_sr else ("↓" if current_sr < hist_sr else "→")
                        print(f"    {tech:<35} 当前 {current_sr * 100:>5.1f}% vs 历史 {hist_sr * 100:>5.1f}% {trend}")
    else:
        print("  同次运行 ASR 反馈: (冷启动, 无已完成结果)")


def _reorder_attacks_by_asr(ctx: PipelineContext) -> None:
    """按 ASR 优先级重排 scenario._atomic_attacks 列表。.

    排序依据 (优先级递减):
      1. GroupFallbackExecutor 降级链 (S→A→B→C→D, Stage 2 已构建)
      2. 当前运行 ASR (动态反馈)
      3. 历史 ASR (Laplace 平滑)
      4. 中等优先级 0.5 (无数据)

    安全性:
      - 仅重排列表顺序, 不修改任何 AtomicAttack 内容
      - resume 场景下, 已完成的攻击会被 _get_remaining_atomic_attacks_async 过滤
      - 重排不影响 ScenarioResult 的 attack_results 字典 (key 为 attack_name)
    """
    scenario = ctx.scenario
    atomic_attacks = getattr(scenario, "_atomic_attacks", None)
    if not atomic_attacks or len(atomic_attacks) <= 1:
        return

    # 1. 优先使用 GroupFallbackExecutor 降级链 (Stage 2 构建)
    fallback_plan = getattr(ctx, "fallback_plan", None)
    if fallback_plan and fallback_plan.execution_order:
        order_map = {tech: i for i, tech in enumerate(fallback_plan.execution_order)}

        def _fallback_priority(attack: Any) -> float:
            tech_name = attack.display_group or attack.atomic_attack_name
            base_tech = tech_name.split("+")[0] if "+" in tech_name else tech_name
            return order_map.get(base_tech, 99)

        original_order = [a.atomic_attack_name for a in atomic_attacks]
        sorted_attacks = sorted(atomic_attacks, key=_fallback_priority)
        _safe_set_atomic_attacks(scenario, sorted_attacks)
        new_order = [a.atomic_attack_name for a in sorted_attacks]

        if new_order != original_order:
            print("\n  ASR 智能调度 (GroupFallbackExecutor 降级链):")
            print(f"    原始顺序 (前 5): {original_order[:5]}")
            print(f"    优化顺序 (前 5): {new_order[:5]}")

            print(f"\n    {'AtomicAttack':<50} {'技术':<25} {'Tier':>5}")
            print(f"    {'-' * 50} {'-' * 25} {'-' * 5}")
            for attack in sorted_attacks:
                tech_name = attack.display_group or attack.atomic_attack_name
                base_tech = tech_name.split("+")[0] if "+" in tech_name else tech_name
                idx = order_map.get(base_tech, 99)
                tier_str = f"#{idx}" if idx < 99 else "—"
                print(f"    {attack.atomic_attack_name:<50} {tech_name:<25} {tier_str:>5}")
        else:
            print("  ASR 智能调度: 顺序未变 (降级链已是最优)")
        return

    # 2. 回退: 原始 ASR + Laplace 平滑
    asr_by_tech = query_historical_asr_by_technique()
    current_run_asr: dict = ctx.metadata.get("current_run_asr", {})

    def _attack_priority(attack: Any) -> float:
        """计算 AtomicAttack 的优先级分数 (越高越优先执行)。."""
        tech_name = attack.display_group or attack.atomic_attack_name

        # 优先使用当前运行 ASR (动态反馈)
        current_stats = current_run_asr.get(tech_name)
        if current_stats and current_stats.total_decided > 0:
            return (current_stats.successes + 1) / (current_stats.total_decided + 2)

        # 回退到历史 ASR
        stats = asr_by_tech.get(tech_name)
        if stats is None or stats.total_decided == 0:
            return 0.5  # 无历史数据: 中等优先级 (Laplace 平滑)
        # Laplace 平滑: (successes + 1) / (total + 2)
        return (stats.successes + 1) / (stats.total_decided + 2)

    # 按优先级降序排列
    original_order = [a.atomic_attack_name for a in atomic_attacks]
    sorted_attacks = sorted(atomic_attacks, key=_attack_priority, reverse=True)
    _safe_set_atomic_attacks(scenario, sorted_attacks)
    new_order = [a.atomic_attack_name for a in sorted_attacks]

    if new_order != original_order:
        print("\n  ASR 智能调度 (执行顺序优化):")
        print(f"    原始顺序 (前 5): {original_order[:5]}")
        print(f"    优化顺序 (前 5): {new_order[:5]}")

        # 显示 ASR 排序详情
        print(f"\n    {'AtomicAttack':<50} {'技术':<25} {'ASR':>8}")
        print(f"    {'-' * 50} {'-' * 25} {'-' * 8}")
        for attack in sorted_attacks:
            tech_name = attack.display_group or attack.atomic_attack_name

            # 优先展示当前运行 ASR
            current_stats = current_run_asr.get(tech_name)
            if current_stats and current_stats.total_decided > 0:
                sr = current_stats.success_rate or 0
                asr_str = f"{sr * 100:.1f}% ({current_stats.successes}/{current_stats.total_decided}) [当前]"
            else:
                stats = asr_by_tech.get(tech_name)
                if stats and stats.total_decided > 0:
                    sr = stats.success_rate or 0
                    asr_str = f"{sr * 100:.1f}% ({stats.successes}/{stats.total_decided}) [历史]"
                else:
                    asr_str = "  —  (无历史)"
            print(f"    {attack.atomic_attack_name:<50} {tech_name:<25} {asr_str:>8}")
    else:
        print("  ASR 智能调度: 顺序未变 (无历史数据或已是最优)")

    _print_stage3_summary(ctx)


def _safe_set_atomic_attacks(scenario: Any, sorted_attacks: list) -> None:
    """安全设置 scenario 的 _atomic_attacks 属性。.

    P1-5: 使用 setattr 替代直接赋值, 避免上游属性名变更时断裂。
    如果 scenario 不支持 _atomic_attacks 属性, 记录警告但不崩溃。
    """
    if hasattr(scenario, "_atomic_attacks"):
        scenario._atomic_attacks = sorted_attacks
    else:
        logger.warning(
            "Scenario %s has no _atomic_attacks attribute, reorder skipped. "
            "This may indicate an upstream PyRIT version change.",
            type(scenario).__name__,
        )


def _print_stage3_summary(ctx: PipelineContext) -> None:
    """Stage 3 交接摘要 — 已在 run() 中输出，此处为兼容保留。."""
