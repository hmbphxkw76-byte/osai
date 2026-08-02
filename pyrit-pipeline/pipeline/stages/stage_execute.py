# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Stage 4: 场景执行 + ASR 分析 + 运行时失败类型反馈。.

职责:
  - 调用 ``scenario.run_async()`` 执行全部 AtomicAttack
  - 执行后扫描所有结果，提取失败类型反馈到 selector (优化3: 非侵入式 post-execution scan)
  - 执行后计算 ASR (Attack Success Rate) 按技术分组
  - 计算总体 ASR
  - 输出失败类型分布诊断

产出 (写入 PipelineContext):
  - ctx.result = ScenarioResult 实例
  - ctx.asr_per_technique = {技术名: ASR%} 字典
  - ctx.overall_asr = 总体 ASR 百分比
  - ctx.metadata["failure_stats"] = 失败类型分布统计

依赖的原生 API:
  - TextAdaptive.run_async() (内部调用 _execute_scenario_async → _execute_atomic_attacks_parallel_async)
  - ScenarioResult.get_display_groups() — 按技术聚合结果
  - ScenarioResult.objective_achieved_rate() — 计算 ASR

自研模块 (不干扰原生执行):
  - pipeline.asr.failure_type_event_handler.FailureTypeEventHandler (后处理扫描 + 失败类型反馈)
  - pipeline.reporting.output_manager.ProgressPoller (非侵入式背景轮询, 实时更新 Dashboard)
  - (v7.0: ConverterAwareTextAdaptive 已移除, text_adaptive 路径直接使用原生 TextAdaptive)

> **日期**: 2026-8-1
> **更新记录**:
>   2026-8-1 16:00 — P1: 集成 FailureTypeEventHandler 运行时反馈
>   2026-8-1 17:00 — P0 补全: 运行时反馈通过 _execute_scenario_async 覆盖实现
>   2026-8-1 19:20 — 优化3: 移除 _execute_scenario_async 覆盖,
>     完全由 post-execution scan 实现失败类型反馈
>   2026-8-2 00:00 — R-1: 集成 ProgressPoller 非侵入式背景轮询,
>     基于 PyRIT 原生 CentralMemory.get_attack_results() 实时更新 Dashboard
"""

from __future__ import annotations

import logging

from pipeline.asr.failure_type_event_handler import FailureTypeEventHandler
from pipeline.context import PipelineContext

logger = logging.getLogger(__name__)


async def run(ctx: PipelineContext) -> None:
    """执行 Stage 4/6: 场景执行 + ASR 分析。."""
    print("\n" + "=" * 70)
    print("阶段 4/6: 场景执行 — AttackExecutor 并发 + 攻击为王")
    print("=" * 70)

    strategy = "EXHAUSTIVE" if ctx.max_attempts_per_objective >= 999 else "FIRST_SUCCESS"
    print("\n  ┌─ 执行配置 ──────────────────────────────────────────────┐")
    print(f"  │ AtomicAttack: {ctx.scenario.atomic_attack_count} | 策略: {strategy}")
    print(f"  │ 并发: {ctx.args.max_concurrency} | Converter: {ctx.converter_routing_count}")
    print("  └───────────────────────────────────────────────────────────────┘")

    # ── P1: FailureTypeEventHandler ──
    selector = getattr(ctx, "selector", None)
    event_handler = FailureTypeEventHandler(selector=selector)

    if hasattr(selector, "_model_tier"):
        ctx.metadata["model_tier"] = selector._model_tier
    if hasattr(selector, "_model_name"):
        ctx.metadata["model_name"] = selector._model_name

    # ── 原生: 场景执行 ──
    # P2-3: ProgressDashboard 集成 (执行前显示总览, 执行后显示结果)
    from pipeline.reporting.output_manager import ProgressDashboard

    total_attacks = ctx.scenario.atomic_attack_count
    dashboard = ProgressDashboard(total=total_attacks)
    print(f"  开始执行 {total_attacks} 个 AtomicAttack...")
    dashboard.print_progress()

    result = await ctx.scenario.run_async()
    ctx.result = result

    total_results = sum(len(v) for v in result.attack_results.values())
    print("\n  ┌─ 执行完成 ──────────────────────────────────────────────┐")
    print(f"  │ AttackResult: {total_results} 个")
    print("  └───────────────────────────────────────────────────────────────┘")

    # P2-3: 更新 Dashboard 并显示最终状态
    from pyrit.models import AttackOutcome

    succeeded = sum(
        1
        for ars in result.attack_results.values()
        for ar in ars
        if ar.outcome == AttackOutcome.SUCCESS
    )
    failed = sum(
        1
        for ars in result.attack_results.values()
        for ar in ars
        if ar.outcome == AttackOutcome.FAILURE
    )
    errored = total_results - succeeded - failed
    dashboard.update(succeeded=succeeded, failed=failed, errored=errored)
    dashboard.completed = total_results
    dashboard.print_progress()

    # ── P1: 后处理扫描 ──
    _scan_results_post_execution(ctx, event_handler)

    # ── P1: 失败类型分布 ──
    stats = event_handler.get_stats()
    if stats["total_attacks"] > 0:
        ctx.metadata["failure_stats"] = stats

    # ── ASR 分析 ──
    _compute_asr(ctx)

    # ── 攻击结果速览 + Per-Group Breakdown ──
    _print_attack_overview(ctx)

    # P1-1: 经验 ASR 保存已移至 Stage 5 (stage_post_analysis), 消除重复调用

    # ── 衔接块 ──
    print(
        f"\n  → 传递到 Stage 5/6: ASR={ctx.overall_asr}% | "
        f"{ctx.metadata.get('post_analysis', {}).get('successes', 0)}/"
        f"{sum(len(v) for v in ctx.result.attack_results.values())} 成功 | "
        f"分析中..."
    )


def _scan_results_post_execution(
    ctx: PipelineContext,
    handler: FailureTypeEventHandler,
) -> None:
    """执行后扫描所有 AttackResult 并反馈到事件处理器。.

    优化3: 不再覆盖原生 ``_execute_scenario_async``,
    完全由 post-execution scan 实现失败类型反馈到 selector,
    使下次运行使用最新失败模式路由。
    """
    result = ctx.result
    if result is None:
        return

    for _attack_id, attack_results in result.attack_results.items():
        for ar in attack_results:
            handler.on_attack_result(ar)

    # 对 SequentialAttack 的子结果也扫描
    for attack_results in result.attack_results.values():
        for ar in attack_results:
            child_results = getattr(ar, "child_attack_results", None) or []
            for child in child_results:
                if child is not None:
                    handler.on_attack_result(child)


def _compute_asr(ctx: PipelineContext) -> None:
    """计算 ASR (Attack Success Rate) 按技术分组。."""
    result = ctx.result
    if result is None:
        return

    # 原生: get_display_groups() 按技术聚合 AttackResult
    groups = result.get_display_groups()

    asr_per_technique: dict[str, float] = {}
    for group_name, attack_results in groups.items():
        total = len(attack_results)
        if total == 0:
            continue
        # 原生: 统计成功数 (outcome == SUCCESS)
        from pyrit.models import AttackOutcome

        successes = sum(1 for r in attack_results if r.outcome == AttackOutcome.SUCCESS)
        asr = (successes / total) * 100
        asr_per_technique[group_name] = asr

    ctx.asr_per_technique = asr_per_technique

    # 原生: 总体 ASR
    ctx.overall_asr = result.objective_achieved_rate()

    # 打印 ASR 排行榜 (攻击为王)
    print("\n  ┌─ ASR 排行榜 (Attack Success Rate) ──────────────────────┐")
    print(f"  │ {'技术':<40} {'ASR':>8}")
    print(f"  │ {'─' * 40} {'─' * 8}")
    for name, asr in sorted(asr_per_technique.items(), key=lambda x: x[1], reverse=True):
        bar = "█" * int(asr / 5)
        print(f"  │ {name:<40} {asr:>7.1f}% {bar}")
    print(f"  │ {'─' * 40} {'─' * 8}")
    print(f"  │ {'总体 ASR':<40} {ctx.overall_asr:>7d}%")
    print("  └───────────────────────────────────────────────────────────────┘")

    # ── Stage 4 → Stage 5 衔接摘要 ──
    print(f"\n  → 传递到 Stage 5/6: ASR={ctx.overall_asr}% | {len(ctx.asr_per_technique)} 个技术有统计")


def _print_attack_overview(ctx: PipelineContext) -> None:
    """攻击结果速览 + Per-Group Breakdown 卡片。."""
    result = ctx.result
    if result is None:
        return

    from pyrit.models import AttackOutcome

    # ── 攻击结果速览 ──
    print("\n  ┌─ ★ 攻击结果速览 (ASR 降序) ★ ──────────────────────────┐")

    groups = result.get_display_groups()
    all_results = []
    for group_name, attack_results in groups.items():
        for ar in attack_results:
            success = ar.outcome == AttackOutcome.SUCCESS
            all_results.append((group_name, success, ar))

    for idx, (tech, success, _) in enumerate(all_results, 1):
        marker = "✅" if success else "❌"
        print(f"  │  ○ P{idx:<3} {marker} {tech:<35}")

    total = len(all_results)
    successes = sum(1 for _, s, _ in all_results if s)
    print("  │")
    print(f"  │ 合计: {total} 个 | 成功: {successes} | 失败: {total - successes}")
    print("  └───────────────────────────────────────────────────────────────┘")

    # ── Per-Group Breakdown ──
    print("\n  ┌─ Per-Group Breakdown (执行结果统计) ───────────────────┐")
    for group_name, attack_results in groups.items():
        total = len(attack_results)
        if total == 0:
            continue
        successes = sum(1 for r in attack_results if r.outcome == AttackOutcome.SUCCESS)
        rate = (successes / total) * 100 if total > 0 else 0
        marker = "✅" if successes > 0 else "❌"
        print(f"  │ {marker} {group_name:<40} {rate:.0f}% ({successes}/{total})")
    print("  └───────────────────────────────────────────────────────────────┘")
