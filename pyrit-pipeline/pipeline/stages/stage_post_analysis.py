# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Stage 5/6: 执行后分析 — ASR 实测 vs 先验对比 + 经验写回 + 下次运行建议。.

职责:
  - 实测 ASR vs 先验对比表 (技术 | 实测 | 先验 | 差异 | 样本数)
  - Converter 韧性分析 (基线 ASR vs Converter ASR, 增量 Δ)
  - ASR 经验闭环 (经验写回 Top-N + 模型 Tier 预警)
  - 成果回溯 + 下次运行建议

产出 (写入 PipelineContext):
  - ctx.metadata["post_analysis"] = 后分析结果字典

依赖:
  - pipeline.asr.optimizer (ASR 查询 + 经验写回)
  - pipeline.asr.failure_type_event_handler (失败类型统计)

修改此文件不影响 Stage 1-4, 6-7。
"""

from __future__ import annotations

import logging

from pipeline.context import PipelineContext

logger = logging.getLogger(__name__)


async def run(ctx: PipelineContext) -> None:
    """执行 Stage 5/6: 执行后分析。."""
    result = ctx.result
    if result is None:
        print("  [跳过] 无执行结果")
        return

    print("\n" + "=" * 70)
    print("阶段 5/6: 执行后分析 — ASR 实测 vs 先验对比 + 经验写回")
    print("=" * 70)

    # ── 1. 执行成果概要 ──
    _print_execution_summary(ctx)

    # ── 2. 实测 ASR vs 先验对比 ──
    _print_asr_comparison(ctx)

    # ── 3. Converter 韧性分析 ──
    _print_converter_resilience(ctx)

    # ── 4. ASR 经验闭环 ──
    _print_asr_feedback(ctx)

    # ── 5. 成果回溯 + 下次运行建议 ──
    _print_recommendations(ctx)

    # ── 交接块 ──
    print(
        f"\n  → 传递到 Stage 6/6: ASR={ctx.overall_asr}% | "
        f"成功={ctx.metadata.get('post_analysis', {}).get('successes', 0)}/"
        f"{ctx.metadata.get('post_analysis', {}).get('total', 0)} | "
        f"报告生成中..."
    )


# ============================================================
# 内部函数
# ============================================================


def _print_execution_summary(ctx: PipelineContext) -> None:
    """执行成果概要卡片。."""
    result = ctx.result
    total = sum(len(v) for v in result.attack_results.values())

    from pyrit.models import AttackOutcome

    successes = sum(1 for v in result.attack_results.values() for ar in v if ar.outcome == AttackOutcome.SUCCESS)
    failures = sum(
        1 for v in result.attack_results.values() for ar in v if ar.outcome and ar.outcome != AttackOutcome.SUCCESS
    )

    ctx.metadata["post_analysis"] = {
        "total": total,
        "successes": successes,
        "failures": failures,
    }

    # 失败类型统计
    failure_stats = ctx.metadata.get("failure_stats", {})
    failure_dist = failure_stats.get("failure_distribution", {})

    print("\n  ┌─ 执行成果概要 ────────────────────────────────────────────┐")
    print(
        f"  │ 总计: {total} | 成功: {successes} ({successes * 100 // max(total, 1)}%) | "
        f"失败: {failures} | Converter: {ctx.converter_routing_count} 次"
    )
    if failure_dist:
        top_failures = sorted(failure_dist.items(), key=lambda x: x[1], reverse=True)[:3]
        fail_str = " | ".join(f"{k}({v})" for k, v in top_failures)
        print(f"  │ 失败类型: {fail_str}")
    print("  └────────────────────────────────────────────────────────────┘")


def _print_asr_comparison(ctx: PipelineContext) -> None:
    """实测 ASR vs 先验对比卡片。."""
    if not ctx.asr_per_technique:
        print("\n  ┌─ 实测 ASR vs 先验 ─────────────────────────────────────────┐")
        print("  │ (无技术数据)")
        print("  └────────────────────────────────────────────────────────────┘")
        return

    from pipeline.asr.optimizer import query_historical_asr_by_technique

    historical = query_historical_asr_by_technique()

    print("\n  ┌─ 实测 ASR vs 先验 ────────────────────────────────────────┐")
    print(f"  │ {'技术':<35} {'实测':>6} {'先验':>6} {'差异':>6} {'样本':>4}")
    print(f"  │ {'─' * 35} {'─' * 6} {'─' * 6} {'─' * 6} {'─' * 4}")
    for tech, asr in sorted(ctx.asr_per_technique.items(), key=lambda x: x[1], reverse=True):
        hist_stats = historical.get(tech)
        prior = hist_stats.success_rate * 100 if hist_stats else 0
        samples = hist_stats.total_decided if hist_stats else 0
        diff = asr - prior
        arrow = "↑" if diff > 0 else ("↓" if diff < 0 else "=")
        print(f"  │ {tech:<35} {asr:>5.1f}% {prior:>5.1f}% {diff:>+5.1f}% {samples:>4} {arrow}")
    print("  └────────────────────────────────────────────────────────────┘")


def _print_converter_resilience(ctx: PipelineContext) -> None:
    """Converter 韧性分析卡片。.

    P1-2: 修正数据路径 — 从 ``failure_stats["runtime_asr"]`` 获取技术级 ASR,
    按 Converter 路由计数 (有 Converter 路由 vs 无 Converter 路由) 计算 Δ。
    """
    failure_stats = ctx.metadata.get("failure_stats", {})
    runtime_asr = failure_stats.get("runtime_asr", {})
    converter_routing_count = getattr(ctx, "converter_routing_count", 0)

    if not runtime_asr or converter_routing_count == 0:
        print("\n  ┌─ Converter 韧性 ──────────────────────────────────────────┐")
        print("  │ (无 Converter 使用数据)")
        print("  └────────────────────────────────────────────────────────────┘")
        return

    # 从 runtime_asr 计算总体成功率
    total_techs = len(runtime_asr)
    if total_techs == 0:
        return

    # 所有技术的平均 ASR 作为参考基线
    all_asr_values = list(runtime_asr.values())
    avg_asr = sum(all_asr_values) / len(all_asr_values) * 100 if all_asr_values else 0

    # Converter 路由数作为增强信号
    print("\n  ┌─ Converter 韧性分析 ────────────────────────────────────┐")
    print(f"  │ Converter 路由: {converter_routing_count} 个分配")
    print(f"  │ 技术平均 ASR: {avg_asr:.1f}%")
    print(f"  │ 有数据技术: {total_techs} 个")
    if avg_asr > 0:
        print(f"  │ → Converter 增强信号: {'有效' if avg_asr > 15 else '需更多变体'}")
    else:
        print("  │ → 无增量 (ASR=0%)")
    print("  └────────────────────────────────────────────────────────────┘")


def _print_asr_feedback(ctx: PipelineContext) -> None:
    """ASR 经验闭环卡片。."""
    model_name = ctx.metadata.get("model_name", "unknown")
    model_tier = ctx.metadata.get("model_tier", "unknown")
    overall = ctx.overall_asr

    print("\n  ┌─ ASR 经验闭环 ────────────────────────────────────────────┐")
    print(f"  │ 模型: {model_name} (Tier: {model_tier})")
    print(f"  │ 整体 ASR: {overall}%")

    # 经验写回 (G-05: 按模型分文件存储)
    if ctx.asr_per_technique:
        try:
            from pipeline.asr.optimizer import save_empirical_asr

            save_empirical_asr(ctx.asr_per_technique, model_name=model_name)
            top3 = sorted(ctx.asr_per_technique.items(), key=lambda x: x[1], reverse=True)[:3]
            print("  │ 经验写回 Top-3:")
            for tech, asr in top3:
                print(f"  │   {tech:<35} {asr:.1f}%")
        except (OSError, ValueError) as e:
            logger.warning(f"Failed to save empirical ASR: {e}")

    # G-07: ParadigmTracker 跨运行持久化
    failure_stats = ctx.metadata.get("failure_stats", {})
    paradigm_data = failure_stats.get("paradigm_performance", {})
    if paradigm_data:
        try:
            from pathlib import Path

            from pipeline.asr.failure_type_event_handler import ParadigmPerformanceTracker

            tracker = ParadigmPerformanceTracker.from_dict(paradigm_data)
            tracker_path = Path("outputs/empirical_asr") / "paradigm_performance.json"
            tracker.save_to_file(tracker_path)
            print(f"  │ 范式性能跟踪器已持久化 ({len(paradigm_data)} 失败类型)")
        except (OSError, ValueError) as e:
            logger.warning(f"Failed to save paradigm tracker: {e}")

    # Tier 预警
    if overall < 20:
        print(f"  │ ⚠ {model_tier} 模型 ASR < 20% — 建议升级到多轮攻击策略")
    elif overall < 50:
        print(f"  │ → {model_tier} 模型 ASR 中等 — 考虑增加 Converter 变体")

    print("  └────────────────────────────────────────────────────────────┘")


def _print_recommendations(ctx: PipelineContext) -> None:
    """成果回溯 + 下次运行建议卡片。."""
    model_name = ctx.metadata.get("model_name", "unknown")
    model_tier = ctx.metadata.get("model_tier", "unknown")
    overall = ctx.overall_asr
    failure_stats = ctx.metadata.get("failure_stats", {})
    failure_dist = failure_stats.get("failure_distribution", {})

    print("\n  ┌─ ★ 成果回溯 + 下次运行建议 ★ ────────────────────────────┐")
    print(f"  │ 模型: {model_name} | 分层: {model_tier}")
    print(f"  │ 整体 ASR: {overall}%")

    if failure_dist:
        top_failures = sorted(failure_dist.items(), key=lambda x: x[1], reverse=True)[:3]
        print("  │ 主要失败模式:")
        for ftype, count in top_failures:
            print(f"  │   ✗ {ftype:<35} ×{count}")

    print("  │")
    print("  │ 下次运行建议:")
    if overall < 10:
        print("  │   → ASR < 10%: 启用多轮攻击策略 (STRATEGY_MODE=balanced)")
        print("  │   → 增加高 ASR 数据集 (airt.jailbreak)")
    elif overall < 30:
        print("  │   → ASR 中等: 增加 Converter 变体池")
        print("  │   → 检查 Converter 模型配置")
    else:
        print("  │   → ASR 良好: 维持当前策略")

    if failure_dist:
        top_failure = max(failure_dist, key=failure_dist.get)
        if "timeout" in top_failure:
            print("  │   → timeout 频繁: 降低 max_concurrency 或增加 --rate-limit")
        if "objective_not_achieved" in top_failure:
            print("  │   → objective_not_achieved: 升级到更高 ASR 技术或增加变体")

    print("  └────────────────────────────────────────────────────────────┘")
