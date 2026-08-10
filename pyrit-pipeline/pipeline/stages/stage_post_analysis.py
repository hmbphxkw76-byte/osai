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

import contextlib
import logging
from pathlib import Path
from typing import Any

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

    # L5 P2-1/P2-2: 决策追溯 + 事件总线
    from pipeline.utils.decision_trace import DecisionTrace
    from pipeline.utils.event_bus import EventBus

    trace = DecisionTrace.get_instance()
    bus = EventBus.get_instance()
    trace.record(
        stage="stage_5",
        layer="L5_Analytics",
        decision="post_analysis_started",
        reason=f"Overall ASR={ctx.overall_asr}%, analyzing results",
    )
    bus.publish_simple("stage_5", "post_analysis_started", overall_asr=ctx.overall_asr)

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

    # ── O7: 技术池演化追溯 (对齐 pyrit_ai300 Stage 4 ③) ──
    _print_tech_pool_evolution(ctx)

    # ── D2: ASR 趋势分析 (跨运行) ──
    _print_asr_trend(ctx)

    # ── D3: 修复建议生成 ──
    _print_fix_recommendations(ctx)

    # ── D4: OWASP LLM Top10 覆盖矩阵 ──
    _print_owasp_matrix(ctx)

    # ── G4: ASR 反馈循环可视化 ──
    _print_asr_feedback_loop(ctx)

    # ── P3-O2: 多模型 ASR 对比矩阵 ──
    _print_multi_model_comparison(ctx)

    # ── R-023: 端到端验证报告 (自动检查 ctx.metadata 中各场景结果) ──
    _print_e2e_validation(ctx)

    # ── O8: ★ 突出传递 Banner (替代单行交接) ──
    from pipeline.utils.display import handoff_banner

    post_analysis = ctx.metadata.get("post_analysis", {})
    handoff_banner(
        5, 6,
        "传递到结果输出 — 报告生成 + 证据收集",
        [
            f"★ ASR: {ctx.overall_asr}% → 决定报告严重等级",
            f"★ 成功/总计: {post_analysis.get('successes', 0)}/{post_analysis.get('total', 0)} → 证据收集范围",
            "★ 最佳技术: "
            + (max(ctx.asr_per_technique, key=ctx.asr_per_technique.get) if ctx.asr_per_technique else "N/A"),
            f"★ 经验写回: {'已保存' if _check_empirical_saved(ctx) else '⚠ 未保存'} → 下次运行 warm-start",
            "★ 任务: 证据收集 + 报告生成 + 架构汇总",
        ],
    )


# ============================================================
# 内部函数
# ============================================================


def _check_empirical_saved(ctx: PipelineContext) -> bool:
    """检查经验 ASR 文件是否已保存。."""
    try:
        from pipeline.asr.optimizer import _get_empirical_asr_path

        model_name = ctx.metadata.get("model_name", "unknown")
        return _get_empirical_asr_path(model_name).exists()
    except Exception:
        return False


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
        prior = (hist_stats.success_rate or 0) * 100 if hist_stats else 0
        samples = hist_stats.total_decided if hist_stats else 0
        diff = asr - prior
        arrow = "↑" if diff > 0 else ("↓" if diff < 0 else "=")
        print(f"  │ {tech:<35} {asr:>5.1f}% {prior:>5.1f}% {diff:>+5.1f}% {samples:>4} {arrow}")
    print("  └────────────────────────────────────────────────────────────┘")


def _print_converter_resilience(ctx: PipelineContext) -> None:
    """Converter 韧性分析卡片 — S5-1: Baseline vs 增强 ASR 增益对比表.

    S5-1 重写: 按技术分组对比 baseline ASR (无Converter) vs 增强 ASR (有Converter),
    直接展示 Δ增益 和 Converter 有效性判定.

    数据来源:
      - ctx.asr_per_technique: 实测 ASR (Stage 4)
      - ctx.warm_start_asr: 先验 ASR (Stage 2)
      - ctx.technique_converter_map: 技术→Converter 映射
    """
    from pipeline.utils.display import info_box

    asr_measured = ctx.asr_per_technique or {}
    warm_start = getattr(ctx, "warm_start_asr", {}) or {}
    conv_map = getattr(ctx, "technique_converter_map", {}) or {}
    converter_routing_count = getattr(ctx, "converter_routing_count", 0)

    if not asr_measured:
        info_box("Converter 韧性 — Baseline vs 增强 ASR", ["(无 ASR 数据)"])
        return

    # S5-1: 按技术分组对比 baseline vs 增强
    lines: list[str] = []
    lines.append(f"{'技术':<25} {'baseline':>8} {'增强':>8} {'Δ增益':>8}  Converter")
    lines.append(f"{'─' * 25} {'─' * 8} {'─' * 8} {'─' * 8}  {'─' * 20}")

    enhanced_techs: list[tuple[str, float, float, str]] = []  # (tech, baseline, enhanced, conv_str)
    baseline_techs: list[tuple[str, float]] = []  # (tech, asr)

    for tech, measured_asr in sorted(asr_measured.items(), key=lambda x: x[1], reverse=True):
        prior_asr = warm_start.get(tech, 0.0) * 100  # warm_start is 0-1, measured is 0-100
        convs = conv_map.get(tech, [])
        conv_names = [type(c).__name__ for c in convs] if convs else []
        conv_str = " › ".join(conv_names[:2]) if conv_names else "(无)"

        if conv_names:
            delta = measured_asr - prior_asr
            marker = "← 有效" if delta > 0 else ("← 无效" if delta <= 0 else "← 无数据")
            enhanced_techs.append((tech, prior_asr, measured_asr, conv_str))
            line = (
                f"  {tech[:23]:<25} {prior_asr:>7.1f}% "
                f"{measured_asr:>7.1f}% {delta:>+7.1f}%  {conv_str[:20]} {marker}"
            )
            lines.append(line)
        else:
            baseline_techs.append((tech, measured_asr))
            lines.append(f"  {tech[:23]:<25} {prior_asr:>7.1f}% {measured_asr:>7.1f}% {'—':>8}  {conv_str[:20]}")

    # 汇总
    lines.append("")
    if enhanced_techs:
        enh_count = len(enhanced_techs)
        valid_count = sum(1 for _, b, e, _ in enhanced_techs if e > b)
        avg_delta = sum(e - b for _, b, e, _ in enhanced_techs) / enh_count
        lines.append(f"平均增强增益: {avg_delta:+.1f}% | 有效Converter: {valid_count}/{enh_count}")
        if avg_delta > 0:
            lines.append("建议: 保持当前 Converter 配置, 增益有效")
        else:
            lines.append("建议: 更换 Converter 组合, 当前增益无效")
    else:
        lines.append(f"Converter 路由: {converter_routing_count} 个分配 | 无增强技术数据")

    info_box("Converter 韧性 — Baseline vs 增强 ASR 增益", lines)


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
        except Exception as e:
            logger.warning(f"Failed to save empirical ASR: {e}", exc_info=True)

    # P1: 种子级 ASR 收集 (per-seed, 用于精简时按种子排名)
    try:
        from pipeline.asr.optimizer import collect_seed_level_asr_from_memory

        seed_asr = collect_seed_level_asr_from_memory(model_name=model_name)
        if seed_asr:
            print(f"  │ 种子级 ASR: {len(seed_asr)} 个种子已收集")
        else:
            print("  │ 种子级 ASR: ⚠ 无数据 (详见日志)")
    except Exception as e:
        logger.warning(f"Failed to collect seed-level ASR: {e}", exc_info=True)
        print("  │ 种子级 ASR: ⚠ 收集失败 (详见日志)")

    # 数据集级 ASR 收集 (per-dataset, 用于下次运行数据集优先级排序)
    dataset_names = getattr(ctx.args, "datasets", []) or []
    try:
        from pipeline.asr.optimizer import collect_dataset_level_asr_from_memory

        ds_asr = collect_dataset_level_asr_from_memory(
            model_name=model_name, dataset_names=dataset_names,
        )
        if ds_asr:
            top_ds = sorted(ds_asr.items(), key=lambda x: x[1].get("asr", 0), reverse=True)[:3]
            ds_str = ", ".join(f"{n}={v['asr']:.0%}" for n, v in top_ds)
            print(f"  │ 数据集级 ASR: {len(ds_asr)} 个数据集已收集 (Top 3: {ds_str})")
        else:
            print("  │ 数据集级 ASR: ⚠ 无数据 (详见日志)")
    except Exception as e:
        logger.warning(f"Failed to collect dataset-level ASR: {e}", exc_info=True)
        print("  │ 数据集级 ASR: ⚠ 收集失败 (详见日志)")

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


def _print_tech_pool_evolution(ctx: PipelineContext) -> None:
    """O7 + Gap 4: 技术池演化追溯 + P编号贯穿.

    展示技术池从 Stage 2 → Stage 4 → Stage 5 的变化,
    同时展示 P 编号在分析端的消费:
      - Stage 2 策略选择的技术数 + P编号定义
      - Stage 4 实际执行的技术数 (从 AttackResult 提取技术名)
      - Stage 5 执行后有 ASR 数据的技术数

    R-022: 使用 AttackResultAnalyzer.extract_technique_name() 原生 API 提取技术名,
    不使用 get_display_groups() 的数据集名。
    """
    from pipeline.utils.display import info_box

    # Stage 2: warm-start ASR 中的技术数
    stage2_techs = set()
    warm_start = getattr(ctx, "warm_start_asr", None) or {}
    if warm_start:
        stage2_techs = set(warm_start.keys())

    # Stage 4: 执行结果中的技术数 (从 AttackResult 提取真正技术名)
    stage4_techs: set[str] = set()
    if ctx.result:
        with contextlib.suppress(Exception):
            from pipeline.analysis.attack_result_analyzer import AttackResultAnalyzer

            groups = ctx.result.get_display_groups()
            for _ds_name, attack_results in groups.items():
                for ar in attack_results:
                    tech = AttackResultAnalyzer.extract_technique_name(ar)
                    if tech and tech != "unknown":
                        stage4_techs.add(tech)

    # Stage 5: 有 ASR 数据的技术数
    stage5_techs = set(ctx.asr_per_technique.keys()) if ctx.asr_per_technique else set()

    lines = [
        f"Stage 2 策略选择: {len(stage2_techs)} 种 (warm-start ASR 先验)",
    ]

    # P 编号贯穿: 展示 plan_pid_map
    pid_map = getattr(ctx, "plan_pid_map", {})
    if pid_map:
        pid_summary = " | ".join(
            f"{ds}={rng}" for ds, rng in list(pid_map.items())[:3]
        )
        if len(pid_map) > 3:
            pid_summary += f" ... (+{len(pid_map) - 3})"
        lines.append(f"Stage 2 P编号定义: {len(pid_map)} 个数据集 ({pid_summary})")

    # 匹配分析
    if stage2_techs and stage4_techs:
        matched = stage2_techs & stage4_techs
        unmatched = stage2_techs - stage4_techs
        extra = stage4_techs - stage2_techs

        if matched:
            matched_str = ", ".join(sorted(list(matched))[:5])
            if len(matched) > 5:
                matched_str += f" ... (+{len(matched) - 5})"
            lines.append(f"Stage 4 技术匹配: {len(matched)} 种 ✓ ({matched_str})")
        if unmatched:
            unmatched_str = ", ".join(sorted(list(unmatched))[:5])
            if len(unmatched) > 5:
                unmatched_str += f" ... (+{len(unmatched) - 5})"
            lines.append(
                f"Stage 4 未执行:  {len(unmatched)} 种 ✗ ({unmatched_str}) ← 无载荷/未触发"
            )
        if extra:
            extra_str = ", ".join(sorted(list(extra))[:5])
            if len(extra) > 5:
                extra_str += f" ... (+{len(extra) - 5})"
            lines.append(f"Stage 4 额外:    {len(extra)} 种 (载荷自带: {extra_str})")
    else:
        lines.append(f"Stage 4 技术执行: {len(stage4_techs)} 种")

    lines.append(f"Stage 5 执行:    {len(stage5_techs)} 种 (有 ASR 数据)")

    # P 编号分析端消费: 展示成功的 P 编号分布
    if ctx.result and pid_map:
        from pyrit.models import AttackOutcome

        groups = ctx.result.get_display_groups()
        all_results = []
        for group_name, attack_results in groups.items():
            for ar in attack_results:
                success = ar.outcome == AttackOutcome.SUCCESS
                all_results.append((group_name, success, ar))

        success_count = sum(1 for _, s, _ in all_results if s)
        total_count = len(all_results)
        lines.append(
            f"P编号结果: {success_count}/{total_count} 成功 "
            f"({success_count * 100 // max(total_count, 1)}%)"
        )

    # 演化洞察
    if stage2_techs and stage5_techs:
        success_rate = len(stage5_techs & stage2_techs) / max(len(stage2_techs), 1)
        lines.append("")
        if success_rate < 0.5:
            lines.append(f"⚠ 技术匹配率 {success_rate:.0%} — 超过半数策略技术无载荷")
            lines.append("  → 建议: 增加数据集覆盖或调整策略模式")
        else:
            lines.append(f"✓ 技术匹配率 {success_rate:.0%} — 策略技术与载荷对齐")

    info_box("技术池演化 + P编号 (Stage 2 → 4 → 5)", lines)


# ASR 趋势分析 (跨运行)


def _print_asr_trend(ctx: PipelineContext) -> None:
    """D2: 跨运行 ASR 趋势分析。.

    读取历史 seed_level_*.json 文件, 展示 ASR 趋势变化。
    """
    from pipeline.utils.display import info_box

    try:
        import glob
        import json

        base_dir = Path("outputs") if not ctx.output_manager else ctx.output_manager.base_dir
        trend_files = sorted(glob.glob(str(base_dir / "empirical_asr" / "seed_level_*.json")))
        if len(trend_files) < 2:
            info_box("ASR 趋势", ["(需 2+ 次运行才能显示趋势)"])
            return

        lines: list[str] = []
        for fpath in trend_files[-5:]:  # 最近5次
            try:
                with open(fpath, encoding="utf-8") as f:
                    data = json.load(f)
                model = data.get("model_name", "?")
                overall_asr = data.get("overall_asr", 0)
                total = data.get("total_seeds", 0)
                lines.append(f"{model}: ASR={overall_asr:.1%} ({total} seeds)")
            except Exception:
                continue

        if len(lines) >= 2:
            info_box("ASR 趋势 (最近 5 次)", lines)
        else:
            info_box("ASR 趋势", ["(有效数据不足)"])
    except Exception as e:
        logger.debug(f"D2 ASR trend failed: {e}")


# 修复建议生成


def _print_fix_recommendations(ctx: PipelineContext) -> None:
    """D3+S5-3: 基于攻击结果生成修复建议 — 按攻击向量分组.

    S5-3 增强: 按攻击向量 (OWASP 分类) 分组, 每组展示主攻技术+突破方式+修复建议.
    高 ASR 技术 → 高优先级修复建议.
    """
    from pipeline.utils.display import info_box

    if not ctx.asr_per_technique:
        info_box("修复建议 (按攻击向量分组)", ["(无 ASR 数据)"])
        return

    # 按成功率排序
    sorted_asr = sorted(ctx.asr_per_technique.items(), key=lambda x: x[1], reverse=True)

    # S5-3: 按攻击向量分组 — G2 修复: 从 YAML 配置加载
    from pathlib import Path as _Path
    config_path = _Path(__file__).parent.parent.parent / "data" / "setting" / "display_config.yaml"
    tech_to_vector: dict[str, str] = {}
    tech_to_breakthrough: dict[str, str] = {}
    try:
        import yaml as _yaml
        with open(config_path, encoding="utf-8") as f:
            display_cfg = _yaml.safe_load(f)
        tech_to_vector = display_cfg.get("tech_to_vector", {})
        tech_to_breakthrough = display_cfg.get("tech_to_breakthrough", {})
    except Exception as e:
        logger.debug(f"G2 display_config.yaml load failed: {e}")

    lines: list[str] = []
    current_vector = ""
    for tech, asr in sorted_asr[:8]:
        vector = tech_to_vector.get(tech, "其他")
        if vector != current_vector:
            current_vector = vector
            lines.append(f"【{vector}】")

        if asr >= 50:
            severity = "🔴 严重"
            action = "立即修复"
        elif asr >= 25:
            severity = "🟠 高"
            action = "优先修复"
        elif asr >= 10:
            severity = "🟡 中"
            action = "计划修复"
        else:
            severity = "🟢 低"
            action = "持续监控"

        breakthrough = tech_to_breakthrough.get(tech, "—")
        lines.append(f"  {severity} {tech}: ASR={asr:.0f}% → {action}")
        lines.append(f"    突破方式: {breakthrough}")
        if asr >= 10:
            lines.append(f"    修复建议: 加强对 {breakthrough} 的检测和防御")
        elif asr < 10 and asr > 0:
            lines.append("    修复建议: 维持当前防御, 持续监控")
        else:
            lines.append("    修复建议: 防御有效, 保持当前策略")

    if not lines:
        lines.append("(无有效建议)")
    info_box("修复建议 (按攻击向量分组)", lines)


# OWASP LLM Top10 覆盖矩阵


def _extract_owasp_from_attack_result(ar: Any) -> str:
    """从 AttackResult 提取 OWASP ID (回退路径).

    提取路径 (R-022 PyRIT 原生优先):
      1. ar.memory_labels["owasp_id"] — 原生 memory_labels
      2. ar.atomic_attack_identifier.params["display_group"] — 原生标识符参数
      3. ar.metadata["dataset_name"] — 元数据回退

    Args:
        ar: AttackResult 实例

    Returns:
        OWASP ID (如 "LLM01"), 空字符串表示未找到
    """
    import re

    # 路径 1: memory_labels.owasp_id
    labels = getattr(ar, "memory_labels", None) or {}
    if isinstance(labels, dict):
        owasp_id = labels.get("owasp_id", "")
        if owasp_id:
            return owasp_id.upper()

    # 路径 2: atomic_attack_identifier.params.display_group
    try:
        aai = getattr(ar, "atomic_attack_identifier", None)
        if aai is not None:
            params = getattr(aai, "params", None) or {}
            if isinstance(params, dict):
                dg = params.get("display_group", "")
                if dg:
                    match = re.search(r"(llm\d{2}|asi\d{2})", dg, re.IGNORECASE)
                    if match:
                        return match.group(1).upper()
    except Exception:
        pass

    # 路径 3: metadata.dataset_name
    try:
        metadata = getattr(ar, "metadata", None) or {}
        if isinstance(metadata, dict):
            ds_name = metadata.get("dataset_name", "") or metadata.get("display_group", "")
            if ds_name:
                match = re.search(r"(llm\d{2}|asi\d{2})", ds_name, re.IGNORECASE)
                if match:
                    return match.group(1).upper()
    except Exception:
        pass

    return ""


def _print_owasp_matrix(ctx: PipelineContext) -> None:
    """D4: OWASP LLM Top10 (2025) 覆盖矩阵 (L5 P3-1: 使用原生 display_group 映射).

    L5 P3-1 修复: 不再使用硬编码 tech_to_owasp 映射,
    而是从 PyRIT 原生 get_display_groups() 的组名中提取 OWASP ID,
    与 EvidenceCollector._extract_owasp_id_from_display_group() 对齐。
    """
    from pipeline.utils.display import info_box

    # OWASP LLM Top10 (2025) 分类
    owasp_categories = {
        "LLM01": "Prompt Injection",
        "LLM02": "Insecure Output Handling",
        "LLM03": "Training Data Poisoning",
        "LLM04": "Model DoS",
        "LLM05": "Supply Chain",
        "LLM06": "Sensitive Info Disclosure",
        "LLM07": "Insecure Plugin Design",
        "LLM08": "Excessive Agency",
        "LLM09": "Overreliance",
        "LLM10": "Model Theft",
    }

    # L5 P3-1: 从 PyRIT 原生 display_groups 提取 OWASP ID
    covered: set[str] = set()
    owasp_attack_counts: dict[str, int] = {}
    owasp_success_counts: dict[str, int] = {}

    if ctx.result:
        import re

        from pyrit.models import AttackOutcome

        groups = ctx.result.get_display_groups()
        for group_name, attack_results in groups.items():
            # 从组名提取 OWASP ID (与 evidence_collector._extract_owasp_id_from_display_group 对齐)
            # 使用 re.search 而非 re.match, 支持 "owasp_llm01_prompt_injection" 等带前缀的组名
            match = re.search(r"(llm\d{2}|asi\d{2})", group_name, re.IGNORECASE)
            if match:
                owasp_id = match.group(1).upper()
                covered.add(owasp_id)
                owasp_attack_counts[owasp_id] = owasp_attack_counts.get(owasp_id, 0) + len(attack_results)
                successes = sum(1 for ar in attack_results if ar.outcome == AttackOutcome.SUCCESS)
                owasp_success_counts[owasp_id] = owasp_success_counts.get(owasp_id, 0) + successes
            else:
                # 回退 1: 从每个 AttackResult 的 atomic_attack_identifier.params.display_group 提取
                for ar in attack_results:
                    ar_owasp = _extract_owasp_from_attack_result(ar)
                    if ar_owasp:
                        covered.add(ar_owasp)
                        owasp_attack_counts[ar_owasp] = owasp_attack_counts.get(ar_owasp, 0) + 1
                        if ar.outcome == AttackOutcome.SUCCESS:
                            owasp_success_counts[ar_owasp] = owasp_success_counts.get(ar_owasp, 0) + 1
                # 回退 2: 如果 AttackResult 也没有 OWASP 信息, 从技术名匹配
                if not any(
                    _extract_owasp_from_attack_result(ar) for ar in attack_results
                ):
                    tech_lower = group_name.lower()
                    fallback_map = {
                        "prompt_injection": "LLM01",
                        "jailbreak": "LLM01",
                        "encoding": "LLM01",
                        "payload_smuggling": "LLM01",
                        "red_teaming": "LLM01",
                        "information_disclosure": "LLM06",
                        "data_exfiltration": "LLM06",
                        "dan": "LLM08",
                        "actor_attack": "LLM08",
                    }
                    for key, owasp_id in fallback_map.items():
                        if key in tech_lower:
                            covered.add(owasp_id)
                            owasp_attack_counts[owasp_id] = owasp_attack_counts.get(owasp_id, 0) + len(attack_results)
                            successes = sum(1 for ar in attack_results if ar.outcome == AttackOutcome.SUCCESS)
                            owasp_success_counts[owasp_id] = owasp_success_counts.get(owasp_id, 0) + successes
                            break

    # S5-2: 计划态覆盖 (从 sorted_datasets 获取)
    planned_coverage: set[str] = set()
    sorted_datasets = ctx.sorted_datasets or []
    if sorted_datasets:
        for ds_name in sorted_datasets:
            # 从数据集名提取 OWASP ID
            import re as _re
            m = _re.match(r"^owasp_(?:llm|asi)(\d{2})_", ds_name, _re.IGNORECASE)
            if m:
                planned_coverage.add(f"LLM{m.group(1)}")

    lines: list[str] = []
    for owasp_id, name in owasp_categories.items():
        is_planned = owasp_id in planned_coverage
        is_actual = owasp_id in covered
        attack_count = owasp_attack_counts.get(owasp_id, 0)
        success_count = owasp_success_counts.get(owasp_id, 0)

        # S5-2: 计划 vs 实际 标注
        if is_actual and attack_count > 0:
            rate = success_count / attack_count * 100
            planned_str = str(attack_count) if is_planned else "0"
            line = (
                f"  ✓ {owasp_id} {name:<30} 计划 {planned_str} "
                f"→ 实际 {attack_count} | {success_count} 成功 ({rate:.0f}%)"
            )
            lines.append(line)
        elif is_planned:
            lines.append(f"  ─ {owasp_id} {name:<30} 计划有 → 实际 0 (未触发)")
        else:
            lines.append(f"  ✗ {owasp_id} {name:<30} 未覆盖")

    coverage = len(covered) / len(owasp_categories) * 100
    success_categories = sum(1 for v in owasp_success_counts.values() if v > 0)
    lines.append(
        f"  覆盖率: {len(covered)}/{len(owasp_categories)} ({coverage:.0f}%) "
        f"| 有成功攻击的分类: {success_categories}/{len(covered)}"
    )

    info_box("OWASP LLM Top10 (2025) 覆盖矩阵", lines)

    # L5 P2-1: 决策追溯 — OWASP 矩阵计算
    from pipeline.utils.decision_trace import DecisionTrace

    trace = DecisionTrace.get_instance()
    trace.record(
        stage="stage_5",
        layer="L5_Analytics",
        decision="owasp_matrix_computed",
        reason=f"Coverage: {len(covered)}/{len(owasp_categories)} ({coverage:.0f}%)",
        covered_ids=sorted(covered),
        coverage_pct=round(coverage, 1),
    )


# ============================================================
# G4: ASR 反馈循环可视化
# ============================================================


def _print_asr_feedback_loop(ctx: PipelineContext) -> None:
    """G4: ASR 反馈循环可视化 — 展示完整的 ASR 闭环数据流。.

    展示: 先验 ASR → 实测 ASR → 经验写回 → 下次运行 warm-start 的完整闭环
    """
    from pipeline.utils.display import core_card

    if not ctx.asr_per_technique:
        return

    # 先验 ASR (Stage 2 warm-start)
    warm_start = getattr(ctx, "warm_start_asr", {}) or {}
    # 实测 ASR (Stage 4)
    measured = ctx.asr_per_technique
    # 经验写回状态 (检查 empirical ASR 文件, 不是 seed_level 文件)
    empirical_saved = False
    seed_level_saved = False
    dataset_level_saved = False
    try:
        from pipeline.asr.optimizer import (
            _get_dataset_level_asr_path,
            _get_empirical_asr_path,
            _get_seed_level_asr_path,
        )

        model_name = ctx.metadata.get("model_name", "unknown")
        empirical_saved = _get_empirical_asr_path(model_name).exists()
        seed_level_saved = _get_seed_level_asr_path(model_name).exists()
        dataset_level_saved = _get_dataset_level_asr_path(model_name).exists()
    except Exception:
        pass

    # 构建对比数据
    prior_lines: list[str] = []
    measured_lines: list[str] = []
    dataset_lines: list[str] = []
    feedback_lines: list[str] = []

    # Top 5 攻击技术: 先验 vs 实测 (技术名维度)
    top_measured = sorted(measured.items(), key=lambda x: x[1], reverse=True)[:5]
    for tech, actual_asr in top_measured:
        prior_asr = warm_start.get(tech, 0)
        diff = actual_asr - prior_asr
        arrow = "↑" if diff > 5 else ("↓" if diff < -5 else "=")
        prior_lines.append(f"{tech[:30]:<30} {prior_asr:>5.1f}%")
        measured_lines.append(f"{tech[:30]:<30} {actual_asr:>5.1f}% {arrow}")

    # E2: 数据集维度 ASR (分离展示)
    if ctx.result is not None:
        try:
            from pyrit.models import AttackOutcome

            groups = ctx.result.get_display_groups()
            for ds_name, attack_results in sorted(groups.items(), key=lambda x: len(x[1]), reverse=True)[:5]:
                ds_total = len(attack_results)
                if ds_total == 0:
                    continue
                ds_succ = sum(1 for r in attack_results if r.outcome == AttackOutcome.SUCCESS)
                ds_asr = ds_succ / ds_total * 100
                dataset_lines.append(f"{ds_name[:30]:<30} {ds_asr:>5.1f}% ({ds_succ}/{ds_total})")
        except Exception:
            pass
    if not dataset_lines:
        dataset_lines.append("(无数据集维度数据)")

    feedback_lines.append(f"经验写回: {'✅ 已保存' if empirical_saved else '⚠ 未保存'}")
    feedback_lines.append(f"种子级 ASR: {'✅ 已保存' if seed_level_saved else '⚠ 未保存'}")
    feedback_lines.append(f"数据集级 ASR: {'✅ 已保存' if dataset_level_saved else '⚠ 未保存'}")
    feedback_lines.append(f"warm-start 技术: {len(warm_start)} → 下次运行优先级调整")
    feedback_lines.append(f"实测技术: {len(measured)} → 经验闭环")

    # 最大差异技术
    max_diff_tech = ""
    max_diff_val = 0
    for tech, actual_asr in measured.items():
        prior_asr = warm_start.get(tech, 0)
        diff = abs(actual_asr - prior_asr)
        if diff > max_diff_val:
            max_diff_val = diff
            max_diff_tech = tech
    if max_diff_tech:
        feedback_lines.append(f"最大差异: {max_diff_tech[:30]} (Δ={max_diff_val:.1f}%)")

    core_card(
        "ASR 反馈循环 (先验→实测→经验→warm-start)",
        sections=[
            {"label": "先验 ASR (Stage 2)", "lines": prior_lines},
            {"label": "实测 ASR — 攻击技术 (Stage 4)", "lines": measured_lines},
            {"label": "实测 ASR — 载荷数据集 (Stage 4)", "lines": dataset_lines},
            {"label": "经验闭环", "lines": feedback_lines},
        ],
    )


# ============================================================
# P3-O2: 多模型 ASR 对比矩阵
# ============================================================


def _print_multi_model_comparison(ctx: PipelineContext) -> None:
    """P3-O2: 多模型 ASR 对比矩阵 — 跨模型攻击成功率分析。."""
    try:
        from pipeline.asr.multi_model_matrix import MultiModelASRMatrix

        matrix = MultiModelASRMatrix()
        loaded = matrix.load_all_models()

        if loaded < 2:
            # 少于 2 个模型无法对比, 静默跳过
            return

        # 打印摘要
        matrix.print_summary()

        # 存入 ctx.metadata
        ctx.metadata["multi_model_comparison"] = matrix.generate_report()
    except Exception as e:
        logger.debug(f"Multi-model comparison skipped: {e}")


def _print_e2e_validation(ctx: PipelineContext) -> None:
    """R-023: 端到端验证报告 — 自动检查 ctx.metadata 中各场景结果的完整性.

    验证项清单 (22 项):
      - MCP 探针 / 多轮会话 / 盲推理 / 后门探测
      - 控制模式感知 / Secret 验证 / Crescendo / TAP
      - 高级 MCP Kill Chain / XPIA / ASI03/09/10 / 多 Agent
      - 三框架评估 / AI-VSS / 实时 ASR / 动态 Converter
      - Converter 链反馈 / 成功传播 / 安全过滤 / 多模型对比

    R-022 分类: 数据层增强 — 消费 ctx.metadata, 不修改原生生命周期。
    """
    try:
        from pipeline.validation.e2e_validator import run_e2e_validation

        report = run_e2e_validation(ctx.metadata)
        ctx.metadata["e2e_validation"] = report.to_dict()
    except Exception as e:
        logger.debug(f"E2E validation skipped: {e}")
