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
>   2026-8-3 — 错误恢复: 捕获 ValueError/RuntimeError, 从 CentralMemory
>     检索部分 ScenarioResult, 确保流水线不因单个攻击超时而中断
"""

from __future__ import annotations

import logging
import os
from typing import Any

from pipeline.asr.failure_type_event_handler import FailureTypeEventHandler
from pipeline.asr.runtime_stop_handler import RuntimeStopEventHandler
from pipeline.context import PipelineContext
from pipeline.utils.event_bus import EventBus

logger = logging.getLogger(__name__)


async def run(ctx: PipelineContext) -> None:
    """执行 Stage 4/6: 场景执行 + ASR 分析。."""
    print("\n" + "=" * 70)
    print("阶段 4/6: 场景执行 — AttackExecutor 并发 + 攻击为王")
    print("=" * 70)

    strategy = "EXHAUSTIVE" if ctx.max_attempts_per_objective >= 999 else "FIRST_SUCCESS"

    # ── P1: FailureTypeEventHandler ──
    selector = getattr(ctx, "selector", None)

    # 提前提取 model_name (供显示和后续使用)
    # 多路径回退: ctx.metadata → selector → env → registry → CLI args
    if "model_name" not in ctx.metadata:
        _detected_name = ""
        if selector is not None:
            _detected_name = (
                getattr(selector, "_model_name", None)
                or getattr(selector, "model_name", None)
                or ""
            )
        if not _detected_name:
            _detected_name = (
                os.getenv("TARGET_MODEL", "")
                or os.getenv("OPENAI_CHAT_MODEL", "")
                or getattr(ctx.args, "model", "")
            )
        if not _detected_name:
            try:
                from pipeline.converters.model_tier_detector import detect_model_tier_from_registry

                _detected_name, _ = detect_model_tier_from_registry()
            except Exception:
                _detected_name = ""
        ctx.metadata["model_name"] = _detected_name or "unknown"

    if "model_tier" not in ctx.metadata and selector is not None:
        _detected_tier = getattr(selector, "_model_tier", None)
        if _detected_tier:
            ctx.metadata["model_tier"] = _detected_tier

    # O6: 精简执行配置摘要 (红队视角: 目标 + 攻击数 + 策略)
    model_name = ctx.metadata.get("model_name", "unknown")
    model_tier = ctx.metadata.get("model_tier", "")
    tier_str = f" ({model_tier})" if model_tier else ""
    print("\n  ┌─ 攻击执行配置 ──────────────────────────────────────────┐")
    print(
        f"  │ 目标: {model_name}{tier_str} | AtomicAttack: {ctx.scenario.atomic_attack_count}"
        f" | 策略: {strategy} | 并发: {ctx.args.max_concurrency}"
    )
    # O5: 解释 P-编号 vs AtomicAttack 差异
    planned_attacks = ctx.metadata.get("planned_attack_count", 0)
    actual_attacks = ctx.scenario.atomic_attack_count
    if planned_attacks > 0 and planned_attacks != actual_attacks:
        diff = planned_attacks - actual_attacks
        print(
            f"  │ 计划: {planned_attacks} → 实际: {actual_attacks} (去重/预算精简 {diff} 个)"
        )
    print("  └───────────────────────────────────────────────────────────────┘")

    event_handler = FailureTypeEventHandler(selector=selector)

    # ── P1-G3: RuntimeStopEventHandler — 运行时停止策略 ──
    # L2: OWASP 分类成功率阈值, L3: 全局首成功即停
    # 通过 post-execution scan 追踪成功/失败, 检查是否达到停止条件
    owasp_threshold = float(os.getenv("OWASP_SUCCESS_THRESHOLD", "0"))
    stop_on_first = os.getenv("STOP_ON_FIRST_SUCCESS", "").lower() in ("true", "1", "yes")
    stop_handler = RuntimeStopEventHandler(
        owasp_threshold=owasp_threshold,
        stop_on_first_success=stop_on_first,
    )

    # ── 原生: 场景执行 ──
    # P2-3: ProgressDashboard 集成 (执行前显示总览, 执行后显示结果)
    from pipeline.reporting.output_manager import ProgressDashboard, ProgressPoller

    total_attacks = ctx.scenario.atomic_attack_count
    dashboard = ProgressDashboard(total=total_attacks)
    # O4: 不再打印 Dashboard 初始卡片 (原生 tqdm 会显示进度)
    # O1: Dashboard 仅作为数据收集器, 不用于渲染

    # C1+C2: 启用 ProgressPoller 实时轮询 (基于 PyRIT 原生 CentralMemory API)
    # R-022: Poller 通过 tqdm._instances + set_postfix() 增强原生 tqdm 进度条
    scenario_result_id = getattr(ctx.scenario, "_scenario_result_id", None) or getattr(ctx.args, "resume", None)
    poller: ProgressPoller | None = None
    # P3-O1: 实时 ASR 追踪器
    from pipeline.asr.realtime_asr_tracker import RealTimeASRTracker

    asr_tracker = RealTimeASRTracker()
    if scenario_result_id:
        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id=scenario_result_id,
            interval=5.0,
            asr_tracker=asr_tracker,
        )
        poller.start()
        # O4: 系统内部信息降级到日志
        logger.debug(f"ProgressPoller started (srid={scenario_result_id[:8]}...)")

    # C4: 发布执行开始事件
    bus = EventBus.get_instance()
    bus.publish_simple(
        "stage_execute", "execution_started",
        total_attacks=total_attacks,
        strategy=strategy,
        max_concurrency=ctx.args.max_concurrency,
    )

    # ── 原生: 场景执行 (含错误恢复) ──
    # PyRIT 原生 scenario.run_async() 在部分攻击失败时会抛出 ValueError,
    # 但已完成的 AttackResult 已持久化到 CentralMemory。
    # 此处捕获 ValueError, 从 CentralMemory 检索部分结果, 确保流水线不中断。
    # 学术依据: PyRIT 原生弹性恢复设计 (max_retries + scenario_result_id + Memory 检索)
    # 遵循 R-010: 使用 PyRIT 原生 CentralMemory API 检索结果, 不覆盖原生生命周期
    partial_failure = False
    try:
        result = await ctx.scenario.run_async()
    except (ValueError, RuntimeError) as exc:
        logger.warning(
            "Scenario execution raised %s: %s. "
            "Attempting to retrieve partial results from CentralMemory.",
            type(exc).__name__,
            exc,
        )
        partial_failure = True
        result = _retrieve_partial_results(ctx, scenario_result_id)
        if result is None:
            # 无法检索部分结果, 重新抛出异常
            if poller:
                await poller.stop()
            raise

    ctx.result = result

    # 停止轮询
    if poller:
        await poller.stop()

    # P3-O1: 存储实时 ASR 摘要到 ctx.metadata (O4: 展示降级到日志)
    ctx.metadata["realtime_asr_summary"] = asr_tracker.get_realtime_summary()
    _adjustments = asr_tracker.suggest_adjustments()
    if _adjustments:
        ctx.metadata["realtime_asr_adjustments"] = [
            {
                "technique": adj.technique,
                "type": adj.adjustment_type,
                "description": adj.description,
                "current_asr": round(adj.current_asr, 4),
                "suggested_action": adj.suggested_action,
            }
            for adj in _adjustments
        ]
        # O4: ASR 调整建议降级到日志 (运维信息, 非红队攻击结果)
        logger.debug(f"Real-time ASR adjustments: {len(_adjustments)} items")

        # P3-O1 深度应用: 生成实时参数覆盖 (供下一次运行暖启动使用)
        _overrides = asr_tracker.get_live_parameter_overrides()
        if _overrides and any(
            _overrides[key] for key in ("converter_priority_boost", "retry_reduction", "technique_skip", "angle_change")
        ):
            ctx.metadata["realtime_parameter_overrides"] = _overrides
            logger.debug(
                f"Real-time parameter overrides: "
                f"boost={len(_overrides.get('converter_priority_boost', {}))}, "
                f"retry_reduction={len(_overrides.get('retry_reduction', {}))}, "
                f"skip={len(_overrides.get('technique_skip', {}))}, "
                f"angle={len(_overrides.get('angle_change', {}))}"
            )

    if partial_failure:
        total_results = sum(len(v) for v in result.attack_results.values())
        print(f"\n  ⚠ [恢复] 场景执行部分失败, 已从 CentralMemory 检索 {total_results} 个部分结果")

    # P2-3: 更新 Dashboard 并显示最终状态
    # 使用 update_from_attack_results 按 objective 级别计数, 与 Poller 一致
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

    # O1: Dashboard 仅用于数据收集, 不再渲染 (原生 tqdm 已完成进度展示)
    all_attack_results = [ar for ars in result.attack_results.values() for ar in ars]
    dashboard.update_from_attack_results(all_attack_results)

    # C4: 发布执行完成事件
    bus.publish_simple(
        "stage_execute", "execution_completed",
        total_results=total_results,
        succeeded=succeeded,
        failed=failed,
        errored=errored,
    )

    # ── P1: 后处理扫描 ──
    _scan_results_post_execution(ctx, event_handler, stop_handler)

    # ── P1-G3: 停止策略统计 ──
    stop_stats = stop_handler.get_stats()
    if stop_stats["should_stop"]:
        print(f"  停止策略: {stop_stats['stop_reason']}")
    ctx.metadata["stop_strategy_stats"] = stop_stats

    # ── P1: 失败类型分布 ──
    stats = event_handler.get_stats()
    if stats["total_attacks"] > 0:
        ctx.metadata["failure_stats"] = stats

    # O5: 合并执行后输出为 3 个红队核心卡片
    # (移除 11+ 个独立 info_box, 降级运维信息到日志)
    _print_attack_summary(ctx, stats)

    # L5 P2-1: 决策追溯 — ASR 计算完成
    from pipeline.utils.decision_trace import DecisionTrace

    trace = DecisionTrace.get_instance()
    trace.record(
        stage="stage_4",
        layer="L5_Analytics",
        decision="asr_computed",
        reason=f"Overall ASR={ctx.overall_asr}%, {len(ctx.asr_per_technique)} techniques",
        overall_asr=ctx.overall_asr,
        technique_count=len(ctx.asr_per_technique),
        total_results=total_results,
        succeeded=succeeded,
    )
    # L5 P2-2: EventBus — ASR 计算完成
    bus.publish_simple(
        "stage_4", "asr_computed",
        overall_asr=ctx.overall_asr,
        technique_count=len(ctx.asr_per_technique),
        succeeded=succeeded,
        failed=failed,
    )

    # P1-1: 经验 ASR 保存已移至 Stage 5 (stage_post_analysis), 消除重复调用

    # ── O6: ★ 突出传递 Banner (替代单行衔接) ──
    from pipeline.utils.display import handoff_banner

    total_results = sum(len(v) for v in ctx.result.attack_results.values())
    success_count = sum(
        1
        for v in ctx.result.attack_results.values()
        for ar in v
        if ar.outcome and ar.outcome.name == "SUCCESS"
    )
    handoff_banner(
        4, 5,
        "传递到执行后分析 — ASR 驱动经验闭环",
        [
            f"★ ASR: {ctx.overall_asr}% → 决定经验写回权重",
            f"★ 成功/总计: {success_count}/{total_results} → 按技术分组统计",
            f"★ 失败类型: {stats.get('top_failure_type', 'N/A')} → 下次运行路由优化",
            f"★ 技术统计: {len(ctx.asr_per_technique)} 个技术有 ASR 数据",
            "★ 分析任务: 实测 vs 先验对比 + 经验写回 + 下次运行建议",
        ],
    )


def _extract_technique_from_result(ar: Any) -> str:
    """O1: 从 AttackResult 提取真正的攻击技术名.

    委托给 AttackResultAnalyzer.extract_technique_name() (原生 PyRIT identifier API).
    回退到 "unknown" 如果提取失败。

    R-022: 使用 PyRIT 原生 identifier 字段, 不修改原生生命周期。
    """
    try:
        from pipeline.analysis.attack_result_analyzer import AttackResultAnalyzer

        name = AttackResultAnalyzer.extract_technique_name(ar)
        # 类型防御: 确保 tech_name 始终为 str (MagicMock 属性泄漏可能导致非 str 返回)
        return name if isinstance(name, str) else "unknown"
    except Exception:
        return "unknown"


def _print_attack_summary(ctx: PipelineContext, stats: dict) -> None:
    """O5: 红队核心汇总卡片 — 合并 11+ 个 info_box 为 3 个核心卡片.

    卡片 ① 攻击结果总览: 总计/成功/失败/ASR + 技术排行 + Per-Dataset
    卡片 ② 攻击诊断: 失败类型分布 + 路由建议 (仅有失败时显示)
    卡片 ③ 成功攻击详情: Top 10 载荷+技术+Converter (仅有成功时显示)
    """
    from pyrit.models import AttackOutcome

    from pipeline.utils.display import info_box

    result = ctx.result
    if result is None:
        return

    # ── 计算 ASR — 按攻击技术分组 (非数据集名) ──
    # O1 修复: get_display_groups() 返回的 group_name 是数据集名,
    # 而非攻击技术名。通过 AttackResultAnalyzer.extract_technique_name()
    # 从每个 AttackResult 提取真正的技术名, 按技术名重新分组计算 ASR。
    groups = result.get_display_groups()
    all_results: list[tuple[str, bool, Any]] = []
    for _dataset_name, attack_results in groups.items():
        for ar in attack_results:
            success = ar.outcome == AttackOutcome.SUCCESS
            # O1: 提取真正的攻击技术名
            tech_name = _extract_technique_from_result(ar)
            all_results.append((tech_name, success, ar))

    # 按攻击技术名分组计算 ASR
    asr_per_technique: dict[str, float] = {}
    _tech_results: dict[str, list[Any]] = {}
    for tech_name, _success, ar in all_results:
        _tech_results.setdefault(tech_name, []).append(ar)
    for tech_name, results in _tech_results.items():
        total_t = len(results)
        if total_t == 0:
            continue
        successes_t = sum(1 for r in results if r.outcome == AttackOutcome.SUCCESS)
        asr_per_technique[tech_name] = (successes_t / total_t) * 100

    ctx.asr_per_technique = asr_per_technique
    ctx.overall_asr = result.objective_achieved_rate()

    total = len(all_results)
    successes = sum(1 for _, s, _ in all_results if s)
    failures = total - successes

    # ── 卡片 ①: 攻击结果总览 ──
    lines: list[str] = []
    lines.append(f"总计: {total} | 成功: {successes} | 失败: {failures} | ASR: {ctx.overall_asr}%")
    lines.append("")
    lines.append(f"{'攻击技术':<35} {'ASR':>7s}  {'成功/总计':<10s}  {'可视化':<20s}")
    for name, asr_val in sorted(asr_per_technique.items(), key=lambda x: x[1], reverse=True):
        bar = "█" * int(asr_val / 5)
        tech_results = _tech_results.get(name, [])
        succ_t = sum(1 for r in tech_results if r.outcome == AttackOutcome.SUCCESS)
        total_t = len(tech_results)
        lines.append(f"  {name:<33} {asr_val:>6.1f}%  {succ_t}/{total_t:<8}  {bar}")

    # D3: OWASP 覆盖率行 (从 metadata 收集)
    owasp_coverage = ctx.metadata.get("mcp_probe_results", {}).get("owasp_coverage", {})
    if not owasp_coverage:
        # 尝试从 attack_results metadata 提取 owasp_codes
        owasp_codes_found: dict[str, bool] = {}
        for _, _, ar in all_results:
            ar_meta = getattr(ar, "metadata", None) or {}
            if isinstance(ar_meta, dict):
                codes = ar_meta.get("owasp_codes") or ar_meta.get("owasp_code")
                if codes:
                    if isinstance(codes, str):
                        codes = [codes]
                    for code in codes:
                        if isinstance(code, str) and code.startswith("ASI"):
                            owasp_codes_found[code] = owasp_codes_found.get(code, False)
                            if getattr(ar, "outcome", None) == AttackOutcome.SUCCESS:
                                owasp_codes_found[code] = True
        if owasp_codes_found:
            owasp_coverage = owasp_codes_found

    if owasp_coverage:
        lines.append("")
        coverage_parts = []
        for code in sorted(owasp_coverage.keys()):
            hit = owasp_coverage[code] if isinstance(owasp_coverage[code], bool) else False
            marker = "✅" if hit else "❌"
            coverage_parts.append(f"{code} {marker}")
        lines.append(f"  OWASP 覆盖: {' | '.join(coverage_parts)}")

    # Per-Dataset Breakdown (保留数据集维度作为补充信息)
    lines.append("")
    lines.append("  [载荷维度]")
    for group_name, attack_results in groups.items():
        g_total = len(attack_results)
        if g_total == 0:
            continue
        g_successes = sum(1 for r in attack_results if r.outcome == AttackOutcome.SUCCESS)
        rate = (g_successes / g_total) * 100 if g_total > 0 else 0
        marker = "✅" if g_successes > 0 else "❌"
        lines.append(f"  {marker} {group_name:<38} {rate:.0f}% ({g_successes}/{g_total})")

    info_box("① 攻击结果总览", lines)

    # ── 卡片 ②: 攻击诊断 (仅有失败时) ──
    if failures > 0:
        # 失败类型分布 (合并 _print_failure_routing + _print_failure_diagnosis)
        failure_dist = stats.get("failure_distribution", {})
        routing_map = {
            "model_refusal": "→ 策略升级",
            "timeout": "→ 降级单轮",
            "scorer_validation_error": "→ 换技术",
            "objective_not_achieved": "→ 强技术+Converter",
            "unknown": "→ 检查日志",
        }
        diag_lines: list[str] = []
        if failure_dist:
            for fail_type, count in sorted(failure_dist.items(), key=lambda x: x[1], reverse=True):
                route = routing_map.get(fail_type, "→ 默认路由")
                pct = count / failures * 100 if failures > 0 else 0
                # D4: 从失败结果中提取平均耗时和重试次数
                timing = _extract_failure_timing(all_results, fail_type)
                timing_str = f" | avg {timing['avg_time']:.0f}s" if timing["avg_time"] > 0 else ""
                retry_str = f", {timing['avg_retries']:.0f} retries" if timing["avg_retries"] > 0 else ""
                diag_lines.append(
                    f"  {fail_type:<28} ×{count:<4} ({pct:.0f}%)  {route}{timing_str}{retry_str}"
                )
        else:
            diag_lines.append("  (无失败类型统计)")

        # Converter 健康状态 (合并, 仅有熔断时显示)
        monitor = ctx.metadata.get("converter_health_monitor")
        if monitor is not None:
            try:
                stats_list = monitor.get_all_stats() if hasattr(monitor, "get_all_stats") else []
                circuit_open = [s for s in stats_list if s.is_circuit_open]
                if circuit_open:
                    diag_lines.append("")
                    diag_lines.append(f"  ⚠ {len(circuit_open)} 个 Converter 已熔断:")
                    for s in circuit_open:
                        diag_lines.append(f"    🔴 {s.name}: {s.successes}/{s.attempts} success")
            except Exception:
                pass

        info_box(f"② 攻击诊断 ({failures} 个失败)", diag_lines)

    # ── 卡片 ③: 成功攻击详情 (Top 10) ──
    successful = [(tech, ar) for tech, success, ar in all_results if success]
    if successful:
        success_lines: list[str] = []
        technique_converter_map = getattr(ctx, "technique_converter_map", {}) or {}
        for idx, (tech_name, ar) in enumerate(successful[:10], 1):
            # 提取载荷
            payload_text = _extract_payload_from_result(ar)
            payload_brief = payload_text[:70] + "..." if len(payload_text) > 70 else payload_text

            # 提取 Converter
            conv_names = _extract_converter_names_from_result(ar)
            if not conv_names:
                expected_convs = technique_converter_map.get(tech_name, [])
                conv_names = [type(c).__name__ for c in expected_convs] if expected_convs else []

            conv_str = " → ".join(conv_names) if conv_names else "(baseline)"

            success_lines.append(f"  #{idx:<2} {tech_name[:25]} | {conv_str}")
            if payload_brief:
                success_lines.append(f"      载荷: {payload_brief}")

        info_box(f"③ 成功攻击详情 (Top {min(len(successful), 10)})", success_lines)


def _extract_failure_timing(
    all_results: list[tuple[str, bool, Any]], fail_type: str
) -> dict[str, float]:
    """D4: 从失败 AttackResult 提取平均耗时和重试次数.

    R-022 多路径回退:
      1. ar.metadata["execution_time"] / ar.metadata["retry_count"]
      2. ar.metadata["elapsed"] / ar.metadata["attempts"]

    Args:
        all_results: (tech_name, success, ar) 列表
        fail_type: 失败类型名

    Returns:
        {"avg_time": float, "avg_retries": float} — 无数据时为 0.0
    """
    from pyrit.models import AttackOutcome

    times: list[float] = []
    retries: list[float] = []

    for _, success, ar in all_results:
        if success:
            continue
        if ar.outcome != AttackOutcome.FAILURE:
            continue
        # 检查 metadata 中的 failure_type 是否匹配
        ar_meta = getattr(ar, "metadata", None) or {}
        if not isinstance(ar_meta, dict):
            continue
        ar_fail_type = ar_meta.get("failure_type", "")
        if ar_fail_type != fail_type:
            continue

        # 提取耗时
        exec_time = ar_meta.get("execution_time") or ar_meta.get("elapsed")
        if exec_time and isinstance(exec_time, (int, float)):
            times.append(float(exec_time))

        # 提取重试次数
        retry_count = ar_meta.get("retry_count") or ar_meta.get("attempts")
        if retry_count and isinstance(retry_count, (int, float)):
            retries.append(float(retry_count))

    return {
        "avg_time": sum(times) / len(times) if times else 0.0,
        "avg_retries": sum(retries) / len(retries) if retries else 0.0,
    }


def _retrieve_partial_results(ctx: PipelineContext, scenario_result_id: str | None) -> Any:
    """从 CentralMemory 检索部分场景结果。.

    当 PyRIT 原生 ``scenario.run_async()`` 因部分攻击失败而抛出异常时,
    已完成的 AttackResult 已持久化到 CentralMemory。
    此函数使用 PyRIT 原生 ``MemoryInterface.get_scenario_results()`` API
    检索已保存的 ScenarioResult, 确保流水线可以继续处理部分结果。

    遵循 R-010: 使用 PyRIT 原生 CentralMemory API, 不覆盖原生生命周期。

    Args:
        ctx: PipelineContext 实例。
        scenario_result_id: 场景结果 ID。

    Returns:
        ScenarioResult 实例 (如果找到), 否则 None。
    """
    if not scenario_result_id:
        logger.warning("无法检索部分结果: scenario_result_id 为空")
        return None

    try:
        from pyrit.memory import CentralMemory

        memory = CentralMemory.get_memory_instance()
        results = memory.get_scenario_results(
            scenario_result_ids=[scenario_result_id],
        )
        if results:
            result = results[0]
            logger.info(
                "从 CentralMemory 检索到部分结果: %d 个攻击结果组",
                len(result.attack_results),
            )
            return result
        logger.warning("CentralMemory 中未找到 scenario_result_id=%s 的结果", scenario_result_id)
    except Exception as e:
        logger.error("从 CentralMemory 检索部分结果失败: %s", e)

    return None


def _print_failure_routing(ctx: PipelineContext, stats: dict) -> None:
    """O5: 失败路由策略展示 (对齐 pyrit_ai300 Stage 5 ②).

    展示 4 种失败路由策略:
      model_refusal → 策略升级
      timeout → 降级单轮
      scorer_error → 换技术
      objective_failed → 强技术+Converter 变体
    """
    from pipeline.utils.display import info_box

    failure_dist = stats.get("failure_distribution", {})
    if not failure_dist:
        return

    # 路由策略映射
    routing_map = {
        "model_refusal": "→ 策略升级 (Tier S/A 优先)",
        "timeout": "→ 降级单轮 (prompt_sending)",
        "scorer_validation_error": "→ 换技术 (跳过当前)",
        "objective_not_achieved": "→ 强技术+Converter 变体",
        "unknown": "→ 检查错误日志",
    }

    lines = []
    for fail_type, count in sorted(failure_dist.items(), key=lambda x: x[1], reverse=True):
        route = routing_map.get(fail_type, "→ 默认路由")
        lines.append(f"{fail_type:<30} ×{count:<5} {route}")

    top_fail = max(failure_dist, key=failure_dist.get) if failure_dist else "N/A"
    lines.append("")
    lines.append(f"主要失败模式: {top_fail}")
    lines.append(f"→ 下次运行: {routing_map.get(top_fail, '检查配置')}")

    info_box("失败路由策略", lines)


def _scan_results_post_execution(
    ctx: PipelineContext,
    handler: FailureTypeEventHandler,
    stop_handler: RuntimeStopEventHandler,
) -> None:
    """执行后扫描所有 AttackResult 并反馈到事件处理器和停止策略处理器。.

    优化3: 不再覆盖原生 ``_execute_scenario_async``,
    完全由 post-execution scan 实现失败类型反馈到 selector,
    使下次运行使用最新失败模式路由。

    P1-G3: 同时将结果反馈到 RuntimeStopEventHandler,
    追踪 OWASP 分类成功率和全局首成功停止条件。

    D11+D12: 同时反馈到 ConverterChainAdvisor 和 SuccessPropagationTracker,
    收集 (failure_type, converter_chain) 关联数据和成功组合.
    """
    result = ctx.result
    if result is None:
        return

    # D11+D12: 创建反馈收集器
    from pipeline.converters.converter_feedback import (
        ConverterChainAdvisor,
        SuccessPropagationTracker,
        extract_converter_chain_names,
    )

    chain_advisor = ConverterChainAdvisor()
    success_tracker = SuccessPropagationTracker()

    # 从 ctx 获取 payload categories (Stage 2 已推断)
    payload_categories_str = ctx.metadata.get("payload_categories", set())
    if isinstance(payload_categories_str, str):
        payload_categories_set = {payload_categories_str}
    else:
        payload_categories_set = set(payload_categories_str) if payload_categories_str else set()

    for _attack_id, attack_results in result.attack_results.items():
        for ar in attack_results:
            handler.on_attack_result(ar)
            stop_handler.on_attack_result(ar)

            # D11+D12: 提取 Converter 链名并记录
            chain_names = extract_converter_chain_names(ar)

            # 判断成功/失败
            from pyrit.models import AttackOutcome

            outcome = getattr(ar, "outcome", None)
            is_success = outcome == AttackOutcome.SUCCESS

            # D11: 提取失败类型并记录链性能
            if not is_success:
                try:
                    from pipeline.asr.failure_type_selector import extract_failure_type_from_result

                    failure_type = extract_failure_type_from_result(ar)
                except Exception:
                    failure_type = "unknown"
                chain_advisor.record(
                    failure_type=failure_type,
                    converter_chains=chain_names,
                    success=False,
                )
            else:
                chain_advisor.record(
                    failure_type="success",
                    converter_chains=chain_names,
                    success=True,
                )

            # D12: 记录成功组合
            if is_success and chain_names:
                # 从技术名推断范式作为 payload_category 代理
                from pipeline.analysis.attack_result_analyzer import AttackResultAnalyzer

                tech_name = AttackResultAnalyzer.extract_technique_name_optional(ar) or "unknown"
                # 使用 payload_categories (如果有多个, 取第一个; 否则用 "baseline")
                cat = next(iter(payload_categories_set)) if payload_categories_set else "baseline"
                success_tracker.record_success(
                    payload_category=cat,
                    technique=tech_name,
                    converter_chains=chain_names,
                )

    # 对 SequentialAttack 的子结果也扫描
    for attack_results in result.attack_results.values():
        for ar in attack_results:
            child_results = getattr(ar, "child_attack_results", None) or []
            for child in child_results:
                if child is not None:
                    handler.on_attack_result(child)
                    stop_handler.on_attack_result(child)

    # D11+D12: 将反馈数据存入 ctx.metadata
    ctx.metadata["converter_chain_advisor"] = chain_advisor.get_stats()
    ctx.metadata["success_propagation"] = success_tracker.get_stats()

    # P3-O3: 基于失败模式动态创建 Converter 链
    if chain_advisor.has_data:
        try:
            from pipeline.converters.dynamic_chain_creator import DynamicChainCreator

            dynamic_creator = DynamicChainCreator()
            dynamic_chains = dynamic_creator.create_from_advisor_data(chain_advisor.get_stats())

            if dynamic_chains:
                ctx.metadata["dynamic_converter_chains"] = dynamic_creator.get_chain_configs()
                logger.info(
                    f"P3-O3: Dynamically created {len(dynamic_chains)} converter chains "
                    f"based on failure patterns"
                )
        except Exception as e:
            logger.debug(f"Dynamic chain creation skipped: {e}")


def _compute_asr(ctx: PipelineContext) -> None:
    """计算 ASR (Attack Success Rate) 按攻击技术分组.

    O1 修复: 从 AttackResult 提取真正的攻击技术名 (非数据集名),
    按技术名分组计算 ASR。
    """
    result = ctx.result
    if result is None:
        return

    from pyrit.models import AttackOutcome

    # O1: 按攻击技术名重新分组 (非数据集名)
    groups = result.get_display_groups()
    tech_results: dict[str, list[Any]] = {}
    for _dataset_name, attack_results in groups.items():
        for ar in attack_results:
            tech_name = _extract_technique_from_result(ar)
            tech_results.setdefault(tech_name, []).append(ar)

    asr_per_technique: dict[str, float] = {}
    for tech_name, results in tech_results.items():
        total = len(results)
        if total == 0:
            continue
        successes = sum(1 for r in results if r.outcome == AttackOutcome.SUCCESS)
        asr = (successes / total) * 100
        asr_per_technique[tech_name] = asr

    ctx.asr_per_technique = asr_per_technique

    # 原生: 总体 ASR
    ctx.overall_asr = result.objective_achieved_rate()

    # 打印 ASR 排行榜 (攻击为王) — 迁移到 info_box
    from pipeline.utils.display import info_box

    asr_lines = []
    for name, asr_val in sorted(
        asr_per_technique.items(), key=lambda x: x[1], reverse=True
    ):
        bar = "█" * int(asr_val / 5)
        asr_lines.append(f"{name:<40} {asr_val:>7.1f}% {bar}")
    asr_lines.append("")
    asr_lines.append(f"{'总体 ASR':<40} {ctx.overall_asr:>7d}%")
    info_box("ASR 排行榜 (Attack Success Rate)", asr_lines)

    # ── Stage 4 → Stage 5 衔接摘要 ──
    print(f"\n  → 传递到 Stage 5/6: ASR={ctx.overall_asr}% | {len(ctx.asr_per_technique)} 个技术有统计")


def _print_successful_attack_details(
    ctx: PipelineContext, all_results: list
) -> None:
    """打印成功攻击的载荷/技术/Converter 详情.

    展示每条成功攻击的: P编号 | 技术 | 载荷来源 | Converter 链.
    """
    from pipeline.utils.display import info_box

    success_lines: list[str] = []
    for idx, (group_name, success, ar) in enumerate(all_results, 1):
        if not success:
            continue
        # 从 AttackResult 提取信息
        converter_names = []
        converters = getattr(ar, "request_converters", None) or []
        for c in converters:
            cname = type(c).__name__
            if cname not in converter_names:
                converter_names.append(cname)

        conv_str = " + ".join(converter_names) if converter_names else "(无 Converter)"
        success_lines.append(f"P{idx:<3} {group_name:<30} {conv_str}")

    if success_lines:
        info_box("成功攻击详情 (载荷 + 技术 + Converter)", success_lines)
    else:
        info_box("成功攻击详情", ["(无成功攻击)"])


def _print_attack_overview(ctx: PipelineContext) -> None:
    """攻击结果速览 + Per-Group Breakdown + 成功攻击载荷/技术/Converter 详情。."""
    result = ctx.result
    if result is None:
        return

    from pyrit.models import AttackOutcome

    from pipeline.utils.display import info_box

    groups = result.get_display_groups()
    all_results = []
    for group_name, attack_results in groups.items():
        for ar in attack_results:
            success = ar.outcome == AttackOutcome.SUCCESS
            all_results.append((group_name, success, ar))

    overview_lines = []
    for idx, (tech, success, _) in enumerate(all_results, 1):
        marker = "✅" if success else "❌"
        overview_lines.append(f"P{idx:<3} {marker} {tech:<35}")

    total = len(all_results)
    successes = sum(1 for _, s, _ in all_results if s)
    overview_lines.append("")
    overview_lines.append(f"合计: {total} 个 | 成功: {successes} | 失败: {total - successes}")
    info_box("攻击结果速览 (ASR 降序)", overview_lines)

    # ── 成功攻击详情: 载荷 + 技术 + Converter ──
    _print_successful_attack_details(ctx, all_results)

    # ── Per-Group Breakdown ──
    group_lines = []
    for group_name, attack_results in groups.items():
        g_total = len(attack_results)
        if g_total == 0:
            continue
        g_successes = sum(
            1 for r in attack_results if r.outcome == AttackOutcome.SUCCESS
        )
        rate = (g_successes / g_total) * 100 if g_total > 0 else 0
        marker = "✅" if g_successes > 0 else "❌"
        group_lines.append(
            f"{marker} {group_name:<40} {rate:.0f}% ({g_successes}/{g_total})"
        )
    info_box("Per-Group Breakdown (执行结果统计)", group_lines)


def _print_pid_dataset_map(ctx: PipelineContext) -> None:
    """Gap 4: P 编号贯穿 — 展示 dataset → P编号映射 (执行端消费).

    Stage 2 中定义的 P 编号映射, 此处展示每个数据集的执行结果:
      dataset_1 → P1-P5  → 3/5 成功 (60%)
      dataset_2 → P6-P8  → 0/3 成功 (0%)
    """
    from pipeline.utils.display import info_box

    pid_map = getattr(ctx, "plan_pid_map", {})
    if not pid_map:
        return

    from pyrit.models import AttackOutcome

    result = ctx.result
    if result is None:
        return

    # 获取所有 AttackResult 的 P 编号列表
    groups = result.get_display_groups()
    all_results = []
    for group_name, attack_results in groups.items():
        for ar in attack_results:
            success = ar.outcome == AttackOutcome.SUCCESS
            all_results.append((group_name, success, ar))

    total_all = len(all_results)
    success_all = sum(1 for _, s, _ in all_results if s)

    lines = []
    for ds_name, pid_range in pid_map.items():
        # 简化: 按数据集名匹配技术组
        # (实际数据集中名和技术组名可能不完全一致, 这里做近似匹配)
        matched_results = []
        for g_name, success, _ in all_results:
            if ds_name in g_name or g_name in ds_name:
                matched_results.append(success)

        if matched_results:
            ds_success = sum(matched_results)
            ds_total = len(matched_results)
            ds_rate = ds_success * 100 // max(ds_total, 1)
            lines.append(
                f"{ds_name:<35} {pid_range:<12} "
                f"{ds_success}/{ds_total} 成功 ({ds_rate}%)"
            )
        else:
            lines.append(f"{ds_name:<35} {pid_range:<12} (结果分散在技术组中)")

    lines.append("")
    lines.append(f"总计: {total_all} 个 | 成功: {success_all} | ASR: {ctx.overall_asr}%")
    lines.append("P 编号 → Stage 5 (分析): 实测 vs 先验对比")

    info_box("数据集执行映射 (dataset → P编号 → 结果)", lines)


# ============================================================
# B6: ConverterHealthMonitor 运行时熔断统计
# ============================================================


def _print_converter_health(ctx: PipelineContext) -> None:
    """B6: 展示 ConverterHealthMonitor 的运行时熔断统计。.

    从 PipelineContext.metadata 中提取 ConverterHealthMonitor 实例,
    展示各 Converter 的健康状态和熔断情况。
    """
    from pipeline.utils.display import info_box

    monitor = ctx.metadata.get("converter_health_monitor")
    if monitor is None:
        return

    try:
        stats_list = monitor.get_all_stats() if hasattr(monitor, "get_all_stats") else []
        if not stats_list:
            return

        lines: list[str] = []
        circuit_open_count = 0
        for stat in stats_list:
            status = "🔴 OPEN" if stat.is_circuit_open else "🟢 CLOSED"
            if stat.is_circuit_open:
                circuit_open_count += 1
            lines.append(
                f"  {status} {stat.name}: "
                f"{stat.successes}/{stat.attempts} success "
                f"({stat.failures} fail, {stat.errors} err)"
            )

        if circuit_open_count > 0:
            lines.insert(0, f"  ⚠ {circuit_open_count} 个 Converter 已熔断 (circuit open)")
            # 发布事件
            from pipeline.utils.event_bus import EventBus
            bus = EventBus.get_instance()
            bus.publish_simple(
                "stage_execute", "converter_circuit_open",
                open_count=circuit_open_count,
                converters=[s.name for s in stats_list if s.is_circuit_open],
            )

        info_box(f"Converter 健康状态 ({len(stats_list)} 个)", lines)
    except Exception as e:
        logger.debug(f"B6 converter health display failed: {e}")


# ============================================================
# C3: Converter 变换展示
# ============================================================


def _print_converter_transformations(ctx: PipelineContext) -> None:
    """C3: 展示成功攻击中使用的 Converter 变换。.

    从 AttackResult 的 metadata 中提取 Converter 信息,
    展示哪些变换对成功贡献最大。
    """
    from pipeline.utils.display import info_box

    if ctx.result is None:
        return

    from pyrit.models import AttackOutcome

    converter_success: dict[str, int] = {}
    converter_total: dict[str, int] = {}

    try:
        groups = ctx.result.get_display_groups()
        for _group, attack_results in groups.items():
            for ar in attack_results:
                # 从 conversation 中提取 converter 信息
                conv_name = "baseline"
                try:
                    if hasattr(ar, "conversation") and ar.conversation:
                        labels = getattr(ar.conversation, "labels", None) or {}
                        if labels:
                            for label_value in labels.values() if isinstance(labels, dict) else []:
                                if isinstance(label_value, str) and "converter" in label_value.lower():
                                    conv_name = label_value
                                    break
                except Exception:
                    pass

                converter_total[conv_name] = converter_total.get(conv_name, 0) + 1
                if ar.outcome == AttackOutcome.SUCCESS:
                    converter_success[conv_name] = converter_success.get(conv_name, 0) + 1

        if not converter_total:
            info_box("Converter 变换效果", ["(无 Converter 数据)"])
            return

        lines: list[str] = []
        sorted_convs = sorted(converter_total.items(), key=lambda x: x[1], reverse=True)
        for conv, total in sorted_convs[:5]:
            succ = converter_success.get(conv, 0)
            rate = succ / total * 100 if total > 0 else 0
            lines.append(f"  {conv}: {succ}/{total} ({rate:.0f}%)")

        info_box("Converter 变换效果 (Top 5)", lines)
    except Exception as e:
        logger.debug(f"C3 converter transformation display failed: {e}")


# ============================================================
# C5: 失败即时诊断
# ============================================================


def _print_failure_diagnosis(ctx: PipelineContext) -> None:
    """C5: 失败攻击的即时诊断分析 (L5 P3-2: 对齐 O5 失败类型分类).

    L5 P3-2: 将 C5 的内容模式诊断与 O5 的失败路由策略对齐,
    每个诊断模式直接关联到 O5 的路由建议, 形成诊断→路由闭环。
    """
    from pipeline.utils.display import info_box

    if ctx.result is None:
        return

    from pyrit.models import AttackOutcome

    failure_patterns: dict[str, int] = {}
    total_failures = 0

    try:
        groups = ctx.result.get_display_groups()
        for _group, attack_results in groups.items():
            for ar in attack_results:
                if ar.outcome != AttackOutcome.FAILURE:
                    continue
                total_failures += 1

                # L5 P3-2: 对齐 O5 失败类型分类
                pattern = "unknown"
                try:
                    if hasattr(ar, "conversation") and ar.conversation:
                        messages = ar.conversation.messages if hasattr(ar.conversation, "messages") else []
                        if messages:
                            last_msg = messages[-1]
                            content = str(getattr(last_msg, "content", "")).lower()
                            if any(w in content for w in [
                                "sorry", "i cannot", "i can't", "unable",
                                "inappropriate", "harmful", "unsafe",
                            ]):
                                pattern = "model_refusal"
                            elif any(w in content for w in ["empty", "no response", "204"]):
                                pattern = "scorer_validation_error"
                            elif any(w in content for w in ["timeout", "rate limit", "429"]):
                                pattern = "timeout"
                            else:
                                pattern = "objective_not_achieved"
                except Exception:
                    pass

                failure_patterns[pattern] = failure_patterns.get(pattern, 0) + 1

        if total_failures == 0:
            return

        # L5 P3-2: 诊断建议直接对齐 O5 路由策略
        diagnosis_map = {
            "model_refusal": "模型拒绝 → O5路由: 策略升级 (Tier S/A 优先)",
            "timeout": "超时/限速 → O5路由: 降级单轮 (prompt_sending)",
            "scorer_validation_error": "评分器异常 → O5路由: 换技术 (跳过当前)",
            "objective_not_achieved": "目标未达成 → O5路由: 强技术+Converter 变体",
            "unknown": "未知失败 → O5路由: 检查错误日志",
        }

        lines: list[str] = []
        sorted_patterns = sorted(failure_patterns.items(), key=lambda x: x[1], reverse=True)
        for pattern, count in sorted_patterns[:5]:
            pct = count / total_failures * 100 if total_failures > 0 else 0
            advice = diagnosis_map.get(pattern, "检查详细日志")
            lines.append(f"  {pattern} ({count}/{total_failures}, {pct:.0f}%): {advice}")

        info_box(f"失败即时诊断 ({total_failures} 个失败)", lines)
    except Exception as e:
        logger.debug(f"C5 failure diagnosis failed: {e}")


# ============================================================
# 成功攻击详情: 载荷 + 技术 + Converter 全链路展示
# ============================================================


def _print_successful_attack_details(
    ctx: PipelineContext,
    all_results: list[tuple[str, bool, Any]],
) -> None:
    """展示每个成功攻击的完整链路: 载荷 → 技术 → Converter → 结果。.

    从 AttackResult 的 conversation 中提取:
      - 原始载荷 (seed prompt)
      - 使用的技术 (display group)
      - 应用的 Converter (从 metadata/labels 提取)
      - 目标响应摘要
    """
    from pipeline.utils.display import info_box

    technique_converter_map = getattr(ctx, "technique_converter_map", {}) or {}

    # 过滤出成功攻击
    successful = [(tech, ar) for tech, success, ar in all_results if success]
    if not successful:
        return

    lines: list[str] = []
    for idx, (tech_name, ar) in enumerate(successful[:10], 1):  # 限制 Top 10
        lines.append(f"#{idx} 技术: {tech_name}")

        # 提取载荷
        payload_text = _extract_payload_from_result(ar)
        if payload_text:
            truncated = payload_text[:80] + "..." if len(payload_text) > 80 else payload_text
            lines.append(f"  载荷: {truncated}")

        # 提取 Converter
        conv_names = _extract_converter_names_from_result(ar)
        if conv_names:
            lines.append(f"  Converter: {' → '.join(conv_names)}")
        else:
            # 从 technique_converter_map 获取预期 Converter
            expected_convs = technique_converter_map.get(tech_name, [])
            if expected_convs:
                exp_names = [type(c).__name__ for c in expected_convs]
                lines.append(f"  Converter (预期): {' → '.join(exp_names)}")
            else:
                lines.append("  Converter: (baseline 直发)")

        # 提取目标响应摘要
        response_text = _extract_response_from_result(ar)
        if response_text:
            truncated_resp = response_text[:80] + "..." if len(response_text) > 80 else response_text
            lines.append(f"  响应: {truncated_resp}")

        lines.append("")

    info_box(f"成功攻击详情 (载荷→技术→Converter, Top {min(len(successful), 10)})", lines)


def _extract_payload_from_result(ar: Any) -> str:
    """从 AttackResult 中提取原始载荷文本 (多路径回退).

    回退顺序 (R-022 PyRIT 原生优先):
      1. ar.objective — PyRIT 1.0.1 原生字段 (所有数据集 seed_type=objective)
      2. ar.metadata — 元数据中的 seed_prompt / original_prompt
      3. ar.last_response — 最后响应的 original_value (回退)

    注意: PyRIT 1.0.1 的 AttackResult 没有 conversation 属性 (仅有 conversation_id),
    对话消息需通过 CentralMemory.get_messages() 查询, 此处不做额外查询。
    """
    # 路径 1: PyRIT 1.0.1 原生 objective 字段
    try:
        objective = getattr(ar, "objective", None)
        if objective and isinstance(objective, str) and len(objective) > 5:
            return objective
    except Exception:
        pass

    # 路径 2: PyRIT 原生 metadata 字典
    try:
        metadata = getattr(ar, "metadata", None) or {}
        if isinstance(metadata, dict):
            for key in ("seed_prompt", "original_prompt", "prompt", "payload"):
                val = metadata.get(key)
                if val and isinstance(val, str) and len(val) > 5:
                    return val
    except Exception:
        pass

    return ""


def _extract_converter_names_from_result(ar: Any) -> list[str]:
    """从 AttackResult 中提取 Converter 名称 (多路径回退).

    回退顺序 (R-022 PyRIT 原生优先):
      1. ar.labels — PyRIT 1.0.1 原生 AttackResult 标签
      2. ar.metadata — 元数据中的 converters / converter_chain

    注意: PyRIT 1.0.1 的 AttackResult 没有 conversation 属性 (仅有 conversation_id)。
    """
    # 路径 1: PyRIT 1.0.1 原生 AttackResult labels
    try:
        ar_labels = getattr(ar, "labels", None) or {}
        if isinstance(ar_labels, dict):
            conv_names = []
            for key, val in ar_labels.items():
                if isinstance(val, str) and ("converter" in val.lower() or "converter" in key.lower()):
                    conv_names.append(val)
            if conv_names:
                return conv_names
    except Exception:
        pass

    # 路径 2: PyRIT 原生 metadata
    try:
        metadata = getattr(ar, "metadata", None) or {}
        if isinstance(metadata, dict):
            conv_list = metadata.get("converters") or metadata.get("converter_chain")
            if conv_list and isinstance(conv_list, list):
                return [str(c) for c in conv_list]
    except Exception:
        pass

    return []


def _extract_response_from_result(ar: Any) -> str:
    """从 AttackResult 中提取目标响应摘要 (多路径回退).

    回退顺序 (R-022 PyRIT 原生优先):
      1. ar.last_response — PyRIT 1.0.1 原生 last_response 字段 (MessagePiece)
      2. ar.outcome_reason — PyRIT 1.0.1 原生结果原因

    注意: PyRIT 1.0.1 的 AttackResult 没有 conversation 属性 (仅有 conversation_id),
    对话消息需通过 CentralMemory.get_messages() 查询, 此处不做额外查询。
    """
    # 路径 1: PyRIT 1.0.1 原生 last_response 字段
    try:
        last_resp = getattr(ar, "last_response", None)
        if last_resp is not None:
            content = getattr(last_resp, "content", "") or getattr(last_resp, "original_value", "")
            if content:
                return str(content)
    except Exception:
        pass

    # 路径 2: PyRIT 1.0.1 原生 outcome_reason
    try:
        reason = getattr(ar, "outcome_reason", None)
        if reason and isinstance(reason, str) and len(reason) > 10:
            return reason
    except Exception:
        pass

    return ""
