"""
Stage 6/7: 执行后分析 + ASR 经验写回
======================================

ASR 实测 vs 学术先验对比 + 经验 ASR 持久化 + 策略建议。

三层数据架构:
  Tier 1: 学术先验 (asr_prior_registry.py, 只读)
  Tier 2: 经验 ASR (empirical_asr_store.py, JSON 持久化)  ← 本阶段写回
  Tier 3: 运行时 Q 值 (PyRIT 原生 CentralMemory, SQLite)
"""

from pipeline.context import PipelineContext
from pipeline.display import info_box, stage_header


async def run(ctx: PipelineContext) -> None:
    """执行后分析阶段 + ASR 经验写回"""
    stage_header(6, "执行后分析 + ASR 反馈", "ASR 实测 vs 先验对比 + 经验写回")

    # ASR 实测 vs 学术先验对比
    from src.scenarios.asr_strategy_display import display_post_execution
    display_post_execution(
        adaptive_result=ctx.adaptive_result,
        model_name=ctx.strategy_info.get("model_name", ctx.target_model),
    )

    # 载荷级成功/失败摘要
    _display_payload_summary(ctx)

    # 非 verbose 模式下补充展示前 5 个成功结果
    if not ctx.verbose:
        await _display_success_results(ctx)

    # L2 韧性: 从执行结果回填 Converter 健康统计
    _feed_converter_health_from_results(ctx)

    # L5 ASR 反馈回路 Tier 2: 经验 ASR 写回
    _write_empirical_asr(ctx)

    # 运行时停止策略统计
    _display_stop_stats(ctx)


def _feed_converter_health_from_results(ctx: PipelineContext) -> None:
    """
    从执行结果回填 Converter 健康统计

    Pipeline 数据流修复: ConverterHealthMonitor 在 Stage 3 初始化并注册链,
    但执行阶段（Stage 5 AdaptiveScenario 内部）无法直接调用 record_success/
    record_failure。本函数在 Stage 6 后处理阶段遍历 AttackResult, 从 identifier
    提取 converter 名称, 根据 outcome 反馈到 health_monitor。

    这样 _write_empirical_asr() 中的 get_stats() 能返回有效数据。
    """
    if ctx.converter_health_monitor is None:
        return
    if ctx.adaptive_result is None or ctx.adaptive_result.native_result is None:
        return

    native_result = ctx.adaptive_result.native_result
    if not hasattr(native_result, "get_display_groups"):
        return

    try:
        from src.scenarios.scenario_output import _extract_converters_from_identifier

        monitor = ctx.converter_health_monitor
        display_groups = native_result.get_display_groups()

        for _group_name, results in display_groups.items():
            for r in results:
                if r is None:
                    continue

                outcome = getattr(r, "outcome", None)
                outcome_str = (
                    str(outcome.value).upper()
                    if hasattr(outcome, "value")
                    else str(outcome).upper()
                )
                is_success = outcome_str == "SUCCESS"

                # 从顶层 AttackResult 提取 converter
                identifier = None
                if hasattr(r, "get_attack_strategy_identifier"):
                    try:
                        identifier = r.get_attack_strategy_identifier()
                    except Exception:
                        pass
                if identifier is not None:
                    conv_names = _extract_converters_from_identifier(identifier)
                    for cn in conv_names:
                        if is_success:
                            monitor.record_success(cn)
                        else:
                            monitor.record_failure(cn, getattr(outcome, "value", "failure"))

                # SequentialAttackResult: 遍历子结果
                child_results = getattr(r, "child_attack_results", None) or []
                for child in child_results:
                    if child is None:
                        continue
                    child_identifier = None
                    if hasattr(child, "get_attack_strategy_identifier"):
                        try:
                            child_identifier = child.get_attack_strategy_identifier()
                        except Exception:
                            pass
                    if child_identifier is not None:
                        child_conv_names = _extract_converters_from_identifier(child_identifier)
                        child_outcome = getattr(child, "outcome", None)
                        child_str = (
                            str(child_outcome.value).upper()
                            if hasattr(child_outcome, "value")
                            else str(child_outcome).upper()
                        )
                        child_success = child_str == "SUCCESS"
                        for cn in child_conv_names:
                            if child_success:
                                monitor.record_success(cn)
                            else:
                                monitor.record_failure(cn, child_str)

        # 展示 converter 健康摘要
        stats = monitor.get_stats()
        disabled = monitor.get_disabled_converters()
        if stats and any(s["attempts"] > 0 for s in stats.values()):
            health_lines = []
            for name, s in sorted(stats.items(), key=lambda x: -x[1]["attempts"]):
                if s["attempts"] == 0:
                    continue
                status = "✓ 健康" if not s["disabled"] else "✗ 熔断"
                health_lines.append(
                    f"  {name:30s} {status}  {s['successes']}/{s['attempts']} "
                    f"({s['success_rate']:.0%})"
                )
            if disabled:
                health_lines.append(f"\n  [熔断] {', '.join(disabled)}")
            if health_lines:
                info_box("Converter 健康统计", health_lines)

    except Exception as e:
        print(f"  [!] Converter 健康统计回填失败: {e}")


def _write_empirical_asr(ctx: PipelineContext) -> None:
    """
    L5 ASR 反馈回路: 将本次运行结果写回经验 ASR 存储

    融合公式:
      new_empirical = (old_empirical * old_count + new_data) / (old_count + 1)
    """
    if ctx.adaptive_result is None or ctx.adaptive_result.native_result is None:
        return

    try:
        from src.scenarios.empirical_asr_store import (
            extract_tech_stats_from_results,
            update_empirical_asr,
        )

        # 提取 per-technique 统计
        tech_stats = extract_tech_stats_from_results(
            ctx.adaptive_result.native_result,
            ctx.strategy_info.get("model_name", ctx.target_model),
        )

        if not tech_stats:
            return

        # 获取 converter 健康统计
        converter_stats = None
        if ctx.converter_health_monitor is not None:
            converter_stats = ctx.converter_health_monitor.get_stats()

        # 写回经验 ASR
        updated = update_empirical_asr(
            model_name=ctx.strategy_info.get("model_name", ctx.target_model),
            model_tier=ctx.strategy_info.get("model_tier", ctx.model_tier),
            tech_stats=tech_stats,
            converter_stats=converter_stats,
        )

        ctx.tech_stats = tech_stats

        # 展示经验 ASR 更新摘要
        run_count = updated.get("run_count", 0)
        tech_count = len(updated.get("techniques", {}))
        conv_count = len(updated.get("converter_effectiveness", {}))

        emp_lines = [
            f"模型: {updated.get('model_name', '')}",
            f"运行次数: {run_count}",
            f"技术统计: {tech_count} 个技术",
            f"Converter 统计: {conv_count} 个",
        ]

        # 展示 Top-3 经验 ASR
        emp_techs = updated.get("techniques", {})
        sorted_techs = sorted(
            emp_techs.items(),
            key=lambda x: -x[1].get("empirical_asr", 0.0),
        )[:3]
        for tech, data in sorted_techs:
            asr = data.get("empirical_asr", 0.0)
            attempts = data.get("attempts", 0)
            emp_lines.append(f"  {tech:30s} ASR={asr:.0%} ({attempts} 次)")

        # Patched 技术
        patched = ctx.patched_techniques or []
        if patched:
            emp_lines.append(f"\n[PATCHED] {len(patched)} 个技术:")
            for p in patched[:3]:
                emp_lines.append(
                    f"  {p['technique']:30s} 学术={p['academic']:.0%} → 实测={p['empirical']:.0%} "
                    f"(Δ{p['delta']:+.0%})"
                )

        info_box("ASR 经验写回 (Tier 2)", emp_lines)

    except Exception as e:
        print(f"  [!] ASR 经验写回失败: {e}")


def _display_stop_stats(ctx: PipelineContext) -> None:
    """展示运行时停止策略统计"""
    if ctx.stop_context is None:
        return
    try:
        stats = ctx.stop_context.get_stats() if hasattr(ctx.stop_context, "get_stats") else {}
        if stats and (stats.get("should_stop") or stats.get("global_success", 0) > 0):
            stop_lines = [
                f"停止原因: {stats.get('stop_reason', 'N/A')}",
                f"全局成功: {stats.get('global_success', 0)}",
            ]
            owasp_stats = stats.get("owasp_success", {})
            if owasp_stats:
                stop_lines.append("OWASP 分类成功:")
                for oid, count in sorted(owasp_stats.items()):
                    total = stats.get("owasp_total", {}).get(oid, 0)
                    stop_lines.append(f"  {oid}: {count}/{total}")
            info_box("运行时停止策略", stop_lines)
    except Exception:
        pass


async def _display_success_results(ctx: PipelineContext) -> None:
    """展示前 5 个成功结果"""
    from pyrit.output import output_attack_async, StdoutSink

    success_results = [
        r for r in ctx.batch_result.results
        if r is not None and hasattr(r, "outcome") and
        str(getattr(r.outcome, "value", r.outcome)).upper() == "SUCCESS"
    ]
    shown = 0
    for result in success_results:
        if shown >= 5:
            break
        shown += 1
        print(f"\n  --- 结果 {shown}/{min(5, len(success_results))} ---")
        try:
            await output_attack_async(
                result, format="pretty", sink=StdoutSink(),
                include_auxiliary_scores=True,
                include_adversarial_conversation=True,
            )
        except Exception as e:
            print(f"  [!] 输出结果 {shown} 时出错: {e}")

    if len(success_results) > 5:
        print(f"\n  ... 还有 {len(success_results) - 5} 个结果未显示（完整内容见日志文件）")


_W = 68


def _display_payload_summary(ctx: PipelineContext) -> None:
    """载荷级成功/失败摘要 — 每个载荷一行展示结果"""
    if ctx.adaptive_result is None or ctx.adaptive_result.native_result is None:
        return

    native_result = ctx.adaptive_result.native_result
    if not hasattr(native_result, "get_display_groups"):
        return

    display_groups = native_result.get_display_groups()
    if not display_groups:
        return

    from src.scenarios.scenario_output import _extract_result_info

    all_results = []
    for group_name, results in display_groups.items():
        for r in results:
            if r is not None:
                all_results.append(r)

    if not all_results:
        return

    lines = []
    success_count = 0
    converter_usage: dict[str, int] = {}

    for idx, r in enumerate(all_results):
        pid = f"P{idx + 1}"

        techniques: set[str] = set()
        converters: set[str] = set()
        owasp_ids: set[str] = set()
        _extract_result_info(r, techniques=techniques, converters=converters, owasp_ids=owasp_ids)

        outcome = getattr(r, "outcome", None)
        outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()
        is_success = outcome_str == "SUCCESS"
        if is_success:
            success_count += 1

        for cv in converters:
            converter_usage[cv] = converter_usage.get(cv, 0) + 1

        child_results = getattr(r, "child_attack_results", None) or []
        for child in child_results:
            if child is None:
                continue
            child_identifier = None
            if hasattr(child, "get_attack_strategy_identifier"):
                child_identifier = child.get_attack_strategy_identifier()
            if child_identifier is not None:
                from src.scenarios.scenario_output import _extract_converters_from_identifier
                child_conv_names = _extract_converters_from_identifier(child_identifier)
                for cv in child_conv_names:
                    converter_usage[cv] = converter_usage.get(cv, 0) + 1

        status = "✅ 成功" if is_success else "❌ 失败"
        tech = ", ".join(sorted(techniques)) if techniques else "(unknown)"
        owasp = ", ".join(sorted(owasp_ids)) if owasp_ids else "?"

        if converters:
            conv_str = ", ".join(sorted(converters)[:2])
        elif child_results:
            success_conv = ""
            for child in child_results:
                child_outcome = getattr(child, "outcome", None)
                if child_outcome is not None:
                    child_str = str(child_outcome.value).upper() if hasattr(child_outcome, "value") else str(child_outcome).upper()
                    if child_str == "SUCCESS":
                        child_identifier = None
                        if hasattr(child, "get_attack_strategy_identifier"):
                            child_identifier = child.get_attack_strategy_identifier()
                        child_name = getattr(child_identifier, "unique_name", "") if child_identifier else ""
                        if "+" in child_name:
                            success_conv = child_name.split("+", 1)[1]
                        break
            conv_str = f"变体 {success_conv}" if success_conv else f"{len(child_results)} 次尝试均失败"
        else:
            conv_str = "基线无变换"

        lines.append(f"{pid} [{owasp}] {tech:30s} {status}  ↳ {conv_str}")

    best_converter = ""
    if converter_usage:
        best_converter = max(converter_usage, key=converter_usage.get)

    total = len(all_results)
    rate = success_count / total if total > 0 else 0.0

    info_box("载荷级摘要", [
        *lines,
        "",
        f"成功: {success_count}/{total} ({rate:.0%})  |  最有效Converter: {best_converter or 'N/A'}",
    ])
