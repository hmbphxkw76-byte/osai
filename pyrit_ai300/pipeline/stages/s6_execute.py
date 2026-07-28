"""
Stage 6/8: Executor 执行层
=========================

原生 AdaptiveScenario 批量执行。
"""

import os

from pipeline.context import PipelineContext
from pipeline.display import info_box, stage_header


async def run(ctx: PipelineContext) -> bool:
    """执行攻击阶段。返回 False 表示执行失败不可恢复。"""
    stage_header(6, "Executor 执行层", "原生 AdaptiveScenario 批量执行")

    # 执行配置
    ctx.max_concurrency = ctx.config_loader.get_pipeline_max_concurrency()
    ctx.per_attack_timeout = ctx.config_loader.get_pipeline_per_attack_timeout()
    ctx.timeout_overrides = ctx.config_loader.get_pipeline_timeout_overrides()
    ctx.adaptive_max_concurrency = int(os.getenv("ADAPTIVE_MAX_CONCURRENCY", "4"))

    config_lines = [f"最大并发: {ctx.max_concurrency}"]
    if ctx.timeout_overrides:
        override_str = ", ".join(f"{k}={v}s" for k, v in ctx.timeout_overrides.items())
        config_lines.append(f"差异化超时: {override_str}  (默认: {ctx.per_attack_timeout}s)")
    else:
        config_lines.append(f"单次超时: {ctx.per_attack_timeout}s")
    config_lines.append(f"原生并发: {ctx.adaptive_max_concurrency} (API 级限速: {ctx.api_max_concurrent})")
    config_lines.append("执行模式: 原生 AdaptiveScenario (L5 统一路径, Converter 变体)")
    info_box("执行配置", config_lines)

    # 执行前提示
    _exec_model = ctx.strategy_info.get("model_name", ctx.target_model)
    _exec_mode = ctx.strategy_info.get("strategy_mode", "academic")
    print(f"\n  [ASR引导策略] 正在以 {_exec_mode} 策略对 {_exec_model} 发起攻击...")
    print("  [ASR引导策略] 原生 AdaptiveScenario: 技术选择 → Converter路由 → 执行 → 失败路由 → 升级")
    print(f"  [OK] 开始执行 {len(ctx.attack_plans)} 个攻击计划...\n")

    from src.scenarios.adaptive_runner import run_adaptive_scenario_async

    ctx.adaptive_result = await run_adaptive_scenario_async(
        objective_target=ctx.objective_target,
        judge_target=ctx.judge_target,
        attack_plans=ctx.attack_plans,
        owasp_id=",".join(ctx.config_owasp_ids) if ctx.config_owasp_ids else "",
        exam_id=ctx.exam_id,
        max_attempts_per_objective=3,
        per_attack_timeout=ctx.per_attack_timeout,
        max_retries=ctx.scenario_max_retries,
        verbose=ctx.verbose,
        converter_target=ctx.converter_target,
        target_type=ctx.target_type,
        max_concurrency=ctx.adaptive_max_concurrency,
        strategy_mode=ctx.strategy_info.get("strategy_mode", "academic"),
        model_name=ctx.strategy_info.get("model_name", ctx.target_model),
        model_tier=ctx.strategy_info.get("model_tier", ctx.model_tier),
    )
    ctx.batch_result = ctx.adaptive_result.batch_result

    # 执行结果概要
    result_lines = [
        f"总计划: {ctx.batch_result.total_plans}",
        f"已执行: {ctx.batch_result.executed} | 成功: {ctx.batch_result.succeeded} | "
        f"失败: {ctx.batch_result.failed} | 错误: {ctx.batch_result.errored}",
        f"成功率: {ctx.batch_result.success_rate * 100:.1f}%",
        f"执行时间: {ctx.adaptive_result.execution_time:.1f}s",
        f"Converter 变体使用: {ctx.adaptive_result.converter_variants_used} 次",
    ]
    if ctx.batch_result.upgrade_attempts > 0:
        result_lines.append(
            f"升级重试: {ctx.batch_result.upgrade_attempts} 次, "
            f"成功 {ctx.batch_result.upgrade_success} 次"
        )
    if ctx.adaptive_result.failure_type_distribution:
        result_lines.append(f"失败类型分布: {ctx.adaptive_result.failure_type_distribution}")
        if ctx.adaptive_result.most_common_failure_type:
            result_lines.append(f"最常见失败类型: {ctx.adaptive_result.most_common_failure_type}")
    info_box("执行结果", result_lines)

    # Per-Group Breakdown
    if ctx.adaptive_result.native_result is not None:
        try:
            from src.scenarios.scenario_output import display_enhanced_group_breakdown
            display_enhanced_group_breakdown(
                ctx.adaptive_result.native_result,
                owasp_id=",".join(ctx.config_owasp_ids) if ctx.config_owasp_ids else "",
            )
        except Exception as e:
            print(f"  [!] Per-Group Breakdown 输出失败: {e}")

    # L5: 执行后清理
    try:
        from src.executor import reset_executor
        reset_executor()
    except Exception:
        pass

    # 错误详情
    if ctx.batch_result.errors:
        print(f"\n  [!] 错误详情 ({len(ctx.batch_result.errors)} 个):")
        for err in ctx.batch_result.errors[:5]:
            print(f"    - {err.get('plan_id', 'N/A')}: {err.get('error', 'N/A')}")
        if len(ctx.batch_result.errors) > 5:
            print(f"    ... 还有 {len(ctx.batch_result.errors) - 5} 个错误")

    return True
