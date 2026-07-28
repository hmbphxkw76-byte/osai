"""
Stage 7/8: 执行后分析
====================

ASR 实测 vs 学术先验对比 + 成功结果展示 + ASR 先验写回。
"""

from pipeline.context import PipelineContext
from pipeline.display import info_box, stage_header


async def run(ctx: PipelineContext) -> None:
    """执行后分析阶段"""
    stage_header(7, "执行后分析", "ASR 实测 vs 先验 + 先验写回")

    # ASR 实测 vs 学术先验对比
    from src.scenarios.asr_strategy_display import display_post_execution
    display_post_execution(
        adaptive_result=ctx.adaptive_result,
        model_name=ctx.strategy_info.get("model_name", ctx.target_model),
    )

    # 非 verbose 模式下补充展示前 5 个成功结果
    if not ctx.verbose:
        await _display_success_results(ctx)

    # ASR 先验写回
    _writeback_empirical_asr(ctx)


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


def _writeback_empirical_asr(ctx: PipelineContext) -> None:
    """ASR 先验写回"""
    try:
        from src.payloads.asr_prior_registry import batch_update_empirical_asr

        empirical_map: dict = {}
        tech_stats: dict = {}
        for r in ctx.batch_result.results:
            if r is None:
                continue
            tech = _extract_technique(r)
            if not tech:
                continue
            if tech not in tech_stats:
                tech_stats[tech] = {"success": 0, "total": 0}
            tech_stats[tech]["total"] += 1
            outcome = getattr(r, "outcome", None)
            if outcome is not None:
                outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()
                if outcome_str == "SUCCESS":
                    tech_stats[tech]["success"] += 1

        for tech, stats in tech_stats.items():
            if stats["total"] > 0:
                empirical_map[tech] = {
                    "success": float(stats["success"]),
                    "total": float(stats["total"]),
                    "asr": stats["success"] / stats["total"],
                }

        if empirical_map:
            asr_model = ctx.strategy_info.get("model_name", ctx.target_model)
            batch_update_empirical_asr(empirical_map, asr_model)
            info_box("ASR 先验写回", [
                f"更新: {len(empirical_map)} 个技术实测数据 → asr_prior_registry",
                f"模型: {asr_model}",
            ])
    except Exception:
        pass


def _extract_technique(result: any) -> str:
    """从 AttackResult 提取技术名"""
    identifier = getattr(result, "identifier", None)
    if identifier is None and hasattr(result, "get_attack_strategy_identifier"):
        try:
            identifier = result.get_attack_strategy_identifier()
        except Exception:
            pass
    if identifier:
        tech = getattr(identifier, "attack_technique", "")
        if tech:
            return tech
        children = getattr(identifier, "children", {}) or {}
        return children.get("attack_technique", "")
    return ""
