"""
Stage 2/8: Analysis 分析层
==========================

策略选择 + 优先级评估 + ASR引导策略分析。
"""

from pipeline.context import PipelineContext
from pipeline.display import info_box, stage_header
from src.core.models import AuthResult, AuthStatus, AuthType
from src.analysis import select_strategy, evaluate_priority
from src.analysis.strategy_selector import StrategySelector


async def run(ctx: PipelineContext) -> None:
    """执行分析阶段"""
    stage_header(2, "Analysis 分析层", "策略选择 + 优先级评估")

    ctx.auth_result = AuthResult(
        target_url=ctx.target_url,
        auth_type=AuthType.NONE,
        status=AuthStatus.SUCCESS,
        auth_headers={"Content-Type": "application/json"},
    )

    ctx.strategy_selection = select_strategy(ctx.auth_result, ctx.recon_result)
    ctx.recommended_mode = StrategySelector.recommend_strategy_mode(ctx.recon_result)
    ctx.priority_score = evaluate_priority(ctx.recon_result)

    # ASR策略: 策略分析展示
    from src.scenarios.asr_strategy_display import display_analysis_stage
    ctx.strategy_info = display_analysis_stage(
        target_model=ctx.target_model, recon_result=ctx.recon_result
    )

    # 策略分析盒子
    tech_str = ", ".join(ctx.strategy_selection.attack_techniques[:6])
    if len(ctx.strategy_selection.attack_techniques) > 6:
        tech_str += f" ... (+{len(ctx.strategy_selection.attack_techniques) - 6})"

    tier_labels = {
        "strong": "强内容过滤", "moderate": "中等内容过滤",
        "weak": "弱内容过滤", "unknown": "未知过滤强度",
    }
    tier_desc = tier_labels.get(ctx.model_tier, ctx.model_tier)

    analysis_lines = [
        f"Scenario:     {ctx.strategy_selection.scenario_name}",
        f"技术池:       {tech_str}",
        f"优先级:       {ctx.priority_score}/100",
        "",
        "── model_tier 驱动的策略推荐 ──",
        f"模型分层:     {ctx.model_tier} ({tier_desc})",
        f"推荐策略模式: {ctx.recommended_mode}",
    ]

    inferences = {
        "strong": "推论依据:     强过滤模型 → 策略攻击为主, 编码低效",
        "moderate": "推论依据:     中等过滤 → 策略+编码交替",
        "weak": "推论依据:     弱过滤 → 编码攻击也可生效",
    }
    analysis_lines.append(inferences.get(ctx.model_tier, "推论依据:     未知 → 默认强过滤策略"))

    info_box("策略分析", analysis_lines)

    info_box("传递到 Target 接入", [
        f"• strategy_mode: {ctx.strategy_info.get('strategy_mode', 'academic')} → 影响 Tier 执行顺序",
        f"• 技术池: {len(ctx.strategy_selection.attack_techniques)} 种 → 能力感知筛选后保留",
    ])
