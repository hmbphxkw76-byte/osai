"""
Stage 5/8: Target/Converter 自适应匹配
======================================

Target 感知 Converter 路由 + 技术执行顺序排序 + 失败类型路由策略展示。
"""

from pipeline.context import PipelineContext
from pipeline.display import info_box, stage_header


async def run(ctx: PipelineContext) -> None:
    """执行自适应匹配阶段"""
    stage_header(5, "Target/Converter 自适应匹配", "智能路由 + 组合评估")

    # ── 5a: Target 感知 Converter 路由 ──
    try:
        from src.converters.target_aware_router import select_converter_chains_for_target
        ctx.converter_chains = select_converter_chains_for_target(
            ctx.target_type,
            converter_target_available=(ctx.converter_target is not None),
        )
        chain_lines = [
            f"target_group: {ctx.target_group}",
            f"bypass: {ctx.bypass_mechanism}",
            f"推荐链 ({len(ctx.converter_chains)} 条):",
        ]
        for i, chain in enumerate(ctx.converter_chains[:8]):
            chain_lines.append(f"  {i+1}. {chain}")
        if len(ctx.converter_chains) > 8:
            chain_lines.append(f"  ... 还有 {len(ctx.converter_chains) - 8} 条")
        info_box("5a. Target 感知 Converter 路由", chain_lines)
    except Exception:
        pass

    # ── 5b: 技术执行顺序 (按 ASR 排序) ──
    try:
        from src.payloads.technique_name_mapper import get_normalized_asr
        from src.scenarios.asr_strategy_display import _get_tier

        model_name = ctx.strategy_info.get("model_name", ctx.target_model)
        strategy_mode = ctx.strategy_info.get("strategy_mode", "academic")

        tech_list = []
        seen = set()
        for plan in ctx.attack_plans:
            tech = getattr(plan, "attack_technique", "")
            if tech and tech not in seen:
                seen.add(tech)
                asr = get_normalized_asr(tech, model_name)
                tech_list.append((tech, asr, _get_tier(asr)))

        if tech_list:
            if strategy_mode == "exam":
                tech_list.sort(key=lambda x: x[1])
            else:
                tech_list.sort(key=lambda x: -x[1])

            exec_lines = [f"技术执行顺序 ({len(tech_list)} 技术, 策略={strategy_mode}):"]
            for i, (tech, asr, tier) in enumerate(tech_list[:10]):
                bar_len = int(asr * 20)
                bar = "█" * bar_len + "░" * (20 - bar_len)
                exec_lines.append(f"  {i+1}. [{tier}] {tech:36s} {asr:5.0%} {bar}")
            info_box("5b. 技术执行顺序", exec_lines)
    except Exception:
        pass

    # ── 5c: 失败类型路由策略 ──
    info_box("5c. 失败类型路由策略", [
        "model_refusal     → 策略升级 (Tier S/A 优先)",
        "timeout           → 降级单轮 (prompt_sending)",
        "scorer_error      → 换技术 (跳过当前)",
        "objective_failed  → 强技术+Converter 变体",
    ])

    # 传递到 Executor
    pass_exec = [
        f"• 变体池: {len(ctx.converter_chains)} 条 Converter 链",
    ]
    # 列出每条 Converter 链的名称和描述
    try:
        from src.scenarios.technique_factories import CONVERTER_VARIANT_CHAINS
        for i, chain in enumerate(ctx.converter_chains[:8]):
            _info = CONVERTER_VARIANT_CHAINS.get(chain, {})
            _desc = _info.get("description", "")
            _llm = " (LLM)" if _info.get("requires_llm") else ""
            pass_exec.append(f"  {i+1}. {chain}{_llm} — {_desc}")
        if len(ctx.converter_chains) > 8:
            pass_exec.append(f"  ... 还有 {len(ctx.converter_chains) - 8} 条")
    except Exception:
        for i, chain in enumerate(ctx.converter_chains[:8]):
            pass_exec.append(f"  {i+1}. {chain}")
    pass_exec.append(f"• 执行顺序: 按策略 {ctx.strategy_info.get('strategy_mode', 'academic')} 排序")
    pass_exec.append("• 失败路由: 4 种 → 自动降级/升级")
    pass_exec.append("• 变体组合 = Target 路由推荐链 × attack_plans 技术 (extra_request_converters)")
    info_box("传递到 Executor", pass_exec)
