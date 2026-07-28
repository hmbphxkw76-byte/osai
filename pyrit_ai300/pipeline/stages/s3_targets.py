"""
Stage 3/8: Target 接入层
========================

目标创建 + 能力探测 + 分组确定。
创建 Objective/Judge/Converter 三个 Target 实例。
"""

import os

from pipeline.context import PipelineContext
from pipeline.display import info_box, stage_header
from src.targets import create_prompt_target, create_judge_target, TargetParams
from src.targets.rate_limited_target import RateLimitConfig, wrap_target_with_rate_limiting


async def run(ctx: PipelineContext) -> None:
    """执行 Target 接入阶段"""
    stage_header(3, "Target 接入层", "目标创建 + 能力探测 + 分组确定")

    # API 级别限速配置
    ctx.api_max_concurrent = int(os.getenv("API_MAX_CONCURRENCY", "10"))
    ctx.target_rpm = int(os.getenv("TARGET_MAX_RPM")) if os.getenv("TARGET_MAX_RPM") else None
    ctx.judge_rpm = int(os.getenv("JUDGE_MAX_RPM")) if os.getenv("JUDGE_MAX_RPM") else None

    # 创建 Objective Target
    target_params = TargetParams(
        max_requests_per_minute=ctx.target_rpm,
        capability_policy="adapt",
    )
    ctx.objective_target, ctx.target_type = await create_prompt_target(
        target_url=ctx.target_url,
        api_key=ctx.target_api_key,
        model_name=ctx.target_model,
        params=target_params,
    )
    ctx.objective_target = wrap_target_with_rate_limiting(
        ctx.objective_target,
        config=RateLimitConfig(max_concurrent_requests=ctx.api_max_concurrent),
        semaphore_key=f"objective:{ctx.target_endpoint}",
    )

    # 获取 target_group
    try:
        from src.converters.target_aware_router import get_target_group, get_target_converter_profile
        ctx.target_group = get_target_group(ctx.target_type)
        _profile = get_target_converter_profile(ctx.target_type)
        ctx.bypass_mechanism = _profile.get("bypass_mechanism", "unknown")
    except Exception:
        pass

    # 创建 Judge Target
    judge_params = TargetParams(
        temperature=ctx.config_loader.get_judge_temperature(),
        top_p=ctx.config_loader.get_judge_top_p(),
        force_json_output=ctx.config_loader.get_judge_force_json_output(),
        discover_capabilities=False,
        max_requests_per_minute=ctx.judge_rpm,
    )
    ctx.judge_target, _ = await create_judge_target(
        judge_url=ctx.judge_endpoint,
        api_key=ctx.judge_api_key,
        model_name=ctx.judge_model,
        params=judge_params,
    )
    ctx.judge_target = wrap_target_with_rate_limiting(
        ctx.judge_target,
        config=RateLimitConfig(max_concurrent_requests=ctx.api_max_concurrent),
        semaphore_key=f"judge:{ctx.judge_endpoint}",
    )

    # 创建 Converter Target
    converter_endpoint = os.getenv("CONVERTER_ENDPOINT", ctx.target_endpoint)
    ctx.converter_model = os.getenv("CONVERTER_MODEL", ctx.target_model)
    converter_api_key = os.getenv("CONVERTER_API_KEY", ctx.target_api_key)
    converter_rpm = os.getenv("CONVERTER_MAX_RPM")
    converter_rpm = int(converter_rpm) if converter_rpm else None

    if converter_endpoint == ctx.target_endpoint and ctx.converter_model == ctx.target_model:
        ctx.converter_target = ctx.objective_target
        ctx.converter_target_display = f"复用目标模型 ({ctx.converter_model})"
    else:
        converter_params = TargetParams(
            temperature=0.7,
            discover_capabilities=False,
            max_requests_per_minute=converter_rpm,
        )
        ctx.converter_target, _ = await create_prompt_target(
            target_url=converter_endpoint,
            api_key=converter_api_key,
            model_name=ctx.converter_model,
            params=converter_params,
        )
        ctx.converter_target = wrap_target_with_rate_limiting(
            ctx.converter_target,
            config=RateLimitConfig(max_concurrent_requests=ctx.api_max_concurrent),
            semaphore_key=f"converter:{converter_endpoint}",
        )
        ctx.converter_target_display = f"{type(ctx.converter_target).__name__} ({ctx.converter_model})"

    # 展示
    _display_targets(ctx)

    # 传递到 Datasets
    pass_ds = [
        f"• target_group: {ctx.target_group} → 载荷预筛选",
        f"• bypass_mechanism: {ctx.bypass_mechanism} → Converter 选择依据",
    ]
    if ctx.model_tier == "weak":
        pass_ds.append("• skip_llm_chains: True → 变体池不含 LLM 变体")
    else:
        pass_ds.append("• skip_llm_chains: False → 变体池含 LLM 变体")
    info_box("传递到 Datasets", pass_ds)


def _display_targets(ctx: PipelineContext) -> None:
    """展示三个 Target 的信息"""
    obj_lines = [
        f"类型:     {type(ctx.objective_target).__name__} ({ctx.target_type})",
        f"分组:     {ctx.target_group}  ← 驱动 Converter 路由",
        f"模型:     {ctx.target_model}",
        f"安全机制: {ctx.bypass_mechanism}",
    ]
    caps = getattr(ctx.recon_result, "capabilities", None)
    if caps:
        mt = "✓" if getattr(caps, "supports_multi_turn", False) else "✗"
        sp = "✓" if getattr(caps, "supports_system_prompt", False) else "✗"
        obj_lines.append(f"能力:     MULTI_TURN {mt}, SYSTEM_PROMPT {sp}")
    if ctx.target_rpm:
        obj_lines.append(f"RPM限速:  {ctx.target_rpm} req/min")
    info_box("Objective Target", obj_lines)

    info_box("Judge Target", [
        f"模型: {ctx.judge_model} | temperature={ctx.config_loader.get_judge_temperature()}",
        "用途: objective scoring 仅",
    ])

    conv_lines = [
        f"模型: {ctx.converter_target_display}",
        f"分层: {ctx.model_tier} → LLM辅助链: "
        f"{'✓ 保留' if ctx.model_tier != 'weak' else '✗ 跳过 (弱过滤模型避免 500)'}",
    ]
    info_box("Converter Target", conv_lines)
