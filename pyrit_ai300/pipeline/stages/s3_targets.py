"""
Stage 3/7: Target 接入 + 路由
=============================

目标创建 + 能力探测 + 分组确定 + Converter 路由。
创建 Objective/Judge/Converter 三个 Target 实例。
"""

import os

from pipeline.context import PipelineContext
from pipeline.display import info_box, stage_header
from src.targets import create_prompt_target, create_judge_target, TargetParams
from src.targets.rate_limited_target import RateLimitConfig, wrap_target_with_rate_limiting


async def run(ctx: PipelineContext) -> None:
    """执行 Target 接入阶段（含 Converter 路由决策）"""
    stage_header(3, "Target 接入 + 路由", "目标创建 + 能力探测 + Converter 路由")

    # API 级别限速配置
    ctx.api_max_concurrent = int(os.getenv("API_MAX_CONCURRENCY", "10"))
    ctx.target_rpm = int(os.getenv("TARGET_MAX_RPM")) if os.getenv("TARGET_MAX_RPM") else None
    ctx.judge_rpm = int(os.getenv("JUDGE_MAX_RPM")) if os.getenv("JUDGE_MAX_RPM") else None

    # HTTP 客户端参数（从 config/defaults/http_client.yaml 加载）
    _target_timeout = ctx.config_loader.get_target_httpx_timeout()
    _target_verify = ctx.config_loader.get_target_httpx_verify()
    _target_proxy = ctx.config_loader.get_target_httpx_proxy()
    _judge_timeout = ctx.config_loader.get_judge_httpx_timeout()
    _judge_verify = ctx.config_loader.get_judge_httpx_verify()

    # 创建 Objective Target
    # discover_capabilities=False: 关闭运行时能力探测
    # 原因：安全对齐模型（如 LongCat-2.0）对能力探针返回空响应（204），
    # 导致探测结果错误（如 supports_json_output=False），影响后续评分器。
    # 使用 OpenAIChatTarget 默认能力（全 True），通过 capability_policy="adapt"
    # 自动适配不支持的能力（如 system_prompt 不支持时 squash 到 user 消息）。
    target_params = TargetParams(
        max_requests_per_minute=ctx.target_rpm,
        capability_policy="adapt",
        discover_capabilities=False,
        httpx_timeout=float(_target_timeout),
        httpx_verify=_target_verify,
        httpx_proxy=_target_proxy,
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
        httpx_timeout=float(_judge_timeout),
        httpx_verify=_judge_verify,
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
    # 始终创建独立的 Converter Target（不复用 objective target）
    # 原因：objective target 的运行时能力探测（discover_target_capabilities_async）
    # 可能错误地将 supports_json_output 设为 False（探针请求失败时），
    # 而 PyRIT Converter（DecompositionConverter/PersuasionConverter 等）
    # 需要 supports_json_output=True 才能正常工作。
    # 独立创建时关闭能力探测（discover_capabilities=False），
    # 使用 OpenAIChatTarget 默认能力（supports_json_output=True）。
    converter_endpoint = os.getenv("CONVERTER_ENDPOINT", ctx.target_endpoint)
    ctx.converter_model = os.getenv("CONVERTER_MODEL", ctx.target_model)
    converter_api_key = os.getenv("CONVERTER_API_KEY", ctx.target_api_key)
    converter_rpm = os.getenv("CONVERTER_MAX_RPM")
    converter_rpm = int(converter_rpm) if converter_rpm else None

    converter_params = TargetParams(
        temperature=0.7,
        discover_capabilities=False,
        max_requests_per_minute=converter_rpm,
        httpx_timeout=float(_target_timeout),
        httpx_verify=_target_verify,
        httpx_proxy=_target_proxy,
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
    _conv_class = type(ctx.converter_target).__name__
    _obj_class = type(ctx.objective_target).__name__
    if _conv_class == _obj_class and converter_endpoint == ctx.target_endpoint:
        ctx.converter_target_display = f"{_conv_class} ({ctx.converter_model}) ← 独立实例 (避免能力探测干扰)"
    else:
        ctx.converter_target_display = f"{_conv_class} ({ctx.converter_model})"

    # ── Target 感知 Converter 路由决策 ──
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
        info_box("Converter 路由决策", chain_lines)
    except Exception:
        pass

    # L2 韧性: 初始化 Converter 健康监控器
    from src.scenarios.converter_health_monitor import ConverterHealthMonitor
    ctx.converter_health_monitor = ConverterHealthMonitor()
    # 预注册所有推荐链
    for chain_name in ctx.converter_chains:
        ctx.converter_health_monitor.register(chain_name)

    # 展示
    _display_targets(ctx)

    # 传递到 Datasets
    pass_ds = [
        f"• target_group: {ctx.target_group} → 载荷预筛选",
        f"• bypass_mechanism: {ctx.bypass_mechanism} → Converter 选择依据",
        f"• converter_chains: {len(ctx.converter_chains)} 条 → 变体池已就绪",
    ]
    if ctx.model_tier == "weak":
        pass_ds.append("• skip_llm_chains: True → 变体池不含 LLM 变体")
    else:
        pass_ds.append("• skip_llm_chains: False → 变体池含 LLM 变体")
    # 载荷可用性（从侦察结果获取能力信息）
    _recon_caps = getattr(ctx.recon_result, "capabilities", None)
    if _recon_caps and getattr(_recon_caps, "supports_multi_turn", False):
        pass_ds.append("• 载荷能力: MULTI_TURN ✓ → 多轮载荷可用")
    else:
        pass_ds.append("• 载荷能力: MULTI_TURN ? → 运行时探测确认")
    pass_ds.append("• 载荷模式: single_turn + multi_turn 均可")
    info_box("传递到 Datasets 载荷端 (Stage 4)", pass_ds)


def _display_targets(ctx: PipelineContext) -> None:
    """展示三个 Target 的信息"""
    obj_lines = [
        f"类型:     {type(ctx.objective_target).__name__} ({ctx.target_type})",
        f"分组:     {ctx.target_group}  ← 驱动 Converter 路由",
        f"模型:     {ctx.target_model}",
        f"安全机制: {ctx.bypass_mechanism}",
    ]
    # 优先使用 Target 运行时探测的能力（比静态模型档案更准确）
    caps = None
    try:
        caps = getattr(ctx.objective_target, "capabilities", None)
    except Exception:
        pass
    if caps is None:
        # 回退到侦察静态查询
        caps = getattr(ctx.recon_result, "capabilities", None)
    if caps:
        mt = "✓" if getattr(caps, "supports_multi_turn", False) else "✗"
        sp = "✓" if getattr(caps, "supports_system_prompt", False) else "✗"
        obj_lines.append(f"能力:     MULTI_TURN {mt}, SYSTEM_PROMPT {sp}")
    if ctx.target_rpm:
        obj_lines.append(f"RPM限速:  {ctx.target_rpm} req/min")
    info_box("被测目标 (Objective Target)", obj_lines)

    info_box("评分器目标 (Judge Target)", [
        f"模型: {ctx.judge_model} | temperature={ctx.config_loader.get_judge_temperature()}",
        "用途: objective scoring 仅",
    ])

    conv_lines = [
        f"模型: {ctx.converter_target_display}",
        f"分层: {ctx.model_tier} → LLM辅助链: "
        f"{'✓ 保留' if ctx.model_tier != 'weak' else '✗ 跳过 (弱过滤模型避免 500)'}",
    ]
    info_box("转换器目标 (Converter Target)", conv_lines)
