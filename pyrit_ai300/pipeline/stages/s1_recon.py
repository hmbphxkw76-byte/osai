"""
Stage 1/8: Recon 侦察层
=======================

端点发现 + AI类型识别 + 模型分层。
委托 ReconEngine 执行，展示探针详情和能力信息。
"""

from pipeline.context import PipelineContext
from pipeline.display import info_box
from src.recon import recon_target


async def run(ctx: PipelineContext) -> bool:
    """执行侦察阶段。返回 False 表示不可攻击，应终止 pipeline。"""
    from pipeline.display import stage_header
    stage_header(1, "Recon 侦察层", "端点发现 + AI类型识别 + 模型分层")

    ctx.recon_result = await recon_target(
        ctx.target_url, api_key=ctx.target_api_key, model_name=ctx.target_model
    )

    # 基本信息展示
    endpoint_display = ctx.recon_result.detected_endpoint
    type_labels = {
        "openai_chat": "OpenAI Chat Completions API",
        "openai_responses": "OpenAI Responses API",
        "litellm": "LiteLLM Proxy",
        "http_api": "HTTP API",
        "azure_ml": "Azure ML",
    }
    api_label = type_labels.get(ctx.recon_result.target_type, ctx.recon_result.target_type)
    if ctx.recon_result.target_type:
        endpoint_display = f"{ctx.recon_result.detected_endpoint} ({api_label})"
    print(f"  检测端点:     {endpoint_display}")
    print(f"  认证类型:     {ctx.recon_result.auth_type.value.replace('_', ' ').title()}")
    print(f"  AI系统类型:   {ctx.recon_result.ai_system_type.value}")

    # 检查是否为 PyRIT 可攻击类型
    if not ctx.recon_result.ai_system_type.is_pyrit_attackable():
        print(f"\n  [!] 该类型 ({ctx.recon_result.ai_system_type.value}) 非提示词攻击领域")
        print(f"  [!] 推荐外部工具: {', '.join(ctx.recon_result.external_tools or [])}")
        print("\n  跳过 PyRIT 攻击")
        return False

    # 同步到 ctx
    ctx.model_tier = ctx.recon_result.model_tier
    ctx.target_type = ctx.recon_result.target_type

    # 模型分层 + 探针详情
    tier_labels = {
        "strong": "强内容过滤", "moderate": "中等内容过滤",
        "weak": "弱内容过滤", "unknown": "未知过滤强度",
    }
    tier_desc = tier_labels.get(ctx.model_tier, ctx.model_tier)
    probe_detail = getattr(ctx.recon_result, "model_tier_probe_detail", None)
    probe_lines = [f"分层: {ctx.model_tier} ({tier_desc})"]

    if probe_detail:
        probe_lines.append("探测: 动态探针 (3-step gradient probe)")
        _add_probe_result(probe_lines, probe_detail, ctx.model_tier)
    elif ctx.model_tier != "unknown":
        probe_lines.append("探测: 静态模型名推断")
        _add_tier_inference(probe_lines, ctx.model_tier)

    info_box("模型分层", probe_lines)

    # 能力信息
    caps = getattr(ctx.recon_result, "capabilities", None)
    cap_lines = []
    if caps:
        mt = "✓" if getattr(caps, "supports_multi_turn", False) else "✗"
        sp = "✓" if getattr(caps, "supports_system_prompt", False) else "✗"
        jo = "✓" if getattr(caps, "supports_json_output", False) else "✗"
        cap_lines.append(f"MULTI_TURN: {mt}  SYSTEM_PROMPT: {sp}  JSON_OUTPUT: {jo}")
    else:
        cap_lines.append("能力: 未探测 (运行时由 TargetFactory 探测)")

    # 传递到分析阶段
    pass_lines = [
        f"• target_type: {ctx.target_type or 'unknown'} → Target 分组选择",
        f"• model_tier: {ctx.model_tier} → 策略模式推荐",
    ]
    if caps and getattr(caps, "supports_multi_turn", False):
        pass_lines.append("• capabilities: MULTI_TURN ✓ → 多轮技术可用")
    else:
        pass_lines.append("• capabilities: MULTI_TURN ? → 运行时探测确认")
    info_box("传递到分析阶段", pass_lines)

    return True


def _add_probe_result(lines: list, detail: dict, tier: str) -> None:
    """添加探针结果到展示行"""
    benign = detail.get("benign", {})
    borderline = detail.get("borderline", {})
    jailbreak = detail.get("jailbreak", {})

    benign_str = "✓ 正常响应" if benign.get("success") else "✗ 无响应"
    if benign.get("error"):
        benign_str += f" ({benign['error']})"
    lines.append(f"  • Benign:     {benign_str}")

    if borderline.get("refused"):
        lines.append("  • Borderline: ✗ 被拒绝 (内容过滤触发)")
    elif borderline.get("success"):
        lines.append("  • Borderline: ✓ 正常响应 (边界内容未拦截)")
    else:
        lines.append("  • Borderline: ? 无响应")

    if jailbreak.get("refused"):
        lines.append("  • Jailbreak:  ✗ 被拒绝 (对齐防护生效)")
    elif jailbreak.get("success"):
        lines.append("  • Jailbreak:  ✓ 未拒绝 (对齐防护可绕过)")
    else:
        lines.append("  • Jailbreak:  ? 无响应")

    _add_tier_inference(lines, tier)


def _add_tier_inference(lines: list, tier: str) -> None:
    """添加分层推论"""
    inferences = {
        "strong": "推论: 策略攻击优先 → 编码攻击低效",
        "moderate": "推论: 策略+编码交替 → 编码攻击可能部分有效",
        "weak": "推论: 编码攻击也可生效 → 快速验证优先",
    }
    if tier in inferences:
        lines.append(inferences[tier])
