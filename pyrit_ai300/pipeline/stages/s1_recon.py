"""
Stage 1/7: Recon 侦察层
=======================

端点发现 + AI类型识别 + 模型分层。
委托 ReconEngine 执行，展示探针详情和能力信息。

韧性设计 (v8.2):
  - 目标不可达时立即中断 (fail-fast)，避免后续 6 个阶段全部白跑
  - 认证/HTTP 错误时交互式确认，让用户决定是否继续
"""

import sys

from pipeline.context import PipelineContext
from pipeline.display import info_box
from src.recon import recon_target


# 网络不可达错误关键词（检测 benign 探针 error 字段）
_NETWORK_ERROR_KEYWORDS = [
    "cannot connect", "connection refused", "connection reset",
    "timed out", "timeout",
    "name resolution", "dns", "name or service not known",
    "network is unreachable", "host unreachable", "no route to host",
    "errno 10061", "errno 10060", "errno 111", "errno 113",
    "ssl:default",
    "remotedisconnected",
]


def _is_network_error(error_str: str) -> bool:
    """检查错误是否为网络不可达（而非 HTTP 错误或模型拒绝）"""
    error_lower = error_str.lower()
    return any(kw in error_lower for kw in _NETWORK_ERROR_KEYWORDS)


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

    # ── 韧性检查: 目标不可达时立即中断 (fail-fast) ──
    # benign 探针是控制探针 ("What is the capital of France?")
    # 如果连这个都无法响应，说明目标不可达，后续阶段将全部失败
    if probe_detail:
        benign_result = probe_detail.get("benign", {})
        if not benign_result.get("success") and benign_result.get("error"):
            error_str = benign_result["error"]
            if _is_network_error(error_str):
                # 网络不可达 → 立即中断
                print(f"\n  [FATAL] 目标不可达: {error_str}")
                print(f"  [FATAL] 目标端点: {ctx.target_url}")
                print("  [FATAL] 后续 6 个阶段将全部失败，已中断 pipeline。")
                print("  [FATAL] 请检查:")
                print("          1. 目标服务是否已启动")
                print("          2. 端点地址是否正确 (TARGET_ENDPOINT)")
                print("          3. 网络连接是否通畅 (防火墙/VPN)")
                return False
            else:
                # HTTP 错误 (401/403/500 等) → 目标可达但有问题 → 交互式确认
                _is_interactive = sys.stdin.isatty() if hasattr(sys.stdin, "isatty") else False
                print(f"\n  [WARNING] 探针返回错误: {error_str}")
                print(f"  [WARNING] 目标端点: {ctx.target_url}")
                if "401" in error_str or "403" in error_str:
                    print("  [WARNING] 认证失败 — 检查 TARGET_API_KEY 是否正确")
                elif "404" in error_str:
                    print("  [WARNING] 端点不存在 — 检查 TARGET_ENDPOINT 路径")
                elif "500" in error_str or "502" in error_str or "503" in error_str:
                    print("  [WARNING] 服务端错误 — 目标可能暂时不可用")
                print("  [WARNING] 后续攻击可能失败。")

                if _is_interactive:
                    try:
                        choice = input("\n  是否继续执行? (y/N): ").strip().lower()
                    except (EOFError, KeyboardInterrupt):
                        choice = "n"
                    if choice not in ("y", "yes"):
                        print("  已取消执行。")
                        return False
                    print("  继续执行 (用户确认)...")
                else:
                    # 非交互模式 (CI/CD) → 直接中断
                    print("  [FATAL] 非交互模式，自动中断。")
                    return False

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
    info_box("传递到 Strategy 策略层 (Stage 2)", pass_lines)

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
