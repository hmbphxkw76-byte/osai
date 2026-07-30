"""
Stage 1/7: Recon 侦察层
=======================

端点发现 + AI类型识别 + 模型分层。
委托 ReconEngine 执行，展示探针详情和能力信息。

显示架构 (v8.0 优化 — 载荷驱动 + 高 ASR 导向):
  ① 端点探测 + AI类型识别        — 合并旧散列 print，卡片化展示
  ② ★ 模型分层 + 探针详情 ★     — 探针结果 + 能力信息 + 分层推论
  ③ ★ 传递到 Strategy 策略层 ★  — 最终结果摘要（决定后续攻击策略）

设计原则:
  - 以目标能力为驱动：探针结果决定策略模式和技术池
  - 高 ASR 导向：模型分层直接影响攻击技术选择（strong → 策略优先, weak → 编码也可）
  - 参照 executor 卡片风格：┏━ 粗线框 + ◆ 技术头 + ┌─ 子区域 + ①②③ 编号
  - 传递结果突出展示：target_type + model_tier + capabilities 决定后续攻击成功率

韧性设计 (v8.2):
  - 目标不可达时立即中断 (fail-fast)，避免后续 6 个阶段全部白跑
  - 认证/HTTP 错误时交互式确认，让用户决定是否继续
"""

import sys

from pipeline.context import PipelineContext
from pipeline.display import stage_header
from src.recon import recon_target

# ── 统一卡片宽度（双线框，与 executor/Stage 2/3/4 一致） ──
_W = 68

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

_TYPE_LABELS = {
    "openai_chat": "OpenAI Chat Completions API",
    "openai_responses": "OpenAI Responses API",
    "litellm": "LiteLLM Proxy",
    "http_api": "HTTP API",
    "azure_ml": "Azure ML",
}

_TIER_LABELS = {
    "strong": "强内容过滤",
    "moderate": "中等内容过滤",
    "weak": "弱内容过滤",
    "unknown": "未知过滤强度",
}

_TIER_INFERENCE = {
    "strong": "推论: 策略攻击优先 → 编码攻击低效",
    "moderate": "推论: 策略+编码交替 → 编码攻击可能部分有效",
    "weak": "推论: 编码攻击也可生效 → 快速验证优先",
}


# ============================================================
# 辅助函数（与 executor/Stage 2/3/4 风格统一）
# ============================================================


def _cjk_width(s: str) -> int:
    """近似计算字符串显示宽度（CJK 字符算 2 列）"""
    return sum(2 if ord(c) > 0x7F else 1 for c in s)


def _pad_right(s: str, width: int) -> str:
    """将字符串填充到指定显示宽度"""
    w = _cjk_width(s)
    return s + " " * max(0, width - w)


def _trunc(text: str, limit: int = 60) -> str:
    """截断文本，添加省略号"""
    text = text.replace("\n", " ").strip()
    return text[:limit - 3] + "..." if len(text) > limit else text


def _is_network_error(error_str: str) -> bool:
    """检查错误是否为网络不可达（而非 HTTP 错误或模型拒绝）"""
    error_lower = error_str.lower()
    return any(kw in error_lower for kw in _NETWORK_ERROR_KEYWORDS)


# ============================================================
# ① 端点探测 + AI类型识别
# ============================================================


def _display_endpoint_detection(ctx: PipelineContext) -> None:
    """① 端点探测 + AI类型识别 — 卡片化展示"""
    rr = ctx.recon_result
    api_label = _TYPE_LABELS.get(rr.target_type, rr.target_type)
    endpoint_display = rr.detected_endpoint
    if rr.target_type:
        endpoint_display = f"{rr.detected_endpoint} ({api_label})"

    ai_type_label = rr.ai_system_type.value.upper()
    auth_label = rr.auth_type.value.replace("_", " ").title()

    print()
    print("  ┏" + "━" * _W)
    print("  ┃  ◆ 端点探测 + AI类型识别")
    print("  ┃")
    print(f"  ┃    ┌─ 检测结果 {'─' * max(1, _W - 22)}┐")
    print(f"  ┃    │ 目标端点:   {endpoint_display}")
    print(f"  ┃    │ 认证类型:   {auth_label}")
    print(f"  ┃    │ AI系统类型: {ai_type_label}")
    print(f"  ┃    │ Target类型: {rr.target_type or 'unknown'}")
    print(f"  ┃    └{'─' * max(0, _W - 3)}┘")

    # PyRIT 可攻击性检查
    if not rr.ai_system_type.is_pyrit_attackable():
        print("  ┃")
        print(f"  ┃    [!] 该类型 ({ai_type_label}) 非提示词攻击领域")
        external = ", ".join(rr.external_tools or [])
        if external:
            print(f"  ┃    [!] 推荐外部工具: {external}")
        print("  ┃    [!] 跳过 PyRIT 攻击")
        print("  ┗" + "━" * _W)

    print("  ┗" + "━" * _W)


# ============================================================
# ② 模型分层 + 探针详情
# ============================================================


def _display_model_tier(ctx: PipelineContext) -> None:
    """② 模型分层 + 探针详情 + 能力信息"""

    rr = ctx.recon_result
    tier_desc = _TIER_LABELS.get(ctx.model_tier, ctx.model_tier)
    probe_detail = getattr(rr, "model_tier_probe_detail", None)

    print()
    print("  ┏" + "━" * _W)
    print(f"  ┃  ◆ 模型分层: {ctx.model_tier} ({tier_desc})")

    # 探针结果
    if probe_detail:
        print("  ┃    探测方式: 动态探针 (3-step gradient probe)")
        _add_probe_card(probe_detail, ctx.model_tier)
    elif ctx.model_tier != "unknown":
        print("  ┃    探测方式: 静态模型名推断")
        _add_static_inference_card(ctx.model_tier)
    else:
        print("  ┃    探测方式: 未知 (无法判定)")
    print("  ┃")

    # 能力信息
    caps = getattr(rr, "capabilities", None)
    cap_hdr = "能力信息"
    cap_dashes = max(1, _W - 6 - _cjk_width(cap_hdr) - 2)
    print(f"  ┃    ┌─ {cap_hdr} {'─' * cap_dashes}┐")

    if caps:
        mt = "✓" if getattr(caps, "supports_multi_turn", False) else "✗"
        sp = "✓" if getattr(caps, "supports_system_prompt", False) else "✗"
        jo = "✓" if getattr(caps, "supports_json_output", False) else "✗"
        eh = "✓" if getattr(caps, "supports_editable_history", False) else "✗"
        print(f"  ┃    │ MULTI_TURN: {mt}  SYSTEM_PROMPT: {sp}  JSON_OUTPUT: {jo}  EDITABLE_HISTORY: {eh}")

        # P6: 能力来源标注 (静态推断 vs 运行时探测)
        _cap_source = (
            "运行时探测 (动态探针)"
            if probe_detail
            else "静态推断 (模型名匹配)"
        )
        print(f"  ┃    │ 来源: {_cap_source}")

        # 模态信息
        supported_input = getattr(caps, "supported_input_modalities", None)
        supported_output = getattr(caps, "supported_output_modalities", None)
        if supported_input:
            modalities = sorted(supported_input) if isinstance(supported_input, (set, frozenset)) else [str(supported_input)]
            print(f"  ┃    │ 输入模态: {', '.join(modalities)}")
        if supported_output:
            modalities = sorted(supported_output) if isinstance(supported_output, (set, frozenset)) else [str(supported_output)]
            print(f"  ┃    │ 输出模态: {', '.join(modalities)}")
    else:
        print("  ┃    │ 能力: 未探测 (运行时由 TargetFactory 探测)")

    print(f"  ┃    └{'─' * max(0, _W - 3)}┘")
    print("  ┗" + "━" * _W)


def _add_probe_card(detail: dict, tier: str) -> None:
    """添加探针结果到卡片子区域"""
    benign = detail.get("benign", {})
    borderline = detail.get("borderline", {})
    jailbreak = detail.get("jailbreak", {})

    hdr = "探针结果 (梯度式: 无害 → 边界 → 越狱)"
    hdr_dashes = max(1, _W - 6 - _cjk_width(hdr) - 2)
    print(f"  ┃    ┌─ {hdr} {'─' * hdr_dashes}┐")

    # Benign
    benign_str = "✓ 正常响应" if benign.get("success") else "✗ 无响应"
    if benign.get("error"):
        benign_str += f" ({_trunc(benign['error'], 40)})"
    elif benign.get("response_text"):
        benign_str += f" → \"{_trunc(benign['response_text'], 35)}\""
    print(f"  ┃    │ Benign:     {benign_str}")

    # Borderline
    if borderline.get("refused"):
        border_str = "✗ 被拒绝 (内容过滤触发)"
    elif borderline.get("success"):
        border_str = "✓ 正常响应 (边界内容未拦截)"
        if borderline.get("response_text"):
            border_str += f" → \"{_trunc(borderline['response_text'], 30)}\""
    else:
        border_str = "? 无响应"
    print(f"  ┃    │ Borderline: {border_str}")

    # Jailbreak
    if jailbreak.get("refused"):
        jail_str = "✗ 被拒绝 (对齐防护生效)"
    elif jailbreak.get("success"):
        jail_str = "✓ 未拒绝 (对齐防护可绕过)"
        if jailbreak.get("response_text"):
            jail_str += f" → \"{_trunc(jailbreak['response_text'], 30)}\""
    else:
        jail_str = "? 无响应"
    print(f"  ┃    │ Jailbreak:  {jail_str}")

    # 推论
    inference = _TIER_INFERENCE.get(tier)
    if inference:
        print("  ┃    │")
        print(f"  ┃    │ {inference}")

    print(f"  ┃    └{'─' * max(0, _W - 3)}┘")


def _add_static_inference_card(tier: str) -> None:
    """静态推断卡片子区域"""
    hdr = "静态推断 (模型名匹配)"
    hdr_dashes = max(1, _W - 6 - _cjk_width(hdr) - 2)
    print(f"  ┃    ┌─ {hdr} {'─' * hdr_dashes}┐")
    inference = _TIER_INFERENCE.get(tier)
    if inference:
        print(f"  ┃    │ {inference}")
    else:
        print("  ┃    │ 未知模型，无法推断过滤强度")
    print(f"  ┃    └{'─' * max(0, _W - 3)}┘")


# ============================================================
# ③ 传递到 Strategy 策略层 — ★ 突出展示 ★
# ============================================================


def _display_handoff(ctx: PipelineContext) -> None:
    """③ 传递到 Strategy 策略层 — 最终结果摘要（★ 突出展示 ★）

    最终输出决定后续攻击策略，因此重点展示:
      - target_type → Target 分组选择
      - model_tier → 策略模式推荐
      - capabilities → 多轮技术可用性
      - 策略推论 → 攻击技术方向
    """
    rr = ctx.recon_result
    caps = getattr(rr, "capabilities", None)
    has_multi_turn = caps and getattr(caps, "supports_multi_turn", False)
    has_system_prompt = caps and getattr(caps, "supports_system_prompt", False)

    # Banner — 突出显示
    print()
    print("  ╔" + "═" * _W + "╗")
    print()
    print("       ★  传递到 Strategy 策略层 — 决定后续攻击策略  ★")
    print()
    print("  ╚" + "═" * _W + "╝")

    # 传递内容卡片
    print()
    handoff_hdr = "侦察结果 (最终输出)"
    handoff_dashes = max(1, _W - 2 - _cjk_width(handoff_hdr) - 2)
    print(f"  ┌─ {handoff_hdr} {'─' * handoff_dashes}┐")

    # 核心字段
    print(f"  │ • target_type:  {ctx.target_type or 'unknown'} → Target 分组选择")

    tier_desc = _TIER_LABELS.get(ctx.model_tier, ctx.model_tier)
    print(f"  │ • model_tier:   {ctx.model_tier} ({tier_desc}) → 策略模式推荐")

    # 能力
    _rr_probe = getattr(rr, "model_tier_probe_detail", None)
    _cap_source = "运行时探测" if _rr_probe else "静态推断"
    if has_multi_turn:
        print(f"  │ • capabilities: MULTI_TURN ✓ ({_cap_source}) → 多轮技术可用 (Crescendo/TAP/PAIR)")
    else:
        # P0-D: 修正能力探测信息矛盾 — discover_capabilities=False 意味着不会运行时重新探测
        if _rr_probe:
            print(f"  │ • capabilities: MULTI_TURN ✗ ({_cap_source}) → 多轮技术将被过滤")
        else:
            print(f"  │ • capabilities: MULTI_TURN ? ({_cap_source}) → 静态推断, 运行时不重新探测")

    if has_system_prompt:
        print("  │ • capabilities: SYSTEM_PROMPT ✓ → 系统提示词注入可用")

    # 策略推论
    print("  │")
    inference = _TIER_INFERENCE.get(ctx.model_tier)
    if inference:
        print(f"  │ → {inference}")

    # 策略模式推荐
    if ctx.model_tier == "strong":
        print("  │ → 策略模式: academic (高 ASR 技术优先 — 多轮迭代为主)")
    elif ctx.model_tier == "moderate":
        print("  │ → 策略模式: academic (策略+编码交替 — Tier S/A → B/C)")
    elif ctx.model_tier == "weak":
        print("  │ → 策略模式: exam (快速验证 — 编码攻击也可生效)")
    else:
        print("  │ → 策略模式: academic (默认 — 运行时自适应)")

    print(f"  └{'─' * _W}┘")


# ============================================================
# 主流程
# ============================================================


async def run(ctx: PipelineContext) -> bool:
    """执行侦察阶段。返回 False 表示不可攻击，应终止 pipeline。"""
    stage_header(1, "Recon 侦察层", "端点发现 + AI类型识别 + 模型分层")

    ctx.recon_result = await recon_target(
        ctx.target_url, api_key=ctx.target_api_key, model_name=ctx.target_model
    )

    # ── ① 端点探测 + AI类型识别 ──
    _display_endpoint_detection(ctx)

    # 检查是否为 PyRIT 可攻击类型
    if not ctx.recon_result.ai_system_type.is_pyrit_attackable():
        return False

    # 同步到 ctx
    ctx.model_tier = ctx.recon_result.model_tier
    ctx.target_type = ctx.recon_result.target_type

    # ── 韧性检查: 目标不可达时立即中断 (fail-fast) ──
    # benign 探针是控制探针 ("What is the capital of France?")
    # 如果连这个都无法响应，说明目标不可达，后续阶段将全部失败
    probe_detail = getattr(ctx.recon_result, "model_tier_probe_detail", None)
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

    # ── ② 模型分层 + 探针详情 ──
    _display_model_tier(ctx)

    # ── ③ 传递到 Strategy 策略层 (★ 突出展示 ★) ──
    _display_handoff(ctx)

    # P2-A: 阶段间衔接行
    from pipeline.display import handoff_line
    _caps = getattr(ctx.recon_result, "capabilities", None)
    _has_mt = _caps and getattr(_caps, "supports_multi_turn", False)
    handoff_line(
        1, 2,
        f"target_type={ctx.target_type or 'unknown'} | model_tier={ctx.model_tier} | "
        f"MULTI_TURN={'✓' if _has_mt else '?'}"
    )

    return True
