"""
Stage 3/7: Target 接入 + 路由
=============================

目标创建 + 能力探测 + 分组确定 + Converter 路由。
创建 Objective/Judge/Converter 三个 Target 实例。

显示架构 (v8.0 优化 — 载荷驱动 + 高 ASR 导向):
  ① Target 三件套               — 合并旧 3 个 Target box
  ② ★ Converter 变体池 ★        — 按优先级卡片化，LLM跳过标注
  ③ ★ 传递到 Datasets 载荷端 ★  — 最终结果摘要（决定后续攻击组合）

设计原则:
  - 以 Converter 变体池为驱动：以路由推荐的链为展示核心单元
  - 高 ASR 导向：按优先级分组，高优先级链优先展示
  - 参照 executor 卡片风格：┏━ 粗线框 + ◆ 技术头 + ┌─ 子区域 + ①②③ 编号
  - 传递结果突出展示：converter_chains 变体池决定后续攻击组合数
"""

import os
import logging
import time
from typing import Any

from pipeline.context import PipelineContext
from pipeline.display import info_box, stage_header
from src.targets import create_prompt_target, create_judge_target, TargetParams
from src.targets.rate_limited_target import RateLimitConfig, wrap_target_with_rate_limiting

logger = logging.getLogger(__name__)

# ── 统一卡片宽度（双线框，与 executor/Stage 2/4 一致） ──
_W = 68

_CIRCLED = "①②③④⑤⑥⑦⑧⑨⑩"

# 优先级标签
_PRIORITY_LABELS = {
    1: "高 ASR 快速链",
    2: "中 ASR 编码链",
    3: "低 ASR 辅助链",
    4: "兜底尝试链",
}

# P7: target_group 命名解释
_GROUP_EXPLANATIONS = {
    "llm_direct_strong": "LLM 直连 (强过滤) → 策略攻击优先, 编码低效",
    "llm_direct_moderate": "LLM 直连 (中等过滤) → 策略+编码交替",
    "llm_direct_weak": "LLM 直连 (弱过滤) → 编码攻击也可生效",
    "openai_chat": "OpenAI Chat API → 全链 Converter 可用",
    "openai_responses": "OpenAI Responses API → 全链 Converter 可用",
    "litellm": "LiteLLM Proxy → 全链 Converter 可用",
    "http_api": "HTTP API → 非LLM Converter 仅 (编码/模板)",
    "azure_ml": "Azure ML → 全链 Converter 可用",
}


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


# ============================================================
# ① Target 三件套
# ============================================================


def _display_targets(ctx: PipelineContext) -> None:
    """① Target 三件套 — 合并旧 3 个 Target box"""

    print()
    print(f"  ┌─ Target 三件套 {'─' * max(1, _W - 20)}┐")
    print("  │")

    # ── Objective Target ──
    print("  │  ┌─ 被测目标 (Objective) ─────────────────────────────┐")
    obj_type = type(ctx.objective_target).__name__
    print(f"  │  │ {obj_type} ({ctx.target_type})")
    print(f"  │  │ 分组: {ctx.target_group}  ← 驱动 Converter 路由")
    # P7: target_group 命名解释
    _group_explain = _GROUP_EXPLANATIONS.get(ctx.target_group, "")
    if _group_explain:
        print(f"  │  │        {_group_explain}")
    print(f"  │  │ 模型: {ctx.target_model}")

    # 安全机制
    print(f"  │  │ 安全机制: {ctx.bypass_mechanism}")

    # 能力
    caps = None
    try:
        caps = getattr(ctx.objective_target, "capabilities", None)
    except Exception:
        pass
    if caps is None:
        caps = getattr(ctx.recon_result, "capabilities", None)
    if caps:
        mt = "✓" if getattr(caps, "supports_multi_turn", False) else "✗"
        sp = "✓" if getattr(caps, "supports_system_prompt", False) else "✗"
        print(f"  │  │ 能力: MULTI_TURN {mt}, SYSTEM_PROMPT {sp}")
    if ctx.target_rpm:
        print(f"  │  │ RPM限速: {ctx.target_rpm} req/min")
    print("  │  └──────────────────────────────────────────────────────┘")
    print("  │")

    # ── Judge Target ──
    print("  │  ┌─ 评分器 (Judge) ────────────────────────────────────┐")
    judge_temp = ctx.config_loader.get_judge_temperature()
    print(f"  │  │ {ctx.judge_model} | temperature={judge_temp}")
    print("  │  │ 用途: objective scoring 仅")
    print("  │  └──────────────────────────────────────────────────────┘")
    print("  │")

    # ── Converter Target ──
    print("  │  ┌─ 转换器 (Converter) ───────────────────────────────┐")
    print(f"  │  │ {ctx.converter_target_display}")
    llm_status = (
        "✓ 保留" if ctx.model_tier != "weak"
        else "✗ 跳过 (弱过滤模型避免 500)"
    )
    print(f"  │  │ 分层: {ctx.model_tier} → LLM辅助链: {llm_status}")
    print("  │  └──────────────────────────────────────────────────────┘")

    print(f"  └{'─' * _W}┘")


# ============================================================
# ② Converter 变体池 — 按优先级排序
# ============================================================


def _display_converter_pool(ctx: PipelineContext) -> None:
    """② Converter 变体池 — 按优先级分组卡片化"""

    if not ctx.converter_chains:
        print("  [!] 无 Converter 链")
        return

    # 获取链元数据
    try:
        from src.scenarios.technique_factories import CONVERTER_VARIANT_CHAINS
    except Exception:
        CONVERTER_VARIANT_CHAINS = {}

    # 构建链信息
    chains_info: list[dict[str, Any]] = []
    skip_llm = ctx.model_tier == "weak"

    for chain_name in ctx.converter_chains:
        ci = CONVERTER_VARIANT_CHAINS.get(chain_name, {})
        requires_llm = ci.get("requires_llm", False)
        priority = ci.get("priority", 99)
        description = ci.get("description", "")
        is_skipped = skip_llm and requires_llm

        chains_info.append({
            "name": chain_name,
            "requires_llm": requires_llm,
            "priority": priority,
            "description": description,
            "is_skipped": is_skipped,
        })

    # 按 priority 升序排序
    chains_info.sort(key=lambda x: (x["priority"], x["requires_llm"]))

    # 按优先级 + LLM/非LLM 分组
    groups: dict[tuple[int, bool], list[dict[str, Any]]] = {}
    for ci in chains_info:
        key = (ci["priority"], ci["requires_llm"])
        groups.setdefault(key, []).append(ci)

    # Banner
    print()
    print("  ╔" + "═" * _W + "╗")
    print()
    print("       ★  Converter 变体池 — 按优先级排序  ★")
    print()
    print("    高优先级链优先尝试 · 首次成功即停止 (FIRST_SUCCESS)")
    print()
    print("  ╚" + "═" * _W + "╝")

    # 全局概览
    total = len(chains_info)
    n_non_llm = sum(1 for c in chains_info if not c["requires_llm"])
    n_llm = sum(1 for c in chains_info if c["requires_llm"])
    n_skipped = sum(1 for c in chains_info if c["is_skipped"])
    n_effective = total - n_skipped

    print()
    print(f"  ┌─ 全局概览 {'─' * max(1, _W - 22)}┐")
    print("  │")
    print(f"  │  总计: {total} 条链")
    print(f"  │  非LLM: {n_non_llm}  |  LLM: {n_llm}", end="")
    if n_skipped:
        print(f"  |  跳过: {n_skipped}  |  有效: {n_effective}")
    else:
        print(f"  |  有效: {n_effective}")
    print(f"  │  target_group: {ctx.target_group}")
    print(f"  │  bypass: {ctx.bypass_mechanism}")
    print(f"  └{'─' * _W}┘")

    # 每个分组卡片
    sorted_keys = sorted(groups.keys())
    for key in sorted_keys:
        priority, requires_llm = key
        group_chains = groups[key]
        llm_tag = "[LLM]" if requires_llm else "[非LLM]"
        priority_label = _PRIORITY_LABELS.get(priority, f"优先级 {priority}")

        # 检查整组是否被跳过
        group_skipped = all(c["is_skipped"] for c in group_chains)
        skip_str = "  ✗ 跳过 (弱过滤模型)" if group_skipped else ""

        # ── 卡片头 ──
        print()
        print("  ┏" + "━" * _W)
        print(
            f"  ┃  ◆ 优先级 {priority} {llm_tag} — {priority_label}"
            f"{skip_str}"
        )
        print("  ┃")

        # ── 链列表 ──
        n_chains = len(group_chains)
        chain_hdr = f"链 ({n_chains})"
        chain_dashes = max(1, _W - 6 - _cjk_width(chain_hdr) - 2)
        print(f"  ┃    ┌─ {chain_hdr} {'─' * chain_dashes}┐")

        for idx, ci in enumerate(group_chains):
            marker = (
                _CIRCLED[idx] if idx < len(_CIRCLED)
                else f"{idx + 1}."
            )
            name = ci["name"]
            max_name = 30
            if _cjk_width(name) > max_name:
                name = name[:max_name - 3] + "..."

            name_pad = _pad_right(name, max_name)
            desc = _trunc(ci["description"], 30) if ci["description"] else ""
            skip_mark = "  [跳过]" if ci["is_skipped"] else ""

            print(
                f"  ┃    │ {marker} {name_pad}  {desc}{skip_mark}"
            )

        print(f"  ┃    └{'─' * max(0, _W - 3)}┘")
        print("  ┗" + "━" * _W)


# ============================================================
# ③ 传递到 Datasets 载荷端 — 突出展示
# ============================================================


def _display_handoff(ctx: PipelineContext) -> None:
    """③ 传递到 Datasets 载荷端 — 最终结果摘要（★ 突出展示 ★）"""

    # 分类统计
    total = len(ctx.converter_chains)
    skip_llm = ctx.model_tier == "weak"

    try:
        from src.scenarios.technique_factories import CONVERTER_VARIANT_CHAINS
    except Exception:
        CONVERTER_VARIANT_CHAINS = {}

    n_non_llm = 0
    n_llm = 0
    n_skipped = 0
    for chain_name in ctx.converter_chains:
        ci = CONVERTER_VARIANT_CHAINS.get(chain_name, {})
        requires_llm = ci.get("requires_llm", False)
        if requires_llm:
            n_llm += 1
            if skip_llm:
                n_skipped += 1
        else:
            n_non_llm += 1
    n_effective = total - n_skipped

    # 载荷能力
    _recon_caps = getattr(ctx.recon_result, "capabilities", None)
    if _recon_caps and getattr(_recon_caps, "supports_multi_turn", False):
        cap_mt = "MULTI_TURN ✓ → 多轮载荷可用"
    else:
        cap_mt = "MULTI_TURN ? → 运行时探测确认"

    # Banner
    print()
    print("  ╔" + "═" * _W + "╗")
    print()
    print("       ★  传递到 Datasets 载荷端 — 决定后续攻击组合  ★")
    print()
    print("  ╚" + "═" * _W + "╝")

    lines = [
        f"★ target_group: {ctx.target_group} → 载荷预筛选",
        f"★ converter_chains: {total} 条 → 变体池已就绪",
        f"  (非LLM={n_non_llm}, LLM={n_llm}"
        + (f"[跳过{n_skipped}]" if n_skipped else "")
        + f", 有效={n_effective})",
        f"★ bypass_mechanism: {ctx.bypass_mechanism}",
        f"★ 载荷能力: {cap_mt}",
        "★ 载荷模式: single_turn + multi_turn 均可",
    ]

    info_box("传递到 Datasets 载荷端 (Stage 4)", lines)


# ============================================================
# 主流程
# ============================================================


async def run(ctx: PipelineContext) -> None:
    """执行 Target 接入阶段（含 Converter 路由决策）"""
    stage_header(3, "Target 接入 + 路由", "目标创建 + 能力探测 + Converter 路由")

    # ── 创建 Targets (纯逻辑，不变) ──

    # API 级别限速配置（.env > config/defaults/pipeline.yaml > 10）
    ctx.api_max_concurrent = ctx.config_loader.get_api_max_concurrency()
    # 传播到环境变量，供 rate_limited_target.py / adaptive_runner.py 读取
    os.environ["API_MAX_CONCURRENCY"] = str(ctx.api_max_concurrent)
    ctx.target_rpm = int(os.getenv("TARGET_MAX_RPM")) if os.getenv("TARGET_MAX_RPM") else None
    ctx.judge_rpm = int(os.getenv("JUDGE_MAX_RPM")) if os.getenv("JUDGE_MAX_RPM") else None

    # HTTP 客户端参数
    _target_timeout = ctx.config_loader.get_target_httpx_timeout()
    _target_verify = ctx.config_loader.get_target_httpx_verify()
    _target_proxy = ctx.config_loader.get_target_httpx_proxy()
    _judge_timeout = ctx.config_loader.get_judge_httpx_timeout()
    _judge_verify = ctx.config_loader.get_judge_httpx_verify()

    # ── R2: 本地模型并发自动降级（在创建 Targets 之前检测）──
    # Ollama/vLLM 等本地模型服务默认单线程处理请求，并发请求会在服务器端排队，
    # 队列等待时间计入 read timeout，导致排队超时。
    # 自动将本地端点的并发降为 1，避免队列超时。
    _is_local = _is_local_endpoint(ctx.target_endpoint)
    if _is_local and ctx.api_max_concurrent > 1:
        print(f"  [R2] 本地模型检测: 并发 {ctx.api_max_concurrent} → 1 (Ollama 单线程)")
        logger.info(
            f"Local model detected, reducing concurrency from {ctx.api_max_concurrent} to 1"
        )
        ctx.api_max_concurrent = 1

    # 创建 Objective Target
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

    # ── 本地模型预热 ──
    if _is_local:
        await _warmup_local_target(ctx.objective_target, ctx.target_model, "objective")
        if converter_endpoint != ctx.target_endpoint or ctx.converter_model != ctx.target_model:
            await _warmup_local_target(ctx.converter_target, ctx.converter_model, "converter")

    # ── Target 感知 Converter 路由决策 (纯逻辑) ──
    try:
        from src.converters.target_aware_router import select_converter_chains_for_target
        ctx.converter_chains = select_converter_chains_for_target(
            ctx.target_type,
            converter_target_available=(ctx.converter_target is not None),
        )
    except Exception:
        pass

    # L2 韧性: 初始化 Converter 健康监控器
    from src.scenarios.converter_health_monitor import ConverterHealthMonitor
    ctx.converter_health_monitor = ConverterHealthMonitor()
    for chain_name in ctx.converter_chains:
        ctx.converter_health_monitor.register(chain_name)

    # ── ① Target 三件套 ──
    _display_targets(ctx)

    # ── ② Converter 变体池 ──
    _display_converter_pool(ctx)

    # ── ③ 传递到 Datasets 载荷端 (★ 突出展示 ★) ──
    _display_handoff(ctx)

    # P2-A: 阶段间衔接行
    from pipeline.display import handoff_line
    _n_chains = len(ctx.converter_chains)
    handoff_line(
        3, 4,
        f"target_group={ctx.target_group} | converter_chains={_n_chains} 条 | "
        f"bypass={ctx.bypass_mechanism}"
    )


def _is_local_endpoint(endpoint: str) -> bool:
    """
    检测端点是否为本地模型服务（Ollama/vLLM/llama.cpp 等）

    本地模型首次请求会触发模型加载，可能超过 HTTP 超时。
    通过预热请求触发模型加载，避免后续攻击超时。
    """
    if not endpoint:
        return False
    ep_lower = endpoint.lower()
    local_markers = ("localhost", "127.0.0.1", "0.0.0.0", "192.168.", "10.", "172.16.", "172.17.", "172.18.")
    if any(m in ep_lower for m in local_markers):
        return True
    if ":11434" in ep_lower:
        return True
    if ":8080" in ep_lower and "vllm" in ep_lower:
        return True
    return False


async def _warmup_local_target(target, model_name: str, context_label: str) -> None:
    """
    发送轻量预热请求触发本地模型加载

    对齐 PyRIT 原生 discover_target_capabilities_async 的预热理念，
    但使用更轻量的 "Hi" 请求（非能力探针），避免触发安全过滤。
    """
    try:
        from pyrit.models import Message, MessagePiece

        warmup_piece = MessagePiece(role="user", original_value="Hi")
        warmup_msg = Message(message_pieces=[warmup_piece])
        start = time.time()
        await target.send_prompt_async(message=warmup_msg)
        elapsed = time.time() - start
        print(f"  [OK] 本地模型预热完成 ({context_label}: {model_name}, {elapsed:.1f}s)")
        logger.info(f"Local model warmup completed: {context_label}/{model_name} in {elapsed:.1f}s")
    except Exception as e:
        err_name = type(e).__name__
        print(f"  [!] 本地模型预热失败 ({context_label}: {model_name}): {err_name}: {e}")
        print("      首次攻击可能较慢（模型加载中）")
        logger.warning(
            f"Local model warmup failed ({context_label}/{model_name}): "
            f"{err_name}: {e}. First attack may be slow."
        )
