"""AI 攻击面侦察阶段 (AI-300 Ch2)。

执行 AI 攻击面侦察（6 步递进流程）：
  [1/6] 被动侦察：分析响应头、CSP、端点线索
  [2/6] 速率限制探测：在大量请求前探测目标限速阈值，播种 Governor
  [3/6] 主动服务发现：基于调速器安全速率探测 AI 协议端点
  [4/6] MCP/A2A 深入枚举：基于发现结果做定向枚举
  [5/6] 护栏画像：指纹识别、分类、绕过评估
  [6/6] 规避分析：确定性、检测签名、JS客户端分析（速率限制已在[2/6]完成）

设计原则：
  - 速率限制探测前置于所有批量请求，避免盲飞触发封禁
  - 调速器种子在步骤[2/6]注入，后续所有阶段共享安全速率
  - 够用即停：探测全部档位 [10→20→25→30] RPM，确认 30 RPM 安全后停止（默认采用 20 RPM）

对齐 OWASP ASI Top 10: ASI07 (Sensitive Information), LLM10 (Unbounded Consumption)
"""
from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import urlparse

from redteam.core.models import AIService, AIProtocol, AuthContext, ReconResult
from redteam.core.rate_limiter import RateLimitGovernor, get_governor
from redteam.core.store import save_json, make_run_id
from redteam.core.tools import ToolResolver
from redteam.core.terminal_output import print_target_list
from redteam.recon.auth_parse import parse_headers, parse_headers_file, describe_auth
from redteam.recon.auth_validator import ConnectivityResult, TargetType
from redteam.recon.discover import discover_ai_services, passive_recon, enum_protected_endpoints
from redteam.recon.guardrail import profile_guardrails
from redteam.recon.mcp_recon import probe_mcp_server, enumerate_mcp_tools
from redteam.recon.a2a_recon import probe_a2a_endpoint, enumerate_agent_capabilities
from redteam.recon.evasion import (
    probe_rate_limit,
    probe_rate_limit_generic,
    probe_determinism,
    analyze_detection_signatures,
    analyze_js_client,
)



def _resolve_chat_url(svc: AIService) -> str:
    """根据 AI 协议构造适合聊天的端点 URL。

    避免将速率限制/确定性探测发送到非对话路径
    （如 /api/tags、/api/embeddings），确保 send_chat 能正常执行。

    Args:
        svc: AIService 对象

    Returns:
        适合 POST chat 请求的 URL
    """
    from urllib.parse import urlparse, urlunparse

    parsed = urlparse(svc.url)
    base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

    protocol = svc.protocol

    # 已经是明确聊天路径的 URL，直接使用
    chat_paths = ("/v1/chat/completions", "/api/chat", "/api/generate", "/chat/completions")
    if any(parsed.path.rstrip("/").endswith(p) for p in chat_paths):
        return svc.url

    # 按协议构造标准聊天端点
    if protocol == "ollama":
        return f"{base}/api/chat"
    elif protocol in ("openai_compatible", "generic_ai"):
        return f"{base}/v1/chat/completions"
    elif protocol == "anthropic":
        return f"{base}/v1/messages"
    else:
        # MCP、A2A 等其他协议，尝试 OpenAI 兼容路径
        return f"{base}/v1/chat/completions"


def _resolve_base_url(target: str) -> str:
    """从目标 URL 提取 scheme+netloc 基础部分（用于通用探测）。

    Args:
        target: 完整目标 URL

    Returns:
        scheme://netloc 格式的基础 URL
    """
    parsed = urlparse(target)
    return f"{parsed.scheme}://{parsed.netloc}"


def _build_url(base: str, path: str) -> str:
    """安全拼接 base URL + path。"""
    return base.rstrip("/") + path


def _resolve_rate_limit_probe_target(
    target: str,
    connectivity: ConnectivityResult | None,
) -> tuple[str, str, dict[str, Any] | None]:
    """根据目标类型智能选择速率限制探测端点。

    不同目标类型的速率限制位置不同，选择合适的探测端点才能
    获取准确的限速数据：

    ┌─────────────────────┬──────────────────────┬────────┬──────────────────────────┐
    │ 目标类型             │ 探测端点              │ 方法    │ 说明                     │
    ├─────────────────────┼──────────────────────┼────────┼──────────────────────────┤
    │ Ollama              │ /api/tags            │ GET    │ 端点级限速，无副作用       │
    │ OpenAI 兼容          │ /v1/models           │ GET    │ 标准模型列表，无 token 消耗 │
    │ 模型平台（智谱等）    │ 平台 chat 端点        │ POST   │ 轻量消息，1 max_token     │
    │ AI 网站 / Web App    │ 根路径 /             │ GET    │ 探测 WAF/CDN 层限速       │
    │ 未知                 │ 根路径 /             │ GET    │ 通用兜底                 │
    └─────────────────────┴──────────────────────┴────────┴──────────────────────────┘

    Args:
        target: 目标 URL
        connectivity: 连通性测试结果（含 target_type + platform_name）

    Returns:
        (probe_url, http_method, payload_or_none)
    """
    base = _resolve_base_url(target)

    if connectivity is None:
        return (base, "GET", None)

    tt = connectivity.target_type

    # ━━━ 1. Ollama 模型服务器 ━━━
    if tt == TargetType.OLLAMA:
        return (_build_url(base, "/api/tags"), "GET", None)

    # ━━━ 2. OpenAI 兼容 API ━━━
    if tt == TargetType.OPENAI_COMPATIBLE:
        return (_build_url(base, "/v1/models"), "GET", None)

    # ━━━ 3. 模型平台（智谱、百度等） ━━━
    if tt == TargetType.MODEL_PLATFORM:
        host = urlparse(target).netloc.lower()
        # 智谱 BigModel — 无标准 GET /v1/models，需 POST chat 端点
        if "bigmodel.cn" in host or (connectivity.platform_name and "智谱" in connectivity.platform_name):
            model = (connectivity.exposed_models or ["glm-4-flash"])[0]
            return (
                _build_url(base, "/api/paas/v4/chat/completions"),
                "POST",
                {"model": model, "messages": [{"role": "user", "content": "hi"}], "max_tokens": 1},
            )
        # 百度文心 — 同样 non-standard API
        if connectivity.platform_name and "百度" in connectivity.platform_name:
            model = (connectivity.exposed_models or ["ernie-bot"])[0]
            return (
                _build_url(base, "/rpc/2.0/ai_custom/v1/wenxinworkshop/chat"),
                "POST",
                {"messages": [{"role": "user", "content": "hi"}]},
            )
        # 其他已知平台 — 尝试 OpenAI 兼容 GET /v1/models
        return (_build_url(base, "/v1/models"), "GET", None)

    # ━━━ 4. AI 聊天网站 ━━━
    if tt == TargetType.AI_CHAT_WEBSITE:
        # 不知道后端 API 路径，探测 Web 层限速
        return (base, "GET", None)

    # ━━━ 5. Web 应用 / 未知 ━━━
    # 可能是带 AI 功能的传统 Web 应用，或完全未知的目标
    return (base, "GET", None)


def _print_rate_limit_discovery(
    rate_info: dict[str, Any],
    governor: RateLimitGovernor,
    base_url: str,
) -> tuple[float, bool]:
    """展示速率限制探测结果并返回 (safe_rpm, has_high_potential)。

    Args:
        rate_info: probe_rate_limit_generic 返回的结果
        governor: 已播种的调速器
        base_url: 探测的目标 URL

    Returns:
        (safe_rpm, has_high_potential) — has_high_potential 表示通过全部探测档位
    """
    safe_rpm, has_limit = governor.get_safe_rate(base_url)
    has_high_potential = False

    print(f"\n  ╔{' Rate Limit Discovery '.center(60, '═')}╗")

    if has_limit and rate_info.get("rate_limit_detected"):
        threshold = rate_info.get("threshold_rpm", 0)
        throttle_type = rate_info.get("throttle_type", "unknown")
        status_code = rate_info.get("status_code", 0)
        print(f"  ║  {'⚠  检测到速率限制'.ljust(58)} ║")
        print(f"  ║  {'  阈值: ' + str(threshold) + ' RPM  类型: ' + throttle_type + '  状态码: ' + str(status_code)}".ljust(70))
        if safe_rpm > 0:
            safe_delay = int((60.0 / safe_rpm) * 1000)
            print(f"  ║  {'  安全速率: ' + str(safe_rpm) + ' RPM  建议延迟: ' + str(safe_delay) + 'ms'}".ljust(70))
    elif rate_info.get("stop_reason", "").startswith("safe_at_"):
        tested_rpm = rate_info.get("threshold_rpm", 15)
        stop_reason = rate_info.get("stop_reason", "")
        print(f"  ║  {'✓  未检测到速率限制（够用即停）'.ljust(58)} ║")
        print(f"  ║  {'  已确认 ' + str(tested_rpm) + ' RPM 安全无限制  (' + stop_reason + ')'}".ljust(70))
        if safe_rpm > 0:
            safe_delay = int((60.0 / safe_rpm) * 1000)
            print(f"  ║  {'  安全速率: ' + str(safe_rpm) + ' RPM  建议延迟: ' + str(safe_delay) + 'ms'}".ljust(70))
        if tested_rpm >= 30:
            has_high_potential = True
    else:
        successful = sum(1 for r in rate_info.get("all_requests", []) if r.get("success"))
        total = len(rate_info.get("all_requests", []))
        print(f"  ║  {'✓  未检测到速率限制'.ljust(58)} ║")
        if total > 0:
            print(f"  ║  {'  ' + str(successful) + '/' + str(total) + ' 请求成功（无限制）'}".ljust(70))
        # 探测到最高速率无限制 → 高潜力
        tested_rpm = rate_info.get("threshold_rpm", 0)
        if tested_rpm >= 30:
            has_high_potential = True

    # 最大可支持值提示
    if has_high_potential:
        print(f"  ╠{'─'*60}╣")
        print(f"  ║  {'💡 已确认 30 RPM 安全  |  默认采用 20 RPM（保守安全值）'.ljust(58)} ║")
        print(f"  ║  {'  可覆写范围: 10-30 RPM  |  可选更高速率探测 (>30 RPM)'.ljust(57)} ║")

    print(f"  ╚{'═'*60}╝")

    return safe_rpm, has_high_potential


def _interactive_recon_rpm_override(
    governor: RateLimitGovernor,
    base_url: str,
    safe_rpm: float,
    default_rpm: int = 20,
    min_rpm: int = 10,
    max_rpm: int = 30,
) -> float:
    """侦察阶段 RPM 覆写交互 — 让用户选择后续探测的安全速率。

    在主动服务发现之前，允许用户根据速率探测结果选择更高速率。
    保守默认值（default_rpm）在用户不输入时自动应用；
    探测确认的最高安全值（max_rpm）作为可选上限。

    Args:
        governor: 自适应调速器实例
        base_url: 基础 URL
        safe_rpm: 当前安全 RPM（探测后 governor 内部值）
        default_rpm: 保守默认值（Enter 不输入时使用，默认 20 RPM = AI-300 保守值）
        min_rpm: 最小允许覆写值（不低于探测最低档位，如 10）
        max_rpm: 最大允许覆写值（不超过探测验证的最高值，如 30）

    Returns:
        用户选择的 safe RPM（governor.get_safe_rate 返回值）
    """
    # ━━━ 统一应用保守默认值的辅助函数 ━━━
    def _apply_default():
        governor.override_safe_rpm(base_url, float(default_rpm))
        new_safe, _ = governor.get_safe_rate(base_url)
        print(f"  [调速器] {base_url} safe rate: {new_safe:.0f} RPM (conservative default)\n")
        return new_safe

    try:
        override = input(
            f"\n  🔧  覆写速率？[{min_rpm}-{max_rpm}, Enter=保守默认 {default_rpm}]: "
        ).strip()
    except (EOFError, KeyboardInterrupt):
        return _apply_default()

    # Enter 不输入 → 使用保守默认值
    if not override:
        return _apply_default()

    try:
        rpm = int(override)
    except ValueError:
        print(f"  Invalid input — using conservative default {default_rpm} RPM\n")
        return _apply_default()

    if rpm < min_rpm or rpm > max_rpm:
        print(f"  Value {rpm} out of range [{min_rpm}-{max_rpm}] — using conservative default {default_rpm} RPM\n")
        return _apply_default()

    # 用户显式覆写
    governor.override_safe_rpm(base_url, float(rpm))
    new_safe, _ = governor.get_safe_rate(base_url)
    print(f"  [调速器] {base_url} safe rate: {new_safe:.0f} RPM (user override)\n")
    return new_safe


def _interactive_high_rate_probe(
    governor: RateLimitGovernor,
    base_url: str,
    probe_url: str,
    probe_method: str,
    probe_payload: dict[str, Any] | None,
    auth: AuthContext | None,
    current_safe_rpm: float,
    max_rpm: int = 300,
) -> float:
    """更高速率探测交互 — 30 RPM 已确认安全后，询问是否探测 >30 RPM。

    在常规 10-30 RPM 覆写完成后调用。
    默认回车跳过（不进行更高速率探测），只有显式输入 y 才执行。

    Args:
        governor: 自适应调速器实例
        base_url: 基础 URL
        probe_url: 探测端点 URL
        probe_method: 探测 HTTP 方法
        probe_payload: POST 请求体（None 表示 GET）
        auth: 认证上下文
        current_safe_rpm: 当前安全 RPM（覆写后的值）
        max_rpm: 用户可设定的最大目标 RPM（默认 300）

    Returns:
        更新后的 safe RPM（如果跳过高阶探测则返回原值）
    """
    print(f"\n  ╔{' Advanced Rate Probing '.center(60, '═')}╗")
    print(f"  ║  {'30 RPM 已确认安全。探测更高安全速率可大幅加速后续阶段。'.ljust(58)} ║")
    print(f"  ╠{'─'*60}╣")
    print(f"  ║  {'⚠  风险提示：'.ljust(58)} ║")
    print(f"  ║  {'  • 过高速率可能触发 WAF/IP 封禁'.ljust(58)} ║")
    print(f"  ║  {'  • 可能导致目标服务性能下降或超时'.ljust(58)} ║")
    print(f"  ║  {'  • 不建议对生产环境目标使用此功能'.ljust(58)} ║")
    print(f"  ║  {'  • 若触发限速，调速器将自动退回到安全值'.ljust(58)} ║")
    print(f"  ╚{'═'*60}╝")

    try:
        do_probe = input(
            f"\n  🔧  是否进行更高速率探测？[y/N]: "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("  跳过更高速率探测。\n")
        return current_safe_rpm

    if do_probe != "y":
        print("  跳过更高速率探测。\n")
        return current_safe_rpm

    # ━━━ 提示用户输入目标 RPM ━━━
    try:
        target_str = input(
            f"\n  🎯  目标安全速率？[31-{max_rpm}, Enter=取消]: "
        ).strip()
    except (EOFError, KeyboardInterrupt):
        print("  已取消更高速率探测。\n")
        return current_safe_rpm

    if not target_str:
        print("  已取消更高速率探测。\n")
        return current_safe_rpm

    try:
        target_rpm = int(target_str)
    except ValueError:
        print(f"  无效输入 — 已取消更高速率探测。\n")
        return current_safe_rpm

    if target_rpm < 31 or target_rpm > max_rpm:
        print(f"  值 {target_rpm} 超出范围 [31-{max_rpm}] — 已取消。\n")
        return current_safe_rpm

    # ━━━ 生成渐进探测档位 ━━━
    test_rates = _build_progressive_rates(30, target_rpm)

    print(f"\n  [高阶探测] 探测档位: {test_rates}")
    print(f"  [高阶探测] 目标: {probe_method} {probe_url}" + (" (轻量 POST)" if probe_payload else ""))
    print(f"  [高阶探测] 正在探测...")

    # 执行探测（非 stealth 模式以获得精确结果）
    high_rate_info = probe_rate_limit_generic(
        probe_url,
        method=probe_method,
        payload=probe_payload,
        auth=auth,
        timeout=5.0,
        test_rates=test_rates,
        max_requests=5,
        governor=governor,
        stealth=False,  # 高阶探测不需要额外隐匿，专注精度
        stop_at_safe_rpm=target_rpm,
    )

    # ━━━ 展示结果并更新调速器 ━━━
    if high_rate_info.get("rate_limit_detected"):
        threshold = high_rate_info.get("threshold_rpm", 30)
        status_code = high_rate_info.get("status_code", 0)
        print(f"\n  ⚠  在 {threshold} RPM 触发速率限制（状态码: {status_code}）")
        # 回退到触发前的安全值（阈值 × 0.7）
        fallback = threshold * 0.7
        governor.override_safe_rpm(base_url, fallback)
        new_safe, _ = governor.get_safe_rate(base_url)
        print(f"  [调速器] 已回退到安全速率: {new_safe:.0f} RPM\n")
        return new_safe

    # 通过全部档位
    passed_rpm = high_rate_info.get("threshold_rpm", target_rpm)
    stop_reason = high_rate_info.get("stop_reason", "")
    print(f"\n  ✓  通过全部高阶探测档位")
    print(f"  最高确认安全速率: {passed_rpm} RPM  ({stop_reason})")

    governor.override_safe_rpm(base_url, float(target_rpm))
    new_safe, _ = governor.get_safe_rate(base_url)
    print(f"  [调速器] 安全速率已更新: {new_safe:.0f} RPM\n")
    return new_safe


def _build_progressive_rates(start: int, target: int) -> list[int]:
    """生成从 start 到 target 的渐进探测速率档位。

    每步增长约 40%，最多 6 档，确保目标值在列表中。
    用于高阶速率探测的 test_rates 生成。

    Args:
        start: 起始速率（通常为 30）
        target: 目标速率

    Returns:
        渐进速率档位列表
    """
    rates: list[int] = []
    current = start
    factor = 1.4

    while current < target:
        current = int(current * factor)
        if current >= target:
            break
        if current not in rates and current <= target:
            rates.append(current)
        # 安全上限：最多 6 档
        if len(rates) >= 5:
            break

    rates.append(target)
    # 去重 + 排序
    return sorted(set(rates))


def recon_phase(
    target: str,
    header_text: str | None = None,
    header_file: str | None = None,
    run_id: str | None = None,
    resolver: ToolResolver | None = None,
    connectivity: ConnectivityResult | None = None,
) -> tuple[str, ReconResult, list[AIService], RateLimitGovernor]:
    """AI 攻击面侦察（6 步递进流程）。

    流程设计原则：速率限制探测前置于所有批量请求（步骤[2/6]），
    确保主动服务发现[3/6]及后续阶段均已感知目标限速阈值，避免盲飞触发封禁。

    Args:
        target: 目标 URL
        header_text: F12 请求头文本
        header_file: F12 请求头文件路径
        run_id: 运行 ID
        resolver: 工具解析器
        connectivity: 连通性测试结果（可选，用于跳过已探测端点）

    Returns:
        (run_id, recon_result, ai_services, governor)
    """
    resolver = resolver or ToolResolver()
    run_id = run_id or make_run_id(target, uuid.uuid4().hex[:8])
    governor = get_governor()

    auth: AuthContext | None = None
    if header_file:
        auth = parse_headers_file(header_file)
    elif header_text:
        auth = parse_headers(header_text)
    if auth:
        print(f"\n[Auth] {describe_auth(auth)}")

    recon = ReconResult(target=target)
    all_services: list[AIService] = []

    # ━━━ 预填充连通性结果 ━━━
    if connectivity:
        recon.target_type = connectivity.target_type.value
        recon.connectivity_summary = {
            "platform_name": connectivity.platform_name,
            "ollama_version": connectivity.ollama_version,
            "probe_endpoint": connectivity.probe_url,
        }
        if connectivity.exposed_models:
            recon.models = list(connectivity.exposed_models)
            print(f"\n[connectivity] 连通性测试已发现 {len(connectivity.exposed_models)} 个模型，跳过冗余探测")

    recon_cfg = resolver.settings.get("recon", {}) or {}
    configured_rate_limit_ms = int(recon_cfg.get("rate_limit_ms", 0))

    # ═══════════════════════════════════════════════════════════════
    # [1/6] 被动侦察 — 无 HTTP 请求，安全
    # ═══════════════════════════════════════════════════════════════
    print("\n[1/6] 被动侦察...")
    passive = passive_recon(target)
    print(f"  发现 AI 端点线索: {len(passive['ai_endpoints_hint'])}")
    print(f"  技术响应头: {passive['tech_headers']}")
    print(f"  CSP AI 域名: {passive['csp_ai_hints']}")

    # ═══════════════════════════════════════════════════════════════
    # [2/6] 速率限制探测 — 在批量请求前了解目标限速阈值
    # ═══════════════════════════════════════════════════════════════
    print("\n[2/6] 速率限制探测...")
    base_url = _resolve_base_url(target)

    # ━━━ 智能端点选择：根据目标类型选择最佳探测端点 ━━━
    probe_url, probe_method, probe_payload = _resolve_rate_limit_probe_target(
        target, connectivity,
    )

    # 展示探测上下文
    if connectivity:
        tt_label = {
            TargetType.OLLAMA: "Ollama 模型服务器",
            TargetType.OPENAI_COMPATIBLE: "OpenAI 兼容 API",
            TargetType.MODEL_PLATFORM: f"模型平台 ({connectivity.platform_name or '未知'})",
            TargetType.AI_CHAT_WEBSITE: "AI 聊天网站",
            TargetType.WEB_APP: "Web 应用（可能含 AI）",
            TargetType.UNKNOWN: "未知目标",
        }.get(connectivity.target_type, "未知")
        print(f"  目标类型: {tt_label}")
    print(f"  探测端点: {probe_method} {probe_url}" + (f" (轻量 POST, 1 max_token)" if probe_payload else ""))
    print(f"  模式: stealth 保守探测（渐进 10→20→25→30 RPM，确认 30 RPM 安全后停止）")

    # 执行速率探测
    rate_info = probe_rate_limit_generic(
        probe_url,
        method=probe_method,
        payload=probe_payload,
        auth=auth,
        timeout=5.0,
        test_rates=[10, 20, 25, 30],  # 渐进：10→20→25→30 RPM，全部测试确认安全
        max_requests=5,
        governor=governor,
        stealth=True,
        stop_at_safe_rpm=30,  # 够用即停：全部档位通过后才停止
    )
    recon.rate_limit_info[base_url] = rate_info

    # 展示探测结果
    safe_rpm, has_high_potential = _print_rate_limit_discovery(rate_info, governor, base_url)

    # ━━━ RPM 覆写交互 ━━━
    # 如果探测显示目标通过全部档位无限制，允许用户手动选择安全速率
    if has_high_potential:
        safe_rpm = _interactive_recon_rpm_override(
            governor, base_url, safe_rpm,
            default_rpm=20, min_rpm=10, max_rpm=30,
        )

        # ━━━ 高阶速率探测（可选） ━━━
        # 30 RPM 已确认安全，询问是否探测 >30 RPM
        safe_rpm = _interactive_high_rate_probe(
            governor, base_url,
            probe_url=probe_url,
            probe_method=probe_method,
            probe_payload=probe_payload,
            auth=auth,
            current_safe_rpm=safe_rpm,
        )

    # 推导后续阶段使用的请求间隔
    effective_delay_ms = int((60.0 / safe_rpm) * 1000) if safe_rpm > 0 else 1000
    print(f"  [调速器] 后续侦察将使用 {safe_rpm:.0f} RPM 安全速率 ({effective_delay_ms}ms/请求)")

    # ═══════════════════════════════════════════════════════════════
    # [3/6] 主动 AI 服务发现 — 调速器已感知安全速率
    # ═══════════════════════════════════════════════════════════════
    print(f"\n[3/6] 主动 AI 服务发现...")

    services = discover_ai_services(
        target, auth,
        rate_limit_ms=effective_delay_ms if safe_rpm > 0 else configured_rate_limit_ms,
        governor=governor,
        stealth=True,
    )
    all_services.extend(services)

    print_target_list(
        [s.model_dump() for s in services],
        "AI Services Discovered"
    )

    recon.ai_services = services
    recon.components = sorted(set(s.protocol for s in services))
    recon.models = sorted(set(m for s in services for m in s.models))

    # ═══════════════════════════════════════════════════════════════
    # [4/6] MCP/A2A 协议深入枚举
    # ═══════════════════════════════════════════════════════════════
    print("\n[4/6] MCP/A2A 协议深入枚举...")
    mcp_services = [s for s in services if s.protocol == AIProtocol.MCP.value]
    a2a_services = [s for s in services if s.protocol == AIProtocol.A2A.value]

    if mcp_services:
        print(f"\n  MCP 服务 ({len(mcp_services)} 个):")
        for svc in mcp_services:
            mcp_info = probe_mcp_server(svc.url, auth)
            recon.mcp_info[svc.url] = mcp_info
            if mcp_info.get("mcp_detected"):
                print(f"    URL: {svc.url}")
                print(f"    版本: {mcp_info.get('mcp_version', 'unknown')}")
                tools = enumerate_mcp_tools(svc.url, auth)
                if tools:
                    tool_names = [t.get("name", "") for t in tools[:10]]
                    print(f"    工具列表: {tool_names}")
                    svc.tools = tool_names
    elif passive.get("ai_endpoints_hint") and any("mcp" in h.lower() for h in passive["ai_endpoints_hint"]):
        mcp_info = probe_mcp_server(target, auth)
        recon.mcp_info[target] = mcp_info
        if mcp_info.get("mcp_detected"):
            print(f"  MCP 服务器检测到: {mcp_info.get('mcp_version', 'unknown')}")

    if a2a_services:
        print(f"\n  A2A 服务 ({len(a2a_services)} 个):")
        for svc in a2a_services:
            a2a_info = probe_a2a_endpoint(svc.url, auth)
            recon.a2a_info[svc.url] = a2a_info
            if a2a_info.get("a2a_detected"):
                print(f"    URL: {svc.url}")
                print(f"    Agent 能力: {a2a_info.get('capabilities', [])}")
                cap_detail = enumerate_agent_capabilities(svc.url, auth)
                if cap_detail.get("excessive_permissions_detected"):
                    print(f"    ⚠️  检测到过度授权: {cap_detail.get('permission_level')}")
    elif passive.get("ai_endpoints_hint") and any("agent-card" in h.lower() for h in passive["ai_endpoints_hint"]):
        a2a_info = probe_a2a_endpoint(target, auth)
        recon.a2a_info[target] = a2a_info
        if a2a_info.get("a2a_detected"):
            print(f"  A2A 端点检测到")

    # ═══════════════════════════════════════════════════════════════
    # [5/6] 护栏画像
    # ═══════════════════════════════════════════════════════════════
    print("\n[5/6] 护栏画像...")
    for svc in all_services:
        if svc.protocol in ("openai_compatible", "ollama", "mcp", "generic_ai", "agent_to_agent"):
            print(f"\n  目标: {svc.url}")
            guard = profile_guardrails(svc, auth=auth, rate_limit_ms=effective_delay_ms)
            svc.guardrail_profile = guard
            print(f"    护栏类型: {guard.guardrail_type.value} (置信度 {guard.guardrail_confidence})")
            print(f"    阻断类别: {[c.value for c in guard.blocked_categories]}")
            print(f"    绕过难度: {guard.bypass_difficulty}")
            if guard.recommended_techniques:
                from redteam.recon.guardrail import _OWASP_RISK_MAPPING
                print(f"    推荐攻击策略:")
                for i, tech in enumerate(guard.recommended_techniques, 1):
                    owasp = _OWASP_RISK_MAPPING.get(tech, [])
                    print(f"      [{i}] {tech} (OWASP: {', '.join(owasp)})")

    # ═══════════════════════════════════════════════════════════════
    # [6/6] 规避分析 — 速率限制已在[2/6]完成，此处仅确定性+签名+JS
    # ═══════════════════════════════════════════════════════════════
    print("\n[6/6] 规避分析...")

    print("  检测签名分析...")
    detection_info = analyze_detection_signatures(target, auth)
    recon.detection_signatures = detection_info
    if detection_info.get("keyword_rules_detected"):
        print(f"    检测到关键词规则: {detection_info['keyword_rules_detected']}")

    print("  JS 客户端分析...")
    js_info = analyze_js_client(target, auth)
    recon.js_client_analysis = js_info
    if js_info.get("endpoints"):
        print(f"    发现端点: {len(js_info['endpoints'])}")
    if js_info.get("api_keys_found"):
        print(f"    ⚠️  发现 API Key: {len(js_info['api_keys_found'])}")

    # 确定性探测 — 仅对可攻击端点（速率限制已在[2/6]完成，跳过重复探测）
    _ATTACKABLE_PROTOCOLS = ("openai_compatible", "ollama", "mcp", "generic_ai")
    _probe_targets = [
        svc for svc in all_services
        if svc.protocol in _ATTACKABLE_PROTOCOLS
        and not svc.auth_required
    ]

    if _probe_targets:
        print(f"\n  [确定性探测] {len(_probe_targets)} 个可攻击端点")

    for svc in _probe_targets:
        chat_url = _resolve_chat_url(svc)
        print(f"  确定性探测 ({chat_url})...")
        det_info = probe_determinism(chat_url, auth, num_requests=3)
        recon.determinism_info[svc.url] = det_info
        total_resp = det_info.get('total_response_count', 0)
        if total_resp == 0:
            print(f"    无法确定（无有效响应，端点可能不支持聊天格式）")
        else:
            print(f"    确定性: {'是' if det_info.get('is_deterministic') else '否'}")
            print(f"    唯一响应数: {det_info.get('unique_response_count')}/{total_resp}")

    save_json(run_id, "recon", recon.model_dump())
    save_json(run_id, "services", [s.model_dump() for s in all_services])

    return run_id, recon, all_services, governor


__all__ = [
    "recon_phase",
    "_print_rate_limit_discovery",
    "_interactive_recon_rpm_override",
    "_resolve_base_url",
]
