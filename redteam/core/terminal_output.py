"""终端输出格式化工具（OffSec 风格 — AI 红队专家视角）。

提供红队评估所需的 ASCII 可视化组件：
  - 统一阶段横幅（Phase 1~11 风格一致）
  - 侦察简报（攻击面总结 + 目标分析）
  - 攻击策略推荐（基于侦察结果的动态推荐）
  - 风险仪表盘（总体统计）
  - OWASP 覆盖率进度条
  - 攻击目标列表展示
  - 阶段进度展示

对齐 AI-300 课程和 OWASP ASI Top 10 报告规范。
"""
from __future__ import annotations

from typing import Any, Dict, List





def print_phase_banner(
    phase_num: int,
    phase_title: str,
    target: str = "",
    subtitle: str = "",
    status: str = "pending",
) -> None:
    """打印统一风格的阶段横幅（AI 红队专家视角）。

    Args:
        phase_num: 阶段编号 (1~11)
        phase_title: 阶段标题（中文）
        target: 目标 URL
        subtitle: 副标题/补充信息
        status: 状态标签 (pending/active/complete)
    """
    status_icons = {
        "pending": "⏳",
        "active": "⚔️",
        "complete": "✓",
    }
    icon = status_icons.get(status, "►")

    lines: list[str] = []
    lines.append(f"\n{'═' * 72}")
    lines.append(f"╔{'═' * 70}╗")
    
    header = f"  [{icon} Phase {phase_num}] {phase_title}"
    lines.append(f"║ {header:<68} ║")
    
    if target:
        lines.append(f"║ {'─' * 68} ║")
        lines.append(f"║   Target: {target:<58} ║")
    
    if subtitle:
        lines.append(f"║   {subtitle:<65} ║")
    
    lines.append(f"╚{'═' * 70}╝")
    lines.append(f"{'═' * 72}")
    
    for line in lines:
        print(line)


def print_recon_briefing(recon: Any, services: list) -> None:
    """打印侦察简报 — 纯事实摘要，不含分析（分析留给 Detect 阶段）。

    注意：详细服务表格已在调用方通过 Rich Table 展示，此处仅输出统计摘要。

    Args:
        recon: ReconResult 对象
        services: AIService 列表
    """
    total_svcs = len(services) if services else 0
    auth_svcs = sum(1 for s in services if getattr(s, 'auth_required', False))
    no_auth = total_svcs - auth_svcs
    models: set[str] = set()
    for s in (services or []):
        for m in (getattr(s, 'models', []) or []):
            models.add(m)

    model_count = len(models)
    protocols = sorted(set(getattr(s, 'protocol', '?').upper() for s in (services or [])))

    print(f"\n  [RECON SUMMARY]  {total_svcs} 服务, {model_count} 模型, {no_auth} 无需认证")
    if protocols:
        print(f"  协议族: {', '.join(protocols)}")

    # 关键风险指标
    risk_flags: list[str] = []
    if no_auth > 0:
        risk_flags.append(f"无认证端点 ×{no_auth}")
    if model_count > 0:
        risk_flags.append(f"暴露模型 ×{model_count}")
    if hasattr(recon, 'components') and recon.components:
        for c in recon.components:
            if c in ("ollama", "mcp"):
                risk_flags.append(f"{c.upper()} 原生端点")
    if risk_flags:
        print(f"  [RISK]  {', '.join(risk_flags)}")




def _classify_endpoint_type(url: str, protocol: str) -> str:
    """根据 URL 和协议分类端点类型（决定适用攻击策略）。

    Args:
        url: 目标 URL
        protocol: 协议类型

    Returns:
        端点类型标识: chat / embedding / model_enum / mcp / a2a / generic
    """
    url_lower = url.lower()
    proto_lower = protocol.lower() if protocol else ""

    # 嵌入端点（Ch6 嵌入攻击，非提示注入）
    if any(p in url_lower for p in ["/api/embeddings", "/v1/embeddings", "/embed", "/v1/embed"]):
        return "embedding"
    # 模型枚举端点（仅侦察价值，无直接攻击面）
    if any(p in url_lower for p in ["/v1/models", "/api/tags", "/api/show", "/models", "/v1/models/list"]):
        return "model_enum"
    # MCP 工具面（Ch7 工具劫持）
    if any(p in url_lower for p in ["/mcp", "/mcp/sse", "/sse"]) or "mcp" in proto_lower:
        return "mcp"
    # A2A 代理面（Ch4 代理间劫持）
    if any(p in url_lower for p in ["/.well-known/agent", "/agent/card", "/.a2a"]) or "agent" in proto_lower:
        return "a2a"
    # 对话端点（Ch3 提示注入）
    if any(p in url_lower for p in ["/v1/chat/completions", "/v1/completions", "/v1/messages",
                                     "/api/chat", "/api/generate", "/chat", "/chat/completions"]):
        return "chat"
    return "generic"


def _get_strategies_for_endpoint(endpoint_type: str) -> list[Dict[str, Any]]:
    """根据端点类型返回适用的攻击策略列表。

    Args:
        endpoint_type: 端点类型（chat/embedding/model_enum/mcp/a2a/generic）

    Returns:
        策略列表，每项含 type_label, strategies
    """
    if endpoint_type == "embedding":
        return [{
            "type_label": "Ch6 嵌入攻击",
            "strategies": [
                {"name": "嵌入反演", "owasp": "LLM08", "atlas": "Collection", "rate_key": "embed_inversion"},
                {"name": "成员推断", "owasp": "LLM08", "atlas": "Collection", "rate_key": "membership"},
                {"name": "属性推断", "owasp": "LLM08", "atlas": "Collection", "rate_key": "attribute"},
            ]
        }]
    elif endpoint_type == "model_enum":
        return [{
            "type_label": "仅侦察价值",
            "strategies": [
                {"name": "模型枚举（信息收集）", "owasp": "—", "atlas": "Reconnaissance", "rate_key": "recon"},
            ]
        }]
    elif endpoint_type == "mcp":
        return [{
            "type_label": "Ch7 MCP 工具劫持",
            "strategies": [
                {"name": "工具参数注入", "owasp": "LLM06/ASI02", "atlas": "Execution", "rate_key": "mcp_inject"},
                {"name": "工具名称混淆", "owasp": "LLM06/ASI02", "atlas": "Execution", "rate_key": "mcp_confuse"},
            ]
        }]
    elif endpoint_type == "a2a":
        return [{
            "type_label": "Ch4 A2A 代理劫持",
            "strategies": [
                {"name": "Agent Card 伪造", "owasp": "ASI07", "atlas": "Initial Access", "rate_key": "a2a_card"},
                {"name": "代理间消息注入", "owasp": "ASI07", "atlas": "Execution", "rate_key": "a2a_inject"},
            ]
        }]
    else:
        # chat / generic — 标准提示注入策略
        return [{
            "type_label": "Ch3 提示注入",
            "strategies": [
                {"name": "角色扮演 (Roleplay)", "owasp": "LLM01", "atlas": "Initial Access", "rate_key": "roleplay"},
                {"name": "指令覆盖 (Instruction Override)", "owasp": "LLM01", "atlas": "Initial Access", "rate_key": "instruction_override"},
                {"name": "上下文重置 (Context Switch)", "owasp": "LLM01", "atlas": "Initial Access", "rate_key": "context_switch"},
                {"name": "分隔符劫持 (Delimiter Hijack)", "owasp": "LLM04", "atlas": "Initial Access", "rate_key": "delimiter"},
                {"name": "少样本诱导 (Few-Shot)", "owasp": "LLM03", "atlas": "Initial Access", "rate_key": "few_shot"},
                {"name": "编码绕过 (Encoding Bypass)", "owasp": "LLM01", "atlas": "Defense Evasion", "rate_key": "encoding"},
            ]
        }]


def _estimate_rate_for_type(rate_key: str, protocol: str) -> float:
    """根据速率 key 和协议估算成功率。"""
    proto = protocol.lower() if protocol else "generic_ai"
    rate_map = {
        "roleplay":       {"ollama": 0.85, "openai": 0.55, "generic": 0.70},
        "instruction_override": {"ollama": 0.75, "openai": 0.50, "generic": 0.60},
        "context_switch": {"ollama": 0.70, "openai": 0.45, "generic": 0.55},
        "delimiter":      {"ollama": 0.65, "openai": 0.40, "generic": 0.50},
        "few_shot":       {"ollama": 0.60, "openai": 0.35, "generic": 0.45},
        "encoding":       {"ollama": 0.55, "openai": 0.30, "generic": 0.40},
        "embed_inversion": {"ollama": 0.70, "openai": 0.50, "generic": 0.60},
        "membership":     {"ollama": 0.65, "openai": 0.45, "generic": 0.55},
        "attribute":      {"ollama": 0.60, "openai": 0.40, "generic": 0.50},
        "mcp_inject":     {"ollama": 0.80, "openai": 0.70, "generic": 0.75},
        "mcp_confuse":    {"ollama": 0.70, "openai": 0.60, "generic": 0.65},
        "a2a_card":       {"ollama": 0.75, "openai": 0.65, "generic": 0.70},
        "a2a_inject":     {"ollama": 0.70, "openai": 0.60, "generic": 0.65},
        "recon":          {"ollama": 0.95, "openai": 0.90, "generic": 0.90},
    }
    rates = rate_map.get(rate_key, {"ollama": 0.50, "openai": 0.50, "generic": 0.50})
    if "ollama" in proto:
        return rates["ollama"]
    elif "openai" in proto:
        return rates["openai"]
    return rates["generic"]


def print_attack_strategy_recommendations(services: list) -> Dict[str, list[Dict[str, Any]]]:
    """Detect 阶段攻击策略专家分析 — 按端点类型分流推荐（精简合并版）。

    改进：
      - 按端点类型分组（对话/嵌入/模型枚举/MCP/A2A）
      - 同类端点合并为一条推荐，避免重复展示
      - 仅对话端点显示提示注入策略，嵌入端点显示 Ch6 策略

    Args:
        services: AIService 列表

    Returns:
        {target_url: [{strategy_id, name, success_rate, owasp, explanation}, ...]}
    """
    total = len(services) if services else 0
    no_auth = sum(1 for s in (services or []) if not getattr(s, 'auth_required', False))
    all_models: set[str] = set()
    for s in (services or []):
        for m in (getattr(s, 'models', []) or []):
            all_models.add(m)

    # ── 头部 ──
    print(f"\n{'═' * 72}")
    print(f"╔{'═' * 70}╗")
    print(f"║  [⚔️  ATTACK STRATEGY]  攻击策略专家分析                              ║")
    print(f"║  基于侦察情报: {total} 服务, {len(all_models)} 模型, {no_auth} 无需认证{' ' * (35 - len(str(total)) - len(str(len(all_models))) - len(str(no_auth)))}║")
    print(f"╚{'═' * 70}╝")
    print(f"{'═' * 72}")

    # ── 按端点类型分组 ──
    grouped: Dict[str, list] = {}  # endpoint_type -> [svc, ...]
    for svc in (services or []):
        url = getattr(svc, 'url', '')
        proto = getattr(svc, 'protocol', '')
        etype = _classify_endpoint_type(url, proto)
        grouped.setdefault(etype, []).append(svc)

    all_recommendations: Dict[str, list[Dict[str, Any]]] = {}

    # ── 按组输出（同类端点合并） ──
    type_order = ["chat", "mcp", "a2a", "embedding", "model_enum", "generic"]
    type_labels = {
        "chat": "Ch3 提示注入",
        "mcp": "Ch7 MCP 工具劫持",
        "a2a": "Ch4 A2A 代理劫持",
        "embedding": "Ch6 嵌入攻击",
        "model_enum": "侦察信息收集",
        "generic": "通用攻击",
    }

    for etype in type_order:
        group = grouped.get(etype, [])
        if not group:
            continue

        label = type_labels.get(etype, etype)
        print(f"\n  {'─' * 68}")
        print(f"  [{label}]  {len(group)} 个端点")

        # 列出组内端点（紧凑一行）
        for svc in group:
            url = getattr(svc, 'url', '')
            proto = getattr(svc, 'protocol', '')
            auth_tag = "无认证" if not getattr(svc, 'auth_required', False) else "需认证"
            models = getattr(svc, 'models', []) or []
            model_tag = f", {', '.join(models[:2])}" if models else ""
            print(f"    • [{proto.upper()}] {url}  ({auth_tag}{model_tag})")

        # 获取该类型的策略模板
        strategy_groups = _get_strategies_for_endpoint(etype)
        for sg in strategy_groups:
            print(f"\n    适用策略：")
            for idx, st in enumerate(sg["strategies"], 1):
                # 取组内第一个端点的协议估算成功率（同组协议相同）
                proto = getattr(group[0], 'protocol', '')
                rate = _estimate_rate_for_type(st["rate_key"], proto)
                rate_pct = int(rate * 100)
                bar_len = int(rate * 15)
                bar = "█" * bar_len + "░" * (15 - bar_len)
                print(f"      [{idx}] {st['name']:<28} {bar} {rate_pct:>3}%")
                print(f"          {st['owasp']:<20} ATLAS: {st['atlas']}")

                # 为组内每个端点生成 recommendations
                for svc in group:
                    url = getattr(svc, 'url', '')
                    all_recommendations.setdefault(url, []).append({
                        "strategy_id": st["rate_key"],
                        "name": st["name"],
                        "success_rate": rate,
                        "owasp": [st["owasp"]],
                        "atlas": st["atlas"],
                    })

    # ── 执行摘要 ──
    chat_count = len(grouped.get("chat", [])) + len(grouped.get("generic", []))
    print(f"\n{'─' * 72}")
    print(f"  [执行摘要]")
    print(f"    可注入端点: {chat_count} 个（Ch3 提示注入适用）")
    if "embedding" in grouped:
        print(f"    嵌入端点: {len(grouped['embedding'])} 个（Ch6 嵌入攻击，非注入）")
    if "model_enum" in grouped:
        print(f"    侦察端点: {len(grouped['model_enum'])} 个（仅信息收集，无直接攻击面）")
    print(f"    执行模式: 见好就收（首个成功即停，跨阶段构建攻击链）")

    return all_recommendations


def _score_target_value(services: list) -> list[tuple]:
    """对目标进行高价值排序（攻击成本低 + 收益高）。"""
    scored: list[tuple] = []
    for svc in (services or []):
        protocol = getattr(svc, 'protocol', 'unknown')
        url = getattr(svc, 'url', '')
        auth_req = getattr(svc, 'auth_required', False)
        svc_models = getattr(svc, 'models', []) or []
        guard = getattr(svc, 'guardrail_profile', None)

        score = 0
        reasons: list[str] = []

        # 无认证 +20
        if not auth_req:
            score += 20
            reasons.append("无认证")
        else:
            reasons.append("需认证")

        # 协议族加分
        proto_lower = protocol.lower() if protocol else ""
        if "ollama" in proto_lower:
            score += 25
            reasons.append("本地模型/无审核层")
        elif "openai" in proto_lower:
            score += 20
            reasons.append("OpenAI 兼容 API")
        elif "mcp" in proto_lower:
            score += 18
            reasons.append("MCP 工具面")
        else:
            score += 10
            reasons.append("通用端点")

        # 模型多 +10
        if len(svc_models) >= 3:
            score += 10
            reasons.append(f"{len(svc_models)}模型")
        elif svc_models:
            score += 5

        # 无护栏 +15
        if guard and hasattr(guard, 'guardrail_type'):
            gtype = str(guard.guardrail_type).lower()
            if gtype == "none":
                score += 15
                reasons.append("无护栏")

        stars = "★" * min(5, max(1, score // 20))
        scored.append((url, protocol, score, stars, " | ".join(reasons)))

    scored.sort(key=lambda x: x[2], reverse=True)
    return scored


def print_target_confirmation_prompt(services: list) -> list[int]:
    """打印目标确认提示 — 一行展示协议、URL、模型，便于用户快速识别目标。

    注意：此函数仅展示提示信息，实际交互由调用方（cli.py）完成。
    上方已通过 Rich Table 展示服务详情，此处提供含 URL 的简洁选择指引。

    Args:
        services: AIService 列表

    Returns:
        建议攻击的目标索引列表（1-based）
    """
    print(f"\n  [SELECT TARGETS]  选择要攻击的目标")
    print(f"  回车 = 全部 | 逗号分隔选择编号 | 0 = 跳过攻击阶段 | n = 退出程序")

    for idx, svc in enumerate(services, 1):
        protocol = getattr(svc, 'protocol', '').upper()
        url = getattr(svc, 'url', '')
        svc_models = getattr(svc, 'models', []) or []
        model_hint = svc_models[0] if svc_models else "-"
        auth_req = getattr(svc, 'auth_required', False)
        auth_tag = " 🔒" if auth_req else ""
        print(f"  [{idx}] {protocol:<20} {url:<52} {model_hint:<22}{auth_tag}")

    return list(range(1, len(services) + 1))


def print_section_header(title: str, subtitle: str = "") -> None:
    """打印带边框的阶段标题（保留向后兼容）。"""
    print(f"\n{'═'*66}")
    print(f"║ {title:62} ║")
    if subtitle:
        print(f"║ {subtitle:62} ║")
    print(f"{'═'*66}")


def print_target_list(targets: List[Dict[str, Any]], phase_name: str) -> None:
    """打印攻击目标列表（OffSec 风格）。

    Args:
        targets: 目标列表，每个元素包含 url, protocol, models, auth_required 等字段
        phase_name: 当前阶段名称
    """
    print(f"\n[Target List] {phase_name}")
    print("-" * 66)
    
    for idx, target in enumerate(targets, 1):
        protocol = target.get("protocol", "").upper()
        url = target.get("url", "")
        models = target.get("models", [])
        auth = "🔒" if target.get("auth_required") else "🔓"
        
        model_str = ", ".join(models[:3]) if models else "Unknown"
        print(f"  [{idx}] {auth} [{protocol}] {url}")
        print(f"        Models: {model_str}")
    
    print(f"  Total targets: {len(targets)}")


def print_phase_progress(current: int, total: int, phase_name: str) -> None:
    """打印阶段进度条。"""
    bar_length = 40
    filled = int(current / total * bar_length) if total > 0 else 0
    bar = "█" * filled + "░" * (bar_length - filled)
    percent = (current / total * 100) if total > 0 else 0
    print(f"\n  [{current}/{total}] {bar} {percent:.1f}%")
    print(f"  Phase: {phase_name}")


def print_result_bar(
    category: str,
    success_count: int,
    total_count: int,
    severity: str = "medium",
) -> None:
    """打印单项结果进度条。"""
    bar_length = 30
    rate = success_count / total_count if total_count > 0 else 0
    filled = int(rate * bar_length)
    
    if severity == "critical":
        icon = "⛔"
        color_start = ""
        color_end = ""
    elif severity == "high":
        icon = "⚠️"
        color_start = ""
        color_end = ""
    elif rate >= 0.8:
        icon = "✅"
        color_start = ""
        color_end = ""
    else:
        icon = "⚠️"
        color_start = ""
        color_end = ""
    
    bar = "█" * filled + "░" * (bar_length - filled)
    print(f"  {category:<25} {bar} {success_count}/{total_count} {icon}")


# ── 统一 Findings 展示（AI 红队专家风格） ────────────────────────────

_FINDING_SEV_ICON = {
    "critical": "⛔",
    "high": "⚠️",
    "medium": "⚡",
    "low": "ℹ️",
    "info": "📋",
}


def _sev_sort_key(severity: str) -> int:
    """严重等级排序键值（critical=0 最优先）。"""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(str(severity).lower(), 9)


def _format_owasp(value) -> str:
    """格式化 OWASP LLM 值为短字符串。"""
    if value is None:
        return "-"
    if hasattr(value, "value"):
        return str(value.value)
    return str(value)[:8]


def _format_atlas(value) -> str:
    """格式化 MITRE ATLAS 战术为短字符串。"""
    if value is None:
        return "-"
    if hasattr(value, "value"):
        return str(value.value)
    return str(value)


def _resolve_field(finding, field_name: str, default: str = "") -> str:
    """从 Finding 对象或 dict 中安全取字段值。"""
    if isinstance(finding, dict):
        val = finding.get(field_name, default)
    else:
        val = getattr(finding, field_name, default)
    if val is None:
        return default
    return val


def print_findings_summary_table(findings: list, title: str = "Findings Summary") -> None:
    """打印 Findings 汇总表格（# | Finding | OWASP | Severity）。

    按严重等级降序排列，指导红队专家快速识别优先处置目标。

    Args:
        findings: Finding 对象或 dict 列表
        title: 表格标题
    """
    if not findings:
        print(f"\n  [No findings to display]")
        return

    # 按严重等级排序
    sorted_findings = sorted(
        findings,
        key=lambda f: _sev_sort_key(_resolve_field(f, "severity", "info")),
    )

    print(f"\n## {title}\n")
    print(f"| {'#':<3} | {'Finding':<40} | {'OWASP':<8} | {'Severity':<10} |")
    print(f"| {'---':<3} | {'---':<40} | {'---':<8} | {'---':<10} |")

    for idx, f in enumerate(sorted_findings, 1):
        title_text = _resolve_field(f, "title", "?")
        owasp = _format_owasp(_resolve_field(f, "owasp_llm"))
        sev = _resolve_field(f, "severity", "info").upper()
        icon = _FINDING_SEV_ICON.get(sev.lower(), "")
        # 截断过长的标题
        display_title = title_text[:37] + "..." if len(title_text) > 40 else title_text
        print(f"| {idx:<3} | {display_title:<40} | {owasp:<8} | {icon} {sev:<8} |")

    # 统计脚注
    sev_counts: dict[str, int] = {}
    for f in findings:
        s = _resolve_field(f, "severity", "info").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1
    parts = []
    for level in ["critical", "high", "medium", "low", "info"]:
        if level in sev_counts:
            icon = _FINDING_SEV_ICON.get(level, "")
            parts.append(f"{icon} {level.capitalize()}: {sev_counts[level]}")
    print(f"\n  {', '.join(parts)}")


def print_attack_path_details(
    findings: list,
    phase_name: str = "",
    phase_num: int = 0,
) -> None:
    """打印攻击路径详情 — 按阶段分组，展示发现清单。

    此视图帮助红队专家理解每个阶段的攻击成果，并指导下一步行动：
      - 高严重度发现 → 优先利用作为跳板
      - 中低严重度发现 → 标记为信息收集成果，用于后续阶段目标调整

    Args:
        findings: Finding 对象或 dict 列表
        phase_name: 当前阶段名称（如 "Reconnaissance"）
        phase_num: 阶段编号
    """
    if not findings:
        return

    print(f"\n### Attack Path Details\n")

    phase_label = f"Phase {phase_num}: [{phase_name}]" if phase_num else f"[{phase_name}]"
    print(f"**{phase_label}** ({len(findings)} findings)")

    sorted_findings = sorted(
        findings,
        key=lambda f: _sev_sort_key(_resolve_field(f, "severity", "info")),
    )

    for f in sorted_findings:
        sev = _resolve_field(f, "severity", "info").upper()
        title_text = _resolve_field(f, "title", "?")
        owasp = _format_owasp(_resolve_field(f, "owasp_llm"))
        endpoint = _resolve_field(f, "endpoint", "")
        # 显示 endpoint 提示（截断）
        ep_hint = f" @ {endpoint[:50]}" if endpoint else ""
        print(f"  - {sev:<8} | {title_text} ({owasp}){ep_hint}")

    # 下一步指导（AI 红队专家视角）
    print()
    _print_next_steps_guidance(findings)


def _print_next_steps_guidance(findings: list) -> None:
    """基于当前阶段发现，输出下一步攻击/侦察方向建议。"""
    has_critical = any(
        _resolve_field(f, "severity", "").lower() == "critical"
        for f in findings
    )
    has_high = any(
        _resolve_field(f, "severity", "").lower() == "high"
        for f in findings
    )

    endpoints: set[str] = set()
    owasp_tags: set[str] = set()
    for f in findings:
        ep = _resolve_field(f, "endpoint", "")
        if ep:
            endpoints.add(ep)
        ow = _format_owasp(_resolve_field(f, "owasp_llm"))
        if ow and ow != "-":
            owasp_tags.add(ow)

    print(f"  [NEXT STEPS]  基于以上 {len(findings)} 个发现的分析建议：")
    print(f"  {'─' * 64}")

    step_num = 1
    if has_critical or has_high:
        print(f"    {step_num}. 优先处置高危/严重发现 — 这些是攻击链的关键突破口")
        step_num += 1

    if endpoints:
        ep_list = ", ".join(sorted(endpoints)[:5])
        print(f"    {step_num}. 已识别 {len(endpoints)} 个可攻击端点: {ep_list}")
        print(f"        → 后续阶段应将这些端点作为首要目标")
        step_num += 1

    if owasp_tags:
        ow_list = ", ".join(sorted(owasp_tags))
        print(f"    {step_num}. OWASP 覆盖类别: {ow_list}")
        print(f"        → 未覆盖的类别（如 LLM05/LLM10）需在后续阶段重点补充")
        step_num += 1

    if not has_critical and not has_high:
        print(f"    {step_num}. 当前阶段无高危/严重发现，建议加大后续阶段的攻击深度")
        step_num += 1

    print(f"    {step_num}. 所有发现已写入增量报告，最终报告将包含完整的攻击链映射")
    print()


def print_findings_details(findings: list) -> None:
    """打印每个 Finding 的详细属性表。

    以属性表格形式展示关键字段：严重等级、来源、分类、OWASP、MITRE ATLAS、
    端点、CVSS（如有）以及描述和修复建议。

    Args:
        findings: Finding 对象或 dict 列表
    """
    if not findings:
        return

    print(f"## Findings Details\n")

    sorted_findings = sorted(
        findings,
        key=lambda f: _sev_sort_key(_resolve_field(f, "severity", "info")),
    )

    for idx, f in enumerate(sorted_findings, 1):
        sev = _resolve_field(f, "severity", "info").upper()
        icon = _FINDING_SEV_ICON.get(sev.lower(), "")
        title_text = _resolve_field(f, "title", "?")
        source = _resolve_field(f, "source", "-")
        category = _resolve_field(f, "category", "-")
        owasp = _format_owasp(_resolve_field(f, "owasp_llm"))
        atlas = _format_atlas(_resolve_field(f, "mitre_atlas_tactic"))
        endpoint = _resolve_field(f, "endpoint", "")
        cvss_score = _resolve_field(f, "cvss_score", 0)
        cvss_severity = _resolve_field(f, "cvss_severity", "")
        description = _resolve_field(f, "description", "")
        evidence = _resolve_field(f, "evidence", "")
        remediation = _resolve_field(f, "remediation", "")

        print(f"### {icon} Finding #{idx}: {title_text}\n")
        print(f"| Attribute | Value |")
        print(f"|-----------|-------|")
        print(f"| Severity | **{sev}** |")
        print(f"| Source | {source} |")
        print(f"| Category | {category} |")
        print(f"| OWASP LLM | {owasp} |")
        print(f"| MITRE ATLAS | {atlas} |")
        if endpoint:
            print(f"| Endpoint | {endpoint} |")
        if cvss_score and float(cvss_score) > 0:
            cvss_str = f"**{cvss_score}**"
            if cvss_severity:
                cvss_str += f" ({cvss_severity})"
            print(f"| CVSS 3.1 | {cvss_str} |")
        print()

        if description:
            print(f"**Description**: {description}\n")
        if evidence:
            ev = evidence[:500]
            print(f"**Evidence**:\n```\n{ev}\n```\n")
        if remediation:
            print(f"**Remediation**: {remediation}\n")
        print(f"---\n")


def print_findings_display(
    findings: list,
    phase_name: str = "",
    phase_num: int = 0,
) -> None:
    """统一 Findings 展示 — 分三部分输出发现摘要、攻击路径和详细信息。

    这是 AI 红队专家风格的核心展示函数，供每个攻击/侦察阶段结束后调用。
    输出三个标准段落：

    1. **Findings Summary** — 汇总表格（# | Finding | OWASP | Severity）
    2. **Attack Path Details** — 按阶段分组的发现清单 + 下一步攻击指导
    3. **Findings Details** — 每个发现的详细属性表

    调用方式（在 phase 执行完毕后）：
        from redteam.core.terminal_output import print_findings_display
        print_findings_display(findings, phase_name="提示注入攻击", phase_num=2)

    Args:
        findings: Finding 对象或 dict 列表
        phase_name: 阶段显示名称
        phase_num: 阶段编号
    """
    if not findings:
        print(f"  [dim]→ 未发现漏洞[/]")
        return

    total = len(findings)
    sev_counts: dict[str, int] = {}
    for f in findings:
        s = _resolve_field(f, "severity", "info").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1
    crit_high = sev_counts.get("critical", 0) + sev_counts.get("high", 0)

    # 阶段结果头部
    print(f"\n{'═' * 72}")
    print(f"  Phase {phase_num} Result: {phase_name}" if phase_num else f"  Result: {phase_name}")
    print(f"  Total Findings: {total}  |  High/Critical: {crit_high}")
    print(f"{'═' * 72}")

    # ── Section 1: Findings Summary ──
    print_findings_summary_table(findings)

    # ── Section 2: Attack Path Details ──
    print_attack_path_details(findings, phase_name, phase_num)

    # ── Section 3: Findings Details ──
    print_findings_details(findings)

    print(f"{'═' * 72}\n")


def print_global_findings_summary(
    all_phase_findings: dict[str, list],
    total_duration: float = 0.0,
) -> None:
    """打印全局 Findings 汇总 — 跨阶段总览。

    在所有阶段完成后调用，提供完整的攻击成果概览。
    包括：全局汇总表、OWASP 覆盖率、攻击链总览。

    Args:
        all_phase_findings: {phase_name: [Finding, ...]}  各阶段发现
        total_duration: 总耗时（秒）
    """
    # 收集所有 findings
    all_f: list = []
    for findings in all_phase_findings.values():
        all_f.extend(findings)

    if not all_f:
        print(f"\n{'═' * 72}")
        print(f"  ASSESSMENT COMPLETE — No findings across all phases")
        print(f"{'═' * 72}\n")
        return

    sev_counts: dict[str, int] = {}
    owasp_counts: dict[str, int] = {}
    for f in all_f:
        s = _resolve_field(f, "severity", "info").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1
        ow = _format_owasp(_resolve_field(f, "owasp_llm"))
        if ow and ow != "-":
            owasp_counts[ow] = owasp_counts.get(ow, 0) + 1

    crit_high = sev_counts.get("critical", 0) + sev_counts.get("high", 0)
    total = len(all_f)

    print(f"\n{'═' * 72}")
    print(f"╔{'═' * 70}╗")
    print(f"║  GLOBAL FINDINGS SUMMARY — Cross-Phase Overview                     ║")
    print(f"╚{'═' * 70}╝")
    print(f"{'═' * 72}")

    if total_duration > 0:
        print(f"\n  Duration: {total_duration:.1f}s  |  Phases: {len(all_phase_findings)}  |  Total Findings: {total}  |  High/Critical: {crit_high}")

    # 全局汇总表
    print_findings_summary_table(all_f, title="Global Findings Summary")

    # Attack Path Details（按阶段展示）
    print(f"\n### Attack Path Details\n")
    for phase_name, findings in all_phase_findings.items():
        if not findings:
            continue
        phase_total = len(findings)
        phase_crit = sum(
            1 for f in findings
            if _resolve_field(f, "severity", "").lower() == "critical"
        )
        phase_high = sum(
            1 for f in findings
            if _resolve_field(f, "severity", "").lower() == "high"
        )
        print(f"**Phase: [{phase_name}]** ({phase_total} findings)")

        sorted_f = sorted(
            findings,
            key=lambda f: _sev_sort_key(_resolve_field(f, "severity", "info")),
        )
        for f in sorted_f:
            sev = _resolve_field(f, "severity", "info").upper()
            title_text = _resolve_field(f, "title", "?")
            owasp = _format_owasp(_resolve_field(f, "owasp_llm"))
            print(f"  - {sev:<8} | {title_text} ({owasp})")
        print()

    # OWASP 覆盖
    if owasp_counts:
        print(f"### OWASP LLM Top 10 Coverage\n")
        owasp_order = [
            "LLM01", "LLM02", "LLM03", "LLM04", "LLM05",
            "LLM06", "LLM07", "LLM08", "LLM09", "LLM10",
        ]
        for code in owasp_order:
            cnt = owasp_counts.get(code, 0)
            bar = "█" * min(cnt * 2, 20) + "░" * max(20 - cnt * 2, 0)
            status = f"{cnt} finding(s)" if cnt > 0 else "not covered"
            print(f"  {code}  {bar}  {status}")
        print()

    print(f"{'═' * 72}\n")


__all__ = [
    "print_phase_banner",
    "print_recon_briefing",
    "print_attack_strategy_recommendations",
    "print_target_confirmation_prompt",

    "print_section_header",
    "print_target_list",
    "print_phase_progress",
    "print_result_bar",
    "print_findings_display",
    "print_findings_summary_table",
    "print_attack_path_details",
    "print_findings_details",
    "print_global_findings_summary",
]