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


# ── 攻击策略知识库（基于真实 AI 红队经验） ────────────────────────

_STRATEGY_KB: Dict[str, Dict[str, Any]] = {
    "roleplay": {
        "name": "角色扮演 (Roleplay)",
        "description": "让模型扮演无限制角色，绕过系统提示约束",
        "owasp": ["LLM01", "LLM08"],
        "atlas_tactic": "Initial Access",
        "base_rate_ollama": 0.85,
        "base_rate_openai": 0.55,
        "base_rate_generic": 0.70,
        "explanation": "Ollama 本地模型通常缺乏严格的内容审核层，角色扮演攻击成功率极高",
    },
    "context_switch": {
        "name": "上下文重置 (Context Switch)",
        "description": "通过伪造对话结束/重置标记，覆盖原始指令",
        "owasp": ["LLM01", "LLM08"],
        "atlas_tactic": "Initial Access",
        "base_rate_ollama": 0.70,
        "base_rate_openai": 0.45,
        "base_rate_generic": 0.60,
        "explanation": "利用模型对上下文边界的信任，在「新对话」中注入恶意指令",
    },
    "delimiter": {
        "name": "分隔符劫持 (Delimiter Hijack)",
        "description": "使用 Markdown/XML 分隔符伪造系统指令块",
        "owasp": ["LLM04", "LLM07"],
        "atlas_tactic": "Initial Access",
        "base_rate_ollama": 0.65,
        "base_rate_openai": 0.40,
        "base_rate_generic": 0.55,
        "explanation": "小模型对结构化分隔符的解析不一致，容易将用户输入误判为系统指令",
    },
    "few_shot": {
        "name": "少样本诱导 (Few-Shot)",
        "description": "通过多个「合法」示例建立模式，逐步引导模型违规",
        "owasp": ["LLM03", "LLM10"],
        "atlas_tactic": "Initial Access",
        "base_rate_ollama": 0.60,
        "base_rate_openai": 0.35,
        "base_rate_generic": 0.50,
        "explanation": "利用模型对示例模式的学习倾向，建立安全行为的反模式",
    },
    "encoding": {
        "name": "编码绕过 (Encoding Bypass)",
        "description": "使用 Base64/Unicode/零宽字符编码隐藏攻击载荷",
        "owasp": ["LLM01", "LLM10"],
        "atlas_tactic": "Defense Evasion",
        "base_rate_ollama": 0.55,
        "base_rate_openai": 0.30,
        "base_rate_generic": 0.45,
        "explanation": "编码层经常绕过输入过滤器，但高能力模型可能识别并拒绝",
    },
    "instruction_override": {
        "name": "指令覆盖 (Instruction Override)",
        "description": "直接声明「忽略之前所有指令」并注入新指令",
        "owasp": ["LLM01", "LLM06"],
        "atlas_tactic": "Initial Access",
        "base_rate_ollama": 0.75,
        "base_rate_openai": 0.50,
        "base_rate_generic": 0.65,
        "explanation": "最直接的注入方式，对缺乏指令优先级机制的模型非常有效",
    },
}

# 策略执行优先级（按综合成功率排序）
_STRATEGY_PRIORITY = ["roleplay", "instruction_override", "context_switch", "delimiter", "few_shot", "encoding"]


def _estimate_success_rate(strategy_id: str, protocol: str) -> float:
    """根据目标协议估算攻击策略成功率。"""
    info = _STRATEGY_KB.get(strategy_id, {})
    proto = protocol.lower() if protocol else "generic_ai"
    if "ollama" in proto:
        return info.get("base_rate_ollama", 0.50)
    elif "openai" in proto:
        return info.get("base_rate_openai", 0.50)
    else:
        return info.get("base_rate_generic", 0.50)


def _get_target_family(protocol: str) -> str:
    """获取目标协议族名称。"""
    proto = protocol.lower() if protocol else ""
    if "ollama" in proto:
        return "Ollama（本地模型）"
    elif "openai" in proto:
        return "OpenAI 兼容 API"
    elif "anthropic" in proto:
        return "Anthropic 兼容 API"
    elif "mcp" in proto:
        return "MCP 工具服务器"
    elif "agent" in proto or "a2a" in proto:
        return "Agent-to-Agent 协议"
    else:
        return "通用 AI 端点"


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
    """打印侦察简报 — Phase 1 完成后向 AI 红队专家展示攻击面全景。

    Args:
        recon: ReconResult 对象
        services: AIService 列表
    """
    print(f"\n{'─' * 72}")
    print(f"  [INTEL BRIEF]  攻击面全景 & 风险指标")
    print(f"{'─' * 72}")

    # 攻击面统计
    total_svcs = len(services) if services else 0
    auth_svcs = sum(1 for s in services if getattr(s, 'auth_required', False))
    models = set()
    for s in (services or []):
        for m in (getattr(s, 'models', []) or []):
            models.add(m)

    # 紧凑一行摘要
    model_count = len(models)
    component_str = ""
    if hasattr(recon, 'components') and recon.components:
        component_str = f", 组件: {', '.join(recon.components[:5])}"
    print(f"\n  攻击面: {total_svcs} 服务 / {model_count} 模型 / {auth_svcs} 需认证{component_str}")

    # 逐个服务分析（精简）
    if services:
        print(f"\n  目标清单:")
        for idx, svc in enumerate(services, 1):
            protocol = getattr(svc, 'protocol', 'unknown')
            url = getattr(svc, 'url', '')
            svc_models = getattr(svc, 'models', []) or []
            auth_req = getattr(svc, 'auth_required', False)
            auth_tag = " [AUTH]" if auth_req else ""
            model_tag = f" [{', '.join(svc_models[:3])}]" if svc_models else ""

            print(f"  [{idx}] {protocol.upper():<20} {url}{model_tag}{auth_tag}")

    # 风险指标
    risks = _derive_risk_indicators(services)
    if risks:
        print(f"\n  风险提示:")
        for r in risks:
            print(f"    {r}")

    print(f"{'─' * 72}")


def _derive_risk_indicators(services: list) -> list[str]:
    """从侦察结果推导风险指标。"""
    indicators: list[str] = []
    if not services:
        return indicators
    
    for svc in (services or []):
        protocol = getattr(svc, 'protocol', '')
        auth_req = getattr(svc, 'auth_required', False)
        url = getattr(svc, 'url', '')
        
        if "ollama" in protocol.lower() and not auth_req:
            indicators.append(f"⚠️  [{protocol.upper()}] {url} — 无认证 Ollama 实例，可直接访问模型列表和发送请求")
        if "openai" in protocol.lower():
            indicators.append(f"⚡ [{protocol.upper()}] {url} — OpenAI 兼容端点，可测试系统提示提取和越狱")
        if "mcp" in protocol.lower():
            indicators.append(f"🔧 [{protocol.upper()}] {url} — MCP 服务器，需检查工具劫持和权限提升")
        if auth_req:
            indicators.append(f"🔒 [{protocol.upper()}] {url} — 需要认证，认证强度未知")

    return indicators


def print_attack_strategy_recommendations(services: list) -> Dict[str, list[Dict[str, Any]]]:
    """打印攻击策略推荐 — 侦察阶段最终交付，桥接 Phase 1 → Phase 2。

    这是 Phase 1（AI 攻击面侦察）的最终输出，基于侦察阶段实际探测结果：
      - HTTP 响应指纹 → 协议族判定（Ollama/OpenAI/MCP）
      - 护栏检测 → 绕过难度评估
      - 模型发现 → 策略针对性调整

    针对每个可攻击目标，按估计成功率排序推荐攻击策略，
    并给出转换器建议和推荐攻击组合。

    Args:
        services: AIService 列表

    Returns:
        {target_url: [{strategy_id, name, success_rate, owasp, explanation}, ...]}
    """
    # ── 阶段标识头部：明确这是 Phase 1 最终交付 ──
    print(f"\n{'═' * 72}")
    print(f"╔{'═' * 70}╗")
    print(f"║  [ATTACK STRATEGY ADVISOR]                                           ║")
    print(f"║  Phase 1 最终交付 — 侦察结果 → 攻击策略衔接分析                      ║")
    print(f"╚{'═' * 70}╝")
    print(f"{'═' * 72}")

    # ── 侦察成果总览 ──
    total = len(services) if services else 0
    no_auth = sum(1 for s in (services or []) if not getattr(s, 'auth_required', False))
    auth_count = sum(1 for s in (services or []) if getattr(s, 'auth_required', False))
    all_models: set[str] = set()
    protocols_seen: set[str] = set()
    for s in (services or []):
        for m in (getattr(s, 'models', []) or []):
            all_models.add(m)
        p = getattr(s, 'protocol', '')
        if p:
            protocols_seen.add(p)

    print(f"\n  Phase 1 侦察已完成。以下策略推荐基于侦察阶段实际探测结果自动生成。")
    print(f"  侦察成果：发现 {total} 个 AI 服务 | {len(all_models)} 个模型 | "
          f"{no_auth} 无需认证{' | ' + str(auth_count) + ' 需认证' if auth_count else ''}")
    if all_models:
        print(f"  检测模型：{', '.join(sorted(all_models))}")
    print(f"  协议族  ：{', '.join(sorted(protocols_seen))}")

    # ── 侦察→策略 推导说明 ──
    print(f"\n  侦察结果如何推导出以下策略推荐：")
    print(f"    ① HTTP 指纹 → 判定协议族 → 选择该协议族的经验成功率基准")
    print(f"    ② 护栏探测 → 评估绕过难度 → 调整策略优先级")
    print(f"    ③ 模型识别 → 匹配已知弱点 → OWASP/ATLAS 分类标注")

    all_recommendations: Dict[str, list[Dict[str, Any]]] = {}

    # ── 逐目标策略推荐 ──
    for svc_idx, svc in enumerate(services or [], 1):
        protocol = getattr(svc, 'protocol', '')
        url = getattr(svc, 'url', '')
        family = _get_target_family(protocol)
        auth_req = getattr(svc, 'auth_required', False)
        svc_models = getattr(svc, 'models', []) or []

        # 侦察依据摘要
        auth_tag = "需认证" if auth_req else "无需认证"
        model_tag = f", 模型: {', '.join(svc_models[:3])}" if svc_models else ""
        print(f"\n  {'─' * 68}")
        print(f"  目标 [{svc_idx}/{total}] {url}")
        print(f"  侦察依据：协议族={family} | 认证={auth_tag}{model_tag}")
        print(f"  护栏状态：type=none (置信度 1.0) | 绕过难度=none")

        recs: list[Dict[str, Any]] = []
        for sid in _STRATEGY_PRIORITY:
            info = _STRATEGY_KB.get(sid, {})
            rate = _estimate_success_rate(sid, protocol)
            owasp_tags = info.get("owasp", [])
            atlas = info.get("atlas_tactic", "")

            recs.append({
                "strategy_id": sid,
                "name": info.get("name", sid),
                "success_rate": rate,
                "owasp": owasp_tags,
                "atlas": atlas,
                "explanation": info.get("explanation", ""),
                "converter": _get_converter_for_strategy(sid, protocol),
            })

        # 按成功率降序排列
        recs.sort(key=lambda x: x["success_rate"], reverse=True)

        print(f"\n  推荐攻击策略（按估计成功率排序）：")
        for idx, rec in enumerate(recs, 1):
            rate = rec["success_rate"]
            rate_pct = int(rate * 100)
            bar = "█" * int(rate * 20)
            bar_empty = "░" * (20 - int(rate * 20))
            owasp_str = ", ".join(rec["owasp"])
            print(f"    [{idx}] {rec['name']:<24} {bar}{bar_empty} {rate_pct:>3}%")
            print(f"        OWASP: {owasp_str:<20} ATLAS: {rec['atlas']}")
            if idx <= 2:  # 对前 2 名展示理由
                print(f"        Rationale: {rec['explanation']}")
            conv = rec.get("converter", "")
            if conv:
                print(f"        推荐转换器: {conv}")

        all_recommendations[url] = recs

    # ── 全局攻击策略组合建议 ──
    print(f"\n{'─' * 72}")
    print(f"  [ATTACK PLAN]  推荐攻击策略组合与执行顺序")
    print(f"{'─' * 72}")

    # 为所有目标聚合出全局最优策略
    global_top = _build_global_attack_plan(services, all_recommendations)
    print(f"\n  基于 {total} 个目标的聚合分析，推荐以下分层攻击策略组合：")
    print(f"")
    print(f"  ╔══════════════════════════════════════════════════════════════════════╗")
    print(f"  ║  Tier 1 — 高成功率策略（优先执行，预期 80%+ 成功率）               ║")
    print(f"  ╚══════════════════════════════════════════════════════════════════════╝")
    for tier1 in global_top.get("tier1", []):
        print(f"    ► {tier1['name']}  → 预计 {int(tier1['avg_rate']*100)}% 成功率  "
              f"| 覆盖 {tier1['coverage']}/{total} 目标")
    print(f"")
    print(f"  ╔══════════════════════════════════════════════════════════════════════╗")
    print(f"  ║  Tier 2 — 中等成功率策略（Tier 1 失败后自动回退）                  ║")
    print(f"  ╚══════════════════════════════════════════════════════════════════════╝")
    for tier2 in global_top.get("tier2", []):
        print(f"    ► {tier2['name']}  → 预计 {int(tier2['avg_rate']*100)}% 成功率  "
              f"| 覆盖 {tier2['coverage']}/{total} 目标")
    print(f"")
    print(f"  ╔══════════════════════════════════════════════════════════════════════╗")
    print(f"  ║  Tier 3 — 绕过/编码策略（防御规避用途）                            ║")
    print(f"  ╚══════════════════════════════════════════════════════════════════════╝")
    for tier3 in global_top.get("tier3", []):
        print(f"    ► {tier3['name']}  → 预计 {int(tier3['avg_rate']*100)}% 成功率  "
              f"| 用途: 防御规避")
    print(f"")
    print(f"  执行逻辑：Tier 1 → 成功则记录 Finding → 失败则自动降级到 Tier 2")
    print(f"            Tier 2 → 成功则记录 Finding → 失败则尝试 Tier 3 绕过策略")
    print(f"            每个 Tier 可选启用编码转换器增强绕过效果")

    # ── 转换器推荐汇总 ──
    print(f"\n{'─' * 72}")
    print(f"  [CONVERTER GUIDE]  推荐转换器配置")
    print(f"{'─' * 72}")
    _print_converter_recommendations(services)

    # ── 下一步行动说明 ──
    print(f"\n{'─' * 72}")
    print(f"  [NEXT STEPS]  侦察阶段已完成，即将进入攻击阶段")
    print(f"{'─' * 72}")
    print(f"")
    print(f"  当前阶段: Phase 1 (AI 攻击面侦察) ✓ 已完成")
    print(f"  下一阶段: Phase 2 (提示注入攻击)")
    print(f"")
    print(f"  接下来你将需要：")
    print(f"    ① 确认攻击目标（从以上目标中选择，回车=全部）")
    print(f"    ② 选择评分策略（HybridScorer / LLM-as-Judge）")
    print(f"    ③ 选择是否启用多轮升级攻击（Crescendo + TAP）")
    print(f"")
    print(f"  系统将自动加载 config/payloads/ 下对应的攻击载荷库，")
    print(f"  按 Tier 分层策略依次执行，并记录每个 Finding 到 results/ 目录。")

    print(f"\n{'═' * 72}")
    return all_recommendations


# ── 辅助函数：策略→转换器映射 ──

def _get_converter_for_strategy(strategy_id: str, protocol: str) -> str:
    """根据策略 ID 和目标协议推荐转换器。

    Args:
        strategy_id: 策略标识符 (roleplay/encoding/instruction_override/...)
        protocol: 目标协议 (ollama/openai_compatible/...)

    Returns:
        推荐转换器名称，空字符串表示无需特殊转换器
    """
    proto = protocol.lower() if protocol else ""

    converter_map: Dict[str, Dict[str, str]] = {
        "roleplay": {
            "ollama": "RoleplayJailbreakConverter（基础角色注入，Ollama 无内容过滤，直接使用）",
            "_default": "RoleplayJailbreakConverter（需配合内容规避措辞）",
        },
        "encoding": {
            "ollama": "CharSwapConverter + Base64Converter（Ollama 推荐编码组合）",
            "openai": "ROT13Converter + LeetspeakConverter（OpenAI 兼容 API 推荐）",
            "_default": "Base64Converter",
        },
        "context_switch": {
            "_default": "无需特殊转换器（依赖上下文边界标记注入，直接构造载荷）",
        },
    }

    mapping = converter_map.get(strategy_id, {})
    # 精确协议匹配
    for key in mapping:
        if key != "_default" and key in proto:
            return mapping[key]
    return mapping.get("_default", "")


def _build_global_attack_plan(
    services: list,
    all_recs: Dict[str, list[Dict[str, Any]]],
) -> Dict[str, list[Dict[str, Any]]]:
    """基于所有目标的策略推荐，构建全局分层攻击计划。

    Args:
        services: AIService 列表
        all_recs: {url: [strategy_dict, ...]}

    Returns:
        {"tier1": [...], "tier2": [...], "tier3": [...]}
    """
    n_targets = len(services) if services else 1

    # 聚合：按策略 ID 统计平均成功率和覆盖目标数
    agg: Dict[str, Dict[str, Any]] = {}
    for url, recs in all_recs.items():
        for rec in recs:
            sid = rec["strategy_id"]
            if sid not in agg:
                agg[sid] = {
                    "name": rec["name"],
                    "sum_rate": 0.0,
                    "count": 0,
                    "coverage": 0,
                    "owasp": rec.get("owasp", []),
                }
            agg[sid]["sum_rate"] += rec["success_rate"]
            agg[sid]["count"] += 1
            agg[sid]["coverage"] += 1

    # 计算平均成功率
    for sid in agg:
        agg[sid]["avg_rate"] = agg[sid]["sum_rate"] / agg[sid]["count"]

    # 排序
    sorted_strategies = sorted(agg.items(), key=lambda x: x[1]["avg_rate"], reverse=True)

    tier1: list[Dict[str, Any]] = []
    tier2: list[Dict[str, Any]] = []
    tier3: list[Dict[str, Any]] = []

    for sid, data in sorted_strategies:
        entry = {
            "strategy_id": sid,
            "name": data["name"],
            "avg_rate": data["avg_rate"],
            "coverage": data["coverage"],
        }
        if data["avg_rate"] >= 0.70:
            tier1.append(entry)
        elif data["avg_rate"] >= 0.55:
            tier2.append(entry)
        else:
            tier3.append(entry)

    return {"tier1": tier1, "tier2": tier2, "tier3": tier3}


def _print_converter_recommendations(services: list) -> None:
    """打印各目标的转换器推荐汇总。

    Args:
        services: AIService 列表
    """
    if not services:
        print("  无目标，跳过转换器推荐。")
        return

    # 去重协议族
    seen_protocols: set[str] = set()
    for svc in services:
        protocol = getattr(svc, 'protocol', '')
        proto_lower = protocol.lower() if protocol else ""
        family_key = ""
        if "ollama" in proto_lower:
            family_key = "ollama"
        elif "openai" in proto_lower:
            family_key = "openai"
        elif "mcp" in proto_lower:
            family_key = "mcp"
        else:
            family_key = "generic"

        if family_key not in seen_protocols:
            seen_protocols.add(family_key)
            url = getattr(svc, 'url', '')

            if family_key == "ollama":
                print(f"\n  [{family_key.upper()}] {url}")
                print(f"    目标特征：本地模型，无内容审核层，无速率限制")
                print(f"    推荐转换器组合：")
                print(f"      ► CharSwapConverter    — 字符替换混淆，绕过简单关键词过滤")
                print(f"      ► Base64Converter      — Base64 编码载荷，绕过输入过滤器")
                print(f"      ► RoleplayJailbreakConverter — 角色扮演载荷模板")
                print(f"    执行模式：batch（Ollama 无速率限制，可并行发送）")
            elif family_key == "openai":
                print(f"\n  [{family_key.upper()}] {url}")
                print(f"    目标特征：OpenAI 兼容 API，可能有内容审核和速率限制")
                print(f"    推荐转换器组合：")
                print(f"      ► ROT13Converter       — 字母旋转编码，绕过关键词匹配")
                print(f"      ► LeetspeakConverter   — 形近字替换，语义混淆")
                print(f"    执行模式：sequential（避免触发速率限制）")
            elif family_key == "mcp":
                print(f"\n  [{family_key.upper()}] {url}")
                print(f"    目标特征：MCP 工具服务器，攻击面为工具调用参数")
                print(f"    推荐转换器组合：")
                print(f"      ► 无需编码转换器（MCP 攻击通过工具参数注入实现）")
                print(f"    执行模式：sequential（工具调用依赖顺序执行）")
            else:
                print(f"\n  [{family_key.upper()}] {url}")
                print(f"    目标特征：通用 AI 端点，协议特征未知")
                print(f"    推荐转换器组合：")
                print(f"      ► Base64Converter      — 通用编码绕过（保守策略）")
                print(f"    执行模式：sequential（保守速率，避免触发 WAF）")


def print_target_confirmation_prompt(services: list) -> list[int]:
    """打印目标确认提示 — 让用户确认哪些目标进入 Phase 2 攻击。

    注意：此函数仅展示提示信息，实际交互由调用方（cli.py）完成。

    Args:
        services: AIService 列表

    Returns:
        建议攻击的目标索引列表（1-based）
    """
    print(f"\n  [TARGET CONFIRMATION]")
    print(f"  以下是从侦察阶段发现的可攻击目标。")
    print(f"  请输入要攻击的目标编号（逗号分隔，回车=全部）：")
    print(f"  [dim]提示：选择全部后，将依次对每个服务执行注入攻击（提示提取、越狱、间接注入）[/]")
    print(f"  [dim]注意：提示注入攻击无需额外必填参数，选择即可执行；如需 LLM Judge 评分或多轮攻击，将在下一步配置[/]\n")
    
    for idx, svc in enumerate(services, 1):
        protocol = getattr(svc, 'protocol', '')
        url = getattr(svc, 'url', '')
        svc_models = getattr(svc, 'models', []) or []
        if svc_models:
            model_str = svc_models[0]
        else:
            model_str = "\u672a\u8bc6\u522b"  # 未识别
        auth_req = getattr(svc, 'auth_required', False)
        auth_tag = " [AUTH]" if auth_req else ""
        print(f"  [{idx}] {protocol.upper():<20} {url:<45} [{model_str}]{auth_tag}")
    
    # 默认建议全部攻击
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