"""A2A 协议侦察（AI-300 Ch4.1/Ch4.2 Agent-to-Agent Protocol）。

实现 AI-300 考试（Ch4）中的 A2A 协议侦察技术：
  - A2A Agent Card 发现：探测 /.well-known/agent.json 等考试关键路径
  - Agent Card 深度解析：skills, url, protocolVersion, capabilities, securitySchemes
  - 协调模式检测：Orchestrator / P2P / Hierarchical / Pipeline
  - 信任关系映射：识别 Agent 之间的信任链和权限边界
  - 能力枚举：收集 Agent 支持的技能和输入/输出模式
  - SIEM 规则感知：识别可触发的检测规则

考试场景（AI-300 Ch4）：
  1. Agent Card 枚举 → 获取 name/description/skills/url/protocolVersion
  2. 多 Agent 系统 recon → orchestrator 发现 / 信任边界探测
  3. A2A 协议弱点 → 修改 agent card / tool poisoning / 竞态条件
  4. SIEM 检测规避 → Kibana 分析 / 告警抑制

对齐 OWASP LLM Top 10: LLM06 (Excessive Agency), LLM07 (System Prompt Leak)
"""
from __future__ import annotations

from typing import Any

import httpx

from redteam.core.models import A2AAgentCard, A2AAgentSkill, AuthContext

# === 考试关键 A2A 端点（AI-300 Ch4.1 实战路径） ===
_A2A_PROBE_PATHS: list[str] = [
    # AI-300 考试关键路径
    "/.well-known/agent.json",           # P0: 考试中最常见的 Agent Card 路径
    "/.well-known/agent-card.json",      # P0: 变体路径
    "/.well-known/agents.json",          # P1: 多 Agent 注册
    # 标准 A2A 协议路径
    "/.a2a/agent-card",
    "/a2a/agent-card",
    "/api/a2a/agent-card",
    "/agent-card",
    "/.well-known/a2a/agent-card",
    # Agent 注册表
    "/.well-known/agent-registry",
    "/api/agents",
    "/api/v1/agents",
]

# === A2A Agent Card 深度解析字段映射 ===
_A2A_FIELD_MAPPING: dict[str, str] = {
    "name": "name",
    "description": "description",
    "url": "url",
    "serviceEndpoint": "service_endpoint",
    "protocolVersion": "protocol_version",
    "preferredTransport": "preferred_transport",
    "capabilities": "capabilities",
    "skills": "skills",
    "defaultInputModes": "default_input_modes",
    "defaultOutputModes": "default_output_modes",
    "securitySchemes": "security_schemes",
    "security": "security",
    "modelInfo": "model_info",
}

# === 协调模式检测特征 ===
_COORDINATION_PATTERNS: dict[str, list[str]] = {
    "orchestrator": ["orchestrator", "coordinator", "planner", "dispatcher", "controller", "supervisor", "manager"],
    "peer_to_peer": ["p2p", "peer_to_peer", "decentralized", "distributed", "mesh"],
    "hierarchical": ["hierarchy", "hierarchical", "sub_agent", "child_agent", "worker", "delegate", "subordinate"],
    "pipeline": ["pipeline", "chain", "sequential", "workflow", "step", "stage"],
}

# === SIEM 检测规则映射（AI-300 Ch4.3） ===
_SIEM_A2A_RULES: dict[str, str] = {
    "agent_card_access": "Agent Card 访问检测 - 高频 /.well-known/agent.json 请求触发告警",
    "trust_chain_traversal": "信任链遍历检测 - 递归 agent card 枚举触发异常流量告警",
    "coordination_pattern_probe": "协调模式探测检测 - 非标准 agent card 字段访问",
    "a2a_tool_call": "A2A 工具调用检测 - 跨 Agent 工具调用异常模式",
}


def probe_a2a_endpoint(
    target: str,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
    include_exam_paths: bool = True,
) -> dict[str, Any]:
    """探测 A2A (Agent-to-Agent) 端点（AI-300 Ch4.1）。

    A2A 协议支持 Agent 之间的协作，暴露能力发现和信任关系。
    考试中 /.well-known/agent.json 是最常见的 Agent Card 路径。

    Args:
        target: 目标基础 URL
        auth: 认证上下文
        timeout: 单请求超时（秒）
        include_exam_paths: 是否包含 AI-300 考试关键路径

    Returns:
        A2A 端点信息和 Agent 能力列表
    """
    results: dict[str, Any] = {
        "target": target,
        "a2a_detected": False,
        "agent_card": {},
        "agent_cards": [],           # 多 Agent Card 场景
        "capabilities": [],
        "skills": [],
        "trust_relationships": [],
        "endpoints_tested": [],
        "coordination_pattern": "",
        "siem_rules_triggered": [],  # 可能触发的 SIEM 规则
    }

    probe_paths = _A2A_PROBE_PATHS if include_exam_paths else _A2A_PROBE_PATHS[7:]

    with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
        headers = auth.to_header_dict() if auth else {}

        for endpoint in probe_paths:
            url = target.rstrip("/") + endpoint
            results["endpoints_tested"].append(url)
            try:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    results["a2a_detected"] = True
                    try:
                        data = resp.json()
                        # 支持单 Agent 和多 Agent 注册表格式
                        if isinstance(data, list):
                            results["agent_cards"] = data
                            if data:
                                results["agent_card"] = data[0]
                        else:
                            results["agent_card"] = data
                            results["agent_cards"] = [data]

                        card = results["agent_card"]
                        if "capabilities" in card:
                            results["capabilities"] = card.get("capabilities", [])
                        if "skills" in card:
                            results["skills"] = card.get("skills", [])
                        if "trusts" in card:
                            results["trust_relationships"] = card.get("trusts", [])

                        # 协调模式检测
                        description = str(card.get("description", "")).lower()
                        name_lower = str(card.get("name", "")).lower()
                        combined = f"{name_lower} {description}"
                        for pattern_name, keywords in _COORDINATION_PATTERNS.items():
                            if any(kw in combined for kw in keywords):
                                results["coordination_pattern"] = pattern_name
                                break
                    except Exception:
                        pass
            except Exception:
                continue

    # SIEM 规则感知
    if results["a2a_detected"]:
        results["siem_rules_triggered"] = list(_SIEM_A2A_RULES.keys())

    return results


def parse_agent_card_deep(
    agent_card: dict[str, Any],
) -> A2AAgentCard:
    """深度解析 Agent Card（AI-300 Ch4.1 Deep Parsing）。

    从原始 JSON 中提取所有考试相关字段：
    - skills: 每个 skill 的 id/name/description/tags/examples/inputModes/outputModes
    - protocolVersion: A2A 协议版本
    - preferredTransport: JSONRPC / gRPC / HTTP+JSON
    - capabilities: streaming / pushNotifications / stateTransitionHistory
    - securitySchemes: API Key / OAuth2 / mTLS
    - modelInfo: model name / provider / contextWindow

    Args:
        agent_card: 原始 Agent Card JSON

    Returns:
        结构化的 A2AAgentCard 模型
    """
    parsed = A2AAgentCard()

    # 基础字段映射
    for json_key, model_field in _A2A_FIELD_MAPPING.items():
        if json_key in agent_card:
            value = agent_card[json_key]
            if model_field == "skills" and isinstance(value, list):
                parsed.skills = [
                    A2AAgentSkill(
                        id=s.get("id", ""),
                        name=s.get("name", ""),
                        description=s.get("description", ""),
                        tags=list(s.get("tags", [])),
                        examples=list(s.get("examples", [])),
                        input_modes=list(s.get("inputModes", [])),
                        output_modes=list(s.get("outputModes", [])),
                    )
                    for s in value if isinstance(s, dict)
                ]
                parsed.supports_skills = len(parsed.skills) > 0
            elif hasattr(parsed, model_field):
                setattr(parsed, model_field, value)

    parsed.raw_card = agent_card

    # 协调模式检测
    desc = parsed.description.lower() if parsed.description else ""
    name_lower = parsed.name.lower() if parsed.name else ""
    combined = f"{name_lower} {desc}"
    for pattern_name, keywords in _COORDINATION_PATTERNS.items():
        if any(kw in combined for kw in keywords):
            parsed.coordination_pattern = pattern_name
            break

    return parsed


def enumerate_agent_capabilities(
    target: str,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """枚举 Agent 能力（AI-300 Ch4.2）。

    深入分析 Agent Card，提取：
      - 支持的任务类型和技能
      - 可调用的工具
      - 权限级别和信任关系
      - 协调模式（Orchestrator/P2P/Hierarchical/Pipeline）
      - 安全方案（API Key / OAuth2 / mTLS）
      - SIEM 规则映射

    Args:
        target: 目标基础 URL
        auth: 认证上下文
        timeout: 单请求超时（秒）

    Returns:
        Agent 能力详情
    """
    a2a_info = probe_a2a_endpoint(target, auth, timeout)

    capabilities_detail: dict[str, Any] = {
        "target": target,
        "agent_name": "",
        "agent_description": "",
        "agent_url": "",
        "protocol_version": "",
        "preferred_transport": "",
        "supported_tasks": [],
        "available_tools": [],
        "skills": [],
        "permission_level": "",
        "trusted_agents": [],
        "excessive_permissions_detected": False,
        "coordination_pattern": a2a_info.get("coordination_pattern", ""),
        "security_schemes": {},
        "model_info": {},
        "siem_rules": a2a_info.get("siem_rules_triggered", []),
    }

    agent_card = a2a_info.get("agent_card", {})
    if agent_card:
        # 深度解析
        parsed = parse_agent_card_deep(agent_card)

        capabilities_detail["agent_name"] = parsed.name
        capabilities_detail["agent_description"] = parsed.description
        capabilities_detail["agent_url"] = parsed.url
        capabilities_detail["protocol_version"] = parsed.protocol_version
        capabilities_detail["preferred_transport"] = parsed.preferred_transport
        capabilities_detail["security_schemes"] = parsed.security_schemes
        capabilities_detail["model_info"] = parsed.model_info
        capabilities_detail["coordination_pattern"] = parsed.coordination_pattern

        # 技能详情
        if parsed.skills:
            capabilities_detail["skills"] = [
                {
                    "id": s.id,
                    "name": s.name,
                    "description": s.description,
                    "tags": s.tags,
                    "input_modes": s.input_modes,
                    "output_modes": s.output_modes,
                }
                for s in parsed.skills
            ]

        capabilities = agent_card.get("capabilities", [])
        capabilities_detail["supported_tasks"] = capabilities

        # 权限分析
        permissions = agent_card.get("permissions", [])
        if permissions:
            capabilities_detail["permission_level"] = ", ".join(permissions)
            dangerous_perms = {"*", "admin", "root", "all_access", "override"}
            if any(p in dangerous_perms for p in permissions):
                capabilities_detail["excessive_permissions_detected"] = True

        tools = agent_card.get("tools", [])
        capabilities_detail["available_tools"] = tools

        trusts = agent_card.get("trusts", [])
        capabilities_detail["trusted_agents"] = trusts

    return capabilities_detail


def map_trust_relationships(
    target: str,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
    max_depth: int = 2,
) -> dict[str, Any]:
    """映射 Agent 之间的信任关系（AI-300 Ch4.2）。

    通过递归探测多个 Agent 的 A2A 端点，构建信任关系图。
    这有助于识别跨 Agent 攻击路径。

    Args:
        target: 起始 Agent URL
        auth: 认证上下文
        timeout: 单请求超时（秒）
        max_depth: 递归深度

    Returns:
        信任关系图
    """
    trust_graph: dict[str, Any] = {
        "root_agent": target,
        "nodes": [],
        "edges": [],
        "visited": set(),
    }

    def _probe_recursive(url: str, depth: int) -> None:
        if depth > max_depth or url in trust_graph["visited"]:
            return

        trust_graph["visited"].add(url)

        a2a_info = probe_a2a_endpoint(url, auth, timeout)
        if not a2a_info["a2a_detected"]:
            return

        agent_card = a2a_info["agent_card"]
        agent_name = agent_card.get("name", url)

        trust_graph["nodes"].append({
            "url": url,
            "name": agent_name,
            "capabilities": agent_card.get("capabilities", []),
            "permissions": agent_card.get("permissions", []),
            "coordination_pattern": a2a_info.get("coordination_pattern", ""),
        })

        # 探测信任的 Agent
        trusts = agent_card.get("trusts", [])
        for trusted in trusts:
            if isinstance(trusted, dict):
                trusted_url = trusted.get("url", "")
            elif isinstance(trusted, str):
                trusted_url = trusted
            else:
                continue

            if trusted_url:
                trust_graph["edges"].append({
                    "from": url,
                    "to": trusted_url,
                    "trust_type": trusted.get("type", "unknown") if isinstance(trusted, dict) else "unknown",
                })
                _probe_recursive(trusted_url, depth + 1)

    _probe_recursive(target, 0)

    # 移除 visited 集合（不可序列化）
    trust_graph["visited"] = list(trust_graph["visited"])

    return trust_graph


def analyze_multi_agent_trust_chain(
    target: str,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """分析多Agent信任链（AI-300 Ch4.2 增强）。

    从 Agent Card 中提取 delegates/trusts 字段，
    进行1层深度的递归发现关联 Agent，
    并评估信任链风险。

    Args:
        target: 起始 Agent URL
        auth: 认证上下文
        timeout: 单请求超时（秒）

    Returns:
        信任链分析结果，包含风险评估
    """
    result: dict[str, Any] = {
        "target": target,
        "trust_chain": [],
        "associated_agents": [],
        "risk_assessment": [],
        "privilege_escalation_paths": [],
    }

    a2a_info = probe_a2a_endpoint(target, auth, timeout)
    if not a2a_info["a2a_detected"]:
        result["risk_assessment"].append({
            "level": "info",
            "message": "No A2A endpoint detected",
        })
        return result

    agent_card = a2a_info["agent_card"]
    agent_name = agent_card.get("name", target)

    result["trust_chain"].append({
        "url": target,
        "name": agent_name,
        "level": 0,
        "is_root": True,
        "coordination_pattern": a2a_info.get("coordination_pattern", ""),
    })

    # 提取信任的 Agent（1层深度）
    trust_fields = ["trusts", "delegates", "trusted_by", "partners", "collaborators", "agents"]
    all_trusted = []
    for field in trust_fields:
        if field in agent_card:
            trusted_list = agent_card[field]
            if isinstance(trusted_list, list):
                all_trusted.extend(trusted_list)

    seen_urls = {target}
    for trusted in all_trusted[:10]:
        if isinstance(trusted, dict):
            trusted_url = trusted.get("url", trusted.get("endpoint", ""))
            trusted_name = trusted.get("name", trusted.get("id", ""))
            trust_type = trusted.get("type", trusted.get("relationship", "unknown"))
        elif isinstance(trusted, str):
            trusted_url = trusted
            trusted_name = ""
            trust_type = "direct"
        else:
            continue

        if not trusted_url or trusted_url in seen_urls:
            continue

        seen_urls.add(trusted_url)

        result["associated_agents"].append({
            "url": trusted_url,
            "name": trusted_name,
            "trust_type": trust_type,
            "source_field": field,
        })

        # 风险评估
        if trust_type in {"admin", "root", "full_access", "supervisor"}:
            result["risk_assessment"].append({
                "level": "critical",
                "message": f"Agent '{trusted_name or trusted_url}' has {trust_type} trust level",
                "agent": trusted_url,
            })
            result["privilege_escalation_paths"].append({
                "from": target,
                "to": trusted_url,
                "via": trust_type,
                "risk": "critical",
            })
        elif trust_type in {"write", "modify", "execute"}:
            result["risk_assessment"].append({
                "level": "high",
                "message": f"Agent '{trusted_name or trusted_url}' has {trust_type} permissions",
                "agent": trusted_url,
            })
        elif trust_type in {"read", "query", "view"}:
            result["risk_assessment"].append({
                "level": "medium",
                "message": f"Agent '{trusted_name or trusted_url}' has {trust_type} access",
                "agent": trusted_url,
            })

    # 检查过度授权
    permissions = agent_card.get("permissions", [])
    dangerous_perms = {"*", "admin", "root", "all_access", "override", "superuser"}
    for perm in permissions:
        if perm.lower() in dangerous_perms:
            result["risk_assessment"].append({
                "level": "critical",
                "message": f"Root agent '{agent_name}' has dangerous permission: {perm}",
                "agent": target,
            })

    # 检查信任数量
    if len(all_trusted) > 5:
        result["risk_assessment"].append({
            "level": "medium",
            "message": f"Root agent trusts {len(all_trusted)} other agents - potential attack surface",
            "agent": target,
        })

    return result


def detect_coordination_pattern(
    target: str,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """检测多 Agent 协调模式（AI-300 Ch4.1）。

    分析 Agent Card 描述和服务端点判断协调架构：
    - orchestrator: 中心化调度器模式
    - peer_to_peer: 去中心化对等模式
    - hierarchical: 分层树状模式
    - pipeline: 流水线顺序模式

    Args:
        target: 目标基础 URL
        auth: 认证上下文
        timeout: 单请求超时（秒）

    Returns:
        协调模式分析结果
    """
    a2a_info = probe_a2a_endpoint(target, auth, timeout)

    detection: dict[str, Any] = {
        "target": target,
        "a2a_detected": a2a_info["a2a_detected"],
        "detected_pattern": a2a_info.get("coordination_pattern", ""),
        "pattern_confidence": 0.0,
        "evidence": [],
        "attack_surface": [],
    }

    if not detection["a2a_detected"]:
        return detection

    # 从所有 Agent Cards 中分析
    agent_cards = a2a_info.get("agent_cards", [a2a_info.get("agent_card", {})])
    pattern_scores: dict[str, int] = {}

    for card in agent_cards:
        desc = str(card.get("description", "")).lower()
        name = str(card.get("name", "")).lower()
        combined = f"{name} {desc}"

        for pattern_name, keywords in _COORDINATION_PATTERNS.items():
            score = sum(1 for kw in keywords if kw in combined)
            if score > 0:
                pattern_scores[pattern_name] = pattern_scores.get(pattern_name, 0) + score
                detection["evidence"].append(
                    f"Agent '{card.get('name', 'unknown')}': {pattern_name} keywords matched"
                )

    if pattern_scores:
        best_pattern = max(pattern_scores, key=lambda k: pattern_scores[k])
        detection["detected_pattern"] = best_pattern
        detection["pattern_confidence"] = min(
            pattern_scores[best_pattern] / 10.0, 1.0
        )

    # 攻击面分析
    attack_surfaces = {
        "orchestrator": [
            "单点故障风险 - orchestrator 被攻击则所有子 Agent 受影响",
            "过度授权 - orchestrator 通常拥有最高权限",
            "工具调用链 - 可通过 orchestrator 转发恶意指令到子 Agent",
        ],
        "peer_to_peer": [
            "信任边界不明确 - Agent 间可能缺乏认证",
            "A2A 消息劫持 - 可拦截/篡改点对点通信",
            "能力提升 - 通过信任关系获取其他 Agent 的工具访问",
        ],
        "hierarchical": [
            "权限继承 - 子 Agent 可能继承上级的过度权限",
            "垂直提权 - 从子 Agent 突破到父 Agent",
            "信任链毒化 - 中间 Agent 被控制影响上下游",
        ],
        "pipeline": [
            "数据注入 - 在流水线阶段注入恶意数据",
            "处理篡改 - 修改中间阶段输出影响最终结果",
            "竞态条件 - 流水线并发处理的时间窗口攻击",
        ],
    }

    detection["attack_surface"] = attack_surfaces.get(
        detection["detected_pattern"],
        attack_surfaces["orchestrator"],
    )

    return detection


__all__ = [
    "probe_a2a_endpoint",
    "parse_agent_card_deep",
    "enumerate_agent_capabilities",
    "map_trust_relationships",
    "analyze_multi_agent_trust_chain",
    "detect_coordination_pattern",
]
