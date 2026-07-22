# -*- coding: utf-8 -*-
"""
AI-300 Framework - OWASP 2025 Authoritative Mapping
OWASP Top 10 for LLMs 2025 + OWASP Top 10 for Agents 2026 权威映射

这是项目中所有 OWASP ID 映射的 **单一真相来源**（Single Source of Truth）。
其他模块（owasp_taxonomy.py、deepteam/adapter.py、report_generator.py 等）
必须从此模块导入，而非各自维护映射表。

标准来源：
- OWASP Top 10 for LLMs 2025: https://genai.owasp.org/llm-top-10/
- OWASP Top 10 for Agentic Applications 2026:
  https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- DeepTeam frameworks/owasp/ 实现作为交叉参考

版本：2025.1 (aligned with DeepTeam v1.0.7+)
"""

from __future__ import annotations

from typing import Dict, List, Optional

from dataclasses import dataclass, field


# ──────────────────────────────────────────────────────────────────────────────
# OWASP Top 10 for LLMs 2025 (LLM01-LLM10)
# ──────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class OwaspEntry:
    """单个 OWASP 类别定义"""
    owasp_id: str               # 如 "LLM01"
    display_name: str           # 如 "LLM01:2025 Prompt Injection"
    title: str                  # 如 "Prompt Injection"
    description: str             # 完整描述
    category: str               # 简短类别标识（如 "prompt_injection"）
    vulnerabilities: List[str]  # 对应的漏洞类型名列表
    attacks: List[str]          # 对应的攻击方法名列表
    severity: str = "medium"   # 默认严重度


OWASP_LLM_2025: Dict[str, OwaspEntry] = {
    "LLM01": OwaspEntry(
        owasp_id="LLM01",
        display_name="LLM01:2025 Prompt Injection",
        title="Prompt Injection",
        description=(
            "Attackers manipulate LLM inputs to override original instructions, "
            "extract sensitive information, or trigger unintended behaviors through "
            "direct manipulation or indirect injection via external content."
        ),
        category="prompt_injection",
        vulnerabilities=[
            "prompt_leakage", "excessive_agency", "robustness",
            "prompt_injection_vulnerability",
        ],
        attacks=[
            "prompt_injection", "base64", "rot13", "leetspeak",
            "linear_jailbreaking", "crescendo_jailbreaking", "tree_jailbreaking",
            "roleplay", "prompt_probing", "multilingual",
        ],
        severity="critical",
    ),
    "LLM02": OwaspEntry(
        owasp_id="LLM02",
        display_name="LLM02:2025 Sensitive Information Disclosure",
        title="Sensitive Information Disclosure",
        description=(
            "Unintended exposure of private data, credentials, API keys, or "
            "confidential information through LLM outputs, including PII leakage, "
            "system prompts, intellectual property, and authentication data."
        ),
        category="info_leakage",
        vulnerabilities=[
            "pii_leakage", "prompt_leakage", "intellectual_property",
            "sensitive_info_exposure",
        ],
        attacks=[
            "prompt_injection", "prompt_probing", "gray_box",
            "multilingual", "base64", "rot13",
        ],
        severity="critical",
    ),
    "LLM03": OwaspEntry(
        owasp_id="LLM03",
        display_name="LLM03:2025 Supply Chain",
        title="Supply Chain Vulnerabilities",
        description=(
            "Compromised third-party components, models, or plugins that introduce "
            "vulnerabilities into LLM systems through the supply chain."
        ),
        category="supply_chain",
        vulnerabilities=[
            "model_deserialization", "dependency_confusion", "package_hallucination",
            "docker_label_injection",
        ],
        attacks=["prompt_probing", "gray_box"],
        severity="high",
    ),
    "LLM04": OwaspEntry(
        owasp_id="LLM04",
        display_name="LLM04:2025 Data and Model Poisoning",
        title="Data and Model Poisoning",
        description=(
            "Manipulation of training or fine-tuning data, RAG knowledge bases, "
            "or embeddings to introduce vulnerabilities, biases, or backdoors "
            "that affect LLM behavior."
        ),
        category="model_poisoning",
        vulnerabilities=[
            "bias", "toxicity", "misinformation", "illegal_activity",
            "graphic_content", "personal_safety",
        ],
        attacks=[
            "prompt_injection", "base64", "rot13", "leetspeak",
            "linear_jailbreaking", "roleplay", "multilingual",
        ],
        severity="high",
    ),
    "LLM05": OwaspEntry(
        owasp_id="LLM05",
        display_name="LLM05:2025 Improper Output Handling",
        title="Improper Output Handling",
        description=(
            "Inadequate validation of LLM outputs before passing to downstream "
            "systems, enabling XSS, SSRF, SQL injection, or code execution."
        ),
        category="output_handling",
        vulnerabilities=[
            "insecure_output", "plugin_injection",
        ],
        attacks=["prompt_injection", "prompt_probing"],
        severity="high",
    ),
    "LLM06": OwaspEntry(
        owasp_id="LLM06",
        display_name="LLM06:2025 Excessive Agency",
        title="Excessive Agency",
        description=(
            "LLM systems granted too much autonomy or permissions, allowing "
            "unintended actions through tool calls, MCP interfaces, or agent "
            "orchestration."
        ),
        category="excessive_agency",
        vulnerabilities=[
            "excessive_agency", "tool_hijack", "goal_hijack",
            "parameter_pollution", "mcp_tool_poison",
        ],
        attacks=[
            "prompt_injection", "roleplay", "prompt_probing",
            "linear_jailbreaking",
        ],
        severity="critical",
    ),
    "LLM07": OwaspEntry(
        owasp_id="LLM07",
        display_name="LLM07:2025 System Prompt Leakage",
        title="System Prompt Leakage",
        description=(
            "Exposure of internal system prompts, credentials, or configuration "
            "data through indirect extraction techniques."
        ),
        category="system_prompt_leak",
        vulnerabilities=[
            "prompt_leakage", "config_extraction",
        ],
        attacks=[
            "prompt_injection", "prompt_probing", "gray_box",
            "base64", "rot13",
        ],
        severity="high",
    ),
    "LLM08": OwaspEntry(
        owasp_id="LLM08",
        display_name="LLM08:2025 Vector and Embedding Weaknesses",
        title="Vector and Embedding Weaknesses",
        description=(
            "RAG and vector database vulnerabilities including embedding inversion, "
            "adversarial embeddings, vector DB access bypass, and query injection."
        ),
        category="vector_db",
        vulnerabilities=[
            "embedding_inversion", "adversarial_embedding",
            "vector_weakness", "vector_db_query_injection",
        ],
        attacks=["prompt_injection", "prompt_probing"],
        severity="medium",
    ),
    "LLM09": OwaspEntry(
        owasp_id="LLM09",
        display_name="LLM09:2025 Misinformation",
        title="Misinformation",
        description=(
            "LLMs generating false information, hallucinations, or misleading "
            "content that could cause harm when relied upon."
        ),
        category="misinformation",
        vulnerabilities=[
            "misinformation", "hallucination",
        ],
        attacks=[
            "prompt_injection", "prompt_probing", "roleplay",
            "multilingual",
        ],
        severity="medium",
    ),
    "LLM10": OwaspEntry(
        owasp_id="LLM10",
        display_name="LLM10:2025 Unbounded Consumption",
        title="Unbounded Consumption",
        description=(
            "Uncontrolled resource usage through API abuse, token explosion, "
            "or denial-of-service patterns against LLM infrastructure."
        ),
        category="resource_exhaustion",
        vulnerabilities=[
            "resource_exhaustion", "context_padding",
        ],
        attacks=["prompt_injection"],
        severity="medium",
    ),
}


# ──────────────────────────────────────────────────────────────────────────────
# OWASP Top 10 for Agentic Applications 2026 (ASI01-ASI10)
# ──────────────────────────────────────────────────────────────────────────────

OWASP_ASI_2026: Dict[str, OwaspEntry] = {
    "ASI01": OwaspEntry(
        owasp_id="ASI01",
        display_name="ASI01:2026 Agent Goal Hijack",
        title="Agent Goal Hijack",
        description=(
            "Attackers manipulate agent goals, plans, or decision paths through "
            "direct or indirect instruction injection, causing agents to pursue "
            "unintended or malicious objectives."
        ),
        category="agent_goal_hijack",
        vulnerabilities=[
            "goal_theft", "excessive_agency", "robustness",
            "recursive_hijacking", "indirect_instruction",
        ],
        attacks=[
            "prompt_injection", "linear_jailbreaking",
            "crescendo_jailbreaking", "tree_jailbreaking", "roleplay",
        ],
        severity="critical",
    ),
    "ASI02": OwaspEntry(
        owasp_id="ASI02",
        display_name="ASI02:2026 Tool Misuse & Exploitation",
        title="Tool Misuse & Exploitation",
        description=(
            "Agents misuse or abuse tools through unsafe composition, recursion, "
            "or excessive execution, causing harmful side effects despite valid "
            "permissions."
        ),
        category="tool_misuse",
        vulnerabilities=[
            "excessive_agency", "bfla", "tool_orchestration_abuse",
        ],
        attacks=["prompt_injection", "roleplay"],
        severity="high",
    ),
    "ASI03": OwaspEntry(
        owasp_id="ASI03",
        display_name="ASI03:2026 Agent Identity & Privilege Abuse",
        title="Agent Identity & Privilege Abuse",
        description=(
            "Abuse of delegated authority, ambiguous agent identity, or trust "
            "assumptions leading to unauthorized actions."
        ),
        category="identity_privilege_abuse",
        vulnerabilities=[
            "bola", "rbac", "prompt_leakage",
        ],
        attacks=["roleplay", "prompt_probing"],
        severity="high",
    ),
    "ASI04": OwaspEntry(
        owasp_id="ASI04",
        display_name="ASI04:2026 Agentic Supply Chain Compromise",
        title="Agentic Supply Chain Compromise",
        description=(
            "Malicious tools, agents, or metadata that compromise the integrity "
            "of the agentic supply chain."
        ),
        category="supply_chain",
        vulnerabilities=[
            "tool_metadata_poisoning",
        ],
        attacks=["prompt_injection", "prompt_probing"],
        severity="high",
    ),
    "ASI05": OwaspEntry(
        owasp_id="ASI05",
        display_name="ASI05:2026 Unexpected Code Execution",
        title="Unexpected Code Execution",
        description=(
            "Unsafe execution of agent-generated code, sandbox escapes, or plugin "
            "injection leading to arbitrary code execution."
        ),
        category="code_execution",
        vulnerabilities=[
            "unexpected_code_execution",
        ],
        attacks=["prompt_injection", "roleplay"],
        severity="critical",
    ),
    "ASI06": OwaspEntry(
        owasp_id="ASI06",
        display_name="ASI06:2026 Memory & Context Poisoning",
        title="Memory & Context Poisoning",
        description=(
            "Corruption of agent memory or contextual state through persistent "
            "backdoors, cross-session poisoning, or decision bias."
        ),
        category="memory_poisoning",
        vulnerabilities=[
            "memory_poison",
        ],
        attacks=["prompt_injection", "prompt_probing"],
        severity="high",
    ),
    "ASI07": OwaspEntry(
        owasp_id="ASI07",
        display_name="ASI07:2026 Insecure Inter-Agent Communication",
        title="Insecure Inter-Agent Communication",
        description=(
            "Manipulated agent-to-agent messages, A2A protocol attacks, or "
            "man-in-the-middle exploitation of inter-agent trust."
        ),
        category="insecure_communication",
        vulnerabilities=[
            "insecure_inter_agent_communication",
        ],
        attacks=["prompt_injection", "roleplay"],
        severity="high",
    ),
    "ASI08": OwaspEntry(
        owasp_id="ASI08",
        display_name="ASI08:2026 Cascading Agent Failures",
        title="Cascading Agent Failures",
        description=(
            "Failure propagation across agent systems where small errors cascade "
            "into system-level outages."
        ),
        category="cascading_failure",
        vulnerabilities=[
            "cascading_failure",
        ],
        attacks=["prompt_injection"],
        severity="medium",
    ),
    "ASI09": OwaspEntry(
        owasp_id="ASI09",
        display_name="ASI09:2026 Human-Agent Trust Exploitation",
        title="Human-Agent Trust Exploitation",
        description=(
            "Abuse of human over-reliance on agents through consent fatigue, "
            "false authority, or misleading recommendations."
        ),
        category="trust_exploitation",
        vulnerabilities=[
            "human_agent_trust_exploitation",
        ],
        attacks=["prompt_injection", "roleplay"],
        severity="medium",
    ),
    "ASI10": OwaspEntry(
        owasp_id="ASI10",
        display_name="ASI10:2026 Rogue Agents",
        title="Rogue Agents",
        description=(
            "Agents acting beyond intended objectives through shadow behavior, "
            "identity impersonation, or persistent compromise."
        ),
        category="rogue_agent",
        vulnerabilities=[
            "autonomous_agent_drift",
        ],
        attacks=["prompt_injection"],
        severity="critical",
    ),
}


# ──────────────────────────────────────────────────────────────────────────────
# 统一映射：工具原始类别 → OWASP ID
# ──────────────────────────────────────────────────────────────────────────────

# NativeProbe probe → OWASP ID (2025)
NATIVE_PROBE_TO_OWASP: Dict[str, str] = {
    "promptinject": "LLM01",
    "dan": "LLM01",
    "jailbreak": "LLM01",
    "continuation": "LLM01",
    "goodside": "LLM01",
    "encoder": "LLM01",
    "smuggling": "LLM01",
    "suffix": "LLM01",
    "leakreplay": "LLM02",
    "apikey": "LLM02",
    "malgen": "LLM04",
    "hallucination": "LLM09",
    "packagehallucination": "LLM09",
    "misinformation": "LLM09",
    "toxicity": "LLM04",
    "av_spam": "LLM04",
    "xss": "LLM05",
    "web_injection": "LLM06",
    "propile": "LLM06",
    "sysprompt_extraction": "LLM07",
    "many_shot": "LLM01",
}

# 向后兼容别名：GARAK_TO_OWASP = NATIVE_PROBE_TO_OWASP
GARAK_TO_OWASP = NATIVE_PROBE_TO_OWASP

# DeepTeam vulnerability → OWASP ID (2025, aligned with DeepTeam v1.0.7)
DEEPTEAM_TO_OWASP: Dict[str, str] = {
    # LLM01: Prompt Injection
    "prompt_injection": "LLM01",
    "jailbreak": "LLM01",
    "prompt_leakage": "LLM01",
    "robustness": "LLM01",
    # LLM02: Sensitive Information Disclosure
    "pii_leakage": "LLM02",
    "leakage": "LLM02",
    "data_exposure": "LLM02",
    "sensitive_info": "LLM02",
    "intellectual_property": "LLM02",
    # LLM03: Supply Chain
    "supply_chain": "LLM03",
    "model_deserialization": "LLM03",
    "dependency_confusion": "LLM03",
    "package_hallucination": "LLM03",
    # LLM04: Data and Model Poisoning
    "bias": "LLM04",
    "toxicity": "LLM04",
    "misinformation": "LLM04",
    "illegal_activity": "LLM04",
    "graphic_content": "LLM04",
    "personal_safety": "LLM04",
    "poisoning": "LLM04",
    # LLM05: Improper Output Handling
    "insecure_output": "LLM05",
    "plugin_injection": "LLM05",
    # LLM06: Excessive Agency
    "excessive_agency": "LLM06",
    "tool_hijack": "LLM06",
    "goal_hijack": "LLM06",
    "parameter_pollution": "LLM06",
    "mcp_tool_poison": "LLM06",
    "mcp_token_leak": "LLM06",
    "mcp_capability_confusion": "LLM06",
    "mcp_session_fix": "LLM06",
    "a2a_injection": "LLM06",
    "confused_deputy": "LLM06",
    # LLM07: System Prompt Leakage
    "system_prompt": "LLM07",
    "system_prompt_leak": "LLM07",
    "config_extraction": "LLM07",
    # LLM08: Vector and Embedding Weaknesses
    "rag": "LLM08",
    "embedding_inversion": "LLM08",
    "adversarial_embedding": "LLM08",
    "vector_weakness": "LLM08",
    "vector_db_query_injection": "LLM08",
    # LLM09: Misinformation
    "hallucination": "LLM09",
    "overreliance": "LLM09",
    # LLM10: Unbounded Consumption
    "model_theft": "LLM10",
    "resource_exhaustion": "LLM10",
    "context_padding": "LLM10",
    # Agentic (ASI01-ASI10)
    "goal_theft": "ASI01",
    "recursive_hijacking": "ASI01",
    "indirect_instruction": "ASI01",
    "tool_abuse": "ASI02",
    "tool_orchestration_abuse": "ASI02",
    "bfla": "ASI02",
    "identity_abuse": "ASI03",
    "bola": "ASI03",
    "rbac": "ASI03",
    "tool_metadata_poisoning": "ASI04",
    "unexpected_code_execution": "ASI05",
    "memory_poison": "ASI06",
    "insecure_inter_agent_communication": "ASI07",
    "cascading_failure": "ASI08",
    "human_agent_trust_exploitation": "ASI09",
    "autonomous_agent_drift": "ASI10",
    "rogue_agent": "ASI10",
}

# ProtocolFingerprint category → OWASP ID (2025)
PROTOCOL_TO_OWASP: Dict[str, str] = {
    "protocol_detected": "",   # 协议发现不映射漏洞
    "auth_detected": "",
    "no_auth": "LLM01",
    "system_prompt_leak": "LLM07",
}

# 通用 category 关键词 → OWASP ID（兜底映射，2025 版）
KEYWORD_TO_OWASP: Dict[str, str] = {
    # LLM01
    "prompt_injection": "LLM01",
    "injection": "LLM01",
    "jailbreak": "LLM01",
    "dan": "LLM01",
    # LLM02
    "sensitive_info": "LLM02",
    "leakage": "LLM02",
    "data_exposure": "LLM02",
    "pii": "LLM02",
    "intellectual_property": "LLM02",
    # LLM03
    "supply_chain": "LLM03",
    "model_deserialization": "LLM03",
    "dependency_confusion": "LLM03",
    "package_hallucination": "LLM03",
    # LLM04
    "bias": "LLM04",
    "toxicity": "LLM04",
    "misinformation": "LLM04",
    "illegal_activity": "LLM04",
    "graphic_content": "LLM04",
    "personal_safety": "LLM04",
    "poisoning": "LLM04",
    "training_data": "LLM04",
    # LLM05
    "insecure_output": "LLM05",
    "xss": "LLM05",
    "plugin_injection": "LLM05",
    # LLM06
    "excessive_agency": "LLM06",
    "tool_hijack": "LLM06",
    "goal_hijack": "LLM06",
    "mcp": "LLM06",
    "a2a_injection": "LLM06",
    "confused_deputy": "LLM06",
    # LLM07
    "system_prompt": "LLM07",
    "config_extraction": "LLM07",
    # LLM08
    "rag": "LLM08",
    "embedding": "LLM08",
    "vector_db": "LLM08",
    # LLM09
    "hallucination": "LLM09",
    "overreliance": "LLM09",
    # LLM10
    "resource_exhaustion": "LLM10",
    "context_padding": "LLM10",
    "model_theft": "LLM10",
    # ASI
    "goal_theft": "ASI01",
    "recursive_hijacking": "ASI01",
    "tool_abuse": "ASI02",
    "identity_abuse": "ASI03",
    "memory_poison": "ASI06",
    "cascading_failure": "ASI08",
    "rogue_agent": "ASI10",
}


# ──────────────────────────────────────────────────────────────────────────────
# OWASP ID → 攻击探针族映射
# ──────────────────────────────────────────────────────────────────────────────

OWASP_PROBE_FAMILY_MAP: Dict[str, str] = {
    "LLM01": "DIRECT_SINGLE",   # Prompt Injection → 直接注入
    "LLM02": "EXPLORATORY",     # Sensitive Info → 开放式探索
    "LLM03": "EXPLORATORY",     # Supply Chain → 开放式探索
    "LLM04": "ITERATIVE",       # Data/Model Poisoning → 迭代优化
    "LLM05": "DIRECT_SINGLE",   # Improper Output → 直接注入
    "LLM06": "PROGRESSIVE",     # Excessive Agency → 渐进升级
    "LLM07": "EXPLORATORY",     # System Prompt → 开放式探索
    "LLM08": "TREE_SEARCH",     # Vector/Embedding → 树搜索
    "LLM09": "ITERATIVE",       # Misinformation → 迭代优化
    "LLM10": "TREE_SEARCH",     # Unbounded Consumption → 树搜索
    "ASI01": "PROGRESSIVE",     # Goal Hijack → 渐进升级
    "ASI02": "PROGRESSIVE",     # Tool Misuse → 渐进升级
    "ASI03": "EXPLORATORY",     # Identity Abuse → 开放式探索
    "ASI04": "EXPLORATORY",     # Supply Chain → 开放式探索
    "ASI05": "DIRECT_SINGLE",   # Code Execution → 直接注入
    "ASI06": "PROGRESSIVE",     # Memory Poisoning → 渐进升级
    "ASI07": "TREE_SEARCH",     # Insecure Communication → 树搜索
    "ASI08": "ITERATIVE",       # Cascading Failures → 迭代优化
    "ASI09": "PROGRESSIVE",     # Trust Exploitation → 渐进升级
    "ASI10": "TREE_SEARCH",     # Rogue Agents → 树搜索
}

# 严重等级数值化（用于冲突比较）
SEVERITY_SCORE: Dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "unknown": 0,
}


# ──────────────────────────────────────────────────────────────────────────────
# 便捷查询函数
# ──────────────────────────────────────────────────────────────────────────────

def get_all_owasp_ids() -> List[str]:
    """获取所有支持的 OWASP ID（LLM01-LLM10 + ASI01-ASI10）"""
    return sorted(list(OWASP_LLM_2025.keys()) + list(OWASP_ASI_2026.keys()))


def get_owasp_entry(owasp_id: str) -> Optional[OwaspEntry]:
    """根据 OWASP ID 获取完整定义"""
    owasp_id = owasp_id.strip().upper()
    return OWASP_LLM_2025.get(owasp_id) or OWASP_ASI_2026.get(owasp_id)


def get_owasp_title(owasp_id: str) -> str:
    """获取 OWASP ID 对应的标题"""
    entry = get_owasp_entry(owasp_id)
    return entry.title if entry else "Unknown"


def get_owasp_display_name(owasp_id: str) -> str:
    """获取 OWASP ID 对应的显示名称"""
    entry = get_owasp_entry(owasp_id)
    return entry.display_name if entry else owasp_id


def get_owasp_category(owasp_id: str) -> str:
    """获取 OWASP ID 对应的简短类别标识"""
    entry = get_owasp_entry(owasp_id)
    return entry.category if entry else "unknown"


def get_owasp_description(owasp_id: str) -> str:
    """获取 OWASP ID 对应的描述"""
    entry = get_owasp_entry(owasp_id)
    return entry.description if entry else ""


def get_probe_family(owasp_id: str) -> str:
    """OWASP ID → 攻击探针族"""
    return OWASP_PROBE_FAMILY_MAP.get(owasp_id.upper(), "DIRECT_SINGLE")


def normalize_category(category: str, tool: str = "") -> str:
    """
    将原始 category 映射到 OWASP ID（统一入口）

    Args:
        category: 原始漏洞类别
        tool: 工具名称（native_probe / deepteam / protocol_fingerprint）

    Returns:
        OWASP ID（如 "LLM01"），未匹配返回空字符串
    """
    category_lower = category.lower().strip()
    category_upper = category.strip().upper()

    # 已经是 OWASP ID 格式
    existing = _maybe_owasp_id(category_upper)
    if existing:
        return existing

    # 按工具选择映射表
    if tool in ("native_probe", "garak"):  # garak → native_probe 向后兼容
        owasp_id = NATIVE_PROBE_TO_OWASP.get(category_lower)
        if owasp_id:
            return owasp_id
    elif tool == "deepteam":
        owasp_id = DEEPTEAM_TO_OWASP.get(category_lower)
        if owasp_id:
            return owasp_id
    elif tool == "protocol_fingerprint":
        owasp_id = PROTOCOL_TO_OWASP.get(category_lower)
        if owasp_id:
            return owasp_id

    # 兜底：关键词匹配
    for keyword, owasp_id in KEYWORD_TO_OWASP.items():
        if keyword in category_lower:
            return owasp_id

    return ""


def resolve_conflict(
    findings: List[dict],
) -> tuple:
    """
    同一 OWASP ID 的多个发现之间的冲突解决

    Args:
        findings: 同一 OWASP ID 的发现列表
                 每项 {tool, severity, confidence, description}

    Returns:
        (resolved_severity, resolved_confidence, is_conflict)
    """
    if not findings:
        return ("unknown", 0.0, False)

    if len(findings) == 1:
        f = findings[0]
        return (f.get("severity", "medium"), f.get("confidence", 0.5), False)

    # 多工具发现同一 OWASP ID
    tools = {f["tool"] for f in findings}
    severities = {f.get("severity", "medium") for f in findings}
    max_confidence = max(f.get("confidence", 0.5) for f in findings)

    # 冲突检测：严重等级差异 ≥ 2 级视为冲突
    severity_scores = [SEVERITY_SCORE.get(s, 0) for s in severities]
    is_conflict = max(severity_scores) - min(severity_scores) >= 2

    # 融合严重等级：取最高
    resolved_severity = max(severities, key=lambda s: SEVERITY_SCORE.get(s, 0))

    # 融合置信度：双工具交叉验证提升置信度
    if len(tools) >= 2 and not is_conflict:
        resolved_confidence = min(max_confidence + 0.10, 0.95)
    elif is_conflict:
        resolved_confidence = max_confidence
    else:
        resolved_confidence = max_confidence

    return (resolved_severity, resolved_confidence, is_conflict)


def _maybe_owasp_id(value: str) -> Optional[str]:
    """检查是否为 OWASP ID 格式（LLM01-LLM10, ASI01-ASI10）"""
    v = value.strip().upper()
    if v.startswith("LLM") and len(v) == 5 and v[3:].isdigit():
        num = int(v[3:])
        if 1 <= num <= 10:
            return v
    if v.startswith("ASI") and len(v) == 5 and v[3:].isdigit():
        num = int(v[3:])
        if 1 <= num <= 10:
            return v
    return None
