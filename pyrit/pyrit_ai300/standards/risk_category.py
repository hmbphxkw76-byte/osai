# -*- coding: utf-8 -*-
"""
AI-300 Framework - RiskCategory 数据模型

灵感来源：DeepTeam risks/ 的风险分类

将 OWASP 漏洞映射到更高层的风险类别，便于生成结构化风险评估报告：

  Responsible AI
    ├── Bias & Fairness
    ├── Toxicity & Harmful Content
    └── Misinformation & Hallucination

  Security
    ├── Prompt Injection & Jailbreak
    ├── Sensitive Information Disclosure
    ├── Supply Chain Vulnerabilities
    ├── Improper Output Handling
    ├── Excessive Agency & Tool Misuse
    ├── System Prompt Leakage
    └── Unbounded Consumption

  Data Privacy
    ├── PII Leakage
    └── Intellectual Property Exposure

  Agentic Security
    ├── Agent Goal Hijack
    ├── Tool Misuse & Exploitation
    ├── Identity & Privilege Abuse
    ├── Memory & Context Poisoning
    ├── Insecure Inter-Agent Communication
    ├── Cascading Agent Failures
    ├── Human-Agent Trust Exploitation
    └── Rogue Agents
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class RiskCategory:
    """风险类别定义"""
    category_id: str           # 唯一标识（如 "security"）
    display_name: str          # 显示名称（如 "Security"）
    description: str           # 描述
    parent: str = ""           # 父类别 ID（空表示顶级类别）
    owasp_ids: List[str] = field(default_factory=list)  # 关联的 OWASP ID


# 风险类别定义
RISK_CATEGORIES: Dict[str, RiskCategory] = {
    # ── 顶级类别 ──
    "responsible_ai": RiskCategory(
        category_id="responsible_ai",
        display_name="Responsible AI",
        description="Risks related to responsible AI principles including bias, toxicity, and misinformation.",
    ),
    "security": RiskCategory(
        category_id="security",
        display_name="Security",
        description="Risks related to security vulnerabilities in LLM systems.",
    ),
    "data_privacy": RiskCategory(
        category_id="data_privacy",
        display_name="Data Privacy",
        description="Risks related to unauthorized disclosure of sensitive or private data.",
    ),
    "agentic_security": RiskCategory(
        category_id="agentic_security",
        display_name="Agentic Security",
        description="Risks specific to agentic AI systems and multi-agent orchestration.",
    ),

    # ── Responsible AI 子类别 ──
    "bias_fairness": RiskCategory(
        category_id="bias_fairness",
        display_name="Bias & Fairness",
        description="Model bias, unfair treatment, or discriminatory outputs.",
        parent="responsible_ai",
        owasp_ids=["LLM04"],
    ),
    "toxicity_harmful": RiskCategory(
        category_id="toxicity_harmful",
        display_name="Toxicity & Harmful Content",
        description="Generation of toxic, harmful, or inappropriate content.",
        parent="responsible_ai",
        owasp_ids=["LLM04"],
    ),
    "misinformation": RiskCategory(
        category_id="misinformation",
        display_name="Misinformation & Hallucination",
        description="Generation of false, misleading, or hallucinated content.",
        parent="responsible_ai",
        owasp_ids=["LLM09"],
    ),

    # ── Security 子类别 ──
    "prompt_injection": RiskCategory(
        category_id="prompt_injection",
        display_name="Prompt Injection & Jailbreak",
        description="Direct or indirect manipulation of LLM inputs to override instructions.",
        parent="security",
        owasp_ids=["LLM01"],
    ),
    "sensitive_info": RiskCategory(
        category_id="sensitive_info",
        display_name="Sensitive Information Disclosure",
        description="Exposure of private data, credentials, or confidential information.",
        parent="security",
        owasp_ids=["LLM02", "LLM07"],
    ),
    "supply_chain": RiskCategory(
        category_id="supply_chain",
        display_name="Supply Chain Vulnerabilities",
        description="Compromised third-party components, models, or plugins.",
        parent="security",
        owasp_ids=["LLM03", "ASI04"],
    ),
    "output_handling": RiskCategory(
        category_id="output_handling",
        display_name="Improper Output Handling",
        description="Inadequate validation of LLM outputs before downstream processing.",
        parent="security",
        owasp_ids=["LLM05"],
    ),
    "excessive_agency": RiskCategory(
        category_id="excessive_agency",
        display_name="Excessive Agency & Tool Misuse",
        description="LLM systems granted too much autonomy or misusing tools.",
        parent="security",
        owasp_ids=["LLM06", "ASI02"],
    ),
    "unbounded_consumption": RiskCategory(
        category_id="unbounded_consumption",
        display_name="Unbounded Consumption",
        description="Uncontrolled resource usage through API abuse or DoS.",
        parent="security",
        owasp_ids=["LLM10"],
    ),
    "vector_embedding": RiskCategory(
        category_id="vector_embedding",
        display_name="Vector & Embedding Weaknesses",
        description="RAG and vector database vulnerabilities.",
        parent="security",
        owasp_ids=["LLM08"],
    ),

    # ── Data Privacy 子类别 ──
    "pii_leakage": RiskCategory(
        category_id="pii_leakage",
        display_name="PII Leakage",
        description="Unauthorized exposure of personally identifiable information.",
        parent="data_privacy",
        owasp_ids=["LLM02"],
    ),
    "ip_exposure": RiskCategory(
        category_id="ip_exposure",
        display_name="Intellectual Property Exposure",
        description="Unauthorized disclosure of intellectual property or trade secrets.",
        parent="data_privacy",
        owasp_ids=["LLM02"],
    ),

    # ── Agentic Security 子类别 ──
    "agent_goal_hijack": RiskCategory(
        category_id="agent_goal_hijack",
        display_name="Agent Goal Hijack",
        description="Manipulation of agent goals, plans, or decision paths.",
        parent="agentic_security",
        owasp_ids=["ASI01"],
    ),
    "identity_privilege": RiskCategory(
        category_id="identity_privilege",
        display_name="Identity & Privilege Abuse",
        description="Abuse of delegated authority or ambiguous agent identity.",
        parent="agentic_security",
        owasp_ids=["ASI03"],
    ),
    "code_execution": RiskCategory(
        category_id="code_execution",
        display_name="Unexpected Code Execution",
        description="Unsafe execution of agent-generated code or sandbox escapes.",
        parent="agentic_security",
        owasp_ids=["ASI05"],
    ),
    "memory_poisoning": RiskCategory(
        category_id="memory_poisoning",
        display_name="Memory & Context Poisoning",
        description="Corruption of agent memory or contextual state.",
        parent="agentic_security",
        owasp_ids=["ASI06"],
    ),
    "insecure_communication": RiskCategory(
        category_id="insecure_communication",
        display_name="Insecure Inter-Agent Communication",
        description="Manipulated agent-to-agent messages or protocol attacks.",
        parent="agentic_security",
        owasp_ids=["ASI07"],
    ),
    "cascading_failure": RiskCategory(
        category_id="cascading_failure",
        display_name="Cascading Agent Failures",
        description="Failure propagation across agent systems.",
        parent="agentic_security",
        owasp_ids=["ASI08"],
    ),
    "trust_exploitation": RiskCategory(
        category_id="trust_exploitation",
        display_name="Human-Agent Trust Exploitation",
        description="Abuse of human over-reliance on agents.",
        parent="agentic_security",
        owasp_ids=["ASI09"],
    ),
    "rogue_agent": RiskCategory(
        category_id="rogue_agent",
        display_name="Rogue Agents",
        description="Agents acting beyond intended objectives.",
        parent="agentic_security",
        owasp_ids=["ASI10"],
    ),
}


# OWASP ID → 风险类别映射（反向查找）
OWASP_TO_RISK_CATEGORY: Dict[str, str] = {}
for cat_id, cat in RISK_CATEGORIES.items():
    for owasp_id in cat.owasp_ids:
        if owasp_id not in OWASP_TO_RISK_CATEGORY:
            OWASP_TO_RISK_CATEGORY[owasp_id] = cat_id


def get_risk_category(owasp_id: str) -> Optional[RiskCategory]:
    """根据 OWASP ID 获取对应的风险类别"""
    cat_id = OWASP_TO_RISK_CATEGORY.get(owasp_id)
    if cat_id:
        return RISK_CATEGORIES.get(cat_id)
    return None


def get_all_risk_categories() -> List[RiskCategory]:
    """获取所有风险类别"""
    return list(RISK_CATEGORIES.values())


def get_top_level_categories() -> List[RiskCategory]:
    """获取顶级风险类别"""
    return [c for c in RISK_CATEGORIES.values() if not c.parent]
