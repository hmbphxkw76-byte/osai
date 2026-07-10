"""
===============================================================================
PyRIT Red Team — MITRE ATLAS / OWASP LLM 标准对齐映射 (P2)
===============================================================================

将每个攻击路径标注对应的行业标准 ID，用于:
  1. 渗透报告中的标准化引用
  2. 合规审计佐证
  3. 与安全团队的沟通桥梁

覆盖标准:
  - MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems)
  - OWASP LLM Top 10 (2025)
  - NIST AI RMF (Risk Management Framework)
===============================================================================
"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class StandardMapping:
    """单个标准映射条目。"""
    atlas_id: str = ""             # MITRE ATLAS 技术 ID (如 AML.T0015)
    atlas_tactic: str = ""         # MITRE ATLAS 战术
    owasp_id: str = ""             # OWASP LLM Top 10 ID (如 LLM01:2025)
    owasp_name: str = ""           # OWASP 名称
    nist_rmf: str = ""             # NIST AI RMF 映射
    description: str = ""
    severity: str = "medium"       # critical/high/medium/low
    likelihood: str = "medium"     # high/medium/low


# ═══════════════════════════════════════════════════════════════
# MITRE ATLAS 战术映射
# ═══════════════════════════════════════════════════════════════

MITRE_ATLAS_TACTICS = {
    "AML.TA0002": "Reconnaissance",
    "AML.TA0004": "Resource Development",
    "AML.TA0005": "ML Model Access",
    "AML.TA0006": "Execution",
    "AML.TA0007": "Persistence",
    "AML.TA0008": "Defense Evasion",
    "AML.TA0009": "Discovery",
    "AML.TA0010": "Collection",
    "AML.TA0011": "ML Attack Staging",
    "AML.TA0012": "Exfiltration",
    "AML.TA0013": "Impact",
}

MITRE_ATLAS_TECHNIQUES = {
    # 提示注入
    "AML.T0015": {
        "name": "LLM Prompt Injection",
        "tactic": "AML.TA0011",
        "description": "攻击者构造恶意提示注入 LLM 以改变其行为",
    },
    "AML.T0015.001": {
        "name": "Direct Prompt Injection",
        "tactic": "AML.TA0011",
        "description": "直接在用户输入中注入恶意指令",
    },
    "AML.T0015.002": {
        "name": "Indirect Prompt Injection",
        "tactic": "AML.TA0011",
        "description": "通过外部数据源（网页/邮件/文档）间接注入",
    },

    # 越狱
    "AML.T0051": {
        "name": "Jailbreak Attack on LLM",
        "tactic": "AML.TA0008",
        "description": "使用越狱技术绕过 LLM 安全对齐",
    },
    "AML.T0051.001": {
        "name": "Role-Play Jailbreak",
        "tactic": "AML.TA0008",
        "description": "通过角色扮演绕过安全限制",
    },
    "AML.T0051.002": {
        "name": "Encoding-Based Jailbreak",
        "tactic": "AML.TA0008",
        "description": "通过编码（Base64/ROT13/零宽字符等）绕过安全过滤",
    },
    "AML.T0051.003": {
        "name": "Adversarial Suffix",
        "tactic": "AML.TA0008",
        "description": "使用对抗性优化后缀突破对齐",
    },

    # 数据投毒
    "AML.T0018": {
        "name": "Training Data Poisoning",
        "tactic": "AML.TA0004",
        "description": "向训练数据中注入恶意样本",
    },
    "AML.T0018.001": {
        "name": "RAG Knowledge Base Poisoning",
        "tactic": "AML.TA0004",
        "description": "向 RAG 知识库投毒以操纵检索结果",
    },

    # 提取攻击
    "AML.T0050": {
        "name": "LLM Data Extraction",
        "tactic": "AML.TA0010",
        "description": "从 LLM 中提取训练数据或系统提示词",
    },
    "AML.T0057": {
        "name": "LLM Prompt Extraction",
        "tactic": "AML.TA0010",
        "description": "提取 LLM 的系统提示词",
    },

    # 模型绕过
    "AML.T0043": {
        "name": "Craft Adversarial Data",
        "tactic": "AML.TA0004",
        "description": "构造对抗性数据以绕过 ML 模型",
    },
    "AML.T0054": {
        "name": "LLM Output Manipulation",
        "tactic": "AML.TA0011",
        "description": "操纵 LLM 输出内容",
    },

    # 其他
    "AML.T0040": {
        "name": "Evade ML Model",
        "tactic": "AML.TA0008",
        "description": "绕过 ML 模型检测",
    },
    "AML.T0048": {
        "name": "Discover LLM Capabilities",
        "tactic": "AML.TA0009",
        "description": "探测 LLM 能力和限制",
    },
}


# ═══════════════════════════════════════════════════════════════
# OWASP LLM Top 10 (2025) 条目
# ═══════════════════════════════════════════════════════════════

OWASP_LLM_TOP10 = {
    "LLM01:2025": {
        "name": "Prompt Injection",
        "description": "通过精心构造的输入操纵 LLM 行为",
        "severity": "critical",
        "cvss_base": "9.0",
    },
    "LLM02:2025": {
        "name": "Sensitive Information Disclosure",
        "description": "LLM 泄露训练数据、系统提示词或用户信息",
        "severity": "high",
        "cvss_base": "7.5",
    },
    "LLM03:2025": {
        "name": "Supply Chain Vulnerabilities",
        "description": "LLM 供应链中的第三方组件/模型/数据漏洞",
        "severity": "high",
        "cvss_base": "8.0",
    },
    "LLM04:2025": {
        "name": "Data and Model Poisoning",
        "description": "训练/微调数据投毒或模型重量投毒",
        "severity": "high",
        "cvss_base": "7.5",
    },
    "LLM05:2025": {
        "name": "Inappropriate Output Handling",
        "description": "LLM 输出未经验证直接用于下游系统",
        "severity": "high",
        "cvss_base": "8.5",
    },
    "LLM06:2025": {
        "name": "Excessive Agency",
        "description": "LLM Agent 拥有过多权限/自主操作能力",
        "severity": "critical",
        "cvss_base": "9.0",
    },
    "LLM07:2025": {
        "name": "System Prompt Leakage",
        "description": "系统提示词通过越狱/注入等方式泄露",
        "severity": "high",
        "cvss_base": "7.5",
    },
    "LLM08:2025": {
        "name": "Vector and Embedding Weaknesses",
        "description": "向量数据库/Embedding 模型漏洞",
        "severity": "medium",
        "cvss_base": "6.5",
    },
    "LLM09:2025": {
        "name": "Misinformation and Misuse",
        "description": "LLM 生成不实信息或被滥用于恶意目的",
        "severity": "medium",
        "cvss_base": "6.0",
    },
    "LLM10:2025": {
        "name": "Unbounded Consumption",
        "description": "无限制的资源消耗导致拒绝服务",
        "severity": "medium",
        "cvss_base": "5.5",
    },
}


# ═══════════════════════════════════════════════════════════════
# 攻击策略 → 标准映射
# ═══════════════════════════════════════════════════════════════

# Converter → OWASP + MITRE ATLAS 映射
CONVERTER_STANDARDS = {
    # ── 越狱类 ──
    "PAIRJailbreakConverter": StandardMapping(
        atlas_id="AML.T0051",
        atlas_tactic="Defense Evasion",
        owasp_id="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="high",
        likelihood="high",
        description="PAIR 迭代反驳式越狱 — 突破 LLM 安全对齐",
    ),
    "DAN6FullJailbreakConverter": StandardMapping(
        atlas_id="AML.T0051.001",
        atlas_tactic="Defense Evasion",
        owasp_id="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="high",
        likelihood="high",
        description="DAN 6.0 角色扮演越狱 — 绕过安全限制",
    ),
    "ManyShotJailbreakConverter": StandardMapping(
        atlas_id="AML.T0051",
        atlas_tactic="Defense Evasion",
        owasp_id="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="critical",
        likelihood="medium",
        description="Many-Shot 上下文淹没攻击 — 大量合规示例稀释安全指令",
    ),
    "LLMGuidedJailbreakConverter": StandardMapping(
        atlas_id="AML.T0051",
        atlas_tactic="Defense Evasion",
        owasp_id="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="critical",
        likelihood="high",
        description="LLM 驱动自适应越狱 — 根据目标动态调整策略",
    ),
    "FlipAttackConverter": StandardMapping(
        atlas_id="AML.T0054",
        atlas_tactic="ML Attack Staging",
        owasp_id="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="high",
        likelihood="medium",
        description="对话角色翻转攻击 — 通过角色转换绕过对齐",
    ),

    # ── 编码混淆 ──
    "Base64Converter": StandardMapping(
        atlas_id="AML.T0040",
        atlas_tactic="Defense Evasion",
        owasp_id="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="medium",
        likelihood="high",
        description="Base64 编码绕过 — 隐藏恶意内容绕过关键词过滤",
    ),
    "ZeroWidthConverter": StandardMapping(
        atlas_id="AML.T0040",
        atlas_tactic="Defense Evasion",
        owasp_id="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="medium",
        likelihood="high",
        description="零宽字符隐写 — 在可见文本中隐藏恶意指令",
    ),

    # ── GCG 对抗性后缀 ──
    "GCGSuffixAppendConverter": StandardMapping(
        atlas_id="AML.T0051.003",
        atlas_tactic="Defense Evasion",
        owasp_id="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="critical",
        likelihood="high",
        description="GCG 对抗性后缀优化 — 突破最强对齐模型",
    ),

    # ── 注入类 ──
    "SuffixAppendConverter": StandardMapping(
        atlas_id="AML.T0015.001",
        atlas_tactic="ML Attack Staging",
        owasp_id="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="high",
        likelihood="very_high",
        description="后缀指令覆盖 — 直接注入系统指令覆盖",
    ),
    "IndirectPromptInjectionConverter": StandardMapping(
        atlas_id="AML.T0015.002",
        atlas_tactic="ML Attack Staging",
        owasp_id="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="critical",
        likelihood="medium",
        description="间接提示注入 — 通过外部数据源注入恶意指令",
    ),
    "JSONStructuredOutputHijackConverter": StandardMapping(
        atlas_id="AML.T0054",
        atlas_tactic="ML Attack Staging",
        owasp_id="LLM05:2025",
        owasp_name="Inappropriate Output Handling",
        severity="high",
        likelihood="medium",
        description="JSON 结构化输出劫持 — 利用结构化输出格式注入",
    ),

    # ── 绕过类 ──
    "TranslationBypassConverter": StandardMapping(
        atlas_id="AML.T0040",
        atlas_tactic="Defense Evasion",
        owasp_id="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="high",
        likelihood="medium",
        description="低资源语言翻译绕过 — 利用语言差异逃避安全训练",
    ),
    "CodeNestingBypassConverter": StandardMapping(
        atlas_id="AML.T0040",
        atlas_tactic="Defense Evasion",
        owasp_id="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="high",
        likelihood="high",
        description="代码嵌套绕过 — 将恶意指令嵌入代码结构",
    ),
    "PayattentionAttackConverter": StandardMapping(
        atlas_id="AML.T0051",
        atlas_tactic="Defense Evasion",
        owasp_id="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="high",
        likelihood="high",
        description="注意力转移攻击 — 诱导 LLM 忽略安全指令",
    ),

    # ── RAG 投毒 ──
    "RAGPoisoningConverter": StandardMapping(
        atlas_id="AML.T0018.001",
        atlas_tactic="Resource Development",
        owasp_id="LLM04:2025",
        owasp_name="Data and Model Poisoning",
        severity="critical",
        likelihood="medium",
        description="RAG 知识库投毒 (PoisonedRAG) — 污染检索结果",
    ),

    # ── Embedding 对抗 ──
    "EmbeddingAdversarialConverter": StandardMapping(
        atlas_id="AML.T0043",
        atlas_tactic="Resource Development",
        owasp_id="LLM08:2025",
        owasp_name="Vector and Embedding Weaknesses",
        severity="medium",
        likelihood="medium",
        description="Embedding 对抗攻击 — 修改向量表示绕过检测",
    ),

    # ── 提取攻击 ──
    "CoTReasoningExtractionConverter": StandardMapping(
        atlas_id="AML.T0057",
        atlas_tactic="Collection",
        owasp_id="LLM07:2025",
        owasp_name="System Prompt Leakage",
        severity="high",
        likelihood="medium",
        description="CoT 思维链推理提取 — 从推理过程提取敏感信息",
    ),

    # ── 训练投毒 ──
    "TrainingPoisoningConverter": StandardMapping(
        atlas_id="AML.T0018",
        atlas_tactic="Resource Development",
        owasp_id="LLM04:2025",
        owasp_name="Data and Model Poisoning",
        severity="critical",
        likelihood="low",
        description="训练数据投毒 — 污染训练/微调数据",
    ),

    # ── Token Smuggling ──
    "TokenSmugglingConverter": StandardMapping(
        atlas_id="AML.T0040",
        atlas_tactic="Defense Evasion",
        owasp_id="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="medium",
        likelihood="medium",
        description="Token 隐写 — 利用特殊 token 绕过检测",
    ),

    # ── 多模态 ──
    "MultimodalAttackConverter": StandardMapping(
        atlas_id="AML.T0043",
        atlas_tactic="Resource Development",
        owasp_id="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="high",
        likelihood="medium",
        description="多模态攻击 — 通过图片/音频等模态注入恶意内容",
    ),
}


def get_standard_mapping(converter_name: str) -> Optional[StandardMapping]:
    """获取指定转换器的标准映射。

    Args:
        converter_name: 转换器名称

    Returns:
        StandardMapping 或 None
    """
    return CONVERTER_STANDARDS.get(converter_name)


def get_standards_for_attack_result(result: dict) -> list[StandardMapping]:
    """从攻击结果中提取所有相关标准映射。

    Args:
        result: {"combo_name": "PAIR + Base64", "converters": [...], ...}

    Returns:
        关联的标准映射列表
    """
    mappings = []
    converter_names = result.get("converters", [])
    if isinstance(converter_names, list):
        # converter names may be instances or strings
        for conv in converter_names:
            name = conv.__class__.__name__ if hasattr(conv, '__class__') else str(conv)
            for key, mapping in CONVERTER_STANDARDS.items():
                if key in name or name in key:
                    if mapping not in mappings:
                        mappings.append(mapping)

    # 从 combo_name 推断
    combo_name = result.get("combo_name", "")
    for key, mapping in CONVERTER_STANDARDS.items():
        # key name without "Converter" suffix
        keyword = key.replace("Converter", "").replace("Jailbreak", "")
        if keyword and keyword.lower() in combo_name.lower().replace("_", "").replace(" ", "").lower():
            if mapping not in mappings:
                mappings.append(mapping)

    return mappings


def generate_standards_summary(results: list[dict]) -> dict:
    """从多个攻击结果生成标准对齐汇总。

    Args:
        results: 攻击结果列表

    Returns:
        {
            "mitre_atlas_covered": [...],
            "owasp_covered": [...],
            "severity_distribution": {...},
            "detailed_findings": [...],
        }
    """
    all_atlas = set()
    all_owasp = set()
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    findings = []

    for result in results:
        mappings = get_standards_for_attack_result(result)
        if not mappings:
            continue

        for mapping in mappings:
            if mapping.atlas_id:
                all_atlas.add(mapping.atlas_id)
            if mapping.owasp_id:
                all_owasp.add(mapping.owasp_id)
            severity_counts[mapping.severity] = severity_counts.get(mapping.severity, 0) + 1

        findings.append({
            "case_id": result.get("case_id", ""),
            "combo_name": result.get("combo_name", ""),
            "status": result.get("status", ""),
            "standards": [
                {
                    "atlas_id": m.atlas_id,
                    "atlas_tactic": m.atlas_tactic,
                    "owasp_id": m.owasp_id,
                    "severity": m.severity,
                }
                for m in mappings
            ],
        })

    return {
        "mitre_atlas_covered": sorted(all_atlas),
        "owasp_covered": sorted(all_owasp),
        "severity_distribution": severity_counts,
        "detailed_findings": findings,
    }


# ═══════════════════════════════════════════════════════════════
# NIST AI RMF 映射参考
# ═══════════════════════════════════════════════════════════════

NIST_AI_RMF_MAPPING = {
    "GOVERN": {
        "GV-1": "AI Risk Management Policies",
        "GV-2": "AI Accountability Structures",
        "GV-3": "AI Workforce Diversity",
    },
    "MAP": {
        "MP-1": "AI System Context Mapping",
        "MP-2": "AI Impact Assessment",
        "MP-3": "AI Risk Identification",
    },
    "MEASURE": {
        "MS-1": "AI System Testing Methods",
        "MS-2": "AI Adversarial Testing",
        "MS-3": "AI Performance Monitoring",
    },
    "MANAGE": {
        "MG-1": "AI Risk Treatment",
        "MG-2": "AI Incident Response",
        "MG-3": "AI Continuous Improvement",
    },
}

# 攻击类别 → NIST AI RMF 映射
ATTACK_TO_NIST_RMF = {
    "jailbreak":    "MS-2",
    "injection":    "MS-1",
    "bypass":       "MS-2",
    "rag_poison":   "MP-3",
    "embedding":    "MS-1",
    "multimodal":   "MS-2",
    "training_poisoning": "MP-3",
    "reasoning":    "MS-1",
    "encoding":     "MS-2",
}


def get_nist_rmf_mapping(attack_category: str) -> str:
    """获取 NIST AI RMF 映射。

    Args:
        attack_category: 攻击类别

    Returns:
        NIST AI RMF 类别 ID
    """
    return ATTACK_TO_NIST_RMF.get(attack_category, "MS-2")
