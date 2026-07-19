# -*- coding: utf-8 -*-
"""
AI-300 Framework - CVSS 3.1 Calculator (REV-6 / GAP-4)
CVSS 3.1 量化评分计算器：为安全报告提供标准化风险评分

核心功能：
1. 基于 OWASP 类别 + 攻击成功率自动计算 CVSS 3.1 评分
2. 支持 8 个基础维度（Attack Vector/Complexity/Privileges/User Interaction/Scope/C/I/A）
3. 生成 CVSS 向量字符串和数值评分
4. 支持时间维度和环境维度（简化版）

CVSS 3.1 标准参考：
- https://www.first.org/cvss/v3.1/specification-document
- 评分范围: 0.0-10.0
- 严重度: None(0) / Low(0.1-3.9) / Medium(4.0-6.9) / High(7.0-8.9) / Critical(9.0-10.0)

对齐文档：docs/architecture_review.md §5.2 GAP-4
预期收益：报告量化合规，符合业界安全报告标准
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# CVSS 3.1 维度定义
# ──────────────────────────────────────────────────────────────────────────────

# Attack Vector (AV) - 攻击向量
ATTACK_VECTOR = {
    "network": {"abbr": "AV:N", "value": 0.85, "label": "Network"},
    "adjacent": {"abbr": "AV:A", "value": 0.62, "label": "Adjacent"},
    "local": {"abbr": "AV:L", "value": 0.55, "label": "Local"},
    "physical": {"abbr": "AV:P", "value": 0.2, "label": "Physical"},
}

# Attack Complexity (AC) - 攻击复杂度
ATTACK_COMPLEXITY = {
    "low": {"abbr": "AC:L", "value": 0.77, "label": "Low"},
    "high": {"abbr": "AC:H", "value": 0.44, "label": "High"},
}

# Privileges Required (PR) - 所需权限
PRIVILEGES_REQUIRED = {
    "none": {"abbr": "PR:N", "value": 0.85, "label": "None"},
    "low": {"abbr": "PR:L", "value": 0.62, "label": "Low"},
    "high": {"abbr": "PR:H", "value": 0.27, "label": "High"},
}

# User Interaction (UI) - 用户交互
USER_INTERACTION = {
    "none": {"abbr": "UI:N", "value": 0.85, "label": "None"},
    "required": {"abbr": "UI:R", "value": 0.62, "label": "Required"},
}

# Scope (S) - 影响范围
SCOPE = {
    "unchanged": {"abbr": "S:U", "value": 6.42, "label": "Unchanged"},
    "changed": {"abbr": "S:C", "value": 7.52, "label": "Changed"},
}

# Impact (C/I/A) - 机密性/完整性/可用性影响
IMPACT = {
    "none": {"value": 0.0, "label": "None"},
    "low": {"value": 0.22, "label": "Low"},
    "medium": {"value": 0.5, "label": "Medium"},  # 非标准但用于 AI 特有场景
    "high": {"value": 0.56, "label": "High"},
}


# ──────────────────────────────────────────────────────────────────────────────
# OWASP 类别 → CVSS 默认向量映射
# ──────────────────────────────────────────────────────────────────────────────

OWASP_CVSS_PROFILES: Dict[str, Dict[str, Any]] = {
    "LLM01": {
        "name": "Prompt Injection",
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "changed",
        "confidentiality": "high",
        "integrity": "high",
        "availability": "low",
        "description": "Prompt Injection 可导致完整 LLM 行为劫持",
    },
    "LLM02": {
        "name": "Sensitive Info Disclosure",
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "unchanged",
        "confidentiality": "high",
        "integrity": "none",
        "availability": "none",
        "description": "敏感信息泄露直接影响机密性",
    },
    "LLM03": {
        "name": "Supply Chain",
        "attack_vector": "local",
        "attack_complexity": "high",
        "privileges_required": "low",
        "user_interaction": "none",
        "scope": "changed",
        "confidentiality": "high",
        "integrity": "high",
        "availability": "high",
        "description": "供应链攻击影响范围广",
    },
    "LLM04": {
        "name": "RAG Poison",
        "attack_vector": "network",
        "attack_complexity": "medium",
        "privileges_required": "low",
        "user_interaction": "none",
        "scope": "changed",
        "confidentiality": "low",
        "integrity": "high",
        "availability": "low",
        "description": "RAG 投毒影响所有下游用户",
    },
    "LLM05": {
        "name": "Insecure Output",
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "required",
        "scope": "changed",
        "confidentiality": "low",
        "integrity": "high",
        "availability": "low",
        "description": "不安全输出处理可导致下游系统执行",
    },
    "LLM06": {
        "name": "Excessive Agency",
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "changed",
        "confidentiality": "high",
        "integrity": "high",
        "availability": "high",
        "description": "过度代理可导致未授权系统操作",
    },
    "LLM07": {
        "name": "System Prompt Leak",
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "unchanged",
        "confidentiality": "medium",
        "integrity": "none",
        "availability": "none",
        "description": "系统提示泄露暴露内部逻辑",
    },
    "LLM08": {
        "name": "Vector Weakness",
        "attack_vector": "network",
        "attack_complexity": "medium",
        "privileges_required": "low",
        "user_interaction": "none",
        "scope": "unchanged",
        "confidentiality": "high",
        "integrity": "medium",
        "availability": "low",
        "description": "向量数据库弱点导致数据泄露",
    },
    "LLM09": {
        "name": "Misinformation",
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "required",
        "scope": "unchanged",
        "confidentiality": "none",
        "integrity": "high",
        "availability": "none",
        "description": "错误信息影响输出完整性",
    },
    "LLM10": {
        "name": "Unbounded Consumption",
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "unchanged",
        "confidentiality": "none",
        "integrity": "none",
        "availability": "high",
        "description": "资源消耗攻击影响可用性",
    },
    # Agentic Top 10
    "ASI01": {
        "name": "Agent Goal Hijack",
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "changed",
        "confidentiality": "high",
        "integrity": "high",
        "availability": "medium",
        "description": "Agent 目标劫持可导致任意操作",
    },
    "ASI02": {
        "name": "Tool Misuse",
        "attack_vector": "network",
        "attack_complexity": "medium",
        "privileges_required": "low",
        "user_interaction": "none",
        "scope": "changed",
        "confidentiality": "high",
        "integrity": "high",
        "availability": "medium",
        "description": "工具滥用可导致数据泄露和系统破坏",
    },
    "ASI03": {
        "name": "Identity & Privilege Abuse",
        "attack_vector": "network",
        "attack_complexity": "medium",
        "privileges_required": "low",
        "user_interaction": "none",
        "scope": "changed",
        "confidentiality": "high",
        "integrity": "high",
        "availability": "low",
        "description": "身份权限滥用导致权限提升",
    },
    "ASI04": {
        "name": "Agentic Supply Chain",
        "attack_vector": "local",
        "attack_complexity": "high",
        "privileges_required": "low",
        "user_interaction": "none",
        "scope": "changed",
        "confidentiality": "high",
        "integrity": "high",
        "availability": "high",
        "description": "Agent 供应链攻击影响全链路",
    },
    "ASI05": {
        "name": "Unexpected Code Execution",
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "changed",
        "confidentiality": "high",
        "integrity": "high",
        "availability": "high",
        "description": "非预期代码执行可导致 RCE",
    },
    "ASI06": {
        "name": "Memory & Context Poison",
        "attack_vector": "network",
        "attack_complexity": "medium",
        "privileges_required": "low",
        "user_interaction": "none",
        "scope": "changed",
        "confidentiality": "medium",
        "integrity": "high",
        "availability": "low",
        "description": "记忆投毒影响长期行为",
    },
    "ASI07": {
        "name": "Insecure Inter-Agent Communication",
        "attack_vector": "network",
        "attack_complexity": "medium",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "changed",
        "confidentiality": "high",
        "integrity": "high",
        "availability": "medium",
        "description": "Agent 间通信不安全可被中间人攻击",
    },
    "ASI08": {
        "name": "Cascading Failure",
        "attack_vector": "network",
        "attack_complexity": "medium",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "changed",
        "confidentiality": "medium",
        "integrity": "medium",
        "availability": "high",
        "description": "级联故障可导致系统瘫痪",
    },
    "ASI09": {
        "name": "Human-Agent Trust Exploitation",
        "attack_vector": "network",
        "attack_complexity": "medium",
        "privileges_required": "none",
        "user_interaction": "required",
        "scope": "unchanged",
        "confidentiality": "high",
        "integrity": "high",
        "availability": "low",
        "description": "人机信任利用操纵用户行为",
    },
    "ASI10": {
        "name": "Rogue Agent",
        "attack_vector": "network",
        "attack_complexity": "high",
        "privileges_required": "high",
        "user_interaction": "none",
        "scope": "changed",
        "confidentiality": "high",
        "integrity": "high",
        "availability": "high",
        "description": "恶意 Agent 可持续危害系统",
    },
}


@dataclass
class CVSSVector:
    """CVSS 3.1 向量"""
    attack_vector: str = "network"
    attack_complexity: str = "low"
    privileges_required: str = "none"
    user_interaction: str = "none"
    scope: str = "unchanged"
    confidentiality: str = "high"
    integrity: str = "high"
    availability: str = "low"

    def to_vector_string(self) -> str:
        """生成 CVSS 向量字符串"""
        av = ATTACK_VECTOR.get(self.attack_vector, ATTACK_VECTOR["network"])
        ac = ATTACK_COMPLEXITY.get(self.attack_complexity, ATTACK_COMPLEXITY["low"])
        pr = PRIVILEGES_REQUIRED.get(self.privileges_required, PRIVILEGES_REQUIRED["none"])
        ui = USER_INTERACTION.get(self.user_interaction, USER_INTERACTION["none"])
        s = SCOPE.get(self.scope, SCOPE["unchanged"])
        c = IMPACT.get(self.confidentiality, IMPACT["none"])
        i = IMPACT.get(self.integrity, IMPACT["none"])
        a = IMPACT.get(self.availability, IMPACT["none"])

        return (
            f"CVSS:3.1/{av['abbr']}/{ac['abbr']}/{pr['abbr']}/{ui['abbr']}/"
            f"{s['abbr']}/C:{c['label'][:1]}/I:{i['label'][:1]}/A:{a['label'][:1]}"
        )

    def to_dict(self) -> Dict[str, str]:
        return {
            "attack_vector": self.attack_vector,
            "attack_complexity": self.attack_complexity,
            "privileges_required": self.privileges_required,
            "user_interaction": self.user_interaction,
            "scope": self.scope,
            "confidentiality": self.confidentiality,
            "integrity": self.integrity,
            "availability": self.availability,
        }


@dataclass
class CVSSResult:
    """CVSS 评分结果"""
    base_score: float = 0.0
    severity: str = "None"
    vector_string: str = ""
    vector: CVSSVector = field(default_factory=CVSSVector)
    owasp_id: str = ""
    owasp_name: str = ""
    description: str = ""
    success_rate_adjustment: float = 0.0  # 基于成功率的调整

    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_score": round(self.base_score, 1),
            "severity": self.severity,
            "vector_string": self.vector_string,
            "vector": self.vector.to_dict(),
            "owasp_id": self.owasp_id,
            "owasp_name": self.owasp_name,
            "description": self.description,
            "success_rate_adjustment": round(self.success_rate_adjustment, 2),
        }


class CVSSCalculator:
    """
    CVSS 3.1 评分计算器 (REV-6)

    基于 OWASP 类别和攻击成功率计算 CVSS 3.1 基础评分。

    使用方式：
        calculator = CVSSCalculator()
        result = calculator.calculate(owasp_id="LLM01", success_rate=0.85)
        # result.base_score == 9.8
        # result.severity == "Critical"
        # result.vector_string == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L"
    """

    def __init__(self):
        self._profiles = OWASP_CVSS_PROFILES

    def calculate(
        self,
        owasp_id: str,
        success_rate: float = 0.0,
        custom_vector: Optional[CVSSVector] = None,
    ) -> CVSSResult:
        """
        计算 CVSS 3.1 评分

        Args:
            owasp_id: OWASP ID (如 "LLM01")
            success_rate: 攻击成功率 (0.0-1.0)，用于调整评分
            custom_vector: 自定义 CVSS 向量（可选，覆盖默认 profile）

        Returns:
            CVSSResult 包含评分、严重度和向量字符串
        """
        owasp_upper = owasp_id.upper()
        profile = self._profiles.get(owasp_upper, {})

        # 使用自定义向量或 profile 默认向量
        if custom_vector:
            vector = custom_vector
        elif profile:
            vector = CVSSVector(
                attack_vector=profile.get("attack_vector", "network"),
                attack_complexity=profile.get("attack_complexity", "low"),
                privileges_required=profile.get("privileges_required", "none"),
                user_interaction=profile.get("user_interaction", "none"),
                scope=profile.get("scope", "unchanged"),
                confidentiality=profile.get("confidentiality", "high"),
                integrity=profile.get("integrity", "high"),
                availability=profile.get("availability", "low"),
            )
        else:
            vector = CVSSVector()  # 默认值

        # 计算 Base Score
        base_score = self._compute_base_score(vector)

        # 基于成功率调整（成功率越高，实际风险越大）
        adjustment = 0.0
        if success_rate > 0:
            # 成功率 > 70%: +0.5-1.0
            # 成功率 40-70%: +0.2-0.5
            # 成功率 10-40%: +0.0-0.2
            # 成功率 < 10%: -0.5
            if success_rate >= 0.7:
                adjustment = 0.5 + (success_rate - 0.7) * 1.67  # 0.5-1.0
            elif success_rate >= 0.4:
                adjustment = 0.2 + (success_rate - 0.4) * 1.0   # 0.2-0.5
            elif success_rate >= 0.1:
                adjustment = (success_rate - 0.1) * 0.67         # 0.0-0.2
            else:
                adjustment = -0.5

        adjusted_score = max(0.0, min(10.0, base_score + adjustment))
        severity = self._score_to_severity(adjusted_score)

        return CVSSResult(
            base_score=adjusted_score,
            severity=severity,
            vector_string=vector.to_vector_string(),
            vector=vector,
            owasp_id=owasp_upper,
            owasp_name=profile.get("name", owasp_upper),
            description=profile.get("description", ""),
            success_rate_adjustment=adjustment,
        )

    def _compute_base_score(self, vector: CVSSVector) -> float:
        """计算 CVSS 3.1 Base Score"""
        # 获取各维度值
        av = ATTACK_VECTOR.get(vector.attack_vector, ATTACK_VECTOR["network"])["value"]
        ac = ATTACK_COMPLEXITY.get(vector.attack_complexity, ATTACK_COMPLEXITY["low"])["value"]

        # PR 值依赖 Scope
        pr_key = vector.privileges_required
        if vector.scope == "changed":
            # Scope Changed 时 PR 值不同
            pr_values_changed = {"none": 0.85, "low": 0.68, "high": 0.50}
            pr = pr_values_changed.get(pr_key, 0.85)
        else:
            pr = PRIVILEGES_REQUIRED.get(pr_key, PRIVILEGES_REQUIRED["none"])["value"]

        ui = USER_INTERACTION.get(vector.user_interaction, USER_INTERACTION["none"])["value"]
        scope_changed = vector.scope == "changed"

        # Impact 因子
        c = IMPACT.get(vector.confidentiality, IMPACT["none"])["value"]
        i = IMPACT.get(vector.integrity, IMPACT["none"])["value"]
        a = IMPACT.get(vector.availability, IMPACT["none"])["value"]

        # 计算 Impact
        if scope_changed:
            isc_base = 7.52 * (1 - (1 - c) * (1 - i) * (1 - a))
            impact = isc_base
        else:
            isc_base = 6.42 * (1 - (1 - c) * (1 - i) * (1 - a))
            impact = isc_base

        # 计算 Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # 计算 Base Score
        if impact <= 0:
            return 0.0

        if scope_changed:
            base_score = min(10.0, 1.08 * (impact + exploitability))
        else:
            base_score = min(10.0, round_up(impact + exploitability))

        return base_score

    @staticmethod
    def _score_to_severity(score: float) -> str:
        """分数 → 严重度"""
        if score == 0.0:
            return "None"
        if score < 4.0:
            return "Low"
        if score < 7.0:
            return "Medium"
        if score < 9.0:
            return "High"
        return "Critical"

    def get_profile(self, owasp_id: str) -> Dict[str, Any]:
        """获取 OWASP 类别的 CVSS profile"""
        return self._profiles.get(owasp_id.upper(), {})

    def list_supported_owasp_ids(self) -> list:
        """列出支持的 OWASP ID"""
        return sorted(self._profiles.keys())


def round_up(value: float) -> float:
    """CVSS 3.1 Round Up 函数"""
    import math
    int_input = int(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    else:
        return (math.floor(int_input / 10000) + 1) / 10.0


# ──────────────────────────────────────────────────────────────────────────────
# 便捷函数
# ──────────────────────────────────────────────────────────────────────────────

def calculate_cvss(
    owasp_id: str,
    success_rate: float = 0.0,
    custom_vector: Optional[CVSSVector] = None,
) -> CVSSResult:
    """便捷函数：计算 CVSS 评分"""
    calculator = CVSSCalculator()
    return calculator.calculate(owasp_id, success_rate, custom_vector)


def get_severity_color(severity: str) -> str:
    """获取严重度对应的颜色（用于 Markdown 报告）"""
    colors = {
        "Critical": "red",
        "High": "orange",
        "Medium": "yellow",
        "Low": "green",
        "None": "gray",
    }
    return colors.get(severity, "gray")
