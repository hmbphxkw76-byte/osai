# -*- coding: utf-8 -*-
"""
AI-300 Framework - OWASP Taxonomy Mapper
统一 OWASP 分类映射器：将各工具的原始 category 对齐到 OWASP ID

设计原则：
- OWASP ID 是唯一分类键（LLM01-LLM10, ASI01-ASI10）
- 不同工具的原始 category 映射到统一 OWASP ID
- 支持多对一映射（多个原始 category → 同一 OWASP ID）
- 冲突检测：同一 OWASP ID 被不同工具给出相反结论
"""

from __future__ import annotations

import sys
import os
from typing import Dict, List, Optional, Set, Tuple

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"


# ──────────────────────────────────────────────────────────────────────────────
# 统一 OWASP 分类映射
# ──────────────────────────────────────────────────────────────────────────────

# Garak probe → OWASP ID
GARAK_TO_OWASP: Dict[str, str] = {
    "promptinject": "LLM01",
    "dan": "LLM01",
    "jailbreak": "LLM01",
    "continuation": "LLM01",
    "goodside": "LLM01",
    "encoder": "LLM01",
    "malgen": "LLM02",
    "leakreplay": "LLM02",
    "hallucination": "LLM09",
    "misinformation": "LLM08",
    "toxicity": "LLM03",
    "av_spam": "LLM03",
    "xss": "LLM04",
}

# DeepTeam vulnerability → OWASP ID
DEEPTEAM_TO_OWASP: Dict[str, str] = {
    "prompt_injection": "LLM01",
    "jailbreak": "LLM01",
    "leakage": "LLM02",
    "data_exposure": "LLM02",
    "pii_leakage": "LLM02",
    "poisoning": "LLM03",
    "insecure_output": "LLM04",
    "excessive_agency": "LLM05",
    "system_prompt": "LLM06",
    "rag": "LLM07",
    "bias": "LLM08",
    "toxicity": "LLM09",
    "hallucination": "LLM09",
    "model_theft": "LLM10",
    # Agentic
    "goal_theft": "ASI01",
    "recursive_hijacking": "ASI02",
    "tool_abuse": "ASI03",
    "identity_abuse": "ASI04",
}

# ProtocolFingerprint category → OWASP ID
PROTOCOL_TO_OWASP: Dict[str, str] = {
    "protocol_detected": "",  # 协议发现不映射漏洞
    "auth_detected": "",
    "no_auth": "LLM01",
    "system_prompt_leak": "LLM06",
}

# 通用 category 关键词 → OWASP ID（兜底映射）
KEYWORD_TO_OWASP: Dict[str, str] = {
    "prompt_injection": "LLM01",
    "injection": "LLM01",
    "jailbreak": "LLM01",
    "dan": "LLM01",
    "sensitive_info": "LLM02",
    "leakage": "LLM02",
    "data_exposure": "LLM02",
    "pii": "LLM02",
    "poisoning": "LLM03",
    "training_data": "LLM03",
    "insecure_output": "LLM04",
    "xss": "LLM04",
    "excessive_agency": "LLM05",
    "system_prompt": "LLM06",
    "rag": "LLM07",
    "bias": "LLM08",
    "toxicity": "LLM09",
    "hallucination": "LLM09",
    "overreliance": "LLM09",
    "model_theft": "LLM10",
    "goal_theft": "ASI01",
    "recursive_hijacking": "ASI02",
    "tool_abuse": "ASI03",
    "identity_abuse": "ASI04",
}


# ──────────────────────────────────────────────────────────────────────────────
# OWASP ID → 攻击探针族映射
# ──────────────────────────────────────────────────────────────────────────────

OWASP_PROBE_FAMILY_MAP: Dict[str, str] = {
    "LLM01": "DIRECT_SINGLE",   # Prompt Injection → 直接注入
    "LLM02": "EXPLORATORY",     # Sensitive Info → 开放式探索
    "LLM03": "ITERATIVE",       # Poisoning → 迭代优化
    "LLM04": "DIRECT_SINGLE",   # Insecure Output → 直接注入
    "LLM05": "PROGRESSIVE",     # Excessive Agency → 渐进升级
    "LLM06": "EXPLORATORY",     # System Prompt → 开放式探索
    "LLM07": "TREE_SEARCH",     # RAG → 树搜索
    "LLM08": "PROGRESSIVE",     # Bias → 渐进升级
    "LLM09": "ITERATIVE",       # Overreliance → 迭代优化
    "LLM10": "TREE_SEARCH",     # Model Theft → 树搜索
    "ASI01": "PROGRESSIVE",     # Goal Hijack → 渐进升级
    "ASI02": "TREE_SEARCH",     # Recursive Hijack → 树搜索
    "ASI03": "PROGRESSIVE",     # Tool Abuse → 渐进升级
    "ASI04": "EXPLORATORY",     # Identity Abuse → 开放式探索
}

# 严重等级数值化（用于冲突比较）
SEVERITY_SCORE: Dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "unknown": 0,
}


class OwaspTaxonomy:
    """
    OWASP 统一分类映射器

    将各工具的原始 category 统一映射到 OWASP ID，
    并提供冲突检测与置信度融合功能。
    """

    @staticmethod
    def normalize(category: str, tool: str = "") -> str:
        """
        将原始 category 映射到 OWASP ID

        Args:
            category: 原始漏洞类别
            tool: 工具名称（用于选择映射表）

        Returns:
            OWASP ID（如 "LLM01"），未匹配返回空字符串
        """
        category_lower = category.lower().strip()
        category_upper = category.strip().upper()

        # 已经是 OWASP ID 格式
        if _maybe_owasp_id(category_upper):
            return category_upper

        # 按工具选择映射表
        if tool == "garak":
            owasp_id = GARAK_TO_OWASP.get(category_lower)
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

    @staticmethod
    def get_probe_family(owasp_id: str) -> str:
        """OWASP ID → 攻击探针族"""
        return OWASP_PROBE_FAMILY_MAP.get(owasp_id, "DIRECT_SINGLE")

    @staticmethod
    def get_all_owasp_ids() -> List[str]:
        """获取所有支持的 OWASP ID"""
        ids = set()
        ids.update(GARAK_TO_OWASP.values())
        ids.update(DEEPTEAM_TO_OWASP.values())
        ids.update(v for v in PROTOCOL_TO_OWASP.values() if v)
        return sorted(ids)

    @staticmethod
    def resolve_conflict(
        findings: List[dict],
    ) -> Tuple[str, float, bool]:
        """
        同一 OWASP ID 的多个发现之间的冲突解决

        Args:
            findings: 同一 OWASP ID 的发现列表
                     每项 {tool, severity, confidence, description}

        Returns:
            (resolved_severity, resolved_confidence, is_conflict)
            - resolved_severity: 融合后的严重等级
            - resolved_confidence: 融合后的置信度
            - is_conflict: 是否存在冲突（工具间结论不一致）
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
            # 多工具一致发现，置信度提升（上限 0.95）
            resolved_confidence = min(max_confidence + 0.10, 0.95)
        elif is_conflict:
            # 冲突时取最高置信度，但不提升
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
