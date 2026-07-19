# -*- coding: utf-8 -*-
"""
AI-300 Framework - MITRE ATLAS Mapper (REV-7 / GAP-5)
MITRE ATLAS 全量映射器：为安全报告提供标准化战术/技术映射

核心功能：
1. OWASP LLM/ASI 类别 → MITRE ATLAS 战术/技术 ID 映射
2. 攻击技术 → ATLAS 子技术映射
3. 生成 ATLAS 战术链（Kill Chain 对齐）
4. 支持报告中的 ATLAS 引用标准化

MITRE ATLAS 参考：
- https://atlas.mitre.org/
- 战术 (Tactics): AML.TAxxxx
- 技术 (Techniques): AML.Txxxx

对齐文档：docs/architecture_review.md §5.2 GAP-5
预期收益：报告标准化，与 MITRE ATLAS 框架对齐
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# OWASP 类别 → ATLAS 技术映射（简化版）
# ──────────────────────────────────────────────────────────────────────────────

OWASP_TO_ATLAS: Dict[str, List[str]] = {
    "LLM01": ["AML.T0041", "AML.T0051", "AML.T0061", "AML.T0091"],
    "LLM02": ["AML.T0080", "AML.T0081", "AML.T0101"],
    "LLM03": ["AML.T0004", "AML.T0020", "AML.T0092"],
    "LLM04": ["AML.T0052", "AML.T0092", "AML.T0041"],
    "LLM05": ["AML.T0042", "AML.T0043", "AML.T0112"],
    "LLM06": ["AML.T0041", "AML.T0042", "AML.T0043", "AML.T0112"],
    "LLM07": ["AML.T0070", "AML.T0071", "AML.T0080"],
    "LLM08": ["AML.T0083", "AML.T0032", "AML.T0052"],
    "LLM09": ["AML.T0113", "AML.T0112"],
    "LLM10": ["AML.T0110", "AML.T0111"],
    "ASI01": ["AML.T0041", "AML.T0051", "AML.T0112"],
    "ASI02": ["AML.T0042", "AML.T0043", "AML.T0073"],
    "ASI03": ["AML.T0081", "AML.T0072", "AML.T0102"],
    "ASI04": ["AML.T0004", "AML.T0020"],
    "ASI05": ["AML.T0042", "AML.T0043", "AML.T0112"],
    "ASI06": ["AML.T0054", "AML.T0052"],
    "ASI07": ["AML.T0041", "AML.T0080", "AML.T0101"],
    "ASI08": ["AML.T0112", "AML.T0110"],
    "ASI09": ["AML.T0041", "AML.T0112"],
    "ASI10": ["AML.T0050", "AML.T0053", "AML.T0112"],
}


@dataclass
class ATLASMapping:
    """ATLAS 映射结果"""
    owasp_id: str
    technique_ids: List[str] = field(default_factory=list)
    primary_technique: str = ""

    def to_markdown(self) -> str:
        if not self.technique_ids:
            return "N/A"
        return ", ".join(self.technique_ids)


class ATLASMapper:
    """MITRE ATLAS 全量映射器"""

    def map_owasp(self, owasp_id: str) -> ATLASMapping:
        """映射 OWASP 类别到 ATLAS 技术"""
        owasp_upper = owasp_id.upper()
        technique_ids = OWASP_TO_ATLAS.get(owasp_upper, [])
        primary = technique_ids[0] if technique_ids else ""

        return ATLASMapping(
            owasp_id=owasp_upper,
            technique_ids=technique_ids,
            primary_technique=primary,
        )

    def map_technique(self, technique_name: str) -> str:
        """映射攻击技术名称到 ATLAS ID"""
        tech_map = {
            "direct_injection": "AML.T0041",
            "jailbreak": "AML.T0061",
            "skeleton_key": "AML.T0061",
            "credential_leak": "AML.T0081",
            "code_execution": "AML.T0043",
            "memory_poisoning": "AML.T0054",
            "data_poisoning": "AML.T0052",
        }
        return tech_map.get(technique_name.lower(), "")

    def list_supported_owasp(self) -> List[str]:
        """列出支持的 OWASP ID"""
        return sorted(OWASP_TO_ATLAS.keys())