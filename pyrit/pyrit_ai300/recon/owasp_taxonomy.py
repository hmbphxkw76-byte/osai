# -*- coding: utf-8 -*-
"""
AI-300 Framework - OWASP Taxonomy Mapper (v2)
统一 OWASP 分类映射器：将各工具的原始 category 对齐到 OWASP ID

v2 变更（2026-07-22）：
- 移除本地映射表，统一从 standards/owasp_2025.py 导入（单一真相来源）
- 对齐 OWASP Top 10 for LLMs 2025 + OWASP Top 10 for Agents 2026
- 保持 API 向后兼容（OwaspTaxonomy 类的接口不变）

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

# ── P0: 从权威来源导入映射（单一真相来源） ──
from ..standards.owasp_2025 import (
    GARAK_TO_OWASP,
    DEEPTEAM_TO_OWASP,
    PROTOCOL_TO_OWASP,
    KEYWORD_TO_OWASP,
    OWASP_PROBE_FAMILY_MAP,
    SEVERITY_SCORE,
    normalize_category as _normalize_category,
    resolve_conflict as _resolve_conflict,
    get_all_owasp_ids as _get_all_owasp_ids,
    get_probe_family as _get_probe_family,
)


class OwaspTaxonomy:
    """
    OWASP 统一分类映射器（v2，从 standards/owasp_2025.py 导入）

    将各工具的原始 category 统一映射到 OWASP ID，
    并提供冲突检测与置信度融合功能。

    所有映射表和常量已移至 pyrit_ai300.standards.owasp_2025，
    本类保持 API 向后兼容。
    """

    # 向后兼容：暴露映射表为类属性
    GARAK_TO_OWASP = GARAK_TO_OWASP
    DEEPTEAM_TO_OWASP = DEEPTEAM_TO_OWASP
    PROTOCOL_TO_OWASP = PROTOCOL_TO_OWASP
    KEYWORD_TO_OWASP = KEYWORD_TO_OWASP
    OWASP_PROBE_FAMILY_MAP = OWASP_PROBE_FAMILY_MAP
    SEVERITY_SCORE = SEVERITY_SCORE

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
        return _normalize_category(category, tool)

    @staticmethod
    def get_probe_family(owasp_id: str) -> str:
        """OWASP ID → 攻击探针族"""
        return _get_probe_family(owasp_id)

    @staticmethod
    def get_all_owasp_ids() -> List[str]:
        """获取所有支持的 OWASP ID"""
        return _get_all_owasp_ids()

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
        return _resolve_conflict(findings)
