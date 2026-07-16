# -*- coding: utf-8 -*-
"""
AI-300 Framework - Payloads Module
载荷模块：管理攻击载荷、多维分析、种子数据集和 TextJailBreak 集成
"""

from .payload_manager import PayloadManager
from .payload_classifier import (
    classify_payload,
    classify_payloads,
    get_category_description,
    analyze_payload,
    analyze_payloads,
    get_loaded_pattern_info,
    PayloadProfile,
    ThreatModel,
)
from .text_jailbreak_integration import TextJailBreakIntegration

__all__ = [
    "PayloadManager",
    "TextJailBreakIntegration",
    "classify_payload",
    "classify_payloads",
    "get_category_description",
    "analyze_payload",
    "analyze_payloads",
    "get_loaded_pattern_info",
    "PayloadProfile",
    "ThreatModel",
]
