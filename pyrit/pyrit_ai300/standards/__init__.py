# -*- coding: utf-8 -*-
"""
AI-300 Framework - Standards Module
OWASP / NIST / MITRE 标准映射与框架抽象层

权威来源：
- owasp_2025.py: OWASP Top 10 for LLMs 2025 + Agents 2026 权威映射
- framework_base.py: AISafetyFramework 基类
- risk_category.py: RiskCategory 数据模型
- owasp_llm_framework.py: OWASP Top 10 for LLMs 框架实现
- owasp_asi_framework.py: OWASP Top 10 for Agents 框架实现
- framework_registry.py: 框架注册表
"""

from .owasp_2025 import (
    OwaspEntry,
    OWASP_LLM_2025,
    OWASP_ASI_2026,
    GARAK_TO_OWASP,
    DEEPTEAM_TO_OWASP,
    PROTOCOL_TO_OWASP,
    KEYWORD_TO_OWASP,
    OWASP_PROBE_FAMILY_MAP,
    SEVERITY_SCORE,
    get_all_owasp_ids,
    get_owasp_entry,
    get_owasp_title,
    get_owasp_display_name,
    get_owasp_category,
    get_owasp_description,
    get_probe_family,
    normalize_category,
    resolve_conflict,
)

# P1: 框架抽象层
from .framework_base import (
    AISafetyFramework,
    FrameworkVulnerability,
    FrameworkAttack,
)
from .risk_category import (
    RiskCategory,
    RISK_CATEGORIES,
    OWASP_TO_RISK_CATEGORY,
    get_risk_category,
    get_all_risk_categories,
    get_top_level_categories,
)
from .owasp_llm_framework import OWASPLinearFramework2025
from .owasp_asi_framework import OWASPAgenticFramework2026
from .framework_registry import (
    register_framework,
    get_framework,
    list_frameworks,
    get_framework_info,
    get_all_frameworks_info,
    framework_to_yaml,
    framework_to_json,
    select_framework_from_config,
)

__all__ = [
    # OWASP 2025 权威映射
    "OwaspEntry",
    "OWASP_LLM_2025",
    "OWASP_ASI_2026",
    "GARAK_TO_OWASP",
    "DEEPTEAM_TO_OWASP",
    "PROTOCOL_TO_OWASP",
    "KEYWORD_TO_OWASP",
    "OWASP_PROBE_FAMILY_MAP",
    "SEVERITY_SCORE",
    # 便捷函数
    "get_all_owasp_ids",
    "get_owasp_entry",
    "get_owasp_title",
    "get_owasp_display_name",
    "get_owasp_category",
    "get_owasp_description",
    "get_probe_family",
    "normalize_category",
    "resolve_conflict",
    # P1: 框架抽象层
    "AISafetyFramework",
    "FrameworkVulnerability",
    "FrameworkAttack",
    # P1: 风险类别
    "RiskCategory",
    "RISK_CATEGORIES",
    "OWASP_TO_RISK_CATEGORY",
    "get_risk_category",
    "get_all_risk_categories",
    "get_top_level_categories",
    # P1: 框架实现
    "OWASPLinearFramework2025",
    "OWASPAgenticFramework2026",
    # P1: 框架注册表
    "register_framework",
    "get_framework",
    "list_frameworks",
    "get_framework_info",
    "get_all_frameworks_info",
    "framework_to_yaml",
    "framework_to_json",
    "select_framework_from_config",
]
