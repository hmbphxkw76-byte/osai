# -*- coding: utf-8 -*-
"""
AI-300 Framework - Orchestrators Module v3.0
攻击流程编排器，使用 PyRIT 原生攻击策略执行

子模块：
- component_registry: PyRIT 组件映射表（转换器 + 评分器）
- attack_registry: PyRIT 攻击注册表
- attack_orchestrator: 攻击编排器主类
- smart_matcher: 智能匹配引擎
"""

from .attack_orchestrator import AttackOrchestrator
from .component_registry import (
    CONVERTER_MAP,
    SCORER_MAP,
    SPECIAL_PRESETS,
    LLM_BACKEND_SCORERS,
    CONVERTER_NAME_MAP,
    SCORER_NAME_MAP,
)
from .attack_registry import (
    ATTACK_REGISTRY,
    list_attacks,
    get_attack_info,
    get_attack_class,
    list_types,
)
from .smart_matcher import (
    SmartMatcher,
    select_attack_strategy,
    select_preset_strategy,
    PyRITAttack,
    AttackProbeFamily,
)

__all__ = [
    # AttackOrchestrator
    "AttackOrchestrator",
    # Component Registry
    "CONVERTER_MAP",
    "SCORER_MAP",
    "SPECIAL_PRESETS",
    "LLM_BACKEND_SCORERS",
    "CONVERTER_NAME_MAP",
    "SCORER_NAME_MAP",
    # Attack Registry
    "ATTACK_REGISTRY",
    "list_attacks",
    "get_attack_info",
    "get_attack_class",
    "list_types",
    # Smart Matcher
    "SmartMatcher",
    "select_attack_strategy",
    "select_preset_strategy",
    "PyRITAttack",
    "AttackProbeFamily",
]
