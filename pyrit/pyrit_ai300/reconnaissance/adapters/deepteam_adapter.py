# -*- coding: utf-8 -*-
"""DeepTeam Adapter - 向后兼容 shim（已迁移到 deepteam/ 包）"""

from .deepteam import DeepTeamAdapter
from .deepteam.adapter import (
    VULNERABILITY_OWASP_MAP,
    ATTACK_TYPES_BY_DEPTH,
    AGENTIC_ATTACK_TYPES,
    ATTACK_METHODS,
    DEFAULT_VULNERABILITIES,
)

__all__ = [
    "DeepTeamAdapter",
    "VULNERABILITY_OWASP_MAP",
    "ATTACK_TYPES_BY_DEPTH",
    "AGENTIC_ATTACK_TYPES",
    "ATTACK_METHODS",
    "DEFAULT_VULNERABILITIES",
]
