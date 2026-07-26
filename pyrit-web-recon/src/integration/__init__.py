# -*- coding: utf-8 -*-
"""
外部工具集成层

封装 AI-Infra-Guard、RedAmon 等外部红队/侦察工具的访问接口。
"""

from .aig import AIGClient, AIGClientError, AIGResultNormalizer, AIGTaskBuilder
from .redamon import ProfileToGraphAdapter, RedAmonClient, RedAmonClientError
from .schemas.unified_finding import Evidence, UnifiedFinding, dedup_findings
from .skillspector import (
    SkillSpectorClient,
    SkillSpectorError,
    SkillSpectorMode,
    SkillSpectorResultNormalizer,
)

__all__ = [
    "AIGClient",
    "AIGClientError",
    "AIGResultNormalizer",
    "AIGTaskBuilder",
    "RedAmonClient",
    "RedAmonClientError",
    "ProfileToGraphAdapter",
    "SkillSpectorClient",
    "SkillSpectorError",
    "SkillSpectorMode",
    "SkillSpectorResultNormalizer",
    "Evidence",
    "UnifiedFinding",
    "dedup_findings",
]
