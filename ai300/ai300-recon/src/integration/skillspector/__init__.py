# -*- coding: utf-8 -*-
"""
SkillSpector 集成模块

对 AI agent skills / MCP skills 进行静态安全扫描。
"""

from .client import SkillSpectorClient, SkillSpectorError, SkillSpectorMode
from .result_normalizer import SkillSpectorResultNormalizer

__all__ = [
    "SkillSpectorClient",
    "SkillSpectorError",
    "SkillSpectorMode",
    "SkillSpectorResultNormalizer",
]
