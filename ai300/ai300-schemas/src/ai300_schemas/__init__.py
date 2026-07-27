# -*- coding: utf-8 -*-
"""
ai300-schemas
=============

AI-300 三项目共享数据契约。
"""

from .pyrit_target import PyRITTargetConfig
from .target_profile import (
    FingerprintData,
    TargetProfile,
    VulnerabilityFinding,
)
from .unified_finding import (
    Evidence,
    UnifiedFinding,
    dedup_findings,
)

__all__ = [
    "Evidence",
    "FingerprintData",
    "PyRITTargetConfig",
    "TargetProfile",
    "UnifiedFinding",
    "VulnerabilityFinding",
    "dedup_findings",
]

__version__ = "0.1.0"
