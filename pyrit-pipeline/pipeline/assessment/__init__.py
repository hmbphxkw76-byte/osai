# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""评估方法论模块 — 三框架映射 + 5 阶段评估。.

本包提供:
1. framework_mapper.py — CSA + OWASP Agentic + MITRE ATLAS 三框架映射
2. redteam_methodology.py — 5 阶段红队评估方法论

> **日期**: 2026-8-4
"""

from __future__ import annotations

from pipeline.assessment.framework_mapper import (
    CSA_CATEGORY_OWASP_MAP,
    OWASP_ATLAS_MAP,
    AssessmentPhase,
    CoverageMatrix,
    FrameworkMapper,
    OWASPAgenticCode,
)
from pipeline.assessment.redteam_methodology import (
    AssessmentResult,
    RedTeamMethodology,
)

__all__ = [
    "CSA_CATEGORY_OWASP_MAP",
    "OWASP_ATLAS_MAP",
    "AssessmentPhase",
    "CoverageMatrix",
    "FrameworkMapper",
    "OWASPAgenticCode",
    "AssessmentResult",
    "RedTeamMethodology",
]
