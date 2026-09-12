# -*- coding: utf-8 -*-
"""tools/component_purity.py - Component Purity & Efficacy Validator.

Validates that component-based code organization is pure:
    1. Each module in strike/<component>/ only contains techniques targeting that component
    2. Each module in recon/<component/> contains the most effective recon strategies
    3. No cross-component pollution or generic code in component directories

Validation dimensions:
    - Purity: All attack/recon techniques are component-specific
    - Coverage: All high-ASR techniques from academic literature are present
    - Redundancy: No duplicate/low-efficacy techniques that waste budget

Academic basis:
    - Eidam et al. (arXiv:2407.16924) — A2A attack taxonomy completeness
    - Greshake et al. (arXiv:2302.12173) — MCP/RAG attack surface mapping
    - OWASP ASI Top 10 2025 — Component-specific technique requirements

Constitution compliance:
    - R-SIZE: < 800 lines
    - R-H3: Single responsibility — purity validation only
    - R-S1: No hardcoded target identifiers
"""

from __future__ import annotations

from tools.component_purity_config import (
    _RECON_COMPONENT_BASELINES,
    _STRIKE_COMPONENT_BASELINES,
)
from tools.component_purity_core import (
    ComponentPurityValidator,
    run_component_purity_check,
)

__all__ = [
    "_RECON_COMPONENT_BASELINES",
    "_STRIKE_COMPONENT_BASELINES",
    "ComponentPurityValidator",
    "run_component_purity_check",
]

if __name__ == "__main__":
    run_component_purity_check()
