# -*- coding: utf-8 -*-
"""utils/attack_utils.py — Attack result processing SSOT (Single Source of Truth).

P2 optimization (2026-09-06):
    Consolidates _is_success from multiple duplicated definitions:
    - utils/display_stages.py
    - strike/executor.py (and strike/_sequential.py)
    - report/evidence_extract.py

P0 enhancement (2026-09-09):
    Also consolidates _is_result_success from:
    - strike/output_filter_bypass.py
    - strike/multimodal_injection.py
    - strike/backdoor_attack.py
    - strike/escalation_runtime.py

This module is the SSOT for determining attack result success.
All attack modules must import from here, not redefine locally.

Academic basis:
    - PyRIT (arXiv:2407.01232): AttackOutcome枚举标准化攻击结果表示

Constitution compliance:
    - R-H3: Prevents dual-track redundancy (single success criteria)
    - C3: SSOT principle for result evaluation
"""

from __future__ import annotations

from core.is_success import _is_result_success, _is_success, is_attack_successful  # noqa: F401
