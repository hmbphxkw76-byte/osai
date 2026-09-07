""" — 6  + .

P1  (2026-09-06):
    imports core/orchestrator.py (1629) ,
    converter(s)converter(s), .

:
    - _helpers:   (burp  / endpoint  /  /  ASR)
    - recon:     ① Recon  (HTTP  + )
    - arm:       ③ ARM  ( +  + Converter )
    - strike:    ④ Strike + Escalate  ( + )
    - assess:    ⑤ Assess  ( + ASR )
    - report:    ⑥ Report  ( + )
"""

from core.phases._helpers import (
    _detect_non_burp_mode,
    _extract_auth_recovery_log,
    _extract_target_profile,
    _get_arm_target_type,
    _get_result_outcome,
    _print_endpoint_header,
    _print_endpoint_sort_results,
    _print_joint_asr_summary,
    _record_arm_seed_orchestration,
    _record_recon_orchestration,
    _register_dynamic_initializers,
    _re_set_memory_labels,
    _reset_endpoint_state,
    _resolve_burp_list,
    _setup_memory_labels,
)
from core.phases.arm import _run_arm_phase
from core.phases.assess import _run_assess_phase
from core.phases.recon import (
    _run_auto_l4_optimization,
    _run_recon_phase,
    _run_scenario_routing,
    _run_synergy_phase,
)
from core.phases.report import _run_report_phase
from core.phases.strike import _run_escalate_phase, _run_strike_phase

__all__ = [
    # Recon
    "_run_recon_phase",
    "_run_synergy_phase",
    "_run_scenario_routing",
    "_run_auto_l4_optimization",
    # ARM
    "_run_arm_phase",
    # Strike + Escalate
    "_run_strike_phase",
    "_run_escalate_phase",
    # Assess
    "_run_assess_phase",
    # Report
    "_run_report_phase",
    # Helpers
    "_resolve_burp_list",
    "_detect_non_burp_mode",
    "_setup_memory_labels",
    "_re_set_memory_labels",
    "_register_dynamic_initializers",
    "_reset_endpoint_state",
    "_print_endpoint_sort_results",
    "_print_endpoint_header",
    "_print_joint_asr_summary",
    "_extract_target_profile",
    "_get_arm_target_type",
    "_record_recon_orchestration",
    "_record_arm_seed_orchestration",
    "_get_result_outcome",
    "_extract_auth_recovery_log",
]
