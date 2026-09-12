"""-  main.py + 6

 (God Object):
    - core/phases/executor.py: run_single_endpoint / run_single_endpoint_to_result
    - core/phases/recon.py: Recon
    - core/phases/arm.py: ARM
    - core/phases/strike.py: Strike + Escalate
    - core/phases/assess.py: Assess
    - core/phases/report.py: Report

: core/phases/
"""

from __future__ import annotations

#  ( )
from core.phases.arm import _run_arm_phase  # noqa: E402
from core.phases.assess import _run_assess_phase  # noqa: E402

#  -  orchestrator.py
#  endpoints ()
from core.phases.executor import (  # noqa: E402
    run_attack_pipeline,
    run_single_endpoint,
    run_single_endpoint_to_result,
)
from core.phases.recon import _run_recon_phase  # noqa: E402
from core.phases.report import _run_report_phase  # noqa: E402
from core.phases.strike import (  # noqa: E402
    _run_escalate_phase,
    _run_strike_phase,
)

__all__ = [
    #  endpoints
    "run_single_endpoint",
    "run_single_endpoint_to_result",
    "run_attack_pipeline",
    #  recon
    "_run_recon_phase",
    #  arm
    "_run_arm_phase",
    #  strike + escalate
    "_run_strike_phase",
    "_run_escalate_phase",
    #  assess
    "_run_assess_phase",
    #  report
    "_run_report_phase",
]
