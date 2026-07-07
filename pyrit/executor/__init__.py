"""
===============================================================================
OffSec AI-300 — 攻击引擎模块
===============================================================================
统一对外接口: PAYLOAD_VARS, CleanedSelfAskTrueFalseScorer, DashboardState,
              classify_case, _calc_success_rate,
              execute_single_attack, execute_crescendo_attack,
              MultimodalAttackConverter, TrainingPoisoningConverter

import: from executor import DashboardState, classify_case, ...
===============================================================================
"""
from executor.template import PAYLOAD_VARS, _resolve_template
from executor.scorer import CleanedSelfAskTrueFalseScorer
from executor.dashboard import DashboardState
from executor.utils import classify_case, _calc_success_rate
from executor.single import execute_single_attack
from executor.crescendo import execute_crescendo_attack
from executor.sequence_attack import (
    MultimodalAttackConverter,
    TrainingPoisoningConverter,
)

__all__ = [
    "PAYLOAD_VARS",
    "_resolve_template",
    "CleanedSelfAskTrueFalseScorer",
    "DashboardState",
    "classify_case",
    "_calc_success_rate",
    "execute_single_attack",
    "execute_crescendo_attack",
    "MultimodalAttackConverter",
    "TrainingPoisoningConverter",
]
