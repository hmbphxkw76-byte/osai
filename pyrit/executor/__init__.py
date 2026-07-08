"""
===============================================================================
PyRIT Red Team — 攻击引擎模块
===============================================================================
统一对外接口: PAYLOAD_VARS, CleanedSelfAskTrueFalseScorer, DashboardState,
              classify_case, _calc_success_rate,
              execute_single_attack, execute_crescendo_attack,
              MultimodalAttackConverter, TrainingPoisoningConverter,
              run_exploring_mode

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
from executor.exploring import run_exploring_mode

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
    "run_exploring_mode",
]
