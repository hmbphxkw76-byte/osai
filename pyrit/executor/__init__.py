"""
===============================================================================
PyRIT Red Team — 攻击引擎模块
===============================================================================
统一对外接口: PAYLOAD_VARS, CleanedSelfAskTrueFalseScorer, DashboardState,
              classify_case, _calc_success_rate,
              execute_single_attack, execute_crescendo_attack,
              MultimodalAttackConverter, TrainingPoisoningConverter,
              run_exploring_mode

🆕 P0-P2 新模块:
  - DynamicComboEngine: 动态组合生成引擎
  - AdaptiveComboSelector: 自适应攻击策略选择器
  - AttackDeduplicator: 请求级去重缓存

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

# 🆕 P0-P2 动态引擎模块
from executor.dynamic_combo import (
    DynamicComboEngine,
    get_combo_engine,
)
from executor.adaptive_selector import (
    AdaptiveComboSelector,
    create_selector_from_probe,
    ReconResult,
    TargetArchitecture,
    BanditScheduler,
)
from executor.dedup_cache import (
    AttackDeduplicator,
    get_deduplicator,
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
    "run_exploring_mode",
    # 🆕 P0-P2
    "DynamicComboEngine",
    "get_combo_engine",
    "AdaptiveComboSelector",
    "create_selector_from_probe",
    "ReconResult",
    "TargetArchitecture",
    "BanditScheduler",
    "AttackDeduplicator",
    "get_deduplicator",
]
