# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""ASR 驱动选择与优化子包。.

包含以下模块:
  - prior_registry: 学术 ASR 先验注册表 (arXiv 基准数据)
  - optimizer: ASR 驱动攻击优化器 (历史数据排序)
  - rank_builder: ASR 排序构建器 + 组级降级链
  - failure_type_selector: 失败类型路由技术选择器 (继承原生 EpsilonGreedy)
  - failure_type_event_handler: Post-execution 失败类型扫描器
  - tiered_selection_wizard: 三层渐进式选择向导
  - runtime_stop_handler: 运行时停止策略事件处理器 (L5 执行韧性)

统一入口:
    from pipeline.asr import (
        get_initial_q_value,
        FailureTypeRoutingSelector,
        ASRRankBuilder,
        GroupFallbackExecutor,
        TieredSelectionWizard,
    )
"""

from pipeline.asr.failure_type_event_handler import FailureTypeEventHandler
from pipeline.asr.failure_type_selector import FailureTypeRoutingSelector
from pipeline.asr.optimizer import (
    collect_seed_level_asr_from_memory,
    compute_mtos_score,
    get_asr_summary,
    get_current_run_asr_summary,
    get_technique_asr_summary,
    load_seed_level_asr,
    merge_empirical_with_priors,
    query_current_run_asr_by_technique,
    query_historical_asr_by_category,
    query_historical_asr_by_technique,
    save_seed_level_asr,
    select_multiturn_objectives,
    sort_datasets_by_asr,
)
from pipeline.asr.prior_registry import get_initial_q_value, tier_from_asr
from pipeline.asr.rank_builder import ASRRankBuilder, GroupFallbackExecutor
from pipeline.asr.runtime_stop_handler import RuntimeStopEventHandler, StopStrategyContext
from pipeline.asr.tiered_selection_wizard import TieredSelectionWizard

__all__ = [
    # prior_registry
    "get_initial_q_value",
    "tier_from_asr",
    # optimizer
    "collect_seed_level_asr_from_memory",
    "compute_mtos_score",
    "get_asr_summary",
    "get_current_run_asr_summary",
    "get_technique_asr_summary",
    "load_seed_level_asr",
    "merge_empirical_with_priors",
    "query_current_run_asr_by_technique",
    "query_historical_asr_by_category",
    "query_historical_asr_by_technique",
    "save_seed_level_asr",
    "select_multiturn_objectives",
    "sort_datasets_by_asr",
    # rank_builder
    "ASRRankBuilder",
    "GroupFallbackExecutor",
    # failure_type_selector
    "FailureTypeRoutingSelector",
    # failure_type_event_handler
    "FailureTypeEventHandler",
    # tiered_selection_wizard
    "TieredSelectionWizard",
    # runtime_stop_handler
    "RuntimeStopEventHandler",
    "StopStrategyContext",
]
