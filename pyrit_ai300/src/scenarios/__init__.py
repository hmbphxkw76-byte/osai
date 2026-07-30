"""
AI-300 Scenario Module — 对齐 pyrit.scenario
================================================

PyRIT 1.0.0 Scenario 子系统 — 原生优先 + 自建保留

架构分层（PyRIT 架构师视角）：
    Scenario (顶层编排器) → AtomicAttack (原子测试单元) → ScenarioResult (聚合结果)

核心不变量 🟢：Scenario = {AtomicAttack_1, ..., AtomicAttack_n} -> ScenarioResult
整合策略 🔵：原生优先替代 4 项自建 + 保留 2 项必须自建

原生替代（4 项）：
  1. 智能升级重试 → AdaptiveScenario + FailureTypeRoutingSelector
  2. 双通道输出 → output_scenario_async + StdoutSink/FileSink
  3. ProgressDashboard → 原生 tqdm 进度条
  4. ScenarioEventHandler → 原生 AttackExecutor event handler + logging

保留自建（2 项）：
  1. 差异化超时（per_attack_timeout）— PyRIT 无 per-attack 超时
  2. OWASP 映射 — 通过 memory_labels 集成

模块组成：
  - ai300_scenario.py          AI300Scenario 基类（extends Scenario）
  - ai300_adaptive_scenario.py AI300AdaptiveScenario（extends AdaptiveScenario）
  - ai300_technique.py         AI300Technique 枚举（extends ScenarioTechnique）
  - technique_factories.py     Technique 工厂注册（core + extra）
  - technique_initializer.py   TechniqueInitializer 初始化器
  - failure_type_selector.py   FailureTypeRoutingSelector（替代自建升级重试）
  - scenario_output.py         原生 output_scenario_async 双通道
  - scenario_result_bridge.py  BatchAttackResult <-> ScenarioResult + OWASP 集成

性能优化 (v8.2):
  使用 PEP 562 __getattr__ 实现懒加载。scenarios 包含 13 个子模块，
  eager import 导致 ~4s 启动延迟。懒加载后仅在实际访问属性时才触发导入。
  推荐直接从子模块导入：
    from src.scenarios.technique_factories import register_ai300_techniques  # ✓
"""

_LAZY_IMPORTS = {
    # ── ai300_scenario ──
    "AI300Scenario": ("src.scenarios.ai300_scenario", "AI300Scenario"),
    "AI300RapidResponseScenario": ("src.scenarios.ai300_scenario", "AI300RapidResponseScenario"),
    "AI300JailbreakScenario": ("src.scenarios.ai300_scenario", "AI300JailbreakScenario"),
    "AI300EncodingScenario": ("src.scenarios.ai300_scenario", "AI300EncodingScenario"),
    # ── ai300_technique ──
    "AI300Technique": ("src.scenarios.ai300_technique", "AI300Technique"),
    "AI300EncodingTechnique": ("src.scenarios.ai300_technique", "AI300EncodingTechnique"),
    # ── technique_factories ──
    "get_core_technique_factories": ("src.scenarios.technique_factories", "get_core_technique_factories"),
    "get_extra_technique_factories": ("src.scenarios.technique_factories", "get_extra_technique_factories"),
    "get_all_technique_factories": ("src.scenarios.technique_factories", "get_all_technique_factories"),
    "get_encoding_technique_factories": ("src.scenarios.technique_factories", "get_encoding_technique_factories"),
    "get_simulated_conversation_factories": ("src.scenarios.technique_factories", "get_simulated_conversation_factories"),
    "register_ai300_techniques": ("src.scenarios.technique_factories", "register_ai300_techniques"),
    "AI300_TECHNIQUE_METADATA": ("src.scenarios.technique_factories", "AI300_TECHNIQUE_METADATA"),
    "CONVERTER_VARIANT_CHAINS": ("src.scenarios.technique_factories", "CONVERTER_VARIANT_CHAINS"),
    "BASE_TECHNIQUES_FOR_VARIANTS": ("src.scenarios.technique_factories", "BASE_TECHNIQUES_FOR_VARIANTS"),
    "build_converter_variant_factories": ("src.scenarios.technique_factories", "build_converter_variant_factories"),
    "get_converter_variant_names": ("src.scenarios.technique_factories", "get_converter_variant_names"),
    "is_converter_variant": ("src.scenarios.technique_factories", "is_converter_variant"),
    "get_base_technique_from_variant": ("src.scenarios.technique_factories", "get_base_technique_from_variant"),
    "get_converter_chain_from_variant": ("src.scenarios.technique_factories", "get_converter_chain_from_variant"),
    "_is_chain_modality_compatible": ("src.scenarios.technique_factories", "_is_chain_modality_compatible"),
    "_get_dynamic_chain_mapping": ("src.scenarios.technique_factories", "_get_dynamic_chain_mapping"),
    # ── technique_initializer ──
    "AI300TechniqueInitializer": ("src.scenarios.technique_initializer", "AI300TechniqueInitializer"),
    "initialize_techniques_async": ("src.scenarios.technique_initializer", "initialize_techniques_async"),
    # ── failure_type_selector ──
    "FailureTypeRoutingSelector": ("src.scenarios.failure_type_selector", "FailureTypeRoutingSelector"),
    "extract_failure_type_from_result": ("src.scenarios.failure_type_selector", "extract_failure_type_from_result"),
    "STRATEGY_ACADEMIC": ("src.scenarios.failure_type_selector", "STRATEGY_ACADEMIC"),
    "STRATEGY_EXAM": ("src.scenarios.failure_type_selector", "STRATEGY_EXAM"),
    "STRATEGY_BALANCED": ("src.scenarios.failure_type_selector", "STRATEGY_BALANCED"),
    # ── ai300_adaptive_scenario ──
    "AI300AdaptiveScenario": ("src.scenarios.ai300_adaptive_scenario", "AI300AdaptiveScenario"),
    "AI300EpsilonGreedySelector": ("src.scenarios.ai300_adaptive_scenario", "AI300EpsilonGreedySelector"),
    # ── adaptive_runner ──
    "run_adaptive_scenario_async": ("src.scenarios.adaptive_runner", "run_adaptive_scenario_async"),
    "prepare_scenario_async": ("src.scenarios.adaptive_runner", "prepare_scenario_async"),
    "execute_scenario_async": ("src.scenarios.adaptive_runner", "execute_scenario_async"),
    "AdaptiveRunResult": ("src.scenarios.adaptive_runner", "AdaptiveRunResult"),
    "ScenarioPreparation": ("src.scenarios.adaptive_runner", "ScenarioPreparation"),
    # ── scenario_output ──
    "output_scenario_async": ("src.scenarios.scenario_output", "output_scenario_async"),
    "output_scenario_summary": ("src.scenarios.scenario_output", "output_scenario_summary"),
    "sort_results_by_success_rate": ("src.scenarios.scenario_output", "sort_results_by_success_rate"),
    "get_per_group_breakdown": ("src.scenarios.scenario_output", "get_per_group_breakdown"),
    "display_enhanced_group_breakdown": ("src.scenarios.scenario_output", "display_enhanced_group_breakdown"),
    # ── scenario_result_bridge ──
    "ScenarioResultBridge": ("src.scenarios.scenario_result_bridge", "ScenarioResultBridge"),
    "batch_result_to_scenario_result": ("src.scenarios.scenario_result_bridge", "batch_result_to_scenario_result"),
    "build_memory_labels": ("src.scenarios.scenario_result_bridge", "build_memory_labels"),
    # ── asr_strategy_display ──
    "display_analysis_stage": ("src.scenarios.asr_strategy_display", "display_analysis_stage"),
    "display_selection_stage": ("src.scenarios.asr_strategy_display", "display_selection_stage"),
    "display_execution_stage": ("src.scenarios.asr_strategy_display", "display_execution_stage"),
    "display_post_execution": ("src.scenarios.asr_strategy_display", "display_post_execution"),
    # ── converter_health_monitor ──
    "ConverterHealthMonitor": ("src.scenarios.converter_health_monitor", "ConverterHealthMonitor"),
    "ConverterStats": ("src.scenarios.converter_health_monitor", "ConverterStats"),
    "extract_converter_name_from_error": ("src.scenarios.converter_health_monitor", "extract_converter_name_from_error"),
    "extract_chain_name_from_error": ("src.scenarios.converter_health_monitor", "extract_chain_name_from_error"),
    # ── empirical_asr_store ──
    "load_empirical_asr": ("src.scenarios.empirical_asr_store", "load_empirical_asr"),
    "update_empirical_asr": ("src.scenarios.empirical_asr_store", "update_empirical_asr"),
    "compute_effective_asr": ("src.scenarios.empirical_asr_store", "compute_effective_asr"),
    "detect_patched_techniques": ("src.scenarios.empirical_asr_store", "detect_patched_techniques"),
    "generate_strategy_recommendation": ("src.scenarios.empirical_asr_store", "generate_strategy_recommendation"),
    "extract_tech_stats_from_results": ("src.scenarios.empirical_asr_store", "extract_tech_stats_from_results"),
    # ── runtime_stop_handler ──
    "RuntimeStopEventHandler": ("src.scenarios.runtime_stop_handler", "RuntimeStopEventHandler"),
    "StopStrategyContext": ("src.scenarios.runtime_stop_handler", "StopStrategyContext"),
}

__all__ = list(_LAZY_IMPORTS.keys())


def __getattr__(name: str):
    """PEP 562 懒加载：首次访问属性时才触发对应模块的导入。"""
    import importlib

    mapping = _LAZY_IMPORTS.get(name)
    if mapping is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    module_path, attr_name = mapping
    module = importlib.import_module(module_path)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value
