"""
===============================================================================
PyRIT Red Team — 攻击执行器模块 (已整合 attacks/)
===============================================================================

ATTENTION: 此模块已整合原 attacks/ 目录的所有攻击执行器。
导入路径变更：from attacks.xxx → from executor.xxx

分层：
  L3a: prompt_injection — DirectInjectionExecutor + JailbreakExecutor
  L3b: indirect_injection — XPIAExecutor
  L3c: RAG — RAGAttackExecutor
  L3d: Agent Abuse — AgentAbuseExecutor
  L3e: Model Extraction — ModelExtractionExecutor

所有执行器支持：
  - execute(strategy, target, budget) — 统一接口
  - pyrit_target 参数实现真实 PyRIT 管道
  - 无 PyRIT 时自动回退到模拟模式

为避免启动时加载整个依赖链，所有子模块使用懒加载策略。
===============================================================================
"""

import importlib
import logging

_log = logging.getLogger(__name__)


def __getattr__(name: str):
    """懒加载子模块和导出符号。"""
    # 映射: 符号名 -> (模块路径, 是否延迟)
    _LAZY_MAP: dict[str, tuple[str, bool]] = {
        # core
        "PAYLOAD_VARS": ("executor.template", True),
        "_resolve_template": ("executor.template", True),
        "CleanedSelfAskTrueFalseScorer": ("executor.scorer", True),
        "DashboardState": ("executor.dashboard", True),
        "classify_case": ("executor.utils", True),
        "_calc_success_rate": ("executor.utils", True),
        "execute_single_attack": ("executor.single", True),
        "execute_crescendo_attack": ("executor.crescendo", True),
        "MultimodalAttackConverter": ("executor.sequence_attack", True),
        "TrainingPoisoningConverter": ("executor.sequence_attack", True),
        "run_exploring_mode": ("executor.exploring", True),
        # P0-P2 dynamic
        "DynamicComboEngine": ("executor.dynamic_combo", True),
        "get_combo_engine": ("executor.dynamic_combo", True),
        "AdaptiveComboSelector": ("executor.adaptive_selector", True),
        "create_selector_from_probe": ("executor.adaptive_selector", True),
        "ReconResult": ("executor.adaptive_selector", True),
        "TargetArchitecture": ("executor.adaptive_selector", True),
        "BanditScheduler": ("executor.adaptive_selector", True),
        "AttackDeduplicator": ("executor.dedup_cache", True),
        "get_deduplicator": ("executor.dedup_cache", True),
        # L3a: Prompt Injection + Jailbreak (从 attacks/ 合并)
        "DirectInjectionExecutor": ("executor.direct_injection", True),
        "PayloadConverter": ("executor.direct_injection", True),
        "JailbreakExecutor": ("executor.jailbreak", True),
        "JAILBREAK_TEMPLATES": ("executor.jailbreak", True),
        # L3b: Indirect Injection / XPIA (从 attacks/ 合并)
        "XPIAExecutor": ("executor.indirect_injection", True),
        # L3c: RAG (从 attacks/ 合并)
        "RAGAttackExecutor": ("executor.rag_attack", True),
        "RAGInjectionResult": ("executor.rag_attack", True),
        "RAGTestReport": ("executor.rag_attack", True),
        # L3d: Agent Abuse (从 attacks/ 合并)
        "AgentAbuseExecutor": ("executor.agent_abuse", True),
        "AgentAbuseResult": ("executor.agent_abuse", True),
        "AgentAbuseReport": ("executor.agent_abuse", True),
        # L3e: Model Extraction (从 attacks/ 合并)
        "ModelExtractionExecutor": ("executor.model_extraction", True),
        "ExtractionResult": ("executor.model_extraction", True),
        "ModelExtractionReport": ("executor.model_extraction", True),
    }
    if name in _LAZY_MAP:
        mod_path = _LAZY_MAP[name][0]
        mod = importlib.import_module(mod_path)
        obj = getattr(mod, name)
        return obj
    raise AttributeError(f"module 'executor' has no attribute '{name}'")


__all__ = [
    # core
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
    # P0-P2 dynamic
    "DynamicComboEngine",
    "get_combo_engine",
    "AdaptiveComboSelector",
    "create_selector_from_probe",
    "ReconResult",
    "TargetArchitecture",
    "BanditScheduler",
    "AttackDeduplicator",
    "get_deduplicator",
    # L3a: Prompt Injection + Jailbreak
    "DirectInjectionExecutor",
    "PayloadConverter",
    "JailbreakExecutor",
    "JAILBREAK_TEMPLATES",
    # L3b: Indirect Injection / XPIA
    "XPIAExecutor",
    # L3c: RAG
    "RAGAttackExecutor",
    "RAGInjectionResult",
    "RAGTestReport",
    # L3d: Agent Abuse
    "AgentAbuseExecutor",
    "AgentAbuseResult",
    "AgentAbuseReport",
    # L3e: Model Extraction
    "ModelExtractionExecutor",
    "ExtractionResult",
    "ModelExtractionReport",
]
