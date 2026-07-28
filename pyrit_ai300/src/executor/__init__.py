"""
Executor Module — 对齐 pyrit.executor
======================================

PyRIT 1.0.0 Executor 子系统 — 完整五层架构

核心不变量 🟢：one-objective → one-result
核心 shape 🟢：configured by → consumes Context → produces Result
管道设计 🔵：Orchestrator + Converter + Scorer（组合式攻击管道）

┌─────────────────────────────────────────────────────────────────────┐
│  Layer 5: Benchmarks（标准测试层）⚪                                 │
│  "预定义测试集 + 预定义评分 → 一键出成绩单"                            │
│  → FairnessBiasWrapper, QuestionAnsweringWrapper                   │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 4: Workflow（批量编排层）🟡                                   │
│  "N 个 objectives × 1 套攻击流程"                                    │
│  → ScenarioOrchestrator, BatchAttackOrchestrator, XPIAWorkflow     │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 3: Compound（策略编排层）🟢                                   │
│  "1 个 objective × N 个攻击策略（fallback chain）"                    │
│  → SequentialExecutor                                              │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 2: Attack（执行层）🟢                                         │
│  "1 个 objective → 1 个 AttackResult"                               │
│  → SingleTurnExecutor, MultiTurnExecutor, NativeAttackExecutor      │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 1: Prompt Generators（种子生成层）⚪                          │
│  "把 1 个 objective 扩展成 N 个攻击变体"                              │
│  → AnecdoctorWrapper, FuzzerWrapper                                │
└─────────────────────────────────────────────────────────────────────┘

横切配置（所有层共享）🟢：
  AttackAdversarialConfig / AttackScoringConfig / AttackConverterConfig
  → attack/core/attack_builder.py

与 Datasets 五层架构的衔接：
  ① 数据准备层 → DatasetManager.load_datasets()
  ② 数据管理层 → CentralMemory
  ②.5 交互选择层 → SeedGroupSelector
  ③ 攻击准备层 → AttackPreparator (SeedGroup → AttackSeedGroup)
  ─────────────────────────────────────────────
  ④ 攻击执行层 → 本模块 (src.executor)  ← 衔接点
  ─────────────────────────────────────────────
  ⑤ 评估与追踪层 → Scorer + PyRIT Memory 审计链
"""

# Layer 1: Prompt Generators
from src.executor.promptgen import AnecdoctorWrapper, FuzzerWrapper, GCGWrapper, GCGConfig

# Layer 2: Attack Execution
from src.executor.attack.core.attack_builder import (
    ATTACK_CLASS_MAP,
    ATTACK_METADATA,
    create_attack_instance,
    create_attack_adversarial_config,
    create_prepended_conversation_config,
    create_attack_result_attribution,
    create_attacks_for_scenario,
    create_attacks_for_ai_type,
    get_attack_metadata,
    is_multi_turn_attack,
    list_attacks_by_multi_turn,
    create_simple_attack,
    create_red_team_attack,
    create_jailbreak_attack,
    create_leakage_attack,
    create_xpia_attack,
)
from src.executor.attack.core.native_executor import (
    NativeAttackExecutor,
    DirectAttackExecutor,
    execute_single_attack,
    validate_attack_plan,
    get_attack_execution_summary,
    reset_executor,
)
from src.executor.attack.core.scenario_event_handler import ScenarioEventHandler

# Layer 3: Compound
from src.executor.attack.compound.sequential_executor import SequentialExecutor

# Layer 4: Workflow
from src.executor.workflow.scenario_orchestrator import (
    ScenarioOrchestrator,
    execute_batch_attacks,
)
from src.executor.workflow.batch_orchestrator import BatchAttackOrchestrator
from src.executor.workflow.xpia_workflow import XPIAWorkflowWrapper

# Layer 5: Benchmarks
from src.executor.benchmark.fairness_bias import FairnessBiasWrapper
from src.executor.benchmark.question_answering import QuestionAnsweringWrapper

__all__ = [
    # Layer 1: Prompt Generators
    "AnecdoctorWrapper",
    "FuzzerWrapper",
    "GCGWrapper",
    "GCGConfig",
    # Layer 2: Attack Execution
    "ATTACK_CLASS_MAP",
    "ATTACK_METADATA",
    "create_attack_instance",
    "create_attack_adversarial_config",
    "create_prepended_conversation_config",
    "create_attack_result_attribution",
    "create_attacks_for_scenario",
    "create_attacks_for_ai_type",
    "get_attack_metadata",
    "is_multi_turn_attack",
    "list_attacks_by_multi_turn",
    "create_simple_attack",
    "create_red_team_attack",
    "create_jailbreak_attack",
    "create_leakage_attack",
    "create_xpia_attack",
    "NativeAttackExecutor",
    "DirectAttackExecutor",
    "execute_single_attack",
    "validate_attack_plan",
    "get_attack_execution_summary",
    "reset_executor",
    "ScenarioEventHandler",
    # Layer 3: Compound
    "SequentialExecutor",
    # Layer 4: Workflow
    "ScenarioOrchestrator",
    "execute_batch_attacks",
    "BatchAttackOrchestrator",
    "XPIAWorkflowWrapper",
    # Layer 5: Benchmarks
    "FairnessBiasWrapper",
    "QuestionAnsweringWrapper",
]
