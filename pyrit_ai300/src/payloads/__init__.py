"""
Payloads Module
===============

本模块负责批量多源攻击的数据源管理和载荷规划。

对齐 PyRIT 1.0.0 五层架构：
  ① 数据准备层 → source_loader.py (PayloadSourceLoader)
  ② 数据管理层 → dataset_manager.py (DatasetManager / CentralMemory)
  ②.5 交互式选择层 → seed_selector.py (SeedGroupSelector)
  ③ 攻击准备层 → attack_preparator.py (AttackPreparator / AttackSeedGroup)
  ④ 攻击执行层 → executor/ (NativeAttackExecutor / ScenarioOrchestrator)
  ⑤ 评估与追踪层 → scorers/ + PyRIT Memory

模块清单：
- models.py: 数据模型 (PromptItem, PromptBatch, AttackMode, AttackPlan)
- source_loader.py: 数据源加载器 (OWASP 目录 / 自定义 / PyRIT 远程)
- dataset_manager.py: CentralMemory 数据枢纽 (②层)
- seed_selector.py: 交互式种子组选择 (②.5层)
- attack_preparator.py: AttackSeedGroup 攻击准备 (③层)
- seed_adapter.py: PyRIT SeedDataset ↔ PromptBatch 双向适配器（含多模态支持）
- owasp_provider.py: OWASP 本地数据集 SeedDatasetProvider 桥接层
- planner.py: 载荷规划器 (PromptItem → AttackPlan) [兼容模式]
- simulated_conversation.py: 模拟对话生成与重放 (P0 新增)
- remote_loaders.py: 项目自定义远程数据集加载器 (P1 新增)
- native_pipeline.py: 原生管道快捷路径 (P3 新增)
- target_profile_router.py: 目标类型→OWASP映射 (②.5 Layer 1)
- asr_rank_builder.py: ASR分层排序+启发式代理 (②.5 Layer 2)
- tiered_selection_wizard.py: 三层渐进式选择界面 (②.5 Layer 3)
- group_fallback_executor.py: 组级ASR降级链执行器 (④层增强)
"""

from src.payloads.models import (
    AttackMode,
    AttackPlan,
    BatchAttackResult,
    PromptBatch,
    PromptItem,
    SequentialStep,
)
from src.payloads.source_loader import (
    PayloadSourceLoader,
    load_payloads,
    load_payloads_async,
    load_all_payloads_async,
)
from src.payloads.dataset_manager import (
    DatasetManager,
)
from src.payloads.seed_selector import (
    SeedGroupSelector,
    SeedGroupEntry,
)
from src.payloads.attack_preparator import (
    AttackPreparator,
    AttackExecutionParams,  # deprecated: 使用 AttackSeedGroup 替代
)
from src.payloads.seed_adapter import (
    SeedPromptAdapter,
)
from src.payloads.planner import (
    PayloadPlanner,
    plan_attacks,
)
from src.payloads.simulated_conversation import (
    generate_simulated_conversation_async,
    precompute_simulated_conversation_async,
    precompute_batch_async,
    replay_to_target_async,
    create_simulated_conversation_seed,
    inject_simulated_conversation_into_group,
    create_attack_with_simulated_conversation,
    get_preset,
    get_preset_combos,
)
from src.payloads.remote_loaders import (
    AI300OWASPCustomDataset,
    AI300AgenticThreatsDataset,
    AI300ExamSimDataset,
    get_project_dataset_names,
    is_project_dataset_registered,
)
from src.payloads.native_pipeline import (
    NativePipelineExecutor,
    get_native_pipeline,
    execute_native_async,
    evaluate_attack_plan_necessity,
)
from src.payloads.payload_adapter import (
    convert_payload_file,
    convert_jailbreak_directory,
)
from src.payloads.target_profile_router import (
    TargetType,
    TargetProfile,
    TargetProfileRouter,
    get_target_profile,
    infer_target_profile,
    filter_groups_by_target,
)
from src.payloads.asr_rank_builder import (
    ASRTier,
    TechniqueGroupInfo,
    ASRRankBuilder,
    build_ranked_groups,
    build_fallback_chain,
    get_top_n_groups,
)
from src.payloads.tiered_selection_wizard import (
    FallbackStrategy,
    TieredSelectionResult,
    SelectionPreset,
    TieredSelectionWizard,
    select_with_wizard,
)
from src.payloads.preset_schemes import (
    AttackMechanism,
    PresetScheme,
    PresetSchemeDefinition,
    PresetSchemeBuilder,
    build_preset_schemes,
    get_scheme_by_letter,
    get_mechanism,
    TECHNIQUE_MECHANISM_MAP,
)
from src.payloads.group_fallback_executor import (
    FallbackExecutionResult,
    GroupFallbackExecutor,
    execute_with_fallback,
)

__all__ = [
    # 数据模型
    "AttackMode",
    "AttackPlan",
    "BatchAttackResult",
    "PromptBatch",
    "PromptItem",
    "SequentialStep",
    # ① 数据准备层
    "PayloadSourceLoader",
    "load_payloads",
    "load_payloads_async",
    "load_all_payloads_async",
    # ② 数据管理层
    "DatasetManager",
    # ②.5 交互式选择层
    "SeedGroupSelector",
    "SeedGroupEntry",
    # ③ 攻击准备层
    "AttackPreparator",
    "AttackExecutionParams",  # deprecated
    # 适配器
    "SeedPromptAdapter",
    # 兼容模式规划器
    "PayloadPlanner",
    "plan_attacks",
    # 模拟对话生成与重放 (P0)
    "generate_simulated_conversation_async",
    "precompute_simulated_conversation_async",
    "precompute_batch_async",
    "replay_to_target_async",
    "create_simulated_conversation_seed",
    "inject_simulated_conversation_into_group",
    "create_attack_with_simulated_conversation",
    "get_preset",
    "get_preset_combos",
    # 项目自定义远程数据集加载器 (P1)
    "AI300OWASPCustomDataset",
    "AI300AgenticThreatsDataset",
    "AI300ExamSimDataset",
    "get_project_dataset_names",
    "is_project_dataset_registered",
    # 原生管道 (P3)
    "NativePipelineExecutor",
    "get_native_pipeline",
    "execute_native_async",
    "evaluate_attack_plan_necessity",
    # 载荷模板适配器 (P0-P3 转换)
    "convert_payload_file",
    "convert_jailbreak_directory",
    # ②.5 Layer 1: 目标路由
    "TargetType",
    "TargetProfile",
    "TargetProfileRouter",
    "get_target_profile",
    "infer_target_profile",
    "filter_groups_by_target",
    # ②.5 Layer 2: ASR 排序
    "ASRTier",
    "TechniqueGroupInfo",
    "ASRRankBuilder",
    "build_ranked_groups",
    "build_fallback_chain",
    "get_top_n_groups",
    # ②.5 Layer 3: 三层选择
    "FallbackStrategy",
    "TieredSelectionResult",
    "SelectionPreset",
    "TieredSelectionWizard",
    "select_with_wizard",
    # ②.5 Layer 3 增强: 预设方案 (A/B/C)
    "AttackMechanism",
    "PresetScheme",
    "PresetSchemeDefinition",
    "PresetSchemeBuilder",
    "build_preset_schemes",
    "get_scheme_by_letter",
    "get_mechanism",
    "TECHNIQUE_MECHANISM_MAP",
    # ④层增强: 组级降级链
    "FallbackExecutionResult",
    "GroupFallbackExecutor",
    "execute_with_fallback",
]
