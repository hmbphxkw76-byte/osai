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
- seed_adapter.py: PyRIT SeedDataset ↔ PromptBatch 双向适配器
- owasp_provider.py: OWASP 本地数据集 SeedDatasetProvider 桥接层
- planner.py: 载荷规划器 (PromptItem → AttackPlan) [兼容模式]
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
]
