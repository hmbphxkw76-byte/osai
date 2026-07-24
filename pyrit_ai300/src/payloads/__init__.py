"""
Payloads Module
===============

本模块负责批量多源攻击的数据源管理和载荷规划。

包含：
- models.py: 数据模型 (PromptItem, PromptBatch, AttackMode, AttackPlan)
- source_loader.py: 数据源加载器 (OWASP 目录 / 自定义 / PyRIT 数据集)
- planner.py: 载荷规划器 (PromptItem → AttackPlan)
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
)
from src.payloads.planner import (
    PayloadPlanner,
    plan_attacks,
)

__all__ = [
    "AttackMode",
    "AttackPlan",
    "BatchAttackResult",
    "PromptBatch",
    "PromptItem",
    "SequentialStep",
    "PayloadSourceLoader",
    "load_payloads",
    "PayloadPlanner",
    "plan_attacks",
]
