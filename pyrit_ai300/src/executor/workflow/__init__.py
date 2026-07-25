"""
Workflow Module — 对齐 pyrit.executor.workflow
================================================

Layer 4: 批量编排层
"N 个 objectives × 1 套攻击流程"

子模块：
- scenario_orchestrator.py  批量编排 + 升级重试 + 进度仪表盘
- batch_orchestrator.py     兼容层（委托 ScenarioOrchestrator）
- xpia_workflow.py          XPIA 跨域提示注入专用工作流
"""

from src.executor.workflow.scenario_orchestrator import (
    ScenarioOrchestrator,
    execute_batch_attacks,
)
from src.executor.workflow.batch_orchestrator import (
    BatchAttackOrchestrator,
)
from src.executor.workflow.xpia_workflow import XPIAWorkflowWrapper

__all__ = [
    "ScenarioOrchestrator",
    "execute_batch_attacks",
    "BatchAttackOrchestrator",
    "XPIAWorkflowWrapper",
]
