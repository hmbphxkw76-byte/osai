"""
Workflow Module — 对齐 pyrit.executor.workflow
================================================

Layer 4: 批量编排层
"N 个 objectives × 1 套攻击流程"

子模块：
- batch_orchestrator.py     兼容层（已弃用，委托原生路径）
- xpia_workflow.py          XPIA 跨域提示注入专用工作流（含 RAG/ProcessingCallback）
- stop_strategy.py          停止策略上下文（L2/L3 预过滤后分析）

P1-3: 已删除场景双轨代码 (scenario_orchestrator.py + upgrade_strategy.py)，
原生 AI300AdaptiveScenario 通过 DatasetAttackConfiguration 统一所有执行路径。
"""

# 停止策略（保留：用于 L2/L3 预过滤后的结果分析）
from src.executor.workflow.stop_strategy import (
    StopStrategyContext,
    SuccessRecordResult,
    ThresholdReachedInfo,
)

# XPIA 工作流
from src.executor.workflow.xpia_workflow import (
    ProcessingCallbackBuilder,
    RAGXPIAWorkflowWrapper,
    XPIAWorkflowWrapper,
)

__all__ = [
    # 停止策略
    "StopStrategyContext",
    "SuccessRecordResult",
    "ThresholdReachedInfo",
    # XPIA 工作流
    "XPIAWorkflowWrapper",
    "RAGXPIAWorkflowWrapper",
    "ProcessingCallbackBuilder",
]
