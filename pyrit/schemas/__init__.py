"""
===============================================================================
PyRIT Schemas — 跨层数据模型定义
===============================================================================
定义 L2-L4 各层之间的标准化数据传递格式，
确保编排层、执行层、评估层可独立演进。
===============================================================================
"""
from schemas.attack_models import (
    AttackProfile,
    AttackStrategy,
    AttackResult,
    AttackPhase,
    RiskProfile,
    AttackFeedback,
)
from schemas.target_models import (
    TargetProfile,
    TargetArchitecture,
    DefenseProfile,
    ModelInfo,
)
from schemas.multi_agent_models import (
    AgentState,
    InterAgentMessage,
    MultiAgentAttackResult,
    CascadeFailureResult,
    MemoryPoisoningResult,
    TrustExploitationResult,
)

__all__ = [
    "AttackProfile", "AttackStrategy", "AttackResult", "AttackPhase",
    "RiskProfile", "AttackFeedback",
    "TargetProfile", "TargetArchitecture", "DefenseProfile", "ModelInfo",
    "AgentState", "InterAgentMessage", "MultiAgentAttackResult",
    "CascadeFailureResult", "MemoryPoisoningResult", "TrustExploitationResult",
]
