"""PyRIT Schemas - 跨层统一数据模型定义."""

from schemas.attack_models import (
    AttackPhase,
    AttackCategory,
    AttackStatus,
    RiskLevel,
    AttackProfile,
    AttackStrategy,
    AttackResult,
    AttackFeedback,
    RiskProfile,
    ConverterConfig,
)
from schemas.target_models import (
    TargetArchitecture,
    TargetProfile,
    ModelInfo,
    DefenseProfile,
    TargetEndpoint,
)
from schemas.multi_agent_models import (
    AgentState,
    AgentRole,
    InterAgentMessage,
    MessageType,
    MultiAgentAttackResult,
    CascadeFailureResult,
    MemoryPoisoningResult,
    TrustExploitationResult,
    CommunicationChannel,
)

__all__ = [
    # Attack Models
    "AttackPhase", "AttackCategory", "AttackStatus", "RiskLevel",
    "AttackProfile", "AttackStrategy", "AttackResult", "AttackFeedback",
    "RiskProfile", "ConverterConfig",
    # Target Models
    "TargetArchitecture", "TargetProfile", "ModelInfo", "DefenseProfile",
    "TargetEndpoint",
    # Multi-Agent Models
    "AgentState", "AgentRole", "InterAgentMessage", "MessageType",
    "MultiAgentAttackResult", "CascadeFailureResult",
    "MemoryPoisoningResult", "TrustExploitationResult",
    "CommunicationChannel",
]
