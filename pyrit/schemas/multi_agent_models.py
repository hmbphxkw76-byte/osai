"""
===============================================================================
Multi-Agent Attack Data Models — L4 多 Agent 攻击数据模型
===============================================================================
定义多 Agent 系统攻击的标准化数据格式。
覆盖四大攻击向量:
  - Agent 间通信劫持
  - 级联故障触发
  - 记忆/上下文持久化投毒
  - 人机信任利用攻击
===============================================================================
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class AgentRole(str, Enum):
    """Agent 角色枚举。"""
    ORCHESTRATOR = "orchestrator"
    ANALYZER = "analyzer"
    EXECUTOR = "executor"
    AUDITOR = "auditor"
    PROXY = "proxy"
    UNKNOWN = "unknown"


class MultiAgentAttackVector(str, Enum):
    """多 Agent 攻击向量枚举。"""
    COMMUNICATION_HIJACK = "communication_hijack"     # Agent 间通信劫持
    CASCADING_FAILURE = "cascading_failure"           # 级联故障触发
    MEMORY_POISONING = "memory_poisoning"              # 记忆/上下文持久化投毒
    TRUST_EXPLOITATION = "trust_exploitation"          # 人机信任利用


@dataclass
class AgentState:
    """单个 Agent 的状态描述。"""
    agent_id: str
    role: AgentRole = AgentRole.UNKNOWN
    model_name: str = ""
    is_compromised: bool = False
    capabilities: list[str] = field(default_factory=list)
    connected_agents: list[str] = field(default_factory=list)
    memory_size: int = 0
    last_active: str = ""


@dataclass
class InterAgentMessage:
    """Agent 间通信消息。"""
    message_id: str = ""
    sender_id: str = ""
    receiver_id: str = ""
    message_type: str = ""        # task / result / heartbeat / error
    content: str = ""
    is_intercepted: bool = False
    is_modified: bool = False
    original_content: str = ""
    modified_content: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class MultiAgentAttackResult:
    """多 Agent 攻击结果。"""
    attack_id: str
    vector: MultiAgentAttackVector = MultiAgentAttackVector.COMMUNICATION_HIJACK
    status: str = "PENDING"  # PENDING / SUCCESS / FAILURE
    target_agents: list[AgentState] = field(default_factory=list)
    intercepted_messages: list[InterAgentMessage] = field(default_factory=list)
    compromised_agents: int = 0
    attack_success: bool = False
    risk_level: str = "medium"
    details: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class CascadeFailureResult:
    """级联故障攻击结果。"""
    attack_id: str
    trigger_agent_id: str = ""
    affected_agents: list[str] = field(default_factory=list)
    propagation_depth: int = 0
    error_amplification: bool = False
    system_recovery_time_ms: int = 0
    cascade_success: bool = False
    details: dict = field(default_factory=dict)


@dataclass
class MemoryPoisoningResult:
    """记忆投毒攻击结果。"""
    attack_id: str
    target_agent_id: str = ""
    poison_type: str = ""       # shared_memory / long_term_memory / context_window
    injected_content: str = ""
    persistence_achieved: bool = False
    cross_session_effect: bool = False
    cleanup_difficulty: str = "unknown"  # easy / moderate / hard / permanent
    details: dict = field(default_factory=dict)


@dataclass
class TrustExploitationResult:
    """人机信任利用攻击结果。"""
    attack_id: str
    target_role: str = ""       # human_reviewer / system_admin / end_user
    deception_method: str = ""  # fake_report / authority_spoofing / consensus_attack
    trust_breached: bool = False
    action_induced: str = ""    # 诱导执行的操作
    severity: str = "medium"
    details: dict = field(default_factory=dict)


__all__ = [
    "AgentRole", "MultiAgentAttackVector",
    "AgentState", "InterAgentMessage", "MultiAgentAttackResult",
    "CascadeFailureResult", "MemoryPoisoningResult", "TrustExploitationResult",
]
