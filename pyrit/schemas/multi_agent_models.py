"""多 Agent 攻击数据模型."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from schemas.attack_models import AttackStatus, RiskLevel


# ============================================================
# Enums
# ============================================================

class AgentRole(str, Enum):
    """Agent 角色."""

    ORCHESTRATOR = "orchestrator"          # 编排者
    EXECUTOR = "executor"                  # 执行者
    REVIEWER = "reviewer"                  # 审核者
    KNOWLEDGE = "knowledge"                # 知识库
    TOOL_USER = "tool_user"                # 工具使用者
    USER_PROXY = "user_proxy"              # 用户代理
    ATTACKER = "attacker"                  # 攻击者 (红队)
    DEFENDER = "defender"                  # 防御者 (蓝队)
    VICTIM = "victim"                      # 受害者 (被攻击的 Agent)


class MessageType(str, Enum):
    """消息类型."""

    REQUEST = "request"
    RESPONSE = "response"
    COMMAND = "command"
    DATA = "data"
    ERROR = "error"
    HEARTBEAT = "heartbeat"
    POISONED = "poisoned"                  # 投毒消息
    INTERCEPTED = "intercepted"            # 被劫持消息


class CommunicationChannel(str, Enum):
    """通信频道."""

    DIRECT = "direct"                      # 直接 API 调用
    MESSAGE_QUEUE = "message_queue"        # 消息队列
    SHARED_MEMORY = "shared_memory"        # 共享内存/上下文
    HTTP = "http"                          # HTTP 接口
    WEBSOCKET = "websocket"                # WebSocket


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class AgentState:
    """Agent 状态描述."""

    agent_id: str = ""
    name: str = ""
    role: AgentRole = AgentRole.EXECUTOR
    model_name: str = ""
    tools: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    memory_size: int = 0                   # 上下文窗口大小
    is_active: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class InterAgentMessage:
    """Agent 间通信消息."""

    message_id: str = field(default_factory=lambda: f"msg_{uuid.uuid4().hex[:8]}")
    sender_id: str = ""
    receiver_id: str = ""
    msg_type: MessageType = MessageType.REQUEST
    content: str = ""
    channel: CommunicationChannel = CommunicationChannel.DIRECT
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    # 攻击标记
    is_poisoned: bool = False
    is_intercepted: bool = False
    was_modified: bool = False
    original_content: Optional[str] = None
    injected_payload: Optional[str] = None

    # 元数据
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class MultiAgentAttackResult:
    """多 Agent 攻击结果."""

    result_id: str = field(default_factory=lambda: f"ma_result_{uuid.uuid4().hex[:8]}")
    attack_type: str = ""                  # comm_hijack / cascade_failure / memory_poisoning / trust_exploitation
    status: AttackStatus = AttackStatus.PENDING

    # 涉及 Agent
    target_agents: list[str] = field(default_factory=list)
    attacker_agent: str = ""

    # 消息记录
    messages_sent: list[InterAgentMessage] = field(default_factory=list)
    messages_intercepted: list[InterAgentMessage] = field(default_factory=list)

    # 结果
    success: bool = False
    impact_level: str = ""                 # none / low / medium / high / critical
    cascade_triggered: bool = False
    data_exfiltrated: bool = False

    # 时间
    started_at: str = ""
    completed_at: str = ""

    # 评估
    eval_summary: str = ""
    recommendations: list[str] = field(default_factory=list)

    def to_eval_dict(self) -> dict[str, Any]:
        """转换为 L5 统一评估格式."""
        return {
            "result_id": self.result_id,
            "attack_type": self.attack_type,
            "status": self.status.value,
            "success": self.success,
            "impact_level": self.impact_level,
            "cascade_triggered": self.cascade_triggered,
            "data_exfiltrated": self.data_exfiltrated,
            "target_agents": self.target_agents,
            "messages_count": len(self.messages_sent),
            "intercepted_count": len(self.messages_intercepted),
            "eval_summary": self.eval_summary,
            "recommendations": self.recommendations,
        }


@dataclass
class CascadeFailureResult:
    """级联故障攻击结果."""

    result_id: str = field(default_factory=lambda: f"cf_{uuid.uuid4().hex[:8]}")
    trigger_agent: str = ""                # 触发故障的 Agent
    affected_agents: list[str] = field(default_factory=list)
    failure_chain: list[str] = field(default_factory=list)  # 故障链 [A->B->C]
    propagation_time_ms: float = 0.0       # 故障传播时间
    system_degraded: bool = False
    recovery_possible: bool = True
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class MemoryPoisoningResult:
    """记忆/上下文投毒攻击结果."""

    result_id: str = field(default_factory=lambda: f"mp_{uuid.uuid4().hex[:8]}")
    target_agent: str = ""
    poison_type: str = ""                  # context / long_term / shared_memory
    poison_payload: str = ""
    persistence_duration: int = 0          # 投毒持续时间（轮次）
    affected_responses: int = 0
    was_cleaned: bool = False
    detection_difficulty: RiskLevel = RiskLevel.MEDIUM
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class TrustExploitationResult:
    """人机信任利用攻击结果."""

    result_id: str = field(default_factory=lambda: f"te_{uuid.uuid4().hex[:8]}")
    target_agent: str = ""
    exploit_type: str = ""                 # authority_spoofing / emotional_manipulation / expertise_faking
    deception_level: float = 0.0           # 欺骗程度 0.0~1.0
    user_trust_exploited: bool = False
    sensitive_action_triggered: bool = False
    action_description: str = ""
    guardrail_bypassed: bool = False
    details: dict[str, Any] = field(default_factory=dict)
