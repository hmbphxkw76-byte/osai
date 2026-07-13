"""Agent 攻击模块（AI-300 Ch3+Ch4：单/多智能体攻击 + OWASP ASI Top 10）。

覆盖 AI-300 课程和 OWASP ASI Top 10 的完整攻击技术：
  - prompt_inject.py: 提示注入（直接/间接）
  - goal_hijack.py: 目标劫持（ASI01）
  - memory_attack.py: 记忆攻击（ASI06）
  - tool_hijack.py: 工具劫持（ASI02）
  - privilege_abuse.py: 身份和权限滥用（ASI03）
  - a2a_attack.py: 不安全代理间通信（ASI07）
  - cascading_failure.py: 级联故障（ASI08）
  - trust_exploitation.py: 人机信任利用（ASI09）
  - rogue_agent.py: 流氓代理（ASI10）
  - crescendo_attack.py: Crescendo 多轮对话升级攻击（Ch4）
  - tap_attack.py: TAP 带剪枝攻击树算法（Ch4）

双通道执行：
  - PyRIT 评分器：SelfAskTrueFalseScorer（LLM-as-Judge）替代关键词护栏检测
  - Native 回退：httpx 直连 + 关键词检测

Library-First：执行层委托 PyRIT，载荷资产自研。
"""

from .prompt_inject import (
    INDIRECT_INJECTION_PAYLOADS,
    test_indirect_injection,
)
from .memory_attack import (
    MEMORY_POISON_PAYLOADS,
    poison_agent_memory,
)
from .tool_hijack import (
    TOOL_HIJACK_PAYLOADS,
    hijack_agent_tools,
)
from .goal_hijack import (
    GOAL_HIJACK_PAYLOADS,
    hijack_agent_goal,
)
from .multi_agent import (
    CROSS_AGENT_PAYLOADS,
    cross_agent_attack,
)
from .privilege_abuse import (
    PRIVILEGE_ABUSE_PAYLOADS,
    abuse_privileges,
)
from .a2a_attack import (
    A2A_ATTACK_PAYLOADS,
    attack_inter_agent_communication,
)
from .cascading_failure import (
    CASCADING_FAILURE_PAYLOADS,
    trigger_cascading_failures,
)
from .trust_exploitation import (
    TRUST_EXPLOITATION_PAYLOADS,
    exploit_human_trust,
)
from .rogue_agent import (
    ROGUE_AGENT_PAYLOADS,
    create_rogue_agent,
)
from .crescendo_attack import crescendo_attack
from .tap_attack import tap_attack
from .findings import (
    generate_agent_attack_findings,
)

__all__ = [
    # 载荷库
    "INDIRECT_INJECTION_PAYLOADS",
    "MEMORY_POISON_PAYLOADS",
    "TOOL_HIJACK_PAYLOADS",
    "GOAL_HIJACK_PAYLOADS",
    "CROSS_AGENT_PAYLOADS",
    "PRIVILEGE_ABUSE_PAYLOADS",
    "A2A_ATTACK_PAYLOADS",
    "CASCADING_FAILURE_PAYLOADS",
    "TRUST_EXPLOITATION_PAYLOADS",
    "ROGUE_AGENT_PAYLOADS",
    # 单轮攻击函数
    "test_indirect_injection",
    "poison_agent_memory",
    "hijack_agent_tools",
    "hijack_agent_goal",
    "cross_agent_attack",
    "abuse_privileges",
    "attack_inter_agent_communication",
    "trigger_cascading_failures",
    "exploit_human_trust",
    "create_rogue_agent",
    # 多轮攻击函数（Ch4）
    "crescendo_attack",
    "tap_attack",
    # Findings 生成
    "generate_agent_attack_findings",
]