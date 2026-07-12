"""Agent 攻击模块（AI-300 Ch3+Ch4：单/多智能体攻击）。

覆盖 AI-300 课程 Ch3 和 Ch4 的完整攻击技术：
  - prompt_inject.py: 提示注入（直接/间接）
  - goal_hijack.py: 目标劫持
  - memory_attack.py: 记忆攻击
  - tool_hijack.py: 工具劫持

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
    # 攻击函数
    "test_indirect_injection",
    "poison_agent_memory",
    "hijack_agent_tools",
    "hijack_agent_goal",
    "cross_agent_attack",
    # Findings 生成
    "generate_agent_attack_findings",
]