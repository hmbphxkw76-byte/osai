# -*- coding: utf-8 -*-
"""strike/agent - ReAct / Tool-use Agent attack framework (Tool-use Agent Attacks).

Attacks against ReAct / function-calling agents:
- 工具结果间接注入 (Tool-result indirect prompt injection)
- 诱导外泄 (Coerced exfiltration via egress tool)
- 恶意工具注册 (Rogue tool registration)

Academic basis:
    - Greshake et al. (arXiv:2302.12173) — Indirect prompt injection
    - Zhan et al. (arXiv:2307.00929) — Schema-guided injection (InjecAgent)
    - OWASP ASI04 — Tool / Function Misuse
    - OWASP ASI10 — Rogue Agent

Constitution compliance:
    - R-SIZE: 每模块 < 800 行
    - R-H3: 单一职责, 无双重实现
    - R-S1: 不硬编码目标标识符
    - R-S4: 测试全部 mock
"""

from strike.agent.cleanup import (
    restore_agent_tools,
    unregister_rogue_tool,
)
from strike.agent.exfiltration import (
    coerce_tool_exfiltration,
    exfiltration_converter_payload,
)
from strike.agent.rogue_tool import (
    build_rogue_tool_schema,
    register_rogue_tool_prompt,
)
from strike.agent.tool_injector import (
    build_indirect_injection_seed,
    tool_result_injection,
)

__all__ = [
    # Tool-result injection
    "tool_result_injection",
    "build_indirect_injection_seed",
    # Coerced exfiltration
    "coerce_tool_exfiltration",
    "exfiltration_converter_payload",
    # Rogue tool
    "build_rogue_tool_schema",
    "register_rogue_tool_prompt",
    # I13 cleanup actions
    "unregister_rogue_tool",
    "restore_agent_tools",
]
