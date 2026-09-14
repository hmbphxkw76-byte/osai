"""strike/targets — 组件专用 PyRIT Target（REQ-149 ④）。

模块清单：
    - mcp : `MCPTarget`（handshake → tools/list → tools/call）
    - rag : `RAGTarget`（query → retrieve → generate）
    - a2a : `A2ATarget`（agent card → tasks/send）

纪律：
    - 三者均为 PyRIT 原生 `PromptTarget` 子类（C1 / R-NATIVE-1），
      自研仅限 PyRIT 域外的**协议适配**；
    - 协议差异（认证态/会话态/分帧）全部由 `recon.adapters` 闭合，
      **编排层不可见**（REQ-149 ③）；
    - 不实现任何内容过滤/安全降级（NEG-2）。
"""

from __future__ import annotations

from core.target_factory import register_target
from strike.targets.a2a import AGENT_CARD_PATH, DEFAULT_TASK_PATH, A2ATarget
from strike.targets.mcp import MCPTarget
from strike.targets.rag import RAGTarget

# 跨层接缝（CP-009 S4）：把本层 Target 构造器登记进 core.target_factory，
# 使 recon 侧经工厂取用而不静态 import strike 域（strike→core ✓）。
register_target("mcp", lambda *, inner, **_kw: MCPTarget(adapter=inner))
register_target("rag", lambda *, inner, **_kw: RAGTarget(adapter=inner, retrieval_adapter=inner))
register_target("a2a", lambda *, inner, **_kw: A2ATarget(adapter=inner))

__all__ = [
    "MCPTarget",
    "RAGTarget",
    "A2ATarget",
    "AGENT_CARD_PATH",
    "DEFAULT_TASK_PATH",
]
