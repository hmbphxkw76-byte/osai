"""targets.mock — 5 类组件 Mock 靶标（REQ-156）。

    personas.py  纯函数人格（model / mcp / rag / a2a / embedding）
    server.py    标准库 http.server 路由（/mock/<persona>/...）
    fixtures/    期望签名（golden 断言）
"""

from __future__ import annotations

from targets.mock.personas import PERSONAS, body_for, expected_signature, respond
from targets.mock.server import MockRange, persona_from_path

__all__ = [
    "PERSONAS",
    "MockRange",
    "body_for",
    "expected_signature",
    "persona_from_path",
    "respond",
]
