"""mcp-scan（Invariant Labs）封装：MCP 组件专项扫描。

Library-First：调用 mcp-scan 扫描检测到的 MCP 端点（prompt injection / tool poisoning /
cross-origin escalation / rug pull）。其输出格式随版本演进，这里尽力而为地收集输出作为证据。
仅对 detected MCP 端点调用。工具不可用时返回空。
"""
from __future__ import annotations

import subprocess

from redteam.core.models import Finding
from redteam.core.tools import ToolResolver


def scan(mcp_url: str, resolver: ToolResolver | None = None, timeout: int = 900) -> list[Finding]:
    resolver = resolver or ToolResolver()
    cmd = [resolver.resolve("mcp_scan"), mcp_url]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:  # noqa: BLE001
        return []

    out = proc.stdout + proc.stderr
    return [
        Finding(
            source="mcp_scan",
            category="mcp_security",
            severity="medium",
            title="MCP scan output",
            evidence=out[:2000],
            endpoint=mcp_url,
        )
    ]
