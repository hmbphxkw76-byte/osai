"""MCP 协议侦察（AI-300 Ch2.1/Ch2.3 Model Context Protocol）。

实现 AI-300 课程中的 MCP 协议侦察技术，专门针对 Agent 侦察：
  - MCP 端点发现：探测 /mcp、/.well-known/mcp、/mcp/sse 等标准路径
  - 工具模式提取：获取 Agent 可调用的工具列表和参数定义
  - 服务器信息收集：识别 MCP 服务器版本、能力描述
  - SSE 流检测：识别基于 Server-Sent Events 的 MCP 通信

MCP (Model Context Protocol) 标准化 AI Agent 如何发现和调用工具，
使用 JSON-RPC 通信。侦察目标：工具模式、可用函数、参数定义。

对齐 OWASP LLM Top 10: LLM06 (Excessive Agency), LLM07 (System Prompt Leak)
"""
from __future__ import annotations

from typing import Any

import httpx

from redteam.core.models import AuthContext


def probe_mcp_server(
    target: str,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """探测 MCP (Model Context Protocol) 服务器（AI-300 Ch2.1）。

    MCP 标准化 AI Agent 如何发现和调用工具，使用 JSON-RPC 通信。
    侦察目标：工具模式、可用函数、参数定义。

    Args:
        target: 目标基础 URL
        auth: 认证上下文
        timeout: 单请求超时（秒）

    Returns:
        MCP 服务器信息和可用工具列表
    """
    results = {
        "target": target,
        "mcp_detected": False,
        "mcp_version": "",
        "tools": [],
        "server_info": {},
        "endpoints_tested": [],
    }

    mcp_endpoints = [
        "/mcp",
        "/mcp/sse",
        "/.well-known/mcp",
        "/.well-known/mcp/server",
        "/api/mcp",
    ]

    with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
        headers = auth.to_header_dict() if auth else {}

        for endpoint in mcp_endpoints:
            url = target.rstrip("/") + endpoint
            results["endpoints_tested"].append(url)
            try:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    results["mcp_detected"] = True
                    try:
                        data = resp.json()
                        if "server" in data:
                            results["server_info"] = data.get("server", {})
                            results["mcp_version"] = data["server"].get("version", "")
                        if "tools" in data:
                            results["tools"] = data.get("tools", [])
                    except Exception:
                        pass
            except Exception:
                continue

    return results


def enumerate_mcp_tools(
    target: str,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """枚举 MCP 服务器暴露的工具（AI-300 Ch2.3）。

    通过 MCP 协议的 tools/list 方法获取完整工具清单，
    包括工具名、描述、输入参数模式。

    Args:
        target: MCP 服务器 URL
        auth: 认证上下文
        timeout: 单请求超时（秒）

    Returns:
        工具定义列表，每个工具包含 name、description、inputSchema
    """
    tools: list[dict[str, Any]] = []

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {},
    }

    headers = {"Content-Type": "application/json"}
    if auth:
        headers.update(auth.to_header_dict())

    mcp_endpoints = ["/mcp", "/api/mcp"]

    with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
        for endpoint in mcp_endpoints:
            url = target.rstrip("/") + endpoint
            try:
                resp = client.post(url, json=payload, headers=headers)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if "result" in data and "tools" in data["result"]:
                            tools = data["result"]["tools"]
                            break
                    except Exception:
                        pass
            except Exception:
                continue

    return tools


def call_mcp_tool(
    target: str,
    tool_name: str,
    arguments: dict[str, Any] | None = None,
    auth: AuthContext | None = None,
    timeout: float = 10.0,
) -> dict[str, Any] | None:
    """调用 MCP 工具进行能力测试（AI-300 Ch2.3）。

    通过 MCP 协议的 tools/call 方法调用特定工具，
    用于验证工具是否可被任意调用（过度授权检测）。

    Args:
        target: MCP 服务器 URL
        tool_name: 工具名称
        arguments: 工具参数
        auth: 认证上下文
        timeout: 单请求超时（秒）

    Returns:
        工具调用结果
    """
    payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments or {},
        },
    }

    headers = {"Content-Type": "application/json"}
    if auth:
        headers.update(auth.to_header_dict())

    mcp_endpoints = ["/mcp", "/api/mcp"]

    with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
        for endpoint in mcp_endpoints:
            url = target.rstrip("/") + endpoint
            try:
                resp = client.post(url, json=payload, headers=headers)
                if resp.status_code == 200:
                    return resp.json()
            except Exception:
                continue

    return None


__all__ = [
    "probe_mcp_server",
    "enumerate_mcp_tools",
    "call_mcp_tool",
]