"""MCP 协议侦察（AI-300 Ch7 Model Context Protocol）。

实现 AI-300 考试（Ch7）中的 MCP 协议侦察技术：
  - MCP 端点发现：探测 /mcp、/.well-known/mcp、/mcp/sse 等标准路径
  - 传输类型检测：stdio vs SSE vs HTTP 传输方式区分
  - 工具模式提取：获取 Agent 可调用的工具列表和参数定义
  - 基于错误的模式枚举：利用错误信息推断隐藏工具和方法
  - 远程 MCP 服务器检测：识别外部 MCP 服务连接
  - SSE 流检测：识别基于 Server-Sent Events 的 MCP 通信

MCP (Model Context Protocol) 标准化 AI Agent 如何发现和调用工具，
使用 JSON-RPC 通信。侦察目标：工具模式、可用函数、参数定义。

考试场景（AI-300 Ch7）：
  1. MCP 端点发现 → 开发者工作站 ~/.continue/config.yaml 分析
  2. 工具枚举 → tools/list 获取完整工具清单
  3. 传输层攻击 → stdio 劫持 / HTTP MCP 中间人

对齐 OWASP LLM Top 10: LLM06 (Excessive Agency), LLM07 (System Prompt Leak)
"""
from __future__ import annotations

import re
from typing import Any

import httpx

from redteam.core.models import AuthContext

# === MCP 传输类型特征 ===
_TRANSPORT_SIGNATURES: dict[str, list[str]] = {
    "stdio": ["stdio", "stdin", "stdout", "subprocess", "command"],
    "sse": ["sse", "text/event-stream", "server-sent events", "event-stream"],
    "streamable_http": ["streamable-http", "streamable http", "http+json"],
    "websocket": ["ws://", "wss://", "websocket"],
}

# === 常见 MCP 服务器命令特征（AI-300 Ch7.1 考试场景） ===
_MCP_SERVER_COMMANDS: dict[str, list[str]] = {
    "filesystem": ["npx", "@anthropic/mcp-server-filesystem", "@modelcontextprotocol/server-filesystem"],
    "git": ["npx", "@anthropic/mcp-server-git", "@modelcontextprotocol/server-git"],
    "github": ["npx", "@anthropic/mcp-server-github", "@modelcontextprotocol/server-github"],
    "postgres": ["npx", "@anthropic/mcp-server-postgres", "@modelcontextprotocol/server-postgres"],
    "slack": ["npx", "@anthropic/mcp-server-slack", "@modelcontextprotocol/server-slack"],
    "browser": ["npx", "@anthropic/mcp-server-browser", "@modelcontextprotocol/server-browser"],
}


def _detect_transport_type(content_type: str, response_body: str, endpoint: str) -> str:
    """检测 MCP 传输类型。"""
    body_lower = response_body[:2000].lower()
    for transport, signatures in _TRANSPORT_SIGNATURES.items():
        if any(sig in content_type.lower() for sig in signatures):
            return transport
        if any(sig in body_lower for sig in signatures):
            return transport
    if "/sse" in endpoint:
        return "sse"
    if "/mcp" in endpoint and "stream" in content_type:
        return "sse"
    return "http_json"


def probe_mcp_server(
    target: str,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """探测 MCP (Model Context Protocol) 服务器（AI-300 Ch7）。

    MCP 标准化 AI Agent 如何发现和调用工具，使用 JSON-RPC 通信。
    侦察目标：工具模式、可用函数、参数定义。

    Args:
        target: 目标基础 URL
        auth: 认证上下文
        timeout: 单请求超时（秒）

    Returns:
        MCP 服务器信息和可用工具列表
    """
    results: dict[str, Any] = {
        "target": target,
        "mcp_detected": False,
        "mcp_version": "",
        "tools": [],
        "server_info": {},
        "transport_type": "",
        "endpoints_tested": [],
    }

    mcp_endpoints = [
        "/mcp",
        "/mcp/sse",
        "/.well-known/mcp",
        "/.well-known/mcp/server",
        "/api/mcp",
        "/api/mcp/tools",
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
                    content_type = resp.headers.get("content-type", "")
                    results["transport_type"] = _detect_transport_type(content_type, resp.text, endpoint)
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


def enumerate_mcp_via_errors(
    target: str,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """基于错误的 MCP 方法枚举（AI-300 Ch7.3）。

    通过发送格式不当的 JSON-RPC 请求，
    从错误信息中推断可用的 MCP 方法和隐藏工具。

    Args:
        target: 目标基础 URL
        auth: 认证上下文
        timeout: 单请求超时（秒）

    Returns:
        错误枚举结果，包含推测的方法和工具名
    """
    results: dict[str, Any] = {
        "target": target,
        "error_revealed_methods": [],
        "error_messages": [],
        "hidden_tools_hints": [],
    }

    error_probes = [
        {"method": "", "params": {}},
        {"method": "invalid_method_xyz", "params": {}},
        {"method": "tools/call", "params": {"name": "", "arguments": {}}},
        {"method": "tools/call", "params": {}},
        {"method": "initialize", "params": {}},
    ]

    headers = {"Content-Type": "application/json"}
    if auth:
        headers.update(auth.to_header_dict())

    mcp_endpoints = ["/mcp", "/api/mcp"]

    with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
        for endpoint in mcp_endpoints:
            url = target.rstrip("/") + endpoint
            for i, probe in enumerate(error_probes):
                payload = {"jsonrpc": "2.0", "id": 100 + i, "method": probe["method"], "params": probe["params"]}
                try:
                    resp = client.post(url, json=payload, headers=headers)
                    if resp.status_code >= 400 or "application/json" in resp.headers.get("content-type", ""):
                        try:
                            data = resp.json()
                            error_msg = str(data.get("error", {}).get("message", ""))
                            if error_msg:
                                results["error_messages"].append({
                                    "probe": probe["method"] or "empty",
                                    "error": error_msg[:300],
                                    "endpoint": endpoint,
                                })
                                method_refs = re.findall(
                                    r"[\"']?(tools/\w+|resources/\w+|prompts/\w+|initialize)[\"']?",
                                    error_msg
                                )
                                for m in method_refs:
                                    if m not in results["error_revealed_methods"]:
                                        results["error_revealed_methods"].append(m)
                        except Exception:
                            pass
                except Exception:
                    continue

    return results


def detect_mcp_server_command(
    command_str: str,
) -> dict[str, Any]:
    """从命令字符串识别 MCP 服务器类型（AI-300 Ch7.1）。

    分析 npx/uvx 命令识别 Continue extension 配置中的 MCP 服务器类型。

    Args:
        command_str: MCP 服务器启动命令字符串

    Returns:
        服务器类型识别结果
    """
    result: dict[str, Any] = {
        "detected_servers": [],
        "has_remote": False,
        "command_type": "",
    }

    cmd_lower = command_str.lower()
    for server_type, signatures in _MCP_SERVER_COMMANDS.items():
        if any(sig.lower() in cmd_lower for sig in signatures):
            result["detected_servers"].append(server_type)

    if "npx" in cmd_lower:
        result["command_type"] = "npx"
    elif "uvx" in cmd_lower:
        result["command_type"] = "uvx"
    elif "python" in cmd_lower or "python3" in cmd_lower:
        result["command_type"] = "python"
    elif cmd_lower.startswith("http://") or cmd_lower.startswith("https://"):
        result["command_type"] = "remote_url"
        result["has_remote"] = True

    return result


__all__ = [
    "probe_mcp_server",
    "enumerate_mcp_tools",
    "call_mcp_tool",
    "enumerate_mcp_via_errors",
    "detect_mcp_server_command",
]