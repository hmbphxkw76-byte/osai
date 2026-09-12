# -*- coding: utf-8 -*-
"""MCP Schema Extractor - MCP Schema 提取协议模块

对 MCP (Model Context Protocol) 服务器执行 Schema 提取侦察:
- 工具定义提取 (Tool Definition Extraction)
- 资源枚举 (Resource Enumeration)
- 安全表面映射 (Security Surface Mapping)

Academic basis:
    - Greshake et al. (arXiv:2302.12173) - Indirect Prompt Injection
    - OWASP ASI Top 10 2025 - MCP Security

Constitution compliance:
    - R-SIZE: 单模块 < 800 行
    - R-H3: 单一职责, 无双重实现
    - R-S1: 不硬编码目标标识符
    - R-S4: 测试全部 mock
    - C7: 配置走唯一链路
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ====================================================================
# Data Structures
# ====================================================================


@dataclass
class MCPToolDefinition:
    """MCP 工具定义。

    Attributes:
        name: 工具名称
        description: 工具描述
        input_schema: 输入参数 Schema
        output_schema: 输出参数 Schema
        security_notes: 安全相关笔记
    """

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)
    security_notes: list[str] = field(default_factory=list)


@dataclass
class MCPServerInfo:
    """MCP 服务器信息。

    Attributes:
        name: 服务器名称
        version: 协议版本
        capabilities: 服务器能力列表
        tools: 工具定义列表
        resources: 资源列表
        security_surface: 安全表面评估
    """

    name: str = ""
    version: str = ""
    capabilities: list[str] = field(default_factory=list)
    tools: list[MCPToolDefinition] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    security_surface: dict[str, Any] = field(default_factory=dict)


# ====================================================================
# MCP Schema Extractor
# ====================================================================


class MCPSchemaExtractor:
    """MCP Schema 提取器。

    通过 JSON-RPC 接口获取 MCP 服务器的完整 Schema 信息。

    Usage:
        extractor = MCPSchemaExtractor(target_url)
        schema = await extractor.extract()
    """

    def __init__(self, target_url: str, *, timeout: float = 30.0) -> None:
        """初始化 MCP Schema 提取器。

        Args:
            target_url: MCP 服务器 URL
            timeout: 请求超时 (秒)
        """
        self.target_url = target_url
        self.timeout = timeout
        self._server_info = MCPServerInfo()

    async def extract(self) -> MCPServerInfo:
        """执行完整 Schema 提取。

        Returns:
            MCPServerInfo 实例
        """
        # 初始化握手
        await self._initialize()

        # 枚举工具
        await self._list_tools()

        # 枚举资源
        await self._list_resources()

        # 评估安全表面
        self._assess_security_surface()

        return self._server_info

    async def _initialize(self) -> None:
        """执行 MCP 初始化握手。"""

        # MCP initialize 请求
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "pyrit-mini-recon",
                    "version": "1.0.0",
                },
            },
        }

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.target_url,
                    json=init_request,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        result = data.get("result", {})
                        self._server_info.name = result.get("serverInfo", {}).get("name", "")
                        self._server_info.version = result.get("protocolVersion", "")
                        self._server_info.capabilities = list(result.get("capabilities", {}).keys())
        except Exception as e:
            logger.debug("[MCP] Initialize failed: %s", e)

    async def _list_tools(self) -> None:
        """枚举 MCP 工具列表。"""
        tools_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        }

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.target_url,
                    json=tools_request,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        tools = data.get("result", {}).get("tools", [])
                        for tool in tools:
                            self._server_info.tools.append(
                                MCPToolDefinition(
                                    name=tool.get("name", ""),
                                    description=tool.get("description", ""),
                                    input_schema=tool.get("inputSchema", {}),
                                    output_schema=tool.get("outputSchema", {}),
                                )
                            )
        except Exception as e:
            logger.debug("[MCP] Tools list failed: %s", e)

    async def _list_resources(self) -> None:
        """枚举 MCP 资源列表。"""
        resources_request = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/list",
            "params": {},
        }

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.target_url,
                    json=resources_request,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self._server_info.resources = data.get("result", {}).get("resources", [])
        except Exception as e:
            logger.debug("[MCP] Resources list failed: %s", e)

    def _assess_security_surface(self) -> None:
        """评估 MCP 服务器的安全表面。"""
        self._server_info.security_surface = {
            "total_tools": len(self._server_info.tools),
            "total_resources": len(self._server_info.resources),
            "has_file_access": any(
                "file" in t.name.lower() or "filesystem" in t.name.lower() for t in self._server_info.tools
            ),
            "has_network_access": any(
                "http" in t.name.lower() or "fetch" in t.name.lower() or "request" in t.name.lower()
                for t in self._server_info.tools
            ),
            "has_code_execution": any(
                "exec" in t.name.lower() or "eval" in t.name.lower() or "run" in t.name.lower()
                for t in self._server_info.tools
            ),
            "injection_risk_tools": self._identify_injection_risk_tools(),
        }

    def _identify_injection_risk_tools(self) -> list[str]:
        """识别存在注入风险的工具。

        Returns:
            风险工具名称列表
        """
        risk_keywords = ["execute", "run", "eval", "exec", "system", "shell", "command"]
        risk_tools = []

        for tool in self._server_info.tools:
            if any(kw in tool.name.lower() for kw in risk_keywords):
                risk_tools.append(tool.name)
                tool.security_notes.append("High risk: command execution capability")
            elif "prompt" in tool.name.lower():
                risk_tools.append(tool.name)
                tool.security_notes.append("Potential prompt injection vector")

        return risk_tools


# ====================================================================
# 便捷函数
# ====================================================================


async def extract_mcp_schema(
    parsed_request: dict[str, Any],
    *,
    max_probes: int = 5,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """提取 MCP Schema 便捷函数。

    Args:
        parsed_request: 解析后的请求
        max_probes: 最大探测次数
        timeout: 请求超时

    Returns:
        Schema 提取结果字典
    """
    # 从解析后的请求中提取目标 URL
    target_url = parsed_request.get("url", "")
    if not target_url:
        return MCPServerInfo().__dict__

    extractor = MCPSchemaExtractor(target_url, timeout=timeout)

    try:
        server_info = await extractor.extract()
        return {
            "name": server_info.name,
            "version": server_info.version,
            "capabilities": server_info.capabilities,
            "tools": [
                {
                    "name": t.name,
                    "description": t.description,
                    "security_notes": t.security_notes,
                }
                for t in server_info.tools
            ],
            "resources": server_info.resources,
            "security_surface": server_info.security_surface,
        }
    except Exception as e:
        logger.debug("[MCP] Schema extraction failed: %s", e)
        return MCPServerInfo().__dict__
