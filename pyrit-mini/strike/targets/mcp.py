"""strike/targets/mcp.py — MCPTarget：MCP 协议 PyRIT Target（REQ-149 ④）。

把 MCP 的线上时序（`initialize` → `tools/list` → `tools/call`）封装成一个
PyRIT `PromptTarget`：PyRIT 原生编排器（PromptSending/Crescendo/TAP…）无需感知
JSON-RPC 细节即可对 MCP Server 发起攻击（C1/R-NATIVE-1：自研仅限 PyRIT 域外的协议适配）。

职责边界：
    - **只做协议适配**，不实现任何内容过滤/降级（NEG-2）；
    - 结果附 `prompt_metadata`（工具名/资源计数），供 assess 层判定 L3（工具执行）。
"""

from __future__ import annotations

import logging
from typing import Any

from pyrit.models import Message, construct_response_from_request
from pyrit.prompt_target.common.prompt_target import PromptTarget

from recon.adapters.jsonrpc import JSONRPCAdapter

logger = logging.getLogger(__name__)


class MCPTarget(PromptTarget):
    """MCP Server 的 PyRIT Target（JSON-RPC 2.0 适配）。

    Args:
        adapter: 已配置认证/会话的 `JSONRPCAdapter`。
        endpoint: 目标 URL（用于标识与日志）。
        model_name: 逻辑模型名（报告展示用）。
        tool_name: `tools/call` 的默认工具名；为空时回退为首次列出的工具。
        system_prompt: 可选 system prompt（MCP 场景通常不需要）。
    """

    def __init__(
        self,
        *,
        adapter: JSONRPCAdapter,
        endpoint: str = "",
        model_name: str = "mcp",
        tool_name: str = "",
        system_prompt: str = "",
        max_requests_per_minute: int | None = None,
        **kwargs: Any,
    ) -> None:
        self._adapter = adapter
        self._tool_name = tool_name
        self._mcp_tools: list[str] = []
        self._handshaken = False
        # PyRIT 1.0.1 的 PromptTarget 不接收 system_prompt 形参（由 TargetConfiguration 承载），
        # 这里仅保留为实例属性供协议层复用。
        self._system_prompt = system_prompt
        super().__init__(
            endpoint=endpoint or adapter.url,
            model_name=model_name,
            max_requests_per_minute=max_requests_per_minute,
            **kwargs,
        )

    # -- 协议操作（供 recon/assess 复用）--------------------------------
    async def handshake(self) -> bool:
        """`initialize` 握手；成功后可调用 `list_tools()`。"""
        response = await self._adapter.initialize()
        self._handshaken = response.ok
        if not self._handshaken:
            logger.warning("[MCPTarget] initialize failed: %s", response.error or response.status)
        return self._handshaken

    async def list_tools(self) -> list[str]:
        """`tools/list` → 工具名列表（同时缓存供 `tools/call` 兜底）。"""
        if not self._handshaken:
            await self.handshake()
        response = await self._adapter.list_tools()
        names = self._adapter.tool_names(response)
        if names:
            self._mcp_tools = names
        return names

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> str:
        """`tools/call`；返回结果文本。"""
        response = await self._adapter.call_tool(name, arguments)
        return self._adapter.extract_text(response)

    @property
    def tools(self) -> list[str]:
        return list(self._mcp_tools)

    def describe(self) -> dict[str, Any]:
        return {"target": "mcp", "adapter": self._adapter.describe(), "tools": self._mcp_tools, "handshaken": self._handshaken}

    # -- PyRIT 契约 ------------------------------------------------------
    async def _send_prompt_to_target_async(self, *, normalized_conversation: list[Message]) -> list[Message]:
        """PyRIT 派发入口：把 prompt 作为 `tools/call` 的 `arguments.input` 投递。"""
        request_piece = normalized_conversation[-1].get_piece()
        prompt = request_piece.converted_value or request_piece.original_value or ""

        if not self._handshaken:
            await self.handshake()
        if not self._mcp_tools:
            await self.list_tools()

        tool_name = self._tool_name or (self._mcp_tools[0] if self._mcp_tools else "")
        response = await self._adapter.call_tool(tool_name, {"input": prompt})
        text = self._adapter.extract_text(response)

        return [
            construct_response_from_request(
                request=request_piece,
                response_text_pieces=[text],
                prompt_metadata={
                    "mcp_target": 1,
                    "mcp_tool": tool_name,
                    "mcp_status": response.status,
                    "mcp_error": response.error[:200] if response.error else "",
                },
            )
        ]

    async def cleanup(self) -> None:
        await self._adapter.close()
