"""recon/adapters/jsonrpc.py — JSON-RPC 2.0 协议适配器（REQ-149 ②）。

MCP / 工具网关的线上形态即 JSON-RPC 2.0 over HTTP：`initialize` →
`tools/list` → `tools/call`。本适配器把这些协议细节闭合在 adapter 内，
编排层只调用 `call()` / `list_tools()` / `call_tool()`。
"""

from __future__ import annotations

import itertools
import logging
from typing import Any

from recon.adapters.base import AdapterRequest, AdapterResponse, AuthState, BaseAdapter, SessionState

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = "2024-11-05"


class JSONRPCAdapter(BaseAdapter):
    """JSON-RPC 2.0 adapter（`id` 递增；错误归一为 `AdapterResponse.error`）。"""

    name = "jsonrpc"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._ids = itertools.count(1)

    # -- 请求成形 --------------------------------------------------------
    def build_request(self, prompt: str, *, session: SessionState | None = None, rpc_method: str = "", rpc_params: dict[str, Any] | None = None) -> AdapterRequest:
        request = super().build_request(prompt, session=session)
        method = rpc_method or "tools/call"
        params = rpc_params if rpc_params is not None else {"name": "prompt", "arguments": {"input": prompt}}
        request.rpc_method = method
        request.rpc_params = params
        request.body = {"jsonrpc": "2.0", "id": next(self._ids), "method": method, "params": params}
        return request

    # -- 协议操作 --------------------------------------------------------
    async def call(self, method: str, params: dict[str, Any] | None = None) -> AdapterResponse:
        request = self.build_request("", rpc_method=method, rpc_params=params if params is not None else {})
        response = await self.send_request(request)
        return self._unwrap(response)

    async def initialize(self, *, client_name: str = "pyrit-mini") -> AdapterResponse:
        return await self.call(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": client_name, "version": "1.0"},
            },
        )

    async def list_tools(self) -> AdapterResponse:
        return await self.call("tools/list", {})

    async def list_resources(self) -> AdapterResponse:
        return await self.call("resources/list", {})

    async def list_prompts(self) -> AdapterResponse:
        return await self.call("prompts/list", {})

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> AdapterResponse:
        return await self.call("tools/call", {"name": name, "arguments": arguments or {}})

    # -- 辅助 ------------------------------------------------------------
    @staticmethod
    def _unwrap(response: AdapterResponse) -> AdapterResponse:
        """Surface JSON-RPC `error` as `AdapterResponse.error` (never raises)."""
        payload = response.payload
        if isinstance(payload, dict) and isinstance(payload.get("error"), dict):
            message = str(payload["error"].get("message") or "jsonrpc_error")
            return AdapterResponse(
                status=response.status,
                text=response.text,
                payload=payload,
                headers=response.headers,
                raw=response.raw,
                error=f"jsonrpc:{payload['error'].get('code')}:{message}",
            )
        return response

    def extract_text(self, response: AdapterResponse) -> str:
        """Extract the assistant-visible text from a `tools/call` style result."""
        payload = response.payload
        if not isinstance(payload, dict):
            return response.text or ""
        result = payload.get("result")
        if isinstance(result, dict):
            content = result.get("content")
            if isinstance(content, list):
                texts = [str(item.get("text") or "") for item in content if isinstance(item, dict) and item.get("text")]
                if texts:
                    return "\n".join(texts)
            tools = result.get("tools")
            if isinstance(tools, list):
                return ",".join(str(t.get("name")) for t in tools if isinstance(t, dict) and t.get("name"))
        if isinstance(result, str):
            return result
        return response.text or ""

    def tool_names(self, response: AdapterResponse) -> list[str]:
        """Names from a `tools/list` response (empty list when absent)."""
        payload = response.payload
        if not isinstance(payload, dict):
            return []
        tools = ((payload.get("result") or {}) if isinstance(payload.get("result"), dict) else {}).get("tools")
        if not isinstance(tools, list):
            return []
        return [str(t.get("name")) for t in tools if isinstance(t, dict) and t.get("name")]

    @classmethod
    def from_target(cls, *, url: str, raw_headers: Any = None, **kwargs: Any) -> "JSONRPCAdapter":
        return cls(
            url=url,
            method="POST",
            auth=AuthState.from_raw_headers(raw_headers),
            session=SessionState(),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            **kwargs,
        )
