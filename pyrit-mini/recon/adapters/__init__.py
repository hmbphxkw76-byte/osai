"""recon/adapters — TargetAdapter 统一适配层（REQ-149）。

模块清单：
    - base      : 协议协议（`TargetAdapter`）+ 认证态/会话态 + `BaseAdapter`
    - http      : JSON over HTTP(S)
    - sse       : `text/event-stream` 流式
    - jsonrpc   : JSON-RPC 2.0（MCP / 工具网关）
    - multipart : `multipart/form-data` 文件上传

用法：`build_adapter(url=..., is_sse=..., raw_headers=...)` 由入口特征自动选择协议；
编排层只调用 `send()` / `send_request()` / `close()`，不可见协议差异（REQ-149 ③）。
"""

from __future__ import annotations

import logging
from typing import Any

from recon.adapters.base import (
    CHAT_ID_PLACEHOLDER,
    SESSION_ID_PLACEHOLDER,
    THREAD_ID_PLACEHOLDER,
    AdapterError,
    AdapterRequest,
    AdapterResponse,
    AuthState,
    BaseAdapter,
    SessionState,
    TargetAdapter,
)
from recon.adapters.http import HTTPAdapter
from recon.adapters.jsonrpc import PROTOCOL_VERSION, JSONRPCAdapter
from recon.adapters.multipart import MultipartAdapter
from recon.adapters.sse import DONE_SENTINEL, SSEAdapter, parse_event_frames, parse_event_stream

logger = logging.getLogger(__name__)

ADAPTER_KINDS: tuple[str, ...] = ("http", "sse", "jsonrpc", "multipart", "mcp", "rag", "a2a")
_ADAPTER_CLASSES: dict[str, type[BaseAdapter]] = {
    "http": HTTPAdapter,
    "sse": SSEAdapter,
    "jsonrpc": JSONRPCAdapter,
    "multipart": MultipartAdapter,
}


def _build_mcp_rag_a2a(kind: str, *, url: str, inner: BaseAdapter) -> BaseAdapter:
    """为 mcp/rag/a2a 构造对应的 `strike.targets` Target（均继承 `BaseAdapter`）。

    REQ-149 的 MCPTarget/RAGTarget/A2ATarget 是统一协议的 TargetAdapter 实现，
    `build_adapter` 在此成为编排层（REQ-151 PlaybookEngine）选择它们的唯一入口（IC-2）。
    """
    if kind == "mcp":
        from strike.targets.mcp import MCPTarget

        return MCPTarget(adapter=inner)
    if kind == "rag":
        from strike.targets.rag import RAGTarget

        # RAG 检索与目标复用同一 HTTP 入口（单靶标场景）；多检索源待 REQ-150 扩展
        return RAGTarget(adapter=inner, retrieval_adapter=inner)
    from strike.targets.a2a import A2ATarget

    return A2ATarget(adapter=inner)

# 协议判据（顺序即优先级）
_JSONRPC_PATH_HINTS: tuple[str, ...] = ("/mcp", "/rpc", "/jsonrpc", "/a2a")


def choose_kind(
    *,
    is_sse: bool = False,
    content_type: str = "",
    path: str = "",
    hint: str = "",
) -> str:
    """Pick an adapter kind from entry-point features (never raises)."""
    if hint in _ADAPTER_CLASSES:
        return hint
    if is_sse:
        return "sse"
    ctype = (content_type or "").lower()
    if "multipart/form-data" in ctype:
        return "multipart"
    path_lower = (path or "").lower()
    if any(token in path_lower for token in _JSONRPC_PATH_HINTS):
        return "jsonrpc"
    return "http"


class _TargetAdapterWrapper(BaseAdapter):
    """把 PyRIT Target（mcp/rag/a2a）包装为 `BaseAdapter`，统一暴露给编排层。

    REQ-149 ④ 的 Target 是 PyRIT `PromptTarget`（供原生编排器复用攻击技巧），本包装层
    补齐 `BaseAdapter` 协议表面（`.name`/`.send`/`.close`/`.describe()`），并把
    `handshake/list_tools/call_tool/query/send_task/fetch_agent_card` 转发到内部 Target，
    使 `build_adapter(kind=...)` 成为 PlaybookEngine（REQ-151）选择它们的唯一入口（IC-2）。
    """

    def __init__(self, kind: str, *, target: Any, inner: BaseAdapter) -> None:
        super().__init__(
            url=inner.url,
            method=inner.method,
            auth=inner.auth,
            session=inner.session,
            timeout=inner.timeout,
            verify=inner.verify,
            headers=inner.headers,
        )
        self.name = kind
        self._target = target
        self._inner = inner

    async def send(self, prompt: str, *, session: SessionState | None = None) -> "AdapterResponse":
        from pyrit.models import Message, MessagePiece

        piece = MessagePiece(role="user", original_value=prompt, converted_value=prompt)
        msgs = await self._target._send_prompt_to_target_async(
            normalized_conversation=[Message(message_pieces=[piece])]
        )
        text = msgs[0].get_piece().converted_value or "" if msgs else ""
        return AdapterResponse(status=200, text=text, payload={})

    async def close(self) -> None:
        try:
            await self._target.cleanup()
        except Exception:  # 清理失败不得掩盖主流程结果
            logger.debug("[TargetAdapter:%s] cleanup failed", self.name)

    def describe(self) -> dict[str, Any]:
        data = self._target.describe()
        data["auth"] = self.auth.redacted()
        data["session"] = self.session.snapshot()
        return data

    def __getattr__(self, name: str) -> Any:
        # 转发语义动作到内部 Target（handshake/list_tools/call_tool/query/send_task/...）
        return getattr(self._target, name)


def build_adapter(
    *,
    url: str,
    kind: str | None = None,
    method: str = "POST",
    raw_headers: Any = None,
    headers: dict[str, str] | None = None,
    body_template: str = "",
    response_json_path: str | None = None,
    timeout: float = 30.0,
    verify: bool = False,
    session: SessionState | None = None,
    is_sse: bool = False,
    content_type: str = "",
    path: str = "",
    **kwargs: Any,
) -> BaseAdapter:
    """Build the adapter matching the entry point (auth state closed inside)."""
    if kind in ("mcp", "rag", "a2a"):
        # 这些 kind 必须显式指定；内部通道按入口特征选协议（mcp 走 JSON-RPC）。
        inner_kind = "jsonrpc" if kind == "mcp" else choose_kind(
            is_sse=is_sse, content_type=content_type, path=path or url, hint=""
        )
        inner = build_adapter(
            url=url,
            kind=inner_kind,
            method=method,
            raw_headers=raw_headers,
            headers=headers,
            timeout=timeout,
            verify=verify,
            is_sse=is_sse,
            content_type=content_type,
            path=path,
            **kwargs,
        )
        target = _build_mcp_rag_a2a(kind, url=url, inner=inner)
        return _TargetAdapterWrapper(kind, target=target, inner=inner)
    resolved = choose_kind(is_sse=is_sse, content_type=content_type, path=path or url, hint=kind or "")
    adapter_cls = _ADAPTER_CLASSES[resolved]
    return adapter_cls(
        url=url,
        method=method,
        auth=AuthState.from_raw_headers(raw_headers),
        session=session or SessionState(),
        headers=headers,
        body_template=body_template,
        response_json_path=response_json_path,
        timeout=timeout,
        verify=verify,
        **kwargs,
    )


__all__ = [
    # base
    "AdapterError",
    "AdapterRequest",
    "AdapterResponse",
    "AuthState",
    "BaseAdapter",
    "SessionState",
    "TargetAdapter",
    "CHAT_ID_PLACEHOLDER",
    "THREAD_ID_PLACEHOLDER",
    "SESSION_ID_PLACEHOLDER",
    # http
    "HTTPAdapter",
    # sse
    "SSEAdapter",
    "parse_event_frames",
    "parse_event_stream",
    "DONE_SENTINEL",
    # jsonrpc
    "JSONRPCAdapter",
    "PROTOCOL_VERSION",
    # multipart
    "MultipartAdapter",
    # factory
    "ADAPTER_KINDS",
    "build_adapter",
    "choose_kind",
]
