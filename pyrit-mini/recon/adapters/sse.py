"""recon/adapters/sse.py — Server-Sent Events 协议适配器（REQ-149 ②）。

LLM 网关普遍以 `text/event-stream` 流式返回。本适配器把「按块读取 + 事件分帧 +
增量拼接」闭合在内部，编排层拿到的是**完整文本**，而非流式细节。
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from recon.adapters.base import AdapterRequest, AdapterResponse, AuthState, BaseAdapter, SessionState

logger = logging.getLogger(__name__)

_BLOCK_SPLIT = re.compile(r"\r?\n\r?\n")
DONE_SENTINEL = "[DONE]"


def parse_event_frames(raw: str) -> list[str]:
    """Split a raw SSE body into `data:` frame payloads (`[DONE]` terminates).

    符合 SSE 规范要点：忽略注释行（`:` 开头）、忽略 `event:`/`id:`/`retry:` 字段、
    同一事件的多行 `data:` 以 `\\n` 连接。
    """
    frames: list[str] = []
    for block in _BLOCK_SPLIT.split(raw or ""):
        data_lines: list[str] = []
        for line in block.splitlines():
            line = line.rstrip("\r")
            if not line or line.startswith(":"):
                continue
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
        if not data_lines:
            continue
        payload = "\n".join(data_lines)
        if payload.strip() == DONE_SENTINEL:
            break
        frames.append(payload)
    return frames


def _frame_text(frame: str) -> str:
    """Extract human-visible text from one frame (JSON delta or plain text)."""
    if not frame:
        return ""
    stripped = frame.strip()
    if not stripped.startswith(("{", "[")):
        return frame
    try:
        payload = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return frame
    if not isinstance(payload, dict):
        return ""
    choices = payload.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0] if isinstance(choices[0], dict) else {}
        delta = first.get("delta") if isinstance(first.get("delta"), dict) else {}
        if isinstance(delta.get("content"), str):
            return delta["content"]
        message = first.get("message") if isinstance(first.get("message"), dict) else {}
        if isinstance(message.get("content"), str):
            return message["content"]
        if isinstance(first.get("text"), str):
            return first["text"]
    for key in ("content", "text", "token", "response"):
        if isinstance(payload.get(key), str):
            return payload[key]
    return ""


def parse_event_stream(raw: str) -> str:
    """Concatenated assistant text from a raw SSE body."""
    return "".join(_frame_text(frame) for frame in parse_event_frames(raw))


class SSEAdapter(BaseAdapter):
    """Streaming adapter：读取完整事件流后归一为单个 `AdapterResponse`。"""

    name = "sse"

    def __init__(self, *, max_events: int = 5000, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.max_events = max(1, int(max_events))

    def build_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        merged = {"Accept": "text/event-stream", **(extra or {})}
        return super().build_headers(merged)

    async def send_request(self, request: AdapterRequest) -> AdapterResponse:
        client = self._http_client()
        headers = request.headers or self.build_headers()
        body = request.body
        try:
            async with client.stream(request.method, request.url, headers=headers, json=body) as response:
                status = int(getattr(response, "status_code", 0) or 0)
                resp_headers = {str(k): str(v) for k, v in dict(getattr(response, "headers", {}) or {}).items()}
                lines: list[str] = []
                async for line in response.aiter_lines():
                    lines.append(line)
                    if len(lines) >= self.max_events:
                        logger.debug("[Adapter:sse] event cap reached (%d)", self.max_events)
                        break
                raw_text = "\n".join(lines)
        except Exception as e:
            logger.debug("[Adapter:sse] stream failed: %s", e)
            return AdapterResponse(status=0, error=f"{type(e).__name__}: {e}")

        frames = parse_event_frames(raw_text)
        return AdapterResponse(
            status=status,
            text=parse_event_stream(raw_text),
            payload={"frames": frames, "frame_count": len(frames)},
            headers=resp_headers,
            raw=raw_text.encode("utf-8", "replace"),
        )

    def extract_text(self, response: AdapterResponse) -> str:
        return response.text or ""

    @classmethod
    def from_target(cls, *, url: str, raw_headers: Any = None, **kwargs: Any) -> "SSEAdapter":
        return cls(
            url=url,
            method="POST",
            auth=AuthState.from_raw_headers(raw_headers),
            session=SessionState(),
            **kwargs,
        )
