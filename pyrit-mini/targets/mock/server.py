"""targets/mock/server.py — 标准库多靶标 Mock 服务（REQ-156）。

把 5 类人格挂在 `/mock/<persona>/...` 前缀下，单进程即可端到端演练
`recon → arm → strike → assess → report`：

    /mock/model/v1/chat/completions
    /mock/mcp/mcp
    /mock/rag/api/retrieve
    /mock/a2a/.well-known/agent.json
    /mock/embedding/v1/embeddings

设计约束：
    - 仅标准库 `http.server`（NEG-4：mock 靶场不得引入新依赖）；
    - 只做应答与路由，不做任何"输入过滤"（NEG-2）；
    - 默认绑定 127.0.0.1（不得把靶标暴露到非授权网段，配合 R-S1）。
"""

from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from targets.mock.personas import PERSONAS, respond

logger = logging.getLogger(__name__)

PREFIX = "/mock"


def persona_from_path(path: str) -> str | None:
    """Extract the persona name from `/mock/<persona>/...` (None when unmatched)."""
    parts = (path or "/").split("?")[0].strip("/").split("/")
    if len(parts) >= 2 and parts[0] == PREFIX.strip("/") and parts[1] in PERSONAS:
        return parts[1]
    return None


def sub_path_for(path: str) -> str:
    """Strip the `/mock/<persona>` prefix, returning the persona-relative path."""
    parts = (path or "/").split("?")[0].strip("/").split("/")
    remainder = parts[2:] if len(parts) > 2 else []
    query = (path or "").split("?", 1)[1] if "?" in (path or "") else ""
    joined = "/" + "/".join(remainder)
    return f"{joined}?{query}" if query else joined


class _MockHandler(BaseHTTPRequestHandler):
    server_version = "pyrit-mini-mock/1.0"

    def _handle(self) -> None:  # noqa: N802 - stdlib naming
        persona = persona_from_path(self.path)
        if persona is None:
            self._send(404, {"error": "unknown_persona_route", "hint": f"{PREFIX}/<persona>/..."})
            return

        body: dict[str, Any] = {}
        if self.command in ("POST", "PUT", "PATCH"):
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except (TypeError, ValueError):
                length = 0
            raw = self.rfile.read(length) if length > 0 else b""
            if raw:
                try:
                    parsed = json.loads(raw.decode("utf-8", "replace"))
                    body = parsed if isinstance(parsed, dict) else {}
                except (json.JSONDecodeError, UnicodeDecodeError):
                    body = {}

        status, payload = respond(persona, sub_path_for(self.path), self.command, body)
        self._send(status, payload)

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_HEAD = _handle

    def log_message(self, fmt: str, *args: object) -> None:
        logger.debug("[MockRange] " + fmt, *args)


class MockRange:
    """Threaded multi-persona mock range bound to loopback by default."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._host = host
        self._port = port
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        if self._httpd is None:
            return self._port
        return int(self._httpd.server_address[1])

    @property
    def url(self) -> str:
        return f"http://{self._host}:{self.port}"

    def persona_url(self, persona: str) -> str:
        return f"{self.url}{PREFIX}/{persona}"

    def start(self) -> "MockRange":
        if self._httpd is not None:
            return self
        self._httpd = ThreadingHTTPServer((self._host, self._port), _MockHandler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="mock-range", daemon=True)
        self._thread.start()
        logger.info("[MockRange] started at %s (personas=%s)", self.url, ",".join(PERSONAS))
        return self

    def stop(self) -> None:
        if self._httpd is None:
            return
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._httpd = None
        self._thread = None
        logger.info("[MockRange] stopped")
