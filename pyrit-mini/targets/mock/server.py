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
import socket
import threading
import time
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
        # 无论方法一律排空请求体：适配器对 GET 同样带 JSON body，
        # 未在回包前排空会让服务端在客户端仍在发送时关闭连接 → 客户端
        # ReadError(BrokenResourceError) / 后续 connect_tcp ConnectTimeout
        # （test_a2a_fetch_card_and_send_task 等偶发失败的真正根因）。
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            length = 0
        raw = self.rfile.read(length) if length > 0 else b""
        if raw and self.command in ("GET", "POST", "PUT", "PATCH"):
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


class _ReadyHTTPServer(ThreadingHTTPServer):
    """带 accept 循环就绪信号的 `ThreadingHTTPServer`。

    `ThreadingHTTPServer` 在 `__init__` 即完成 bind/listen，故**裸 TCP 连接在
    `serve_forever()` 开始 accept 之前就会成功**（内核 backlog 收下）—— 仅靠
    "端口可连"无法证明"已可服务"，这正是 `test_a2a_fetch_card_and_send_task`
    偶发 `KeyError: 'name'` 的来源（BL-066 的探针不够强）。
    `service_actions()` 由 `serve_forever` 每轮循环调用，置位即代表 accept 循环已运行。
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.ready = threading.Event()

    def service_actions(self) -> None:
        if not self.ready.is_set():
            self.ready.set()
        super().service_actions()


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
        self._httpd = _ReadyHTTPServer((self._host, self._port), _MockHandler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="mock-range", daemon=True)
        self._thread.start()
        # 就绪等待：确认 accept 循环已运行（Event）+ 端口可连（TCP）——
        # 这是就绪确认，非掩盖：服务本身无法 accept 时仍会在超时后失败。
        self._wait_until_ready(timeout=5.0)
        logger.info("[MockRange] started at %s (personas=%s)", self.url, ",".join(PERSONAS))
        return self

    def _wait_until_ready(self, timeout: float = 5.0) -> None:
        """Wait until the accept loop is running, then confirm the port answers.

        两段确认：① `serve_forever` 的 `service_actions()` 置位（accept 循环已运行）；
        ② TCP 可连。仅 ② 不足——listen backlog 会让连接在 accept 之前就成功。
        """
        ready = getattr(self._httpd, "ready", None)
        if ready is not None and not ready.wait(timeout):
            logger.warning("[MockRange] accept loop not ready within %.1fs for %s", timeout, self.url)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection((self._host, self.port), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.02)
        logger.warning("[MockRange] readiness probe timed out for %s", self.url)

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
