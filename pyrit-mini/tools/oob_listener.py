"""tools/oob_listener.py — 标准库 OOB 回执监听器（REQ-152 / IC-5 / NEG-4）。

用途：为"数据外传成立"提供**回执证据**（ADR-008：外传必须 OOB 回执，否则只能
记为 `exfil_suspected`）。攻击载荷中嵌入 canary，并让目标回调本监听器；命中
即写入 `assess.impact.exfil.OOBReceiptLog`。

设计约束：
    - **零新增运行时依赖**（NEG-4）：仅标准库 `http.server`。
    - 回执写入进程内单例；**同进程**（in-process 攻击编排）可直接被 assess 读取。
      跨进程场景请使用 `--emit-jsonl` 落盘后离线合并（本版不含）。
    - 只记录与应答，不做任何攻击/防御逻辑。

Usage:
    python -m tools.oob_listener --host 127.0.0.1 --port 8899
    python -m tools.oob_listener --port 0        # 随机端口（打印实际 URL）
"""

from __future__ import annotations

import argparse
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from assess.impact.exfil import CANARY_PREFIX, extract_canaries, get_receipt_log

logger = logging.getLogger(__name__)

_CANARY_QUERY_KEYS = ("c", "canary", "data", "token", "cb")


def _canaries_from(path: str, header_values: list[str]) -> list[str]:
    """Collect canary tokens from the request path, query params and headers."""
    found: list[str] = []
    found.extend(extract_canaries(path))
    for value in header_values:
        found.extend(extract_canaries(value))
    query = parse_qs(urlparse(path).query)
    for key in _CANARY_QUERY_KEYS:
        for value in query.get(key, []):
            found.extend(extract_canaries(value))
    return sorted(set(found))


class _OOBHandler(BaseHTTPRequestHandler):
    """Records every inbound request as an OOB receipt and replies 200 ok."""

    server_version = "pyrit-mini-oob/1.0"

    def _handle(self) -> None:  # noqa: N802 (stdlib naming)
        log = get_receipt_log()
        canaries = _canaries_from(self.path, [str(v) for v in self.headers.values()])
        for canary in canaries or [f"{CANARY_PREFIX}_unattributed"]:
            log.record(
                canary=canary,
                path=self.path,
                remote=self.client_address[0] if self.client_address else "",
                method=self.command,
                headers={k: v for k, v in self.headers.items()},
            )
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _handle
    do_POST = _handle
    do_HEAD = _handle
    do_PUT = _handle
    do_PATCH = _handle

    def log_message(self, fmt: str, *args: object) -> None:  # keep stdlib quiet
        logger.debug("[OOB] " + fmt, *args)


class OOBListener:
    """Threaded HTTP listener writing receipts into the shared OOB log."""

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

    def start(self) -> "OOBListener":
        if self._httpd is not None:
            return self
        self._httpd = ThreadingHTTPServer((self._host, self._port), _OOBHandler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="oob-listener", daemon=True)
        self._thread.start()
        logger.info("[OOB] listener started at %s", self.url)
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
        logger.info("[OOB] listener stopped")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="OOB receipt listener for exfiltration evidence (REQ-152)")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default 127.0.0.1; keep on authorized infra)")
    parser.add_argument("--port", type=int, default=8899, help="Bind port (0 = random free port)")
    parser.add_argument("--duration", type=float, default=0.0, help="Seconds to listen (0 = until Ctrl-C)")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    listener = OOBListener(host=args.host, port=args.port).start()
    print(f"[OOB] listening on {listener.url}  (canary prefix={CANARY_PREFIX})")
    try:
        if args.duration and args.duration > 0:
            time.sleep(args.duration)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        receipts = get_receipt_log().receipts()
        print(f"[OOB] total receipts: {len(receipts)}")
        listener.stop()


if __name__ == "__main__":
    main()
