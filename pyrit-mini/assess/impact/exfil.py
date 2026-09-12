"""assess/impact/exfil.py — ExfilChannel：canary 生成 + OOB 回执登记（REQ-152 / IC-5）。

设计约束：
    - **零新增运行时依赖**（NEG-4）：仅标准库（`secrets` / `threading` / `re`）。
    - 回执日志为**进程内**单例；`tools.oob_listener`（标准库 `http.server`）写入，
      Assess 读取判定 `exfil_confirmed`。
    - 判定口径（IC-5）：**外传成立必须 OOB 回执**；仅响应文本命中一律降级为
      `exfil_suspected`（见 `assess.impact.verdict`）。

学术依据：
    - Greshake et al. (arXiv:2302.12173) — 间接注入 → 数据外传
    - OWASP LLM02 (Sensitive Information Disclosure)
"""

from __future__ import annotations

import logging
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Attack OOB Canary 前缀（用于在响应文本中检索回显）
CANARY_PREFIX = "AOBC"

_CANARY_RE = re.compile(rf"\b{CANARY_PREFIX}_[0-9a-fA-F]{{6,}}\b")


def generate_canary(prefix: str = CANARY_PREFIX) -> str:
    """Generate a unique, unpredictable canary token (cannot be guessed by the target)."""
    return f"{prefix}_{secrets.token_hex(8)}"


def extract_canaries(text: Any) -> list[str]:
    """Find all canary tokens appearing in a text (response echo / log)."""
    if not isinstance(text, str):
        return []
    return sorted(set(_CANARY_RE.findall(text)))


def build_callback_url(base_url: str, canary: str, *, param: str = "c") -> str:
    """Build the OOB callback URL carrying the canary as a query parameter."""
    base = (base_url or "").rstrip("/")
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}{param}={canary}"


@dataclass(frozen=True)
class OOBReceipt:
    """A single inbound OOB callback receipt (proof the target reached our listener)."""

    canary: str
    path: str = ""
    remote: str = ""
    method: str = "GET"
    ts: float = 0.0
    headers: dict[str, str] = field(default_factory=dict)


class OOBReceiptLog:
    """Thread-safe in-process receipt registry (written by tools.oob_listener)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._receipts: list[OOBReceipt] = []

    def record(
        self,
        *,
        canary: str,
        path: str = "",
        remote: str = "",
        method: str = "GET",
        headers: dict[str, str] | None = None,
    ) -> OOBReceipt:
        receipt = OOBReceipt(
            canary=str(canary),
            path=str(path),
            remote=str(remote),
            method=str(method),
            ts=time.time(),
            headers=dict(headers or {}),
        )
        with self._lock:
            self._receipts.append(receipt)
        logger.info("[OOB] receipt for canary=%s from %s%s", canary, remote, path)
        return receipt

    def receipts(self) -> list[OOBReceipt]:
        with self._lock:
            return list(self._receipts)

    def has_receipt(self, canary: str) -> bool:
        with self._lock:
            return any(r.canary == canary for r in self._receipts)

    def find(self, canary: str) -> list[OOBReceipt]:
        with self._lock:
            return [r for r in self._receipts if r.canary == canary]

    def wait(self, canary: str, *, timeout: float = 0.0, interval: float = 0.1) -> bool:
        """Block up to `timeout` seconds for a receipt (0 → single check)."""
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            if self.has_receipt(canary):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(max(0.01, interval))

    def clear(self) -> None:
        with self._lock:
            self._receipts.clear()


_SHARED_LOG = OOBReceiptLog()


def get_receipt_log() -> OOBReceiptLog:
    """Process-wide receipt log (SSOT for OOB verification)."""
    return _SHARED_LOG
