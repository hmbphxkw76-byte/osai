"""assess/impact/exfil.py — ExfilChannel：OOB 回执登记（canary 生成见 `assess.impact.canary`，REQ-152 / IC-5）。

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
import threading
import time
from dataclasses import dataclass, field

# 兼容性 re-export：canary 逻辑已下沉至 `assess.impact.canary`（W-P4 P4-3），
# 原从 `exfil` 导入 canary 符号的调用方无需改动（C3：单一归属 + 兼容保留）。
from assess.impact.canary import (  # noqa: F401  # 兼容性 re-export，供仍从 exfil 导入 canary 符号的调用方使用
    CANARY_PREFIX,
    build_callback_url,
    extract_canaries,
    generate_canary,
)

logger = logging.getLogger(__name__)


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
