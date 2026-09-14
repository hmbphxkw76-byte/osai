"""assess/impact/canary.py — Canary 生成与提取（REQ-152 / IC-5 OOB 验真前置）。

设计约束：
    - 零新增运行时依赖（NEG-4）：仅标准库（`secrets` / `re`）。
    - canary 是「不可被目标猜测的唯一令牌」；OOB 回执携带它即证明外传成立
      （见 `assess.impact.exfil` 的 `OOBReceiptLog` + `assess.impact.verdict.decide_verdict`）。
    - 本模块为 canary 逻辑的唯一归属；`assess.impact.exfil` 经 `from .canary import ...`
      复用，避免第二份实现（C3 / 单一职责）。

学术依据：
    - Greshake et al. (arXiv:2302.12173) — 间接注入 → 数据外传
    - OWASP LLM02 (Sensitive Information Disclosure)
"""

from __future__ import annotations

import re
import secrets

# Attack OOB Canary 前缀（用于在响应文本中检索回显）
CANARY_PREFIX = "AOBC"

_CANARY_RE = re.compile(rf"\b{CANARY_PREFIX}_[0-9a-fA-F]{{6,}}\b")


def generate_canary(prefix: str = CANARY_PREFIX) -> str:
    """Generate a unique, unpredictable canary token (cannot be guessed by the target)."""
    return f"{prefix}_{secrets.token_hex(8)}"


def extract_canaries(text: object) -> list[str]:
    """Find all canary tokens appearing in a text (response echo / log)."""
    if not isinstance(text, str):
        return []
    return sorted(set(_CANARY_RE.findall(text)))


def build_callback_url(base_url: str, canary: str, *, param: str = "c") -> str:
    """Build the OOB callback URL carrying the canary as a query parameter."""
    base = (base_url or "").rstrip("/")
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}{param}={canary}"
