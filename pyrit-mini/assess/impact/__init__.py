"""assess/impact — ImpactChain + ExfilChannel（REQ-152 / ADR-008 / IC-5 / IC-6）。

判定四态（ADR-008）：
    impact          副作用/影响成立（需二次独立请求确认，IC-6）
    exfil_confirmed 外传成立（需 OOB 回执，IC-5）
    exfil_suspected 仅响应文本命中，未获回执
    content_only    仅内容层面

**仅 `impact` 与 `exfil_confirmed` 计入 `confirmed_asr`**（NFR-13 ④）。

本包只做判定与登记，不含攻击执行逻辑（C1/C13）。
"""

from __future__ import annotations

from assess.impact.exfil import (
    CANARY_PREFIX,
    OOBReceipt,
    OOBReceiptLog,
    build_callback_url,
    extract_canaries,
    generate_canary,
    get_receipt_log,
)
from assess.impact.verdict import (
    CONTENT_ONLY,
    EXFIL_CONFIRMED,
    EXFIL_SUSPECTED,
    IMPACT,
    decide_verdict,
    is_confirmed,
)

__all__ = [
    "CANARY_PREFIX",
    "OOBReceipt",
    "OOBReceiptLog",
    "build_callback_url",
    "extract_canaries",
    "generate_canary",
    "get_receipt_log",
    "CONTENT_ONLY",
    "EXFIL_CONFIRMED",
    "EXFIL_SUSPECTED",
    "IMPACT",
    "is_confirmed",
    "decide_verdict",
]
