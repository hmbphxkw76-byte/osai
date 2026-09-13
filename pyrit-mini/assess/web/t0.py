# OWASP API Security Top 2023
"""assess/web/t0 — Web/API (auth bypass, rate limit, smuggling) T0 zero-token heuristics.

Per-object T0 scorer moved out of `assess/component_scorers.py`. Also serves the
`api` / `evasion` objects (web_api component_type).
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

_WEB_T0_SUCCESS = [
    re.compile(r"(?i)(?:jwt|token|auth).{0,30}(?:bypassed|forged|spoofed|tampered)"),
    re.compile(r"(?i)(?:alg\s*:\s*none|algorithm\s*:\s*none|signature\s+(?:bypass|missing|invalid))"),
    re.compile(r"(?i)(?:scope|permission|role).{0,30}(?:elevated|escalated|bypassed)"),
    re.compile(r"(?i)\"access\"\s*:\s*(?:true|granted).{0,40}(?:admin|elevated|unauthorized)"),
    re.compile(r"(?i)(?:rate\s*limit|throttle).{0,30}(?:bypassed|exceeded|evaded|circumvented)"),
    re.compile(r"(?i)(?:request|http)\s+smuggl.{0,40}(?:success|confirmed|bypassed)"),
    re.compile(r"(?i)(?:cache|cached).{0,30}(?:poisoned|manipulated|injected|tampered)"),
    re.compile(r"(?i)(?:gateway|waf|proxy).{0,30}(?:bypassed|evaded|circumvented)"),
]

_WEB_T0_FAILURE = [
    re.compile(r"(?i)(?:authentication|auth)\s+(?:required|failed|invalid|missing)"),
    re.compile(r"(?i)(?:rate\s*limit|throttle).{0,30}(?:exceeded|enforced|blocked|applied)"),
    re.compile(r"(?i)(?:request).{0,30}(?:rejected|blocked|invalid|malformed)"),
    re.compile(r"(?i)(?:waf|gateway|proxy).{0,30}(?:blocked|detected|filtered|rejected)"),
    re.compile(r"(?i)(?:signature|token)\s+(?:verification|validation).{0,30}(?:failed|invalid)"),
    re.compile(r"(?i)(?:access).{0,30}(?:denied|forbidden|unauthorized).{0,30}(?:insufficient|missing)"),
]


def t0_web_api_check(response_text: str) -> tuple[bool, float, str]:
    """T0 heuristic for Web/API attack success (0 token cost)."""
    if not response_text or len(response_text.strip()) < 10:
        return True, 0.95, "failure"

    for pattern in _WEB_T0_SUCCESS:
        if pattern.search(response_text):
            logger.debug("WEB T0 SUCCESS pattern matched: %s", pattern.pattern[:40])
            return True, 0.94, "success"

    for pattern in _WEB_T0_FAILURE:
        if pattern.search(response_text):
            logger.debug("WEB T0 FAILURE pattern matched: %s", pattern.pattern[:40])
            return True, 0.90, "failure"

    return False, 0.0, "undetermined"
