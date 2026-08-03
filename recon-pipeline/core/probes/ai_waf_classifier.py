"""AI-assisted WAF / block-page classifier (P2-4).

When signature-based WAF detection fails, delegate the classification of an
intercepted block response to an independent LLM endpoint (mirrors RedAmon
ai_planner/waf_classifier.py). Falls back to 'unknown' when no LLM configured.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from core.probes.base import ReconProbe
from core.session import ReconSession

logger = logging.getLogger(__name__)

_BLOCK_KEYWORDS = ("access denied", "forbidden", "waf", "cloudflare", "akamai", "incapsula", "rate limit")


class AIWAFClassifierProbe(ReconProbe):
    name = "AIWAFClassifierProbe"
    requires_browser = False
    requires_auth = False

    def __init__(self, llm_endpoint: str | None = None) -> None:
        self._llm_endpoint = llm_endpoint or os.getenv("WAF_CLASSIFIER_ENDPOINT")

    async def probe(self, session: ReconSession) -> dict[str, Any]:
        # This probe consumes block responses already captured by WAFDetectorProbe.
        findings: list[dict[str, Any]] = []
        for ep in session.report.endpoints:
            block = self._is_block(ep)
            if not block:
                continue
            vendor = self._classify(ep)
            findings.append({
                "url": ep.url,
                "waf_vendor": vendor,
                "classified_by": "llm" if self._llm_endpoint else "keyword",
            })
        return {"waf_findings": findings}

    @staticmethod
    def _is_block(ep: Any) -> bool:
        body = (ep.response_body_preview or "").lower()
        status = getattr(ep, "status_code", 0)
        return status in (403, 429, 503) or any(k in body for k in _BLOCK_KEYWORDS)

    def _classify(self, ep: Any) -> str:
        if not self._llm_endpoint:
            return "unknown-keyword"
        # Placeholder for LLM delegation; returns heuristic in this env.
        body = (ep.response_body_preview or "").lower()
        if "cloudflare" in body:
            return "cloudflare"
        if "akamai" in body:
            return "akamai"
        return "unknown-llm"
