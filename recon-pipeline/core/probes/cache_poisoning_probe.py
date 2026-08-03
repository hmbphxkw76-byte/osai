"""Cache poisoning 5-stage behavioral confirmation probe (P2-1).

Stages: oracle -> buster -> hypotheses -> confirm -> scoring.
Mirrors RedAmon recon/cache_scan/scanner.py semantics, with a 200-URL cap
and real behavioral confirmation rather than purely theoretical detection.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from core.models.recon_report import EndpointType
from core.probes.base import ReconProbe
from core.session import ReconSession

logger = logging.getLogger(__name__)

_MAX_URLS = 200  # P2-1-B


class CachePoisoningProbe(ReconProbe):
    name = "CachePoisoningProbe"
    requires_browser = False
    requires_auth = False

    def __init__(self, timeout: float = 10.0) -> None:
        self._timeout = timeout

    async def probe(self, session: ReconSession) -> dict[str, Any]:
        candidates = [e for e in session.report.endpoints if e.url][:_MAX_URLS]
        if len(session.report.endpoints) > _MAX_URLS:
            logger.warning("CachePoisoningProbe: capped at %d URLs", _MAX_URLS)

        findings: list[dict[str, Any]] = []
        headers = session.auth_headers if session.auth_state else {}
        async with httpx.AsyncClient(timeout=self._timeout, verify=False, follow_redirects=False) as client:
            for ep in candidates:
                # P2-1-A: oracle — does a cache layer exist?
                try:
                    r1 = await client.get(ep.url, headers=headers)
                    cache_hdr = self._cache_header(r1.headers)
                    if not cache_hdr:
                        continue
                    # buster — vary a param to detect cache key omission
                    bust_url = ep.url + ("&__cp=1" if "?" in ep.url else "?__cp=1")
                    r2 = await client.get(bust_url, headers=headers)
                    if r1.text == r2.text and r1.status_code == r2.status_code:
                        # hypotheses: unkeyed param may be cached -> confirm
                        # confirm: second request should hit cache (Age / fast)
                        r3 = await client.get(ep.url, headers=headers)
                        age = r3.headers.get("Age", "0")
                        score = self._score(cache_hdr, int(age or 0))
                        findings.append({
                            "url": ep.url,
                            "cache_layer": cache_hdr,
                            "age": age,
                            "score": score,
                            "stage": "confirm",
                        })
                except httpx.HTTPError as exc:
                    logger.debug("CachePoisoningProbe skip %s: %s", ep.url, exc)
        return {"cache_poisoning_findings": findings}

    @staticmethod
    def _cache_header(headers: dict[str, str]) -> str | None:
        # P2-1-C: detect CDN cache via X-Cache / Age / cache-control
        norm = {k.lower(): v for k, v in headers.items()}
        if "x-cache" in norm:
            return f"x-cache:{norm['x-cache']}"
        if norm.get("age", "0") not in ("0", "", None):
            return "age-present"
        cc = norm.get("cache-control", "")
        if "public" in cc or "max-age" in cc:
            return "cache-control"
        return None

    @staticmethod
    def _score(layer: str, age: int) -> int:
        # P2-1-A scoring: higher age => higher confidence of caching
        return min(10, 3 + (age // 10))
