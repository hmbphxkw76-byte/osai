"""ProbePackProbe — bridges the declarative probe-pack engine into the ReconProbe interface.

P0-2-G: Wraps probe_pack_engine so YAML-declared probes run as first-class
ReconProbe instances inside PipelineRunner without disturbing the existing 17 probes.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import httpx

from core.models.recon_report import EndpointType
from core.probes.base import ReconProbe
from core.probes.probe_pack_engine import (
    ProbeRequest,
    load_probe_packs,
    run_probe_packs,
)
from core.session import ReconSession

logger = logging.getLogger(__name__)

_DEFAULT_PACKS_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "probe_packs"


class ProbePackProbe(ReconProbe):
    """Runs declarative YAML probe packs against discovered AI base URLs.

    Uses the base URLs already discovered by NetworkInterceptor/LLMProbe as
    probe targets, so it does not duplicate discovery work.
    """

    def __init__(
        self,
        packs_dir: str | Path | None = None,
        timeout: float = 10.0,
        max_per_base: int = 8,
    ) -> None:
        self._packs_dir = Path(packs_dir) if packs_dir else _DEFAULT_PACKS_DIR
        self._timeout = timeout
        self._max_per_base = max_per_base

    @property
    def name(self) -> str:
        return "ProbePackProbe"

    @property
    def requires_browser(self) -> bool:
        return False

    @property
    def requires_auth(self) -> bool:
        return False

    def _base_urls(self, session: ReconSession) -> list[str]:
        bases: set[str] = set()
        for ep in session.report.endpoints:
            if ep.url:
                from urllib.parse import urlparse
                parsed = urlparse(ep.url)
                if parsed.scheme and parsed.netloc:
                    bases.add(f"{parsed.scheme}://{parsed.netloc}")
        if session.target_url:
            bases.add(session.target_url.rstrip("/"))
        return sorted(bases)

    async def probe(self, session: ReconSession) -> dict[str, Any]:
        probes = load_probe_packs(self._packs_dir)
        if not probes:
            logger.warning("ProbePackProbe: no probe packs found in %s", self._packs_dir)
            return {"endpoints": [], "probe_pack_results": []}

        base_urls = self._base_urls(session)
        headers = session.auth_headers if session.auth_state else {}

        async with httpx.AsyncClient(
            timeout=self._timeout, verify=False, follow_redirects=False
        ) as client:
            def requester(req: ProbeRequest) -> dict[str, Any]:
                url = req.path
                try:
                    if req.method == "POST":
                        resp = client.post(url, headers={**headers, **req.headers}, content=req.body)
                    else:
                        resp = client.get(url, headers={**headers, **req.headers})
                except httpx.HTTPError as exc:
                    return {"body": "", "status_code": None, "headers": {}, "error": str(exc)}
                return {
                    "body": resp.text,
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                }

            results = []
            for base in base_urls:
                # requester needs absolute base URL; patch ProbeRequest.path per base
                base_probes = []
                for p in probes:
                    from dataclasses import replace
                    patched = []
                    for r in p.requests:
                        patched.append(replace(r, path=base.rstrip("/") + r.path))
                    from dataclasses import replace as _r
                    base_probes.append(_r(p, requests=patched))
                base_results = run_probe_packs(base_probes, requester)
                matched = [r for r in base_results if r.matched]
                results.extend([r.to_dict() for r in matched])

        logger.info("ProbePackProbe: %d matched signals across %d base URLs", len(results), len(base_urls))
        return {"endpoints": [], "probe_pack_results": results}
