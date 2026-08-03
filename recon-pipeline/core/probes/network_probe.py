# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""NetworkProbe: ReconProbe wrapper for NetworkInterceptor.

Wraps the standalone NetworkInterceptor as a proper ReconProbe subclass,
allowing it to be orchestrated by ReconPipeline with timeout protection,
skip/fail tracking, and unified result merging.

Architecture alignment (DESIGN.md):
  - Input: browser_page
  - Output: endpoints (all types discovered by NetworkInterceptor)
  - Browser: True (required)

Previously NetworkInterceptor was called directly in stage_recon.py,
bypassing the ReconPipeline orchestration layer.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from core.probes.base import ReconProbe
from core.probes.network_interceptor import NetworkInterceptor

if TYPE_CHECKING:
    from core.session import ReconSession

logger = logging.getLogger(__name__)


class NetworkProbe(ReconProbe):
    """Network interception probe — ReconProbe wrapper for NetworkInterceptor.

    Attaches a Playwright response handler to the session's browser page,
    intercepts all HTTP responses, and classifies discovered API endpoints.

    Usage::
        probe = NetworkProbe(duration=10)
        result = await probe.probe(session)
        # result["endpoints"] -> list of DiscoveredEndpoint
    """

    def __init__(self, duration: float = 10.0) -> None:
        self._interceptor = NetworkInterceptor()
        self._duration = duration

    @property
    def name(self) -> str:
        return "NetworkProbe"

    @property
    def requires_browser(self) -> bool:
        return True

    @property
    def requires_auth(self) -> bool:
        return False

    async def probe(self, session: ReconSession) -> dict[str, Any]:
        """Execute network interception.

        Args:
            session: Recon session with browser_page.

        Returns:
            Dict with "endpoints" key containing discovered endpoints.

        Raises:
            RuntimeError: If browser_page is not available.
        """
        if session.browser_page is None:
            raise RuntimeError("NetworkProbe requires a browser page")

        endpoints = await self._interceptor.probe_endpoints(
            session.browser_page,
            session.target_url,
            duration=self._duration,
        )

        logger.info(
            "NetworkProbe: discovered %d endpoints (%d responses captured)",
            len(endpoints), self._interceptor.response_count,
        )

        return {"endpoints": endpoints}
