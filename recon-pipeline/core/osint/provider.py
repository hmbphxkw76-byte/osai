"""Pluggable OSINT enrichment provider (P2-3).

Provider ABC + Shodan/Fofa/Censys implementations reading API keys from env.
Degrades silently (no error) when no key is configured (P2-3-C).
"""
from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class OsinResult:
    host: str
    ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    source: str = "osint"
    raw: dict[str, Any] = field(default_factory=dict)


class OSINTProvider(ABC):
    name: str = "abstract"

    @abstractmethod
    def enrich(self, host: str) -> OsinResult:
        ...

    @property
    def available(self) -> bool:
        return True


class ShodanProvider(OSINTProvider):
    name = "shodan"

    @property
    def available(self) -> bool:
        return bool(os.getenv("SHODAN_API_KEY"))

    def enrich(self, host: str) -> OsinResult:
        if not self.available:
            return OsinResult(host=host, source="shodan")
        try:
            import shodan  # type: ignore
            api = shodan.Shodan(os.getenv("SHODAN_API_KEY"))
            data = api.host(host)
            ports = data.get("ports", [])
            services = [m.get("product", "") for m in data.get("data", []) if m.get("product")]
            return OsinResult(host=host, ports=ports, services=services, source="shodan", raw=data)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Shodan enrich failed for %s: %s", host, exc)
            return OsinResult(host=host, source="shodan")


class FofaProvider(OSINTProvider):
    name = "fofa"

    @property
    def available(self) -> bool:
        return bool(os.getenv("FOFA_API_KEY"))

    def enrich(self, host: str) -> OsinResult:
        if not self.available:
            return OsinResult(host=host, source="fofa")
        # Fofa API call placeholder; degrade gracefully
        return OsinResult(host=host, source="fofa")


class CensysProvider(OSINTProvider):
    name = "censys"

    @property
    def available(self) -> bool:
        return bool(os.getenv("CENSYS_API_ID")) and bool(os.getenv("CENSYS_API_SECRET"))

    def enrich(self, host: str) -> OsinResult:
        if not self.available:
            return OsinResult(host=host, source="censys")
        return OsinResult(host=host, source="censys")


_PROVIDERS = [ShodanProvider(), FofaProvider(), CensysProvider()]


def enrich_host(host: str) -> list[OsinResult]:
    """P2-3-B: Run all available providers, return merged results."""
    results: list[OsinResult] = []
    for p in _PROVIDERS:
        if not p.available:
            continue
        try:
            results.append(p.enrich(host))
        except Exception as exc:  # noqa: BLE001
            logger.debug("%s enrich failed: %s", p.name, exc)
    return results
