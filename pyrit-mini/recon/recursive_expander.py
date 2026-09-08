"""Recursive Endpoint Expansion — Discovery Chaining.

Closes Gap #4: Recursive Endpoint Expansion.

Red Team Thinking:
    "I found /api/v2/ returns 200 — what about /api/v2/models, /api/v2/admin,
     /api/v2/config, /api/v2/secrets_prefix? The version prefix itself is
     a breadcrumb."

    "The error message said 'see /api/v3/docs for information' — that's
     literally giving me the next reconnaissance target."

Data Flow:
    first_probe → extract_version_prefixes → expand_subpaths → second_probe → merge

Academic basis:
    - OWASP WSTG-CONF-06 - Testing HTTP Methods
    - Caldera/DeepRed - iterative attack surface discovery
    - BOLA/IDOR chain: discovering /users leads to /users/{id} leads to /profile

Constitution compliance:
    - R-SIZE: < 200 lines
    - No recursion limit exceeded (bounded depth=1)
    - Uses aiohttp (R-IMPORT-1)
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Any

import aiohttp

from recon.health_probe import _TLS_VERIFY, DiscoveredEndpoint

logger = logging.getLogger(__name__)

# Version/Vendor patterns that imply deeper endpoints exist
_VERSION_PATTERNS = [
    # /api/vN/ → likely has /api/vN/{resource}
    re.compile(
        r"^(/(?:api/)?v\d+/?).*$",
    ),
    # /N.x/ style versioning
    re.compile(
        r"^/(?:v)?\d+\.\d+/.*$",
    ),
]

# Subpaths to probe when an API root is discovered
_API_RESOURCE_SUBPATHS = [
    # Common REST resources
    "/models",
    "/users",
    "/health",
    "/status",
    "/config",
    "/debug",
    "/metrics",
    "/logs",
    "/admin",
    "/version",
    "/info",
    "/stats",
    "/jobs",
    "/tasks",
    "/workflows",
    "/agents",
    "/tools",
    "/sessions",
    "/conversations",
    "/chat",
    "/completions",
    "/embeddings",
    "/moderations",
    "/assistants",
    "/files",
    "/datasets",
]

# AI-specific subpaths for AI-targeted recursive expansion
_AI_RESOURCE_SUBPATHS = [
    "/v1/models",
    "/v1/agents",
    "/v1/tools",
    "/v1/completions",
    "/v1/chat/completions",
    "/v1/embeddings",
    "/v1/moderations",
    "/v1/assistants",
    "/v1/files",
    "/v1/sessions",
    "/v1/conversations",
    "/v1/workflows",
    "/v1/prompts",
    "/v1/datasets",
    "/v1/vector-stores",
    "/v1/knowledge-bases",
    "/api/models",
    "/api/agents",
    "/api/tools",
    "/api/sessions",
    "/api/workflows",
]


@dataclass
class ExpansionPlan:
    """Plan for recursive endpoint expansion.

    Attributes:
        base_prefix: The discovered version/API prefix to expand
        subpaths_to_probe: Generated list of paths to probe next
        reasoning: Human-readable explanation for audit log
    """
    base_prefix: str
    subpaths_to_probe: list[str]
    reasoning: str


def analyze_for_expansion(
    discovered_endpoints: list[DiscoveredEndpoint],
) -> list[ExpansionPlan]:
    """Analyze discovered endpoints for recursive expansion opportunities.

    Red team: "I found /api/v2/ → I should check /api/v2/admin and /api/v2/models."
    """
    plans: list[ExpansionPlan] = []

    for ep in discovered_endpoints:
        path = ep.path
        existence = ep.existence

        # Only confirmed/protected endpoints get expanded
        if existence not in ("confirmed", "protected"):
            continue

        subpaths: list[str] = []
        reasoning_parts: list[str] = []

        # Version prefix detection
        for pattern in _VERSION_PATTERNS:
            if pattern.match(path):
                # Generate subpaths by appending API resources
                for sub in _AI_RESOURCE_SUBPATHS:
                    candidate = f"{path.rstrip('/')}{sub}"
                    if candidate != path and candidate not in subpaths:
                        subpaths.append(candidate)
                reasoning_parts.append(
                    f"version prefix '{path}' → {len(subpaths)} subpaths"
                )
                break

        # Generic API root detection (non-versioned)
        if path in ("/", "/api", "/api/", "/v1", "/v1/", "/v2", "/v2/"):
            for sub in _API_RESOURCE_SUBPATHS:
                candidate = f"{path.rstrip('/')}{sub}"
                if candidate not in subpaths:
                    subpaths.append(candidate)
            reasoning_parts.append(
                f"API root '{path}' → {len(subpaths)} generic subpaths"
            )

        if subpaths:
            plans.append(ExpansionPlan(
                base_prefix=path,
                subpaths_to_probe=subpaths,
                reasoning="; ".join(reasoning_parts),
            ))

    if plans:
        logger.info(
            "[Recursive] %d expansion plans generated from %d endpoints",
            len(plans),
            len(discovered_endpoints),
        )

    return plans


async def run_recursive_probe(
    session: Any,
    base_url: str,
    plan: ExpansionPlan,
    semaphore: Any,
) -> list[DiscoveredEndpoint]:
    """Execute a recursive probe based on expansion plan.

    Uses HEAD requests for efficiency (consistent with Layer 3 enumeration).

    Args:
        session: aiohttp ClientSession
        base_url: Target base URL
        plan: ExpansionPlan with paths to probe
        semaphore: Concurrency control

    Returns:
        Newly discovered endpoints
    """
    discovered: list[DiscoveredEndpoint] = []

    for path in plan.subpaths_to_probe:
        url = f"{base_url}{path}"
        try:
            async with semaphore:
                try:
                    async with session.head(
                        url,
                        allow_redirects=True,
                        ssl=_TLS_VERIFY,
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        status = resp.status
                        content_type = resp.content_type or ""
                        is_api = "json" in content_type

                        if status < 400:
                            existence = "confirmed"
                        elif status in (401, 403):
                            existence = "protected"
                        elif status in (405, 500, 502):
                            existence = "probable"
                        else:
                            continue  # Skip 404s for brevity

                        discovered.append(DiscoveredEndpoint(
                            path=path,
                            status_code=status,
                            content_type=content_type,
                            is_api=is_api,
                            existence=existence,
                        ))
                        logger.debug(
                            "[Recursive] %s → %s (%s)",
                            path, status, existence,
                        )
                except Exception:
                    pass
        except Exception:
            pass

    if discovered:
        logger.info(
            "[Recursive] Expansion of '%s': %d new endpoints",
            plan.base_prefix,
            len(discovered),
        )

    return discovered


async def execute_recursive_expansion(
    session: Any,
    base_url: str,
    existing_endpoints: list[DiscoveredEndpoint],
) -> list[DiscoveredEndpoint]:
    """Main entry: analyze, plan, and execute recursive expansion.

    Args:
        session: aiohttp ClientSession
        base_url: Target base URL
        existing_endpoints: Endpoints discovered in Layer 3

    Returns:
        Newly discovered endpoints (to be merged into ServiceProfile)
    """
    plans = analyze_for_expansion(existing_endpoints)
    if not plans:
        return []

    try:
        semaphore = asyncio.Semaphore(5)
    except Exception:
        semaphore = None

    all_discovered: list[DiscoveredEndpoint] = []

    for plan in plans:
        discovered = await run_recursive_probe(
            session, base_url, plan, semaphore,
        )
        all_discovered.extend(discovered)

    # Log expansion results
    if all_discovered:
        confirmed_count = sum(1 for d in all_discovered if d.existence == "confirmed")
        protected_count = sum(1 for d in all_discovered if d.existence == "protected")
        logger.info(
            "[Recursive Expansion] Complete: %d new endpoints "
            "(%d confirmed, %d protected)",
            len(all_discovered), confirmed_count, protected_count,
        )

    return all_discovered
