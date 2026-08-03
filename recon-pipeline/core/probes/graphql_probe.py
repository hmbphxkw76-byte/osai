"""GraphQL introspection probe (P2-2).

Sends an __schema introspection query and identifies AI-related resolvers
(chat / completion / embed).
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from core.probes.base import ReconProbe
from core.session import ReconSession

logger = logging.getLogger(__name__)

_INTROSPECTION = {
    "query": """
    query Introspection {
      __schema {
        queryType { name fields { name } }
        mutationType { name fields { name } }
      }
    }
    """,
    "operationName": "Introspection",
}

_AI_RESOLVER_HINTS = ("chat", "completion", "complet", "embed", "generate", "llm", "prompt")


class GraphQLProbe(ReconProbe):
    name = "GraphQLProbe"
    requires_browser = False
    requires_auth = False

    def __init__(self, timeout: float = 10.0) -> None:
        self._timeout = timeout

    async def probe(self, session: ReconSession) -> dict[str, Any]:
        bases = self._base_urls(session)
        headers = session.auth_headers if session.auth_state else {}
        findings: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=self._timeout, verify=False, follow_redirects=False) as client:
            for base in bases:
                url = base.rstrip("/") + "/graphql"
                try:
                    r = await client.post(url, json=_INTROSPECTION, headers=headers)
                except httpx.HTTPError:
                    continue
                if r.status_code != 200:
                    continue
                try:
                    data = r.json()
                except ValueError:
                    continue
                schema = data.get("data", {}).get("__schema", {})
                if not schema:
                    continue
                ai_resolvers = self._ai_resolvers(schema)
                findings.append({
                    "url": url,
                    "query_type": schema.get("queryType", {}).get("name"),
                    "mutation_type": schema.get("mutationType", {}).get("name"),
                    "ai_resolvers": ai_resolvers,
                })
        return {"graphql_findings": findings}

    @staticmethod
    def _base_urls(session: ReconSession) -> list[str]:
        from urllib.parse import urlparse
        bases: set[str] = set()
        for ep in session.report.endpoints:
            if ep.url:
                p = urlparse(ep.url)
                if p.scheme and p.netloc:
                    bases.add(f"{p.scheme}://{p.netloc}")
        if session.target_url:
            bases.add(session.target_url.rstrip("/"))
        return sorted(bases)

    @staticmethod
    def _ai_resolvers(schema: dict[str, Any]) -> list[str]:
        out: list[str] = []
        for t in ("queryType", "mutationType"):
            fields = schema.get(t, {}).get("fields", []) or []
            for f in fields:
                name = f.get("name", "")
                if any(h in name.lower() for h in _AI_RESOLVER_HINTS):
                    out.append(name)
        return out
