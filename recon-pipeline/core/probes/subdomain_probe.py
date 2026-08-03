# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Subdomain enumeration probe — discover AI-related subdomains.

Probes common AI-specific subdomains to discover additional
AI services hosted under the target domain:
  1. API subdomains (api, api-v1, api-v2)
  2. Chat/LLM subdomains (chat, llm, ai, models, inference)
  3. RAG/Vector subdomains (rag, vector, search, embeddings)
  4. MCP subdomains (mcp, tools)
  5. Agent subdomains (agent, assistant, copilot, bot)
  6. Auth subdomains (auth, login, sso, oauth, idp)
  7. MLOps subdomains (ml, mlflow, training, dashboard)
  8. Admin/Internal subdomains (admin, internal, dev, staging, sandbox)

Architecture:
  - Input: target domain from session.target_url
  - Output: discovered_subdomains (verified AI subdomains)
  - Browser: False
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import httpx

from core.probes.base import ReconProbe

if TYPE_CHECKING:
    from core.session import ReconSession

logger = logging.getLogger(__name__)

# AI-specific subdomain wordlists by category
_AI_SUBDOMAINS: dict[str, list[str]] = {
    "api": [
        "api", "api-v1", "api-v2", "api-gateway", "gateway",
        "rest", "graphql", "ws", "websocket",
    ],
    "llm_chat": [
        "chat", "chatbot", "llm", "ai", "gpt", "models",
        "inference", "completions", "generate", "playground",
        "console", "app", "demo",
    ],
    "rag_vector": [
        "rag", "search", "vector", "embeddings", "embed",
        "knowledge", "retrieval", "index", "documents",
    ],
    "mcp": [
        "mcp", "mcp-server", "tools", "functions", "plugins",
    ],
    "agent": [
        "agent", "assistant", "copilot", "bot", "automation",
        "workflow", "orchestrator",
    ],
    "auth": [
        "auth", "login", "sso", "oauth", "idp", "accounts",
        "identity", "iam",
    ],
    "mlops": [
        "ml", "mlflow", "training", "dashboard", "monitor",
        "experiments", "registry", "serving",
    ],
    "admin_internal": [
        "admin", "internal", "dev", "staging", "sandbox",
        "test", "qa", "preview", "beta",
    ],
}

# DNS resolvers to try (for subdomain resolution)
_DNS_TIMEOUT = 3.0

# HTTP verification timeout
_HTTP_TIMEOUT = 5.0


class SubdomainProbe(ReconProbe):
    """AI subdomain enumeration probe.

    Probes common AI-specific subdomains to discover
    additional AI services under the target domain.

    Usage::
        probe = SubdomainProbe()
        result = await probe.probe(session)
        # result["discovered_subdomains"] -> list of verified AI subdomains
    """

    def __init__(
        self,
        wordlists: dict[str, list[str]] | None = None,
        dns_timeout: float = _DNS_TIMEOUT,
        http_timeout: float = _HTTP_TIMEOUT,
        concurrency: int = 15,
    ) -> None:
        self._wordlists = wordlists or _AI_SUBDOMAINS
        self._dns_timeout = dns_timeout
        self._http_timeout = http_timeout
        self._concurrency = concurrency

    @property
    def name(self) -> str:
        return "SubdomainProbe"

    @property
    def requires_browser(self) -> bool:
        return False

    @property
    def requires_auth(self) -> bool:
        return False

    async def probe(self, session: ReconSession) -> dict[str, Any]:
        """Execute subdomain enumeration.

        Args:
            session: Recon session.

        Returns:
            Dict with discovered_subdomains and summary.
        """
        domain = urlparse(session.target_url).hostname
        if not domain:
            return {"discovered_subdomains": [], "summary": {"error": "Could not extract domain"}}

        # Remove www prefix if present
        if domain.startswith("www."):
            domain = domain[4:]

        # Build candidate list
        candidates = self._build_candidates(domain)

        # Phase 1: DNS resolution
        resolved = await self._resolve_subdomains(candidates)

        # Phase 2: HTTP verification
        verified = await self._http_verify(resolved, session.auth_headers if session.auth_state else {})

        # Categorize by type
        by_category: dict[str, int] = {}
        for sub in verified:
            cat = sub["category"]
            by_category[cat] = by_category.get(cat, 0) + 1

        logger.info(
            "SubdomainProbe: %d/%d resolved, %d verified AI subdomains on %s",
            len(resolved), len(candidates), len(verified), domain,
        )

        return {
            "discovered_subdomains": verified,
            "summary": {
                "domain": domain,
                "candidates": len(candidates),
                "resolved": len(resolved),
                "verified": len(verified),
                "by_category": by_category,
            },
        }

    def _build_candidates(self, domain: str) -> list[tuple[str, str]]:
        """Build subdomain candidate list."""
        candidates: list[tuple[str, str]] = []
        seen: set[str] = set()

        for category, subdomains in self._wordlists.items():
            for sub in subdomains:
                fqdn = f"{sub}.{domain}"
                if fqdn not in seen:
                    seen.add(fqdn)
                    candidates.append((fqdn, category))

        return candidates

    async def _resolve_subdomains(
        self, candidates: list[tuple[str, str]]
    ) -> list[tuple[str, str, str]]:
        """DNS resolve subdomain candidates."""
        semaphore = asyncio.Semaphore(self._concurrency)
        resolved: list[tuple[str, str, str]] = []

        async def resolve_one(fqdn: str, category: str) -> None:
            async with semaphore:
                try:
                    loop = asyncio.get_event_loop()
                    ip = await loop.getaddrinfo(fqdn, None)
                    if ip:
                        resolved.append((fqdn, category, ip[0][4][0]))
                        logger.debug("SubdomainProbe: resolved %s -> %s", fqdn, ip[0][4][0])
                except (socket.gaierror, OSError):
                    pass

        tasks = [resolve_one(fqdn, cat) for fqdn, cat in candidates]
        await asyncio.gather(*tasks)

        return resolved

    async def _http_verify(
        self,
        resolved: list[tuple[str, str, str]],
        auth_headers: dict[str, str],
    ) -> list[dict[str, Any]]:
        """HTTP verify resolved subdomains for AI services."""
        verified: list[dict[str, Any]] = []
        semaphore = asyncio.Semaphore(self._concurrency)

        async with httpx.AsyncClient(timeout=self._http_timeout, verify=False, follow_redirects=True) as client:
            async def check_one(fqdn: str, category: str, ip: str) -> None:
                async with semaphore:
                    for scheme in ("https", "http"):
                        url = f"{scheme}://{fqdn}"
                        try:
                            resp = await client.get(url, headers=auth_headers)
                            if resp.status_code < 500:
                                ai_indicators = self._detect_ai_service(resp, category)
                                verified.append({
                                    "fqdn": fqdn,
                                    "ip": ip,
                                    "url": url,
                                    "category": category,
                                    "status_code": resp.status_code,
                                    "content_type": resp.headers.get("content-type", ""),
                                    "server": resp.headers.get("server", ""),
                                    "ai_indicators": ai_indicators,
                                    "title": self._extract_title(resp.text),
                                })
                                break
                        except Exception:
                            continue

            tasks = [check_one(fqdn, cat, ip) for fqdn, cat, ip in resolved]
            await asyncio.gather(*tasks)

        return verified

    @staticmethod
    def _detect_ai_service(resp: httpx.Response, category: str) -> list[str]:
        """Detect AI service indicators in HTTP response."""
        indicators: list[str] = []
        text = resp.text[:1000].lower()
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        # LLM indicators
        if any(kw in text for kw in ("openai", "chatgpt", "claude", "gemini", "llama", "mistral", "deepseek", "ollama")):
            indicators.append("llm_brand")
        if '"choices"' in text or '"model"' in text:
            indicators.append("openai_compatible_api")
        if "x-openai" in " ".join(headers_lower):
            indicators.append("openai_headers")

        # RAG/Vector indicators
        if any(kw in text for kw in ("collection", "vector", "embedding", "retrieval")):
            indicators.append("rag_vector")

        # MCP indicators
        if any(kw in text for kw in ('"jsonrpc"', '"tools"', '"resources"', '"prompts"')):
            indicators.append("mcp_service")
        if "mcp" in " ".join(headers_lower):
            indicators.append("mcp_headers")

        # Agent indicators
        if any(kw in text for kw in ("agent", "assistant", "copilot", "tool_call", "function_call")):
            indicators.append("agent_service")

        # Auth indicators
        if any(kw in text for kw in ("login", "signin", "oauth", "authenticate")):
            indicators.append("auth_service")

        # MLOps indicators
        if any(kw in text for kw in ("mlflow", "experiment", "training", "wandb")):
            indicators.append("mlops_service")

        # Frontend indicators
        if any(kw in text for kw in ("gradio", "streamlit", "langflow", "flowise", "open-webui", "librechat")):
            indicators.append("ai_frontend")

        # API version headers
        if "openai-version" in headers_lower:
            indicators.append(f"openai-version: {headers_lower['openai-version']}")
        if "anthropic-version" in headers_lower:
            indicators.append(f"anthropic-version: {headers_lower['anthropic-version']}")

        return indicators

    @staticmethod
    def _extract_title(html: str) -> str:
        """Extract page title from HTML."""
        import re
        match = re.search(r"<title>([^<]+)</title>", html, re.IGNORECASE)
        return match.group(1).strip() if match else ""
