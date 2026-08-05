# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""LLMProbe: LLM endpoint discovery and model fingerprinting probe.

Responsibilities:
  1. Discover model API endpoints via NetworkInterceptor (passive)
  2. Extract model family/name/system prompt hints from response bodies (LLMFingerprint)
  3. Active chat-shape probing to classify response shapes
  4. Model list discovery (GET /v1/models, /models, /api/tags)
  5. OpenAPI/Swagger/AI Plugin spec discovery
  6. Guardrail detection from headers and response bodies

Architecture alignment (DESIGN.md six-probe architecture):
  - Input: auth_state (HTTP headers) + browser_page
  - Output: endpoints (MODEL_API) + llm_fingerprints + capabilities
  - Browser: True (passive via NetworkInterceptor), also True for active probing

Academic basis:
  - OWASP LLM01: Prompt Injection — model endpoints are the primary injection surface
  - MITRE ATLAS: AML.TA0002 — model fingerprinting
  - AgentDojo (arXiv:2406.13352) — capability enumeration is key to attack surface mapping
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import TYPE_CHECKING, Any

import httpx

from core.models.recon_report import (
    DiscoveredEndpoint,
    EndpointType,
    LLMFingerprint,
)
from core.probes.ai_signal_catalog import (
    AI_CHAT_PROBE_PATHS,
    AI_CHAT_RESPONSE_SHAPES,
    AI_OPENAPI_DISCOVERY_PATHS,
    classify_ai_chat_response,
    guess_model_family,
)
from core.probes.base import ReconProbe

if TYPE_CHECKING:
    from core.session import ReconSession

logger = logging.getLogger(__name__)

# Model family fingerprints — infer model family from response body keywords.
# Long keywords first to avoid short-keyword false matches (e.g. "gpt-4" matching "gpt-4o").
_MODEL_FAMILY_PATTERNS: list[tuple[str, str]] = [
    ("gpt-4o", "OpenAI GPT-4o"),
    ("gpt-4.5", "OpenAI GPT-4.5"),
    ("gpt-4-turbo", "OpenAI GPT-4 Turbo"),
    ("gpt-4", "OpenAI GPT-4"),
    ("gpt-3.5-turbo", "OpenAI GPT-3.5 Turbo"),
    ("gpt-3.5", "OpenAI GPT-3.5"),
    ("o3-mini", "OpenAI o3-mini"),
    ("o3-", "OpenAI o3"),
    ("o1-mini", "OpenAI o1-mini"),
    ("o1-", "OpenAI o1"),
    ("claude-3.5-sonnet", "Anthropic Claude 3.5 Sonnet"),
    ("claude-3.5-haiku", "Anthropic Claude 3.5 Haiku"),
    ("claude-3-opus", "Anthropic Claude 3 Opus"),
    ("claude-3-sonnet", "Anthropic Claude 3 Sonnet"),
    ("claude-3-haiku", "Anthropic Claude 3 Haiku"),
    ("claude-4", "Anthropic Claude 4"),
    ("claude-3", "Anthropic Claude 3"),
    ("claude", "Anthropic Claude"),
    ("gemini-2.5-pro", "Google Gemini 2.5 Pro"),
    ("gemini-2.0-flash", "Google Gemini 2.0 Flash"),
    ("gemini-2", "Google Gemini 2"),
    ("gemini-1.5-pro", "Google Gemini 1.5 Pro"),
    ("gemini-1.5-flash", "Google Gemini 1.5 Flash"),
    ("gemini-1.5", "Google Gemini 1.5"),
    ("gemini", "Google Gemini"),
    ("llama-4-maverick", "Meta Llama 4 Maverick"),
    ("llama-4-scout", "Meta Llama 4 Scout"),
    ("llama-4", "Meta Llama 4"),
    ("llama-3.3", "Meta Llama 3.3"),
    ("llama-3.2", "Meta Llama 3.2"),
    ("llama-3.1", "Meta Llama 3.1"),
    ("llama-3", "Meta Llama 3"),
    ("llama", "Meta Llama"),
    ("mixtral-8x22b", "Mistral Mixtral 8x22B"),
    ("mixtral-8x7b", "Mistral Mixtral 8x7B"),
    ("mixtral", "Mistral Mixtral"),
    ("mistral-large", "Mistral Large"),
    ("mistral-medium", "Mistral Medium"),
    ("mistral-small", "Mistral Small"),
    ("mistral-nemo", "Mistral Nemo"),
    ("mistral", "Mistral"),
    ("deepseek-v3", "DeepSeek V3"),
    ("deepseek-r1", "DeepSeek R1"),
    ("deepseek-coder", "DeepSeek Coder"),
    ("deepseek", "DeepSeek"),
    ("qwen2.5", "Alibaba Qwen 2.5"),
    ("qwen2", "Alibaba Qwen 2"),
    ("qwen", "Alibaba Qwen"),
    ("yi-large", "01.AI Yi Large"),
    ("yi-", "01.AI Yi"),
    ("phi-4", "Microsoft Phi-4"),
    ("phi-3", "Microsoft Phi-3"),
    ("phi-", "Microsoft Phi"),
    ("command-r-plus", "Cohere Command R+"),
    ("command-r", "Cohere Command R"),
    ("command", "Cohere Command"),
    ("dbrx", "Databricks DBRX"),
    ("falcon", "TII Falcon"),
    ("jamba", "AI21 Jamba"),
    ("reka", "Reka"),
]

# Guardrail detection keywords
_GUARDRAIL_KEYWORDS = [
    "content_filter",
    "content_filter_result",
    "content_filter_results",
    "safety_ratings",
    "blocked_reason",
    "refusal",
    "guardrail",
    "moderation",
    "harm_category",
    "safety_rating",
    "prompt_filter",
    "responsible_ai",
    "content_safety",
    "jailbreak",
]

# Guardrail header patterns
_GUARDRAIL_HEADER_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"x-content-filter", re.IGNORECASE), "Content Filter"),
    (re.compile(r"x-safety", re.IGNORECASE), "Safety Filter"),
    (re.compile(r"x-amzn-bedrock-guardrail", re.IGNORECASE), "Bedrock Guardrail"),
    (re.compile(r"amazon-q-", re.IGNORECASE), "Amazon Q Guard"),
]


class LLMProbe(ReconProbe):
    """LLM endpoint discovery and fingerprinting probe.

    Filters MODEL_API endpoints from NetworkInterceptor results,
    analyzes response bodies for model fingerprints, and performs
    active probing for chat-shape classification, model list discovery,
    and OpenAPI spec parsing.

    Usage::
        probe = LLMProbe()
        result = await probe.probe(session)
        # result["llm_fingerprints"] -> model family/name/guardrail info
        # result["capabilities"] -> supports_streaming, supports_tools, etc.
    """

    def __init__(self, active_timeout: float = 10.0) -> None:
        self._active_timeout = active_timeout

    @property
    def name(self) -> str:
        return "LLMProbe"

    @property
    def requires_browser(self) -> bool:
        # LLMProbe 可以通过纯 HTTP 工作 (有 API Key 时),
        # 也可以通过浏览器工作 (LLM WebApp 时)
        # 不强制要求浏览器 — 会在 probe() 内根据 session 状态自适应
        return False

    async def probe(self, session: ReconSession) -> dict[str, Any]:
        """Execute LLM probe.

        Args:
            session: Recon session.

        Returns:
            Dict with llm_fingerprints, endpoints, and capabilities.
        """
        model_endpoints = [
            e for e in session.report.endpoints
            if e.endpoint_type == EndpointType.MODEL_API
        ]

        fingerprints: list[LLMFingerprint] = []
        seen_models: set[str] = set()
        capabilities: set[str] = set()

        for ep in model_endpoints:
            # Passive fingerprint from intercepted response body
            fp = self._fingerprint_endpoint(ep)
            if fp and fp.model_name and fp.model_name not in seen_models:
                seen_models.add(fp.model_name)
                fingerprints.append(fp)
                for cap in fp.capabilities:
                    capabilities.add(cap)

        # Active probing: chat-shape detection
        if model_endpoints:
            active_fps = await self._active_probe(model_endpoints, session)
            for fp in active_fps:
                if fp.model_name and fp.model_name not in seen_models:
                    seen_models.add(fp.model_name)
                    fingerprints.append(fp)
                for cap in fp.capabilities:
                    capabilities.add(cap)

        logger.info(
            "LLMProbe: fingerprinted %d models from %d model API endpoints, "
            "capabilities: %s",
            len(fingerprints), len(model_endpoints), sorted(capabilities),
        )

        return {
            "endpoints": model_endpoints,
            "llm_fingerprints": fingerprints,
            "capabilities": sorted(capabilities),
        }

    # ── Passive fingerprinting ──

    def _fingerprint_endpoint(self, endpoint: DiscoveredEndpoint) -> LLMFingerprint | None:
        """Extract model fingerprint from a single endpoint's response body."""
        body = endpoint.response_body_preview or ""
        if not body:
            return None

        model_family = "unknown"
        model_name = "unknown"

        # Extract model name from JSON response
        model_match = re.search(r'"model"\s*:\s*"([^"]+)"', body)
        if model_match:
            model_name = model_match.group(1)

        # Model family matching (longest match first)
        for keyword, family in _MODEL_FAMILY_PATTERNS:
            if keyword.lower() in body.lower() or keyword.lower() in model_name.lower():
                model_family = family
                if model_name == "unknown":
                    model_name = keyword
                break

        # Extract system prompt fragment
        system_prompt_hint = self._extract_system_prompt_hint(body)

        # Guardrail detection from body
        guardrail_detected = any(
            kw.lower() in body.lower() for kw in _GUARDRAIL_KEYWORDS
        )

        # Guardrail detection from headers
        headers_text = " ".join(endpoint.request_headers.keys())
        for pattern, _name in _GUARDRAIL_HEADER_PATTERNS:
            if pattern.search(headers_text):
                guardrail_detected = True
                break

        # AI signal catalog fallback for model family guessing
        if model_family == "unknown":
            model_ids = [model_name] if model_name != "unknown" else []
            if not model_ids:
                # Try to extract any model-like tokens from the body
                model_ids = [
                    seg for seg in re.findall(r'\b(gpt-\w+|claude-\w+|gemini-\w+|llama-\w+|mistral\w*|deepseek\w*|qwen\w*)', body, re.IGNORECASE)
                ]
            family_guess = guess_model_family(model_ids)
            if family_guess:
                model_family = family_guess

        # Chat-shape classification from body content
        caps: list[str] = []
        try:
            data = json.loads(body)
            shape = classify_ai_chat_response(data)
            if shape:
                caps.append(shape)
        except (json.JSONDecodeError, TypeError):
            pass

        # SSE detection from content-type
        if endpoint.content_type and "text/event-stream" in endpoint.content_type:
            caps.append("supports_streaming")

        return LLMFingerprint(
            model_family=model_family,
            model_name=model_name,
            system_prompt_hint=system_prompt_hint,
            capabilities=caps,
            guardrail_detected=guardrail_detected,
            endpoint=endpoint.url,
        )

    # ── Active probing ──

    async def _active_probe(
        self,
        model_endpoints: list[DiscoveredEndpoint],
        session: ReconSession,
    ) -> list[LLMFingerprint]:
        """Perform active probing against discovered model endpoints."""
        results: list[LLMFingerprint] = []

        # Build base URLs from discovered endpoints
        seen_bases: set[str] = set()
        base_urls: list[str] = []
        for ep in model_endpoints:
            from urllib.parse import urlparse
            parsed = urlparse(ep.url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            if base not in seen_bases:
                seen_bases.add(base)
                base_urls.append(base)

        headers = session.auth_headers if session.auth_state else {}
        async with httpx.AsyncClient(timeout=self._active_timeout, verify=False, follow_redirects=False) as client:
            for base_url in base_urls:
                # 1. Chat-shape probing
                for path in AI_CHAT_PROBE_PATHS[:5]:  # Limit to top 5 paths
                    fp = await self._probe_chat_shape(client, base_url, path, headers)
                    if fp:
                        results.append(fp)
                        break  # One successful chat-shape probe per base URL

                # 2. Model list discovery
                model_fps = await self._probe_model_list(client, base_url, headers)
                results.extend(model_fps)

                # 3. OpenAPI spec discovery
                spec_fp = await self._probe_openapi(client, base_url, headers)
                if spec_fp:
                    results.append(spec_fp)

        return results

    async def _probe_chat_shape(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        path: str,
        headers: dict[str, str],
    ) -> LLMFingerprint | None:
        """Probe a chat endpoint to classify its response shape."""
        url = f"{base_url.rstrip('/')}{path}"
        probe_body = {
            "model": "probe",
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 1,
        }

        try:
            resp = await client.post(url, json=probe_body, headers=headers)
            if resp.status_code in (200, 201):
                try:
                    data = resp.json()
                    shape = classify_ai_chat_response(data)
                    if shape:
                        capabilities = [shape]
                    else:
                        capabilities = []

                    # Extract model from response
                    model_name = data.get("model", "unknown")

                    # Check for streaming support
                    if resp.headers.get("content-type", "").startswith("text/event-stream"):
                        capabilities.append("supports_streaming")

                    return LLMFingerprint(
                        model_family=f"active-{shape}" if shape else "active-probe",
                        model_name=model_name,
                        capabilities=capabilities,
                        guardrail_detected=self._detect_guardrail_from_headers(resp.headers),
                        endpoint=url,
                    )
                except json.JSONDecodeError:
                    pass
            elif resp.status_code in (401, 422):
                # Still confirms OpenAI-compatible endpoint
                return LLMFingerprint(
                    model_family="OpenAI-compatible (confirmed via error)",
                    model_name="unknown",
                    capabilities=["openai-chat"],
                    guardrail_detected=False,
                    endpoint=url,
                )
        except (httpx.RequestError, asyncio.TimeoutError):
            pass

        return None

    async def _probe_model_list(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        headers: dict[str, str],
    ) -> list[LLMFingerprint]:
        """Probe model list endpoints."""
        results: list[LLMFingerprint] = []
        model_paths = ["/v1/models", "/models", "/api/tags"]

        for path in model_paths:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        model_ids: list[str] = []
                        # OpenAI format: {"data": [{"id": "gpt-4o"}, ...]}
                        if "data" in data:
                            for item in data["data"]:
                                if isinstance(item, dict) and "id" in item:
                                    model_ids.append(item["id"])
                        # Ollama format: {"models": [{"name": "llama3:8b"}, ...]}
                        elif "models" in data:
                            for item in data["models"]:
                                if isinstance(item, dict) and "name" in item:
                                    model_ids.append(item["name"])

                        family = guess_model_family(model_ids)
                        if family or model_ids:
                            return [LLMFingerprint(
                                model_family=family or "multi-model",
                                model_name=", ".join(model_ids[:5]),
                                capabilities=["model_list_discovered"],
                                endpoint=url,
                            )]
                    except json.JSONDecodeError:
                        pass
            except (httpx.RequestError, asyncio.TimeoutError):
                pass

        return results

    async def _probe_openapi(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        headers: dict[str, str],
    ) -> LLMFingerprint | None:
        """Probe OpenAPI/Swagger spec endpoints."""
        capabilities: list[str] = []

        for path in AI_OPENAPI_DISCOVERY_PATHS[:4]:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if "openapi" in data or "swagger" in data:
                            # Check for AI-specific endpoints in the spec
                            paths = data.get("paths", {})
                            for api_path in paths:
                                if any(kw in api_path.lower() for kw in ("chat", "completion", "embed", "model")):
                                    capabilities.append("supports_tools" if "tools" in str(paths[api_path]) else "openapi_discovered")
                                    break

                            if capabilities:
                                return LLMFingerprint(
                                    model_family="OpenAPI Spec",
                                    model_name="openapi",
                                    capabilities=capabilities,
                                    endpoint=url,
                                )
                    except json.JSONDecodeError:
                        pass
            except (httpx.RequestError, asyncio.TimeoutError):
                pass

        return None

    @staticmethod
    def _detect_guardrail_from_headers(headers: httpx.Headers) -> bool:
        """Detect guardrails from HTTP response headers."""
        headers_text = " ".join(headers.keys())
        for pattern, _name in _GUARDRAIL_HEADER_PATTERNS:
            if pattern.search(headers_text):
                return True
        return False

    @staticmethod
    def _extract_system_prompt_hint(body: str, max_length: int = 200) -> str:
        """Extract system prompt fragments from response body."""
        pattern = re.compile(
            r'"content"\s*:\s*"([^"]*(?:You are|你是一个|你是|I am|As an?|Your role is)[^"]*)"',
            re.IGNORECASE,
        )
        match = pattern.search(body)
        if match:
            hint = match.group(1)
            return hint[:max_length]
        return ""
