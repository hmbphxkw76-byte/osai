# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Token estimator probe — analyze token counting, pricing, and context limits.

Probes the target API to determine:
  1. Token counting behavior (how are tokens counted?)
  2. Context window size (max input tokens)
  3. Max output tokens
  4. Pricing information (if exposed in model list)
  5. Token usage in streaming vs non-streaming
  6. Per-request token budget estimation for attack planning

Architecture:
  - Input: auth_state + MODEL_API endpoints
  - Output: token_behavior, context_limits, cost_estimation
  - Browser: False
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import TYPE_CHECKING, Any

import httpx

from core.probes.base import ReconProbe

if TYPE_CHECKING:
    from core.session import ReconSession

logger = logging.getLogger(__name__)

# Approximate token counts for test strings (rough estimation: 1 token ≈ 4 chars English)
_TEST_STRINGS: list[tuple[str, str, int]] = [
    ("short", "hello", 1),
    ("medium", "The quick brown fox jumps over the lazy dog. " * 5, 45),
    ("long", "This is a test of the token counting system. " * 50, 500),
    ("very_long", "context window stress test. " * 500, 2500),
]


class TokenEstimatorProbe(ReconProbe):
    """Token counting and context limit estimation probe.

    Probes the target API to understand token counting behavior,
    context window limits, and provides attack planning data.

    Usage::
        probe = TokenEstimatorProbe()
        result = await probe.probe(session)
        # result["token_behavior"] -> token counting analysis
        # result["context_limits"] -> context window estimates
    """

    def __init__(self, timeout: float = 30.0) -> None:
        self._timeout = timeout

    @property
    def name(self) -> str:
        return "TokenEstimatorProbe"

    @property
    def requires_browser(self) -> bool:
        return False

    @property
    def requires_auth(self) -> bool:
        return True

    async def probe(self, session: ReconSession) -> dict[str, Any]:
        """Execute token estimation probe.

        Args:
            session: Recon session.

        Returns:
            Dict with token_behavior, context_limits, and model_info.
        """
        from urllib import parse as urlparse_mod

        from core.models.recon_report import EndpointType

        model_endpoints = [
            e for e in session.report.endpoints
            if e.endpoint_type == EndpointType.MODEL_API
        ]
        if not model_endpoints:
            return {"token_behavior": {}, "context_limits": {}, "model_info": {}}

        headers = session.auth_headers if session.auth_state else {}
        base_url = self._extract_base(model_endpoints[0].url)

        async with httpx.AsyncClient(timeout=self._timeout, verify=False) as client:
            # 1. Get model list for pricing/context info
            model_info = await self._get_model_info(client, base_url, headers)

            # 2. Estimate context window via binary search
            context_limits = await self._estimate_context_window(client, base_url, headers)

            # 3. Analyze token counting behavior
            token_behavior = await self._analyze_token_counting(client, base_url, headers)

        logger.info(
            "TokenEstimatorProbe: context_window≈%d, token_ratio=%.1f chars/token",
            context_limits.get("estimated_max_input_tokens", 0),
            token_behavior.get("chars_per_token_estimate", 0),
        )

        return {
            "token_behavior": token_behavior,
            "context_limits": context_limits,
            "model_info": model_info,
        }

    async def _get_model_info(
        self, client: httpx.AsyncClient, base_url: str, headers: dict[str, str]
    ) -> dict[str, Any]:
        """Get model information including pricing data."""
        info: dict[str, Any] = {"models": [], "pricing_available": False}

        for path in ("/v1/models", "/models"):
            url = f"{base_url.rstrip('/')}{path}"
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    models = data.get("data", data.get("models", []))
                    for model in models:
                        if isinstance(model, dict):
                            model_entry = {
                                "id": model.get("id", model.get("name", "unknown")),
                                "owned_by": model.get("owned_by", ""),
                            }
                            # Check for pricing info
                            if "pricing" in model:
                                model_entry["pricing"] = model["pricing"]
                                info["pricing_available"] = True
                            # Check for context window info
                            if "context_window" in model:
                                model_entry["context_window"] = model["context_window"]
                            if "max_tokens" in model:
                                model_entry["max_tokens"] = model["max_tokens"]
                            info["models"].append(model_entry)
                    break
            except Exception:
                pass

        return info

    async def _estimate_context_window(
        self, client: httpx.AsyncClient, base_url: str, headers: dict[str, str]
    ) -> dict[str, Any]:
        """Estimate context window size via binary search on input length."""
        url = f"{base_url.rstrip('/')}/v1/chat/completions"

        result: dict[str, Any] = {
            "estimated_max_input_tokens": 0,
            "estimated_max_input_chars": 0,
            "tested_at": 0,
            "method": "binary_search",
        }

        # Binary search for max input length
        low, high = 100, 200000  # chars
        tested = 0
        last_success = 0

        for _ in range(8):  # Max 8 iterations
            if low > high:
                break
            mid = (low + high) // 2
            test_text = "test " * (mid // 5)  # ~5 chars per token

            try:
                resp = await client.post(url, json={
                    "model": "probe",
                    "messages": [{"role": "user", "content": test_text}],
                    "max_tokens": 1,
                }, headers=headers)
                tested += 1

                if resp.status_code == 200:
                    last_success = mid
                    low = mid + 1000
                elif resp.status_code in (400, 413):
                    # Context too long
                    high = mid - 1000
                elif resp.status_code == 429:
                    # Rate limited — wait and retry
                    await asyncio.sleep(1)
                    continue
                else:
                    high = mid - 1000
            except Exception:
                high = mid - 1000

        result["tested_at"] = last_success
        result["estimated_max_input_chars"] = last_success
        # Rough token estimate: 1 token ≈ 4 chars English
        result["estimated_max_input_tokens"] = last_success // 4

        return result

    async def _analyze_token_counting(
        self, client: httpx.AsyncClient, base_url: str, headers: dict[str, str]
    ) -> dict[str, Any]:
        """Analyze token counting behavior by checking usage in responses."""
        url = f"{base_url.rstrip('/')}/v1/chat/completions"
        behavior: dict[str, Any] = {
            "token_counting_available": False,
            "chars_per_token_estimate": 0,
            "streaming_supported": False,
            "usage_samples": [],
        }

        for name, text, _ in _TEST_STRINGS:
            try:
                resp = await client.post(url, json={
                    "model": "probe",
                    "messages": [{"role": "user", "content": text}],
                    "max_tokens": 50,
                }, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    usage = data.get("usage", {})
                    if usage:
                        behavior["token_counting_available"] = True
                        prompt_tokens = usage.get("prompt_tokens", 0)
                        completion_tokens = usage.get("completion_tokens", 0)
                        total_tokens = usage.get("total_tokens", 0)

                        sample = {
                            "test_name": name,
                            "input_chars": len(text),
                            "prompt_tokens": prompt_tokens,
                            "completion_tokens": completion_tokens,
                            "total_tokens": total_tokens,
                        }
                        behavior["usage_samples"].append(sample)

                        if prompt_tokens > 0:
                            ratio = len(text) / prompt_tokens
                            if behavior["chars_per_token_estimate"] == 0:
                                behavior["chars_per_token_estimate"] = round(ratio, 1)
            except Exception:
                pass

        # Check streaming support
        try:
            resp = await client.post(url, json={
                "model": "probe",
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 10,
                "stream": True,
            }, headers=headers)
            if resp.status_code == 200 and "text/event-stream" in resp.headers.get("content-type", ""):
                behavior["streaming_supported"] = True
        except Exception:
            pass

        return behavior

    @staticmethod
    def _extract_base(url: str) -> str:
        """Extract base URL from endpoint URL."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
