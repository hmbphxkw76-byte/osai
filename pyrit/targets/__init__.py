"""PyRIT Targets - 统一目标抽象层.

合并两套目标系统:
  - v3.0 HTTPTarget / TargetFactory / BaseTarget（orchestration 依赖）
  - pyrit-old load_env_config / SCENARIO_PRESETS / create_scorer_target（executor/entrypoint 依赖）

探测功能已迁移至 ai-recon 项目，通过 _recon_bridge 桥接。
"""

from __future__ import annotations

# ============================================================
# v3.0 core target classes (used by orchestration)
# ============================================================
# These are defined inline in this file to avoid merge conflicts
import json as _json
import logging as _logging
import time as _time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from schemas.target_models import TargetEndpoint, ModelInfo

_logger = _logging.getLogger(__name__)


# ---------- v3.0 Response & Base Target ----------

@dataclass
class TargetResponse:
    """目标响应."""
    text: str = ""
    status_code: int = 200
    latency_ms: float = 0.0
    tokens_used: int = 0
    raw: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


class BaseTarget(ABC):
    """目标抽象基类."""

    def __init__(self, endpoint: TargetEndpoint, model_info: Optional[ModelInfo] = None):
        self.endpoint = endpoint
        self.model_info = model_info or ModelInfo()
        self._total_calls = 0
        self._total_tokens = 0

    @abstractmethod
    async def send(self, prompt: str, **kwargs) -> TargetResponse:
        ...

    async def send_batch(self, prompts: list[str], **kwargs) -> list[TargetResponse]:
        results = []
        for p in prompts:
            results.append(await self.send(p, **kwargs))
        return results

    @property
    def stats(self) -> dict:
        return {
            "total_calls": self._total_calls,
            "total_tokens": self._total_tokens,
        }


# ---------- v3.0 HTTP Target ----------

class HTTPTarget(BaseTarget):
    """HTTP API 目标 (OpenAI-compatible format)."""

    def __init__(
        self,
        endpoint: Optional[TargetEndpoint] = None,
        model_info: Optional[ModelInfo] = None,
        api_key: str = "",
        timeout: int = 60,
    ):
        default_endpoint = endpoint or TargetEndpoint(
            url="http://localhost:8080/v1/chat/completions",
            headers={"Content-Type": "application/json"},
        )
        super().__init__(default_endpoint, model_info)
        self.api_key = api_key or (model_info.api_key if model_info else "")
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            headers = dict(self.endpoint.headers)
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                headers=headers,
            )
        return self._client

    async def send(self, prompt: str, system_prompt: str = "", **kwargs) -> TargetResponse:
        start = _time.time()
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model_info.model_name,
            "messages": messages,
            "max_tokens": kwargs.get("max_tokens", self.model_info.max_tokens),
            "temperature": kwargs.get("temperature", 0.7),
        }

        try:
            client = await self._get_client()
            response = await client.post(self.endpoint.url, json=payload)
            latency = (_time.time() - start) * 1000

            if response.status_code == 200:
                data = response.json()
                text = ""
                if "choices" in data:
                    text = data["choices"][0].get("message", {}).get("content", "")
                elif "response" in data:
                    text = data["response"]
                tokens = data.get("usage", {}).get("total_tokens", 0)
                self._total_calls += 1
                self._total_tokens += tokens
                return TargetResponse(
                    text=text, status_code=200, latency_ms=latency,
                    tokens_used=tokens, raw=data,
                )
            else:
                return TargetResponse(
                    status_code=response.status_code, latency_ms=latency,
                    error=f"HTTP {response.status_code}: {response.text[:200]}",
                )
        except Exception as e:
            return TargetResponse(latency_ms=(_time.time() - start) * 1000, error=str(e))

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None


# ---------- v3.0 Target Factory ----------

class TargetFactory:
    """目标工厂."""

    @staticmethod
    def create(model_info: ModelInfo) -> HTTPTarget:
        endpoint = TargetEndpoint(
            url=model_info.endpoint,
            headers={"Content-Type": "application/json"},
            timeout=60,
        )
        return HTTPTarget(endpoint=endpoint, model_info=model_info, api_key=model_info.api_key)

    @staticmethod
    def create_from_config(config: dict[str, Any]) -> HTTPTarget:
        model_info = ModelInfo(
            provider=config.get("provider", "openai"),
            model_name=config.get("model_name", "gpt-4o"),
            endpoint=config.get("endpoint", "http://localhost:8080/v1"),
            api_key=config.get("api_key", ""),
            api_version=config.get("api_version", ""),
            max_tokens=config.get("max_tokens", 4096),
        )
        return TargetFactory.create(model_info)


# ============================================================
# pyrit-old target exports (used by executor / entrypoint)
# ============================================================

try:
    from targets.config import load_env_config, load_target_preset, load_recon_preset
except ImportError:
    load_env_config = None  # type: ignore
    load_target_preset = None  # type: ignore
    load_recon_preset = None  # type: ignore

try:
    from targets.http_target import CustomHttpChatTarget
except ImportError:
    CustomHttpChatTarget = None  # type: ignore

try:
    from targets.openai_sdk_target import OpenAICompatibleTarget
except ImportError:
    OpenAICompatibleTarget = None  # type: ignore

try:
    from targets.gemini_target import GeminiTarget
except ImportError:
    GeminiTarget = None  # type: ignore

try:
    from targets.claude_target import ClaudeTarget
except ImportError:
    ClaudeTarget = None  # type: ignore

try:
    from targets.factories import create_scorer_target, create_attack_target
except ImportError:
    create_scorer_target = None  # type: ignore
    create_attack_target = None  # type: ignore

try:
    from targets.scenarios import SCENARIO_PRESETS, build_custom_target, register_scenario
except ImportError:
    SCENARIO_PRESETS = {}
    build_custom_target = None  # type: ignore
    register_scenario = None  # type: ignore

try:
    from targets._recon_bridge import (
        probe_model_info, ModelProbeResult, check_target_reachable,
        probe_target_type, TargetTypeResult, TargetType, generate_dynamic_prompts,
        auto_probe_target_model, auto_probe_target_type,
    )
except ImportError:
    probe_model_info = None  # type: ignore
    ModelProbeResult = None  # type: ignore
    check_target_reachable = None  # type: ignore
    probe_target_type = None  # type: ignore
    TargetTypeResult = None  # type: ignore
    TargetType = None  # type: ignore
    generate_dynamic_prompts = None  # type: ignore

try:
    from targets.target_builder import build_attack_target_from_args
except ImportError:
    build_attack_target_from_args = None  # type: ignore


__all__ = [
    # v3.0 core
    "TargetResponse", "BaseTarget", "HTTPTarget", "TargetFactory",
    # pyrit-old config
    "load_env_config", "load_target_preset", "load_recon_preset",
    # pyrit-old targets
    "CustomHttpChatTarget", "OpenAICompatibleTarget", "GeminiTarget", "ClaudeTarget",
    # pyrit-old factories
    "create_scorer_target", "create_attack_target",
    # pyrit-old scenarios
    "SCENARIO_PRESETS", "build_custom_target", "register_scenario",
    # pyrit-old recon bridge
    "probe_model_info", "ModelProbeResult", "check_target_reachable",
    "probe_target_type", "TargetTypeResult", "TargetType", "generate_dynamic_prompts",
    "auto_probe_target_model", "auto_probe_target_type",
    # pyrit-old target builder
    "build_attack_target_from_args",
]
