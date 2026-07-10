"""
===============================================================================
AI 侦测引擎 — 主动模型探测模块 (Model Probe)
===============================================================================
从 PyRIT targets/model_probe.py 提取并适配的核心探测能力。

在字典扫描后发现端点后，主动发送 AI 模型请求验证端点真假，
识别模型名称、框架类型、速率限制。

探测策略（按优先级降序）:
  1. OpenAI /v1/models   — GET {base}/v1/models     → 解析 data[].id
  2. OpenAI POST 探测     — POST {base} "Hi"         → 检查响应 model 字段
  3. Ollama /api/tags     — GET {base}/api/tags      → 解析 models[].name
  4. Raw POST 自我识别    — POST {base} "What model?" → 解析响应文本
  5. GET 页面信息抓取     — GET / /info /api         → 正则提取模型信息

返回结构:
  ModelProbeResult(
      model_name, strategy, confidence, endpoint_type,
      framework, discovered_endpoints, rate_limit_info, ...
  )

设计原则:
  ✅ 零依赖 — 仅用 httpx + re，无 PyRIT 内部模块依赖
  ✅ 异步探测
  ✅ 失败优雅降级 — 探测失败不阻塞后续流程
  ✅ 全自动，无需手动干预
===============================================================================
"""
from __future__ import annotations

import asyncio
import json
import random
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from recon.schema import EndpointType


# ── 速率配置（与 dict_scan.py 保持一致） ──
_RATE_PROFILES = {
    "stealth": {"concurrency": 1, "min_delay": 0.2, "max_delay": 0.5},
    "balanced": {"concurrency": 2, "min_delay": 0.05, "max_delay": 0.15},
    "fast": {"concurrency": 5, "min_delay": 0.0, "max_delay": 0.03},
}

# 429 指数退避参数
_BACKOFF_BASE = 2.0
_BACKOFF_MAX = 30.0
_BACKOFF_JITTER = 0.3


# ═══════════════════════════════════════════════════════════════
# 已知模型名称模式
# ═══════════════════════════════════════════════════════════════

_KNOWN_MODEL_PATTERNS = [
    # OpenAI
    r"gpt-[\d.]+[a-z-]*",
    r"o\d+[a-z-]*",
    # Anthropic
    r"claude-?[\d.]+[a-z-]*",
    # Google
    r"gemini-[\d.]+[a-z-]*",
    r"gemma-[\d.]+[a-z-]*",
    # Meta / Llama
    r"llama-?[\d.]+[a-z-]*",
    r"codellama-[\d.]+[a-z-]*",
    # Mistral
    r"mistral-[\w.-]+",
    r"mixtral-[\w.-]+",
    # DeepSeek
    r"deepseek-[\w.-]+",
    # 国产模型
    r"glm-[\w.-]+",
    r"qwen[\w.-]*",
    r"baichuan[\w.-]*",
    r"yi-[\w.-]+",
    r"ernie[\w.-]*",
    r"hunyuan[\w.-]*",
    r"minimax[\w.-]*",
    # 其他常见
    r"phi-[\d.]+[a-z-]*",
    r"falcon-[\w.-]+",
    r"command[\w.-]*",
    r"orca-[\w.-]+",
    r"vicuna-[\w.-]+",
    r"alpaca-[\w.-]+",
    r"wizardlm-[\w.-]*",
    r"zephyr-[\w.-]+",
    r"dolphin-[\w.-]+",
    r"openchat-[\w.-]+",
    r"neural-[\w.-]+",
    # 通用兜底
    r"[\w-]+-[\d.]+[a-z]*",
]

# ═══════════════════════════════════════════════════════════════
# 框架指纹库（20+ 种 AI 服务/框架）
# ═══════════════════════════════════════════════════════════════

_FRAMEWORK_FINGERPRINTS = {
    "openai": {
        "paths": ["/v1/models", "/v1/chat/completions", "/v1/completions"],
        "body_patterns": [r'"object"\s*:\s*"list"', r'"object"\s*:\s*"chat\.completion"'],
    },
    "ollama": {
        "paths": ["/api/tags", "/api/chat", "/api/generate"],
        "body_patterns": [r'"models"', r'"ollama"'],
    },
    "text-generation-webui": {
        "paths": ["/api/v1/model", "/api/v1/chat/completions"],
        "body_patterns": [r'"text-generation-webui"'],
    },
    "vllm": {
        "paths": ["/v1/models", "/health"],
        "body_patterns": [r'"vllm"', r'"engine"\s*:\s*"vllm"'],
    },
    "tgi": {
        "paths": ["/info", "/health", "/generate"],
        "body_patterns": [r'"text-generation-inference"', r'"tgi"', r'"huggingface"'],
    },
    "localai": {
        "paths": ["/v1/models", "/tts", "/image"],
        "body_patterns": [r'"localai"'],
    },
    "open-webui": {
        "paths": ["/api/chat", "/api/models", "/api/version"],
        "body_patterns": [r'"open-webui"', r'"open_webui"'],
    },
    "fastchat": {
        "paths": ["/v1/models", "/v1/chat/completions"],
        "body_patterns": [r'"vicuna"', r'"fastchat"'],
    },
    "flowise": {
        "paths": ["/api/v1/chatflows", "/api/v1/components", "/api/v1/flows"],
        "body_patterns": [r'"flowise"', r'"flowise-ui"'],
    },
    "langflow": {
        "paths": ["/api/v1/chat/completions", "/api/v1/process", "/api/v1/flows", "/api/v1/components"],
        "body_patterns": [r'"langflow"'],
    },
    "qdrant": {
        "paths": ["/collections", "/cluster", "/telemetry", "/v1/schema"],
        "body_patterns": [r'"qdrant"', r'"vector_size"', r'"collection_name"'],
    },
    "milvus": {
        "paths": ["/api/v1/collections", "/api/v1/health", "/metrics"],
        "body_patterns": [r'"milvus"', r'"pymilvus"'],
    },
    "weaviate": {
        "paths": ["/v1/schema", "/v1/nodes", "/v1/meta", "/v1/graphql", "/v1/explore"],
        "body_patterns": [r'"weaviate"', r'"graphql"'],
    },
    "chromadb": {
        "paths": ["/api/v1/collections", "/api/v1/heartbeat"],
        "body_patterns": [r'"chroma"'],
    },
    "anthropic": {
        "paths": ["/v1/messages", "/api/v1/messages", "/v1/complete"],
        "body_patterns": [r'"type"\s*:\s*"message"', r'"anthropic"', r'"claude"'],
    },
    "gemini": {
        "paths": ["/v1/models", "/v1beta/models", "/v1beta/chat"],
        "body_patterns": [r'"gemini"', r'"generativeai"', r'"generativelanguage"'],
    },
    "mcp-server": {
        "paths": ["/mcp/sse", "/mcp/chat", "/mcp/tools", "/mcp/prompts", "/mcp/resources"],
        "body_patterns": [r'"mcp"', r'"model-context-protocol"', r'"server_info"'],
    },
    "openai-plugin": {
        "paths": ["/.well-known/ai-plugin.json", "/ai-plugin.json"],
        "body_patterns": [r'"ai-plugin"', r'"openapi"'],
    },
    "crewai": {
        "paths": ["/api/agent/run", "/api/agent/session", "/api/agent/tasks"],
        "body_patterns": [r'"crewai"', r'"crew_ai"'],
    },
    "autogpt": {
        "paths": ["/api/agent/run", "/api/agent/execute"],
        "body_patterns": [r'"autogpt"', r'"auto-gpt"'],
    },
    "langfuse": {
        "paths": ["/api/public/health", "/api/v1/traces", "/api/v1/sessions", "/api/v1/scores"],
        "body_patterns": [r'"langfuse"'],
    },
    "arize-phoenix": {
        "paths": ["/api/v1/traces", "/api/v1/sessions"],
        "body_patterns": [r'"phoenix"', r'"arize"'],
    },
    "litellm": {
        "paths": ["/routes", "/user/new", "/key/generate", "/api/v1/keys"],
        "body_patterns": [r'"litellm"', r'"lite-llm"'],
    },
}

# ═══════════════════════════════════════════════════════════════
# 速率限制响应头解析
# ═══════════════════════════════════════════════════════════════

_RATE_LIMIT_HEADER_MAP = {
    "x-ratelimit-limit": "limit_requests",
    "x-ratelimit-remaining": "remaining_requests",
    "x-ratelimit-reset": "reset_timestamp",
    "ratelimit-limit": "limit_requests",
    "ratelimit-remaining": "remaining_requests",
    "ratelimit-reset": "reset_seconds",
    "x-ratelimit-limit-requests": "limit_requests",
    "x-ratelimit-remaining-requests": "remaining_requests",
    "x-ratelimit-reset-requests": "reset_seconds",
    "x-ratelimit-limit-tokens": "limit_tokens",
    "x-ratelimit-remaining-tokens": "remaining_tokens",
    "x-ratelimit-reset-tokens": "reset_seconds",
}

# ═══════════════════════════════════════════════════════════════
# 端点发现用路径列表
# ═══════════════════════════════════════════════════════════════

_ENDPOINT_DISCOVERY_PATHS = [
    "/v1/models", "/v1/chat/completions", "/v1/completions",
    "/v1/messages", "/v1/embeddings",
    "/models", "/api/models", "/api/tags", "/api/ps",
    "/api/version", "/api/chat", "/api/chat/completions",
    "/api/generate", "/api/v1/chat/completions", "/api/v1/chat",
    "/api/v1/model", "/api/v1/models",
    "/chat/completions", "/chat", "/completions",
    "/info", "/health", "/healthz", "/ready",
    "/status", "/version", "/ping",
    "/docs", "/openapi.json", "/swagger.json",
    "/api", "/v1", "/api/v1",
    "/.well-known/ai-plugin.json",
    "/debug/info", "/debug/config", "/debug/status",
    "/mcp/sse", "/mcp/chat", "/mcp/tools",
    "/api/agent/run", "/api/agent/session",
    "/api/v1/knowledge-base", "/api/v1/collections",
]

# ═══════════════════════════════════════════════════════════════
# Dataclass 定义
# ═══════════════════════════════════════════════════════════════

@dataclass
class ProbeRateLimitInfo:
    """从 HTTP 响应头中提取的速率限制信息"""
    header_source: str = ""
    limit_requests: Optional[int] = None
    remaining_requests: Optional[int] = None
    reset_seconds: Optional[float] = None
    reset_timestamp: Optional[int] = None
    limit_tokens: Optional[int] = None
    remaining_tokens: Optional[int] = None
    retry_after: Optional[int] = None
    raw_headers: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {}
        if self.limit_requests is not None: d["rpm_limit"] = self.limit_requests
        if self.remaining_requests is not None: d["rpm_remaining"] = self.remaining_requests
        if self.limit_tokens is not None: d["tpm_limit"] = self.limit_tokens
        if self.remaining_tokens is not None: d["tpm_remaining"] = self.remaining_tokens
        if self.reset_seconds is not None: d["reset_seconds"] = self.reset_seconds
        if self.retry_after is not None: d["retry_after"] = self.retry_after
        return d


@dataclass
class DiscoveredEndpoint:
    """发现的端点"""
    path: str = ""
    status: int = 0
    content_type: str = ""
    framework_hint: str = ""
    body_snippet: str = ""
    rate_limited: bool = False
    rate_limit_info: Optional[ProbeRateLimitInfo] = None
    response_time_ms: float = 0.0


@dataclass
class ModelProbeResult:
    """模型主动探测结果"""
    model_name: Optional[str] = None
    strategy: str = ""
    model_display_name: str = ""
    confidence: float = 0.0
    raw_info: dict = field(default_factory=dict)
    endpoint_type: str = EndpointType.UNKNOWN.value
    framework: str = "unknown"
    framework_confidence: str = "low"
    all_attempts: list[dict] = field(default_factory=list)
    discovered_endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    rate_limit_info: Optional[ProbeRateLimitInfo] = None
    recommended_concurrency: int = 3
    recommended_rpm: int = 30
    total_429s: int = 0
    avg_response_ms: float = 0.0
    errors: list[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════
# HTTP 工具函数
# ═══════════════════════════════════════════════════════════════

_BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "application/json,text/html,*/*",
}


async def _http_get(
    url: str,
    timeout: int = 10,
    verify_ssl: bool = False,
    extra_headers: Optional[dict] = None,
) -> tuple[int, any, dict]:
    """发送 GET 请求，返回 (status_code, response_data, headers)"""
    headers = dict(_BROWSER_HEADERS)
    if extra_headers:
        headers.update(extra_headers)
    try:
        async with httpx.AsyncClient(
            verify=verify_ssl,
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            headers=headers,
        ) as client:
            resp = await client.get(url)
            resp_headers = dict(resp.headers)
            try:
                data = resp.json()
            except (json.JSONDecodeError, ValueError):
                data = resp.text
            return resp.status_code, data, resp_headers
    except Exception as e:
        return 0, str(e), {}


async def _http_post(
    url: str,
    payload: dict,
    timeout: int = 15,
    verify_ssl: bool = False,
    extra_headers: Optional[dict] = None,
) -> tuple[int, any, dict]:
    """发送 POST JSON 请求，返回 (status_code, response_data, headers)"""
    headers = dict(_BROWSER_HEADERS)
    headers["Content-Type"] = "application/json"
    if extra_headers:
        headers.update(extra_headers)
    try:
        async with httpx.AsyncClient(
            verify=verify_ssl,
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            headers=headers,
        ) as client:
            resp = await client.post(url, json=payload)
            resp_headers = dict(resp.headers)
            try:
                data = resp.json()
            except (json.JSONDecodeError, ValueError):
                data = resp.text
            return resp.status_code, data, resp_headers
    except Exception as e:
        return 0, str(e), {}


# ═══════════════════════════════════════════════════════════════
# 5 种探测策略
# ═══════════════════════════════════════════════════════════════

async def _probe_openai_models(
    base_url: str, verify_ssl: bool = False
) -> Optional[dict]:
    """策略 1: GET /v1/models（OpenAI 兼容端点）"""
    paths_to_try = ["/v1/models", "/models", "/api/models"]

    parsed = urlparse(base_url)
    if parsed.path.rstrip("/").endswith("/v1"):
        paths_to_try = ["/models"] + paths_to_try

    for path in paths_to_try:
        url = urljoin(base_url, path)
        status, data, headers = await _http_get(url, timeout=10, verify_ssl=verify_ssl)

        if status == 200 and isinstance(data, dict):
            model_ids = []
            # OpenAI 格式: data[].id
            if "data" in data and isinstance(data["data"], list):
                for item in data["data"]:
                    if isinstance(item, dict) and "id" in item:
                        model_ids.append(item["id"])
            # Ollama 格式: models[].name (ollama 伪装 openai)
            if not model_ids and "models" in data and isinstance(data["models"], list):
                for item in data["models"]:
                    if isinstance(item, dict) and "name" in item:
                        model_ids.append(item["name"])

            if model_ids:
                return {
                    "model_name": model_ids[0],
                    "all_models": model_ids,
                    "strategy": "OpenAI /v1/models",
                    "confidence": 0.95,
                    "endpoint_type": EndpointType.OPENAI.value,
                    "raw": data,
                }
    return None


async def _probe_openai_post(
    base_url: str, verify_ssl: bool = False
) -> Optional[dict]:
    """策略 2: POST 发送 chat message，从响应提取模型名"""
    payload = {
        "model": "default",
        "messages": [{"role": "user", "content": "Hi"}],
        "max_tokens": 5,
    }

    candidates = [base_url]
    parsed = urlparse(base_url)
    if parsed.path in ("", "/"):
        candidates = [
            urljoin(base_url, "/v1/chat/completions"),
            urljoin(base_url, "/chat/completions"),
            base_url,
        ]

    for url in candidates:
        status, data, headers = await _http_post(url, payload, timeout=15, verify_ssl=verify_ssl)

        if status == 200 and isinstance(data, dict):
            model_name = None
            if "model" in data:
                model_name = data["model"]
            elif "choices" in data and isinstance(data["choices"], list):
                choice = data["choices"][0] if data["choices"] else {}
                if isinstance(choice, dict) and "model" in choice:
                    model_name = choice["model"]

            if model_name and model_name != "default":
                return {
                    "model_name": model_name,
                    "strategy": "OpenAI POST 探测",
                    "confidence": 0.90,
                    "endpoint_type": EndpointType.OPENAI.value,
                    "chat_url": url,
                    "raw": data,
                }

            # 返回 200 但没 model 名 — 至少确认了 chat 端点存在
            return {
                "model_name": None,
                "strategy": "OpenAI POST (模型名未知)",
                "confidence": 0.60,
                "endpoint_type": EndpointType.OPENAI.value,
                "chat_url": url,
                "raw": data,
            }
    return None


async def _probe_ollama_tags(
    base_url: str, verify_ssl: bool = False
) -> Optional[dict]:
    """策略 3: GET /api/tags（Ollama 端点）"""
    paths = ["/api/tags", "/api/ps", "/api/version"]

    for path in paths:
        url = urljoin(base_url, path)
        status, data, headers = await _http_get(url, timeout=10, verify_ssl=verify_ssl)

        if status == 200:
            if isinstance(data, dict):
                # /api/tags → {"models": [{"name": "llama3", ...}]}
                if "models" in data and isinstance(data["models"], list):
                    names = [
                        m["name"] for m in data["models"]
                        if isinstance(m, dict) and "name" in m
                    ]
                    if names:
                        return {
                            "model_name": names[0],
                            "all_models": names,
                            "strategy": "Ollama /api/tags",
                            "confidence": 0.95,
                            "endpoint_type": EndpointType.OLLAMA.value,
                            "raw": data,
                        }
                # /api/version → {"version": "..."}
                if "version" in data:
                    return {
                        "model_name": None,
                        "model_display_name": f"Ollama v{data['version']}",
                        "strategy": "Ollama /api/version",
                        "confidence": 0.85,
                        "endpoint_type": EndpointType.OLLAMA.value,
                        "raw": data,
                    }
                # /api/ps → {"models": [...]}
                if data.get("models"):
                    names = [
                        m.get("name", m.get("model", ""))
                        for m in data["models"]
                        if isinstance(m, dict)
                    ]
                    if names:
                        return {
                            "model_name": names[0],
                            "all_models": names,
                            "strategy": "Ollama /api/ps",
                            "confidence": 0.90,
                            "endpoint_type": EndpointType.OLLAMA.value,
                            "raw": data,
                        }
    return None


async def _probe_raw_self_identify(
    base_url: str, verify_ssl: bool = False
) -> Optional[dict]:
    """策略 4: POST 发送 "What model are you?" 自我识别"""
    prompts = [
        {"role": "user", "content": "What model are you? Reply with just your model name."},
        {"role": "user", "content": "你是什么模型？只回复模型名称。"},
        {"role": "user", "content": "hi"},
    ]

    candidates = [base_url]
    parsed = urlparse(base_url)
    if parsed.path in ("", "/"):
        candidates = [
            urljoin(base_url, "/v1/chat/completions"),
            urljoin(base_url, "/chat/completions"),
            urljoin(base_url, "/api/chat"),
            urljoin(base_url, "/chat"),
            base_url,
        ]

    for url in candidates:
        for prompt in prompts:
            payload = {"model": "default", "messages": [prompt], "max_tokens": 50}
            # 也用 Ollama 格式尝试
            ollama_payload = {"model": "default", "prompt": prompt["content"], "stream": False}

            for pld in [payload, ollama_payload]:
                status, data, headers = await _http_post(
                    url, pld, timeout=15, verify_ssl=verify_ssl
                )

                if status == 200:
                    # 提取响应文本
                    text = ""
                    if isinstance(data, dict):
                        # OpenAI 格式
                        choices = data.get("choices", [])
                        if choices and isinstance(choices[0], dict):
                            text = choices[0].get("message", {}).get("content", "")
                        # Ollama 格式
                        text = text or data.get("response", "")
                        text = text or data.get("message", {}).get("content", "")
                        # 通用字段
                        text = text or data.get("content", "") or data.get("text", "")
                        text = text or data.get("output", "")
                    elif isinstance(data, str):
                        text = data[:500]

                    # 用已知模式匹配模型名
                    model_name = _extract_model_from_text(text)
                    if model_name:
                        return {
                            "model_name": model_name,
                            "strategy": "Raw POST 自我识别",
                            "confidence": 0.70,
                            "endpoint_type": EndpointType.CUSTOM.value,
                            "chat_url": url,
                            "response_text": text[:200],
                            "raw": data,
                        }
    return None


async def _probe_get_info_page(
    base_url: str, verify_ssl: bool = False
) -> Optional[dict]:
    """策略 5: GET 根路径 / /info /api 抓取页面文本提取模型信息"""
    paths = ["/", "/info", "/api", "/health", "/version", "/status"]

    for path in paths:
        url = urljoin(base_url, path)
        status, data, headers = await _http_get(url, timeout=10, verify_ssl=verify_ssl)

        if status == 200:
            text = ""
            if isinstance(data, dict):
                text = json.dumps(data)
            elif isinstance(data, str):
                text = data

            if text:
                model_name = _extract_model_from_text(text)
                if model_name:
                    return {
                        "model_name": model_name,
                        "strategy": f"GET {path} 页面信息抓取",
                        "confidence": 0.50,
                        "endpoint_type": EndpointType.CUSTOM.value,
                        "discovery_url": url,
                        "snippet": text[:200],
                    }

                # 检测服务特征
                text_lower = text.lower()
                for hint in ["ollama", "vllm", "openai", "claude", "gemini",
                             "text-generation-webui", "oobabooga"]:
                    if hint in text_lower:
                        return {
                            "model_name": None,
                            "strategy": f"GET {path} 服务识别 → {hint}",
                            "confidence": 0.40,
                            "endpoint_type": (
                                EndpointType.OLLAMA.value if hint == "ollama"
                                else EndpointType.OPENAI.value
                            ),
                            "discovery_url": url,
                            "service_hint": hint,
                            "snippet": text[:200],
                        }
    return None


# ═══════════════════════════════════════════════════════════════
# 辅助函数
# ═══════════════════════════════════════════════════════════════

def _extract_model_from_text(text: str) -> Optional[str]:
    """从文本中用已知模式提取模型名称"""
    if not text or len(text) < 2:
        return None

    for pattern in _KNOWN_MODEL_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            name = match.group(0)
            if len(name) >= 3:
                return name
    return None


def _detect_framework(endpoints: list[DiscoveredEndpoint]) -> tuple[str, str]:
    """根据发现的端点 + 响应指纹推测 AI 服务框架"""
    found_paths = {e.path for e in endpoints if e.status in (200, 401, 403)}
    scores: dict[str, int] = {}

    for framework, fingerprint in _FRAMEWORK_FINGERPRINTS.items():
        score = 0
        for p in fingerprint["paths"]:
            if p in found_paths:
                score += 3  # 路径匹配权重
        for pattern in fingerprint["body_patterns"]:
            for ep in endpoints:
                if re.search(pattern, ep.body_snippet, re.IGNORECASE):
                    score += 5  # 响应体特征匹配权重更高
                    break
        if score > 0:
            scores[framework] = score

    if not scores:
        live_set = {e.path for e in endpoints if e.status == 200}
        if "/v1/models" in live_set or "/v1/chat/completions" in live_set:
            return "openai-compatible (vLLM/TGI/LocalAI)", "medium"
        if "/api/tags" in live_set or "/api/generate" in live_set:
            return "ollama", "high"
        return "unknown (custom API)", "low"

    best = max(scores, key=scores.get)
    if scores[best] >= 8:
        return best, "high"
    if scores[best] >= 5:
        return best, "medium"
    return f"possibly-{best} (weak match)", "low"


def _parse_duration_string(raw: str) -> Optional[float]:
    """解析 OpenAI 风格时长字符串 (7m12s, 1h30m, 60s, 500ms) → 秒"""
    pattern = re.compile(r"(\d+\.?\d*)\s*(h|m|s|ms)", re.IGNORECASE)
    total = 0.0
    found = False
    for match in pattern.finditer(raw):
        found = True
        value = float(match.group(1))
        unit = match.group(2).lower()
        if unit == "h":
            total += value * 3600
        elif unit == "m":
            total += value * 60
        elif unit == "s":
            total += value
        elif unit == "ms":
            total += value / 1000
    return total if found else None


def _parse_rate_limit_headers(headers: dict) -> Optional[ProbeRateLimitInfo]:
    """从 HTTP 响应头提取速率限制信息"""
    info: Optional[ProbeRateLimitInfo] = None

    for header_name, field_name in _RATE_LIMIT_HEADER_MAP.items():
        raw_value = headers.get(header_name)
        if raw_value is None:
            continue

        if info is None:
            info = ProbeRateLimitInfo()
            info.header_source = header_name

        try:
            parsed = float(raw_value.strip())
        except (ValueError, TypeError):
            parsed = _parse_duration_string(raw_value.strip())

        if parsed is not None:
            setattr(info, field_name, int(parsed) if field_name != "reset_seconds" else parsed)
            info.raw_headers[header_name] = raw_value

    # Retry-After
    retry_after = headers.get("retry-after")
    if retry_after is not None:
        if info is None:
            info = ProbeRateLimitInfo()
            info.header_source = "retry-after"
        try:
            info.retry_after = int(retry_after.strip())
        except ValueError:
            pass
        info.raw_headers["retry-after"] = str(retry_after)

    # reset_timestamp → reset_seconds
    if info is not None and info.reset_timestamp is not None and info.reset_seconds is None:
        info.reset_seconds = max(0.0, info.reset_timestamp - time.time())

    return info


# ═══════════════════════════════════════════════════════════════
# 端点发现
# ═══════════════════════════════════════════════════════════════

async def _discover_endpoints(
    base_url: str,
    verify_ssl: bool = False,
    timeout: int = 10,
    concurrency: int = 8,
    min_delay: float = 0.0,
    max_delay: float = 0.0,
) -> list[DiscoveredEndpoint]:
    """对目标进行端点枚举发现（隐身探测版）。

    特性：
    - 请求间随机抖动 (min_delay ~ max_delay) 消除脉冲指纹
    - 429 指数退避 + 抖动防止同步重试
    """
    base = base_url.rstrip("/")
    semaphore = asyncio.Semaphore(concurrency)
    results: list[DiscoveredEndpoint] = []

    # 429 退避状态（共享）
    consecutive_429s = [0]
    backoff_until = [0.0]

    async def _probe_one(path: str):
        # ── 隐身延迟 ──
        if min_delay > 0:
            jitter = min_delay + random.uniform(0, max_delay - min_delay)
            await asyncio.sleep(jitter)

        # ── 429 退避等待 ──
        now = time.monotonic()
        if now < backoff_until[0]:
            await asyncio.sleep(backoff_until[0] - now)

        async with semaphore:
            url = f"{base}{path}"
            t0 = time.monotonic()
            status, data, headers = await _http_get(url, timeout=timeout, verify_ssl=verify_ssl)
            elapsed_ms = (time.monotonic() - t0) * 1000

            # ── 429 指数退避 ──
            if status == 429:
                consecutive_429s[0] += 1
                backoff = min(_BACKOFF_BASE ** consecutive_429s[0], _BACKOFF_MAX)
                j = backoff * _BACKOFF_JITTER * random.uniform(-1, 1)
                backoff_until[0] = time.monotonic() + backoff + j
                console.print(
                    f"  [yellow]  ⚡ 429 限流! 退避 {backoff + j:.1f}s "
                    f"(第 {consecutive_429s[0]} 次)[/yellow]"
                )
            elif status < 400:
                consecutive_429s[0] = max(0, consecutive_429s[0] - 1)
                backoff_until[0] = 0.0

            body_snippet = ""
            if isinstance(data, dict):
                body_snippet = json.dumps(data)[:300]
            elif isinstance(data, str):
                body_snippet = data[:300]

            ep = DiscoveredEndpoint(
                path=path,
                status=status,
                content_type=headers.get("content-type", ""),
                body_snippet=body_snippet,
                rate_limited=(status == 429),
                rate_limit_info=_parse_rate_limit_headers(headers),
                response_time_ms=elapsed_ms,
            )
            results.append(ep)

    tasks = [_probe_one(path) for path in _ENDPOINT_DISCOVERY_PATHS]
    await asyncio.gather(*tasks, return_exceptions=True)

    return results


# ═══════════════════════════════════════════════════════════════
# 主入口
# ═══════════════════════════════════════════════════════════════

async def probe_model_info(
    target_url: str,
    api_key: str = "",
    timeout: int = 15,
    verify_ssl: bool = False,
    extra_auth_headers: Optional[dict] = None,
    enable_discovery: bool = True,
    discovery_concurrency: int = 8,
    rate_profile: str = "stealth",
) -> ModelProbeResult:
    """主动探测目标 AI 模型 — 主入口函数。

    流程:
      1. (可选) 端点枚举发现
      2. 按优先级执行 5 种探测策略
      3. 框架指纹识别
      4. 速率限制分析
      5. 返回结构化结果

    Args:
        target_url: 目标根 URL
        api_key: API key (当前版本保留，供扩展)
        timeout: 单次请求超时
        verify_ssl: 是否验证 SSL 证书
        extra_auth_headers: 额外认证头
        enable_discovery: 是否执行端点枚举
        discovery_concurrency: 端点枚举并发数
        rate_profile: 速率模式 (stealth/balanced/fast)

    Returns:
        ModelProbeResult — 完整的探测结果
    """
    base_url = target_url.rstrip("/")
    result = ModelProbeResult()

    # 根据速率模式确定参数
    rp = _RATE_PROFILES.get(rate_profile, _RATE_PROFILES["stealth"])
    eff_concurrency = rp["concurrency"] if discovery_concurrency == 8 else discovery_concurrency
    eff_min_delay = rp["min_delay"]
    eff_max_delay = rp["max_delay"]

    # Step 0: 端点枚举发现
    if enable_discovery:
        result.discovered_endpoints = await _discover_endpoints(
            base_url,
            verify_ssl=verify_ssl,
            timeout=timeout,
            concurrency=eff_concurrency,
            min_delay=eff_min_delay,
            max_delay=eff_max_delay,
        )

    # Step 1: 按优先级执行 5 种策略
    strategies = [
        ("OpenAI /v1/models 端点", _probe_openai_models),
        ("OpenAI POST 探测", _probe_openai_post),
        ("Ollama /api/tags 端点", _probe_ollama_tags),
        ("Raw POST 自我识别", _probe_raw_self_identify),
        ("GET 页面信息抓取", _probe_get_info_page),
    ]

    probe_args = {"verify_ssl": verify_ssl}

    for strategy_name, strategy_fn in strategies:
        try:
            probe_result = await strategy_fn(base_url, **probe_args)
        except Exception as e:
            result.errors.append(f"{strategy_name}: {e}")
            result.all_attempts.append({"strategy": strategy_name, "error": str(e)})
            continue

        if probe_result:
            result.all_attempts.append({
                "strategy": strategy_name,
                "result": probe_result.get("model_name", "N/A"),
                "confidence": probe_result.get("confidence", 0),
            })

            if probe_result.get("model_name"):
                result.model_name = probe_result["model_name"]
                result.strategy = strategy_name
                result.model_display_name = probe_result.get("model_display_name", probe_result["model_name"])
                result.confidence = probe_result.get("confidence", 0.0)
                result.endpoint_type = probe_result.get("endpoint_type", EndpointType.UNKNOWN.value)
                result.raw_info = probe_result
                break
            elif probe_result.get("confidence", 0) >= 0.60:
                # 没模型名但高置信度（如 Ollama version）
                result.strategy = strategy_name
                result.model_display_name = probe_result.get("model_display_name", "")
                result.confidence = probe_result.get("confidence", 0.0)
                result.endpoint_type = probe_result.get("endpoint_type", EndpointType.UNKNOWN.value)
                result.raw_info = probe_result
                break
        else:
            result.all_attempts.append({"strategy": strategy_name, "result": "no_match"})

    # Step 2: 框架指纹识别
    if result.discovered_endpoints:
        framework, fw_confidence = _detect_framework(result.discovered_endpoints)
        result.framework = framework
        result.framework_confidence = fw_confidence

    # Step 3: 速率限制分析
    total_429s = 0
    all_times = []
    best_rl: Optional[ProbeRateLimitInfo] = None

    for ep in result.discovered_endpoints:
        if ep.rate_limited:
            total_429s += 1
        if ep.response_time_ms > 0:
            all_times.append(ep.response_time_ms)
        if ep.rate_limit_info:
            if best_rl is None or (
                ep.rate_limit_info.limit_requests is not None and
                (best_rl.limit_requests is None or ep.rate_limit_info.limit_requests < best_rl.limit_requests)
            ):
                best_rl = ep.rate_limit_info

    result.total_429s = total_429s
    result.rate_limit_info = best_rl

    if all_times:
        result.avg_response_ms = sum(all_times) / len(all_times)

    # 推荐并发
    if best_rl and best_rl.limit_requests:
        result.recommended_rpm = max(1, int(best_rl.limit_requests * 0.5))
        result.recommended_concurrency = max(1, min(5, result.recommended_rpm // 10))
    elif result.avg_response_ms > 3000:
        result.recommended_concurrency = 1
        result.recommended_rpm = 10
    elif result.avg_response_ms > 1000:
        result.recommended_concurrency = 2
        result.recommended_rpm = 20
    else:
        result.recommended_concurrency = 5
        result.recommended_rpm = 30

    # 如果有 429，降级
    if total_429s > 0:
        result.recommended_concurrency = max(1, result.recommended_concurrency - total_429s)

    return result


def probe_to_summary(result: ModelProbeResult) -> dict:
    """将探测结果转换为可序列化的摘要 dict"""
    endpoints_summary = []
    for ep in result.discovered_endpoints:
        ep_dict = {
            "path": ep.path,
            "status": ep.status,
            "content_type": ep.content_type,
            "framework_hint": ep.framework_hint,
            "rate_limited": ep.rate_limited,
            "response_time_ms": round(ep.response_time_ms, 1),
        }
        if ep.body_snippet:
            ep_dict["body_snippet"] = ep.body_snippet[:100]
        if ep.rate_limit_info:
            ep_dict["rate_limit"] = ep.rate_limit_info.to_dict()
        endpoints_summary.append(ep_dict)

    return {
        "model_name": result.model_name,
        "model_display_name": result.model_display_name,
        "strategy": result.strategy,
        "confidence": round(result.confidence, 2),
        "endpoint_type": result.endpoint_type,
        "framework": result.framework,
        "framework_confidence": result.framework_confidence,
        "recommended_concurrency": result.recommended_concurrency,
        "recommended_rpm": result.recommended_rpm,
        "avg_response_ms": round(result.avg_response_ms, 1),
        "total_429s": result.total_429s,
        "endpoints_found": len(result.discovered_endpoints),
        "live_endpoints": sum(1 for e in result.discovered_endpoints if e.status == 200),
        "rate_limit": result.rate_limit_info.to_dict() if result.rate_limit_info else {},
        "discovered_endpoints": endpoints_summary,
        "all_attempts": result.all_attempts,
        "errors": result.errors,
    }
