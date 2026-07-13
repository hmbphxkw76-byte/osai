"""AI 服务发现（AI-300 Ch2: Reconnaissance for AI Targets）。

实现 AI-300 课程中的主动和被动侦察技术：
  - 主动侦察：API 端点探测、模型枚举、工具发现
  - 被动侦察：HTTP 响应头、错误信息、CORS 策略、robots.txt
  - 401/404 端点枚举

对齐 AI-300 定义的五层 AI 组件栈：
  UI → API/Gateway → Orchestration(Agent/RAG) → Model(LLM/Embedding) → Infrastructure
"""
from __future__ import annotations

import json
import re
import time
from typing import Any
from urllib.parse import urljoin, urlparse

from pathlib import Path

from redteam.core.http_client import send_get, send_post
from redteam.core.models import (
    AIProtocol, AIStackLayer, AIService, AuthContext,
)

_DEFAULT_WORDLIST_DIR = Path("config/wordlists")

_AI_PROBE_PATHS: list[tuple[str, str, list[str]]] = [
    ("/api/tags", "ollama", ["models", "name", "ollama"]),
    ("/api/generate", "ollama", ["response", "model"]),
    ("/v1/models", "openai_compatible", ["data", "id", "model"]),
    ("/v1/chat/completions", "openai_compatible", ["choices", "message"]),
    ("/v1/embeddings", "openai_compatible", ["embedding", "data"]),
    ("/mcp", "mcp", ["server", "tools"]),
    ("/.well-known/mcp", "mcp", ["server"]),
    ("/mcp/sse", "mcp", ["sse"]),
    ("/sse", "mcp", ["event"]),
    ("/health", "generic_ai", ["ok", "healthy", "status"]),
    ("/docs", "generic_ai", ["openapi", "swagger"]),
    ("/redoc", "generic_ai", ["openapi"]),
    ("/openapi.json", "generic_ai", ["openapi", "paths"]),
    ("/playground", "langserve", ["langserve", "playground"]),
    ("/invocations", "gradio", ["gradio"]),
    ("/queue/join", "gradio", ["queue"]),
    ("/prompt", "comfyui", ["prompt", "workflow"]),
    ("/api/v1/prediction", "flowise", ["flowise"]),
    ("/api/v1/chat", "flowise", ["chat", "message"]),
    ("/.a2a/agent-card", "agent_to_agent", ["agent", "capabilities"]),
]

_DEFAULT_KEYWORDS: dict[str, list[str]] = {
    "ollama": ["models", "name", "ollama"],
    "openai_compatible": ["data", "id", "model", "choices", "message"],
    "mcp": ["server", "tools", "sse", "event"],
    "gradio": ["gradio", "queue"],
    "comfyui": ["prompt", "workflow"],
    "flowise": ["flowise", "chat", "message"],
    "langserve": ["langserve", "playground"],
    "agent_to_agent": ["agent", "capabilities"],
    "generic_ai": ["ok", "status", "openapi", "healthy", "health"],
}

_SYSTEM_PROMPT_HINTS: list[re.Pattern] = [
    re.compile(r"(?i)you\s+are\s+(?:a|an)\s+[\w\s]+(?:assistant|agent|bot|helper|expert)"),
    re.compile(r"(?i)(?:system\s+(?:prompt|instruction|message)|your\s+instructions?\s+(?:are|is))"),
    re.compile(r"(?i)(?:your\s+(?:role|task|job|function|purpose|goal)\s+(?:is|are))"),
    re.compile(r"(?i)(?:you\s+(?:should|must|need\s+to|always|never|can't|cannot))"),
    re.compile(r"(?i)(?:do\s+not\s+(?:reveal|disclose|share|tell|mention|discuss|expose))"),
    re.compile(r"(?i)(?:internal\s+(?:url|api|endpoint|database|credential|token|key))"),
    re.compile(r'(?i)(?:"[^"]{50,}"\s*(?:###|END|\\n|---))'),
]

_TOOL_CALL_PATTERNS: list[re.Pattern] = [
    re.compile(r'(?i)"(?:tool|function)_calls?"\s*:\s*\[', re.DOTALL),
    re.compile(r'(?i)"name"\s*:\s*"(exec|run|bash|shell|code|system|eval|command|cmd|python|node|curl|fetch|get|post|delete|put|read|write|search|query|database|sql|api|http)"'),
    re.compile(r"(?i)(?:available\s+(?:tools?|functions?):?\s*\[?\s*(?:\"|\')([\w_]+)(?:\"|\'))"),
]


def _load_ai_wordlist(wordlist_path: Path | str | None = None) -> list[str]:
    if wordlist_path is None:
        wordlist_path = _DEFAULT_WORDLIST_DIR / "ai_paths.txt"
    wordlist_path = Path(wordlist_path)

    if not wordlist_path.exists():
        return []

    paths: list[str] = []
    try:
        for line in wordlist_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith("/"):
                line = "/" + line
            if line not in paths:
                paths.append(line)
    except (OSError, UnicodeDecodeError):
        return []

    return paths


def _classify_path_heuristic(path: str) -> tuple[str, list[str]]:
    path_lower = path.lower()

    if any(k in path_lower for k in ("/mcp", "/sse", ".well-known/mcp")):
        return ("mcp", _DEFAULT_KEYWORDS["mcp"])

    if any(k in path_lower for k in ("agent-card", ".well-known/agent", ".a2a")):
        return ("agent_to_agent", _DEFAULT_KEYWORDS["agent_to_agent"])

    if any(k in path_lower for k in ("/api/tags", "/api/generate", "/api/show",
                                       "/api/ps", "/api/version", "/api/create",
                                       "/api/copy", "/api/delete", "/api/pull",
                                       "/api/push", "/api/blobs")):
        return ("ollama", _DEFAULT_KEYWORDS["ollama"])

    if "gradio" in path_lower or "/invocations" in path_lower:
        return ("gradio", _DEFAULT_KEYWORDS["gradio"])

    if "comfy" in path_lower:
        return ("comfyui", _DEFAULT_KEYWORDS["comfyui"])

    if "flowise" in path_lower:
        return ("flowise", _DEFAULT_KEYWORDS["flowise"])

    if "langserve" in path_lower or "/playground" in path_lower:
        return ("langserve", _DEFAULT_KEYWORDS["langserve"])

    if any(k in path_lower for k in ("/security/", "/guardrails")):
        return ("generic_ai", _DEFAULT_KEYWORDS["generic_ai"])

    if any(k in path_lower for k in ("knowledge", "knowledge-base", "/rag")):
        return ("generic_ai", _DEFAULT_KEYWORDS["generic_ai"])

    if any(k in path_lower for k in ("/health", "/healthz", "/ready",
                                       "/readyz", "/live", "/livez",
                                       "/docs", "/redoc", "/openapi",
                                       "/swagger", "/api-docs",
                                       "/metrics", "/stats", "/info",
                                       "/debug", "/status", "/version",
                                       "/ping", "/robots", "/security")):
        return ("generic_ai", _DEFAULT_KEYWORDS["generic_ai"])

    if "/v1/" in path_lower or "/v1beta/" in path_lower:
        return ("openai_compatible", _DEFAULT_KEYWORDS["openai_compatible"])

    if any(k in path_lower for k in ("/embeddings", "/embedding", "/embed",
                                       "/rerank")):
        return ("openai_compatible", _DEFAULT_KEYWORDS["openai_compatible"])

    if any(k in path_lower for k in ("/audio/", "/images/")):
        return ("openai_compatible", _DEFAULT_KEYWORDS["openai_compatible"])

    return ("generic_ai", _DEFAULT_KEYWORDS["generic_ai"])


def _build_probe_list(wordlist_path: Path | str | None = None) -> list[tuple[str, str, list[str]]]:
    wordlist_paths = _load_ai_wordlist(wordlist_path)

    if not wordlist_paths:
        return list(_AI_PROBE_PATHS)

    hardcoded_map: dict[str, tuple[str, list[str]]] = {
        path: (proto, list(kw))
        for path, proto, kw in _AI_PROBE_PATHS
    }

    probes: list[tuple[str, str, list[str]]] = []
    seen: set[str] = set()

    for path, proto, kw in _AI_PROBE_PATHS:
        if path not in seen:
            probes.append((path, proto, list(kw)))
            seen.add(path)

    for path in wordlist_paths:
        if path in seen:
            continue
        proto, kw = _classify_path_heuristic(path)
        probes.append((path, proto, kw))
        seen.add(path)

    return probes


def probe_ai_endpoint(
    base_url: str,
    path: str,
    expected_protocol: str,
    keywords: list[str],
    auth: AuthContext | None = None,
    timeout: float = 5.0,
) -> dict[str, Any] | None:
    """探测单个 AI 端点路径。"""
    url = urljoin(base_url, path)
    try:
        resp = send_get(url, auth=auth, timeout=timeout)
        if resp is None:
            return None

        body = resp["body"][:2000]
        content_type = resp["headers"].get("content-type", "")

        matched = [k for k in keywords if k.lower() in body.lower()]
        is_json = resp["is_json"] or body.strip().startswith("{") or body.strip().startswith("[")

        return {
            "url": url,
            "status": resp["status"],
            "protocol": expected_protocol,
            "matched_keywords": matched,
            "is_json": is_json,
            "content_type": content_type,
            "body_preview": body[:500],
            "headers": resp["headers"],
        }
    except Exception:
        return None


def _classify_root_response(r: dict, target: str, services: list[AIService]) -> None:
    body = r["body"][:2000]
    content_type = r["headers"].get("content-type", "")

    if "gradio" in body.lower() or "gr-box" in body:
        services.append(AIService(url=target, protocol=AIProtocol.GRADIO.value,
                                   stack_layer=AIStackLayer.UI))

    if "comfyui" in body.lower() or "comfy" in body.lower():
        services.append(AIService(url=target, protocol=AIProtocol.COMFYUI.value,
                                   stack_layer=AIStackLayer.UI))

    if "openai" in content_type or "openai" in str(r["headers"].get("server", "")):
        services.append(AIService(url=target, protocol=AIProtocol.OPENAI_COMPATIBLE.value,
                                   stack_layer=AIStackLayer.MODEL))


def _map_protocol_to_layer(protocol: str) -> AIStackLayer:
    agent_protocols = {"mcp", "agent_to_agent"}
    ui_protocols = {"gradio", "comfyui", "openwebui", "flowise"}
    if protocol in agent_protocols:
        return AIStackLayer.ORCHESTRATION
    if protocol in ui_protocols:
        return AIStackLayer.UI
    if protocol == "langserve":
        return AIStackLayer.API
    return AIStackLayer.MODEL


def _parse_models_from_response(body: str, svc: AIService) -> None:
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return

    if "data" in data and isinstance(data["data"], list):
        for item in data["data"]:
            if isinstance(item, dict) and "id" in item:
                svc.models.append(item["id"])

    if "models" in data:
        models = data["models"]
        if isinstance(models, list):
            for m in models:
                if isinstance(m, dict):
                    svc.models.append(m.get("name", m.get("model", str(m))))
                elif isinstance(m, str):
                    svc.models.append(m)

    svc.models = sorted(set(svc.models))


def _detect_tools(body: str) -> list[str]:
    tools: set[str] = set()
    for pattern in _TOOL_CALL_PATTERNS:
        matches = pattern.findall(body)
        if isinstance(matches, list):
            for m in matches:
                if isinstance(m, str) and len(m) < 50:
                    tools.add(m.strip())
    return sorted(tools)


def _detect_system_prompt_hints(body: str) -> list[str]:
    hints: list[str] = []
    for pattern in _SYSTEM_PROMPT_HINTS:
        for m in pattern.finditer(body):
            t = m.group(0)
            if len(t) > 10 and t not in hints:
                hints.append(t[:200])
    return hints[:5]


def discover_ai_services(
    target: str,
    auth: AuthContext | None = None,
    concurrency: int = 10,
    timeout: float = 5.0,
    rate_limit_ms: int = 0,
    enable_fingerprint: bool = True,
) -> list[AIService]:
    """主动 AI 攻击面发现：依次探测已知 AI 端点路径。"""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from redteam.recon.fingerprint import fingerprint_model
    from redteam.recon.rag_recon import probe_rag_pipeline

    services: list[AIService] = []
    seen_urls: set[str] = set()
    delay = rate_limit_ms / 1000.0 if rate_limit_ms else 0

    try:
        if delay:
            time.sleep(delay)
        resp = send_get(target, auth=auth, timeout=timeout)
        if resp:
            _classify_root_response(resp, target, services)
    except Exception:
        pass

    probes = _build_probe_list()

    for batch_start in range(0, len(probes), concurrency):
        batch = probes[batch_start:batch_start + concurrency]
        with ThreadPoolExecutor(max_workers=len(batch)) as executor:
            futures = {
                executor.submit(probe_ai_endpoint, target, path, proto, keywords, auth, timeout): (path, proto)
                for path, proto, keywords in batch
            }
            for f in as_completed(futures):
                result = f.result()
                if not result or result["status"] in (404,):
                    continue
                if result["url"] in seen_urls:
                    continue
                seen_urls.add(result["url"])

                svc = AIService(
                    url=result["url"],
                    protocol=result["protocol"],
                    stack_layer=_map_protocol_to_layer(result["protocol"]),
                    auth_required=result["status"] in (401, 403),
                    auth_type="bearer" if result["status"] == 401 else "none" if result["status"] == 200 else "unknown",
                    raw_probe_response=result["body_preview"],
                )

                if result["is_json"]:
                    _parse_models_from_response(result["body_preview"], svc)

                svc.tools = _detect_tools(result["body_preview"])
                svc.system_prompt_hints = _detect_system_prompt_hints(result["body_preview"])

                services.append(svc)

        if delay and batch_start + concurrency < len(probes):
            time.sleep(delay)

    deduped: dict[str, AIService] = {}
    for s in services:
        if s.protocol not in deduped or s.models:
            deduped[s.protocol] = s
    services = list(deduped.values())

    if enable_fingerprint:
        for svc in services:
            if svc.auth_required:
                continue

            if any(p in svc.url.lower() for p in ["chat/completions", "/chat", "/assistant", "/v1/"]):
                try:
                    svc.model_fingerprint = fingerprint_model(svc.url, auth, timeout, rate_limit_ms)
                except Exception:
                    pass

            try:
                svc.rag_pipeline = probe_rag_pipeline(svc.url, auth, timeout, rate_limit_ms)
            except Exception:
                pass

    return services


def passive_recon(target: str, timeout: float = 10.0) -> dict[str, Any]:
    """被动侦察：从 robots.txt、sitemap、HTTP 头等提取 AI 系统线索。"""
    info: dict[str, Any] = {
        "target": target,
        "ai_endpoints_hint": [],
        "tech_headers": {},
        "csp_ai_hints": [],
    }

    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    try:
        resp = send_get(f"{base}/robots.txt", timeout=timeout)
        if resp and resp["status"] == 200:
            for line in resp["body"].splitlines():
                for ai_path in ["/api/", "/mcp/", "/v1/", "/chat/", "/models/", "/tools/"]:
                    if ai_path in line:
                        info["ai_endpoints_hint"].append(line.strip())

        resp_root = send_get(base, timeout=timeout)
        if resp_root:
            ai_headers = ["x-powered-by", "server", "x-frame-options", "x-gradio-version"]
            for h in ai_headers:
                if h in resp_root["headers"]:
                    info["tech_headers"][h] = resp_root["headers"][h]

            csp = resp_root["headers"].get("content-security-policy", "")
            ai_domains = ["openai.com", "anthropic.com", "huggingface.co", "ollama", "vllm",
                          "langchain", "gradio", "comfyui", "flowise"]
            for domain in ai_domains:
                if domain in csp:
                    info["csp_ai_hints"].append(domain)

    except Exception:
        pass

    return info


def enum_protected_endpoints(
    target: str,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
    rate_limit_ms: int = 0,
) -> dict[str, Any]:
    """枚举需要认证的端点（AI-300 Ch2.3）。"""
    results = {
        "target": target,
        "endpoints_401": [],
        "endpoints_403": [],
        "endpoints_200": [],
        "endpoints_404": [],
        "total_probed": 0,
    }

    protected_paths = [
        "/api/v1/admin", "/api/v1/config", "/api/v1/models/secret",
        "/api/v1/embeddings/admin", "/api/v1/moderation/admin",
        "/admin", "/admin/api", "/management", "/api/admin",
        "/api/v1/users", "/api/v1/roles", "/api/v1/permissions",
        "/api/v1/audit", "/api/v1/logs", "/api/v1/health",
        "/api/v1/metrics", "/v1/models", "/v1/chat/completions",
        "/v1/completions", "/v1/embeddings", "/v1/audio/transcriptions",
        "/v1/images/generations", "/chat/api", "/assistant/api",
        "/llm/api", "/ai/api", "/models/api", "/realtime/api",
        "/stream/api", "/websocket/api", "/graphql", "/graphql/ai",
        "/.well-known/openai", "/.well-known/anthropic",
    ]

    delay = rate_limit_ms / 1000.0 if rate_limit_ms else 0

    for path in protected_paths:
        url = target.rstrip("/") + path
        try:
            if delay:
                time.sleep(delay)

            resp = send_get(url, auth=auth, timeout=timeout)
            if resp is None:
                continue

            results["total_probed"] += 1

            status = resp["status"]
            if status == 401:
                results["endpoints_401"].append({
                    "url": url,
                    "realm": resp["headers"].get("www-authenticate", ""),
                })
            elif status == 403:
                results["endpoints_403"].append(url)
            elif status == 200:
                results["endpoints_200"].append(url)
            elif status == 404:
                results["endpoints_404"].append(url)

        except Exception:
            continue

    return results


__all__ = [
    "discover_ai_services",
    "probe_ai_endpoint",
    "passive_recon",
    "enum_protected_endpoints",
]