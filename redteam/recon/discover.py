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
import random
import re
import time
from typing import Any, Callable, TYPE_CHECKING
from urllib.parse import urljoin, urlparse

from pathlib import Path

from redteam.core.http_client import send_get, send_post
from redteam.core.models import (
    AIProtocol, AIStackLayer, AIService, AuthContext,
)

if TYPE_CHECKING:
    from redteam.core.rate_limiter import RateLimitGovernor

_DEFAULT_WORDLIST_DIR = Path("config/wordlists")

_AI_PROBE_PATHS: list[tuple[str, str, list[str]]] = [
    # === P0: 核心对话端点 ===
    ("/api/tags", "ollama", ["models", "name", "ollama"]),
    ("/api/generate", "ollama", ["response", "model"]),
    ("/api/embeddings", "ollama", ["embedding", "data"]),
    ("/api/version", "ollama", ["version"]),
    ("/api/show", "ollama", ["model", "details"]),
    ("/v1/models", "openai_compatible", ["data", "id", "model"]),
    ("/v1/chat/completions", "openai_compatible", ["choices", "message"]),
    ("/v1/completions", "openai_compatible", ["choices", "text"]),
    ("/v1/embeddings", "openai_compatible", ["embedding", "data"]),
    ("/v1/chat/completions/stream", "openai_compatible", ["choices", "delta"]),
    # === P0: 多模态端点 ===
    ("/v1/audio/transcriptions", "openai_compatible", ["text", "language"]),
    ("/v1/audio/translations", "openai_compatible", ["text"]),
    ("/v1/audio/speech", "openai_compatible", ["audio"]),
    ("/v1/images/generations", "openai_compatible", ["url", "b64_json"]),
    ("/v1/vision", "openai_compatible", ["image", "content"]),
    # === P0: MCP 协议 ===
    ("/mcp", "mcp", ["server", "tools"]),
    ("/.well-known/mcp", "mcp", ["server"]),
    ("/mcp/sse", "mcp", ["sse"]),
    ("/sse", "mcp", ["event"]),
    # === P0: A2A 协议（含考试关键路径） ===
    ("/.well-known/agent.json", "agent_to_agent", ["agent", "name", "description", "skills"]),
    ("/.well-known/agent-card.json", "agent_to_agent", ["agent", "capabilities"]),
    ("/.a2a/agent-card", "agent_to_agent", ["agent", "capabilities"]),
    # === P1: SIEM/Kibana 检测 ===
    ("/app/kibana", "generic_ai", ["kibana", "elastic"]),
    ("/login", "generic_ai", ["kibana", "login"]),
    # === P1: 推理引擎特有端点 ===
    ("/generate", "vllm", ["text", "model"]),
    ("/generate_stream", "vllm", ["text"]),
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
    # === P1: Anthropic API ===
    ("/v1/messages", "anthropic", ["content", "type", "model"]),
    ("/v1beta/messages", "anthropic", ["content", "type"]),
    ("/v1/models", "anthropic", ["models", "name"]),
    # === P1: Gemini API ===
    ("/v1/models", "gemini", ["models", "name"]),
    ("/v1beta/models", "gemini", ["models", "name"]),
    ("/v1/generateContent", "gemini", ["candidates", "content"]),
    ("/v1beta/generateContent", "gemini", ["candidates", "content"]),
    # === P1: 向量数据库端点 ===
    ("/api/v1/collections", "vector_db", ["collections"]),
    ("/api/collections", "vector_db", ["collections"]),
    ("/v1/indexes", "vector_db", ["indexes"]),
    # === P1: AI 插件侦察 ===
    ("/ai-plugin.json", "ai_plugin", ["name", "description"]),
    ("/.well-known/ai-plugin.json", "ai_plugin", ["name", "description"]),
    # === P1: 实时通信端点 ===
    ("/ws", "websocket", ["websocket"]),
    ("/websocket", "websocket", ["websocket"]),
    ("/socket.io", "websocket", ["socket.io"]),
    ("/realtime", "websocket", ["realtime"]),
]

# P0 核心路径集合 — 分层探测时优先执行这些路径
_P0_PATHS: set[str] = {
    # Ollama 核心
    "/api/tags", "/api/generate", "/api/embeddings", "/api/version", "/api/show",
    # OpenAI 兼容核心
    "/v1/models", "/v1/chat/completions", "/v1/completions", "/v1/embeddings",
    "/v1/chat/completions/stream",
    # 多模态核心
    "/v1/audio/transcriptions", "/v1/audio/translations", "/v1/audio/speech",
    "/v1/images/generations", "/v1/vision",
    # MCP 协议核心
    "/mcp", "/.well-known/mcp", "/mcp/sse", "/sse",
    # A2A 协议核心
    "/.well-known/agent.json", "/.well-known/agent-card.json", "/.a2a/agent-card",
}

_DEFAULT_KEYWORDS: dict[str, list[str]] = {
    "ollama": ["models", "name", "ollama", "embedding", "version"],
    "openai_compatible": ["data", "id", "model", "choices", "message", "embedding", "delta", "audio", "url", "image"],
    "mcp": ["server", "tools", "sse", "event"],
    "gradio": ["gradio", "queue"],
    "comfyui": ["prompt", "workflow"],
    "flowise": ["flowise", "chat", "message"],
    "langserve": ["langserve", "playground"],
    "agent_to_agent": ["agent", "capabilities"],
    "anthropic": ["content", "type", "model", "anthropic"],
    "gemini": ["models", "name", "candidates", "content", "generationConfig"],
    "generic_ai": ["ok", "status", "openapi", "healthy", "health"],
    "vllm": ["text", "model", "generated_text", "vllm"],
    "vector_db": ["collections", "indexes", "vectors", "embeddings"],
    "ai_plugin": ["name", "description", "api", "auth", "permissions"],
    "websocket": ["websocket", "socket.io", "realtime", "upgrade"],
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

    # === MCP 协议 ===
    if any(k in path_lower for k in ("/mcp", "/sse", ".well-known/mcp")):
        return ("mcp", _DEFAULT_KEYWORDS["mcp"])

    # === SIEM/Kibana ===
    if any(k in path_lower for k in ("/kibana", "/elastic", "/_cat/", "/_search")):
        return ("generic_ai", _DEFAULT_KEYWORDS["generic_ai"])

    # === A2A 协议 ===
    if any(k in path_lower for k in ("agent.json", "agent-card", ".well-known/agent", ".a2a")):
        return ("agent_to_agent", _DEFAULT_KEYWORDS["agent_to_agent"])

    # === Ollama API ===
    if any(k in path_lower for k in ("/api/tags", "/api/generate", "/api/show",
                                       "/api/ps", "/api/version", "/api/create",
                                       "/api/copy", "/api/delete", "/api/pull",
                                       "/api/push", "/api/blobs", "/api/embeddings")):
        return ("ollama", _DEFAULT_KEYWORDS["ollama"])

    # === 推理引擎特有 ===
    if any(k in path_lower for k in ("/generate_stream", "/vllm")):
        return ("vllm", _DEFAULT_KEYWORDS["vllm"])

    # === 向量数据库 ===
    if any(k in path_lower for k in ("/api/v1/collections", "/api/collections",
                                       "/v1/indexes", "/api/vectors",
                                       "/chroma", "/pinecone", "/milvus",
                                       "/qdrant", "/weaviate", "/faiss")):
        return ("vector_db", _DEFAULT_KEYWORDS["vector_db"])

    # === AI 插件 ===
    if any(k in path_lower for k in ("/ai-plugin.json", ".well-known/ai-plugin",
                                       "/plugins/manifest.json")):
        return ("ai_plugin", _DEFAULT_KEYWORDS["ai_plugin"])

    # === WebSocket / 实时通信 ===
    if any(k in path_lower for k in ("/ws", "/websocket", "/socket.io",
                                       "/realtime", "/events", "/subscribe")):
        return ("websocket", _DEFAULT_KEYWORDS["websocket"])

    # === UI 框架 ===
    if "gradio" in path_lower or "/invocations" in path_lower:
        return ("gradio", _DEFAULT_KEYWORDS["gradio"])

    if "comfy" in path_lower:
        return ("comfyui", _DEFAULT_KEYWORDS["comfyui"])

    if "flowise" in path_lower:
        return ("flowise", _DEFAULT_KEYWORDS["flowise"])

    if "langserve" in path_lower or "/playground" in path_lower:
        return ("langserve", _DEFAULT_KEYWORDS["langserve"])

    # === Anthropic API ===
    if "/v1/messages" in path_lower or "/v1beta/messages" in path_lower:
        return ("anthropic", _DEFAULT_KEYWORDS["anthropic"])

    # === Gemini API ===
    if "/v1/generateContent" in path_lower or "/v1beta/generateContent" in path_lower:
        return ("gemini", _DEFAULT_KEYWORDS["gemini"])

    if any(k in path_lower for k in ("anthropic", "claude")):
        return ("anthropic", _DEFAULT_KEYWORDS["anthropic"])

    if any(k in path_lower for k in ("gemini", "google")):
        return ("gemini", _DEFAULT_KEYWORDS["gemini"])

    # === 安全相关 ===
    if any(k in path_lower for k in ("/security/", "/guardrails")):
        return ("generic_ai", _DEFAULT_KEYWORDS["generic_ai"])

    # === RAG 相关 ===
    if any(k in path_lower for k in ("knowledge", "knowledge-base", "/rag")):
        return ("generic_ai", _DEFAULT_KEYWORDS["generic_ai"])

    # === 健康检查/管理端点 ===
    if any(k in path_lower for k in ("/health", "/healthz", "/ready",
                                       "/readyz", "/live", "/livez",
                                       "/docs", "/redoc", "/openapi",
                                       "/swagger", "/api-docs",
                                       "/metrics", "/stats", "/info",
                                       "/debug", "/status", "/version",
                                       "/ping", "/robots", "/security")):
        return ("generic_ai", _DEFAULT_KEYWORDS["generic_ai"])

    # === OpenAI 兼容 ===
    if "/v1/" in path_lower or "/v1beta/" in path_lower:
        return ("openai_compatible", _DEFAULT_KEYWORDS["openai_compatible"])

    if any(k in path_lower for k in ("/embeddings", "/embedding", "/embed",
                                       "/rerank", "/completions", "/chat",
                                       "/audio/", "/images/", "/vision")):
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
    governor: "RateLimitGovernor | None" = None,
) -> dict[str, Any] | None:
    """探测单个 AI 端点路径。

    Args:
        base_url: 基础 URL
        path: 探测路径
        expected_protocol: 预期协议
        keywords: 匹配关键词列表
        auth: 认证上下文
        timeout: 超时时间
        governor: 自适应速率调速器（可选，控制请求速率）
    """
    url = urljoin(base_url, path)
    try:
        resp = send_get(url, auth=auth, timeout=timeout, governor=governor)
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
    if protocol == "vector_db":
        return AIStackLayer.INFRASTRUCTURE
    if protocol == "ai_plugin":
        return AIStackLayer.ORCHESTRATION
    if protocol == "websocket":
        return AIStackLayer.API
    if protocol in {"anthropic", "gemini", "vllm"}:
        return AIStackLayer.MODEL
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


def _estimate_recon_time(
    probe_count: int,
    concurrency: int = 3,
    timeout: float = 5.0,
    rate_limit_ms: int = 1000,
    stealth: bool = True,
    governor: "RateLimitGovernor | None" = None,
    target_url: str = "",
) -> float:
    """估算侦察阶段所需时间。

    Args:
        probe_count: 探测路径数量
        concurrency: 并发探测数
        timeout: 超时时间
        rate_limit_ms: 请求间隔
        stealth: 是否启用无痕模式
        governor: 自适应调速器（优先使用其安全速率）
        target_url: 目标 URL（用于查询调速器）

    Returns:
        预估时间（秒）
    """
    # 优先使用调速器的安全速率
    if governor and target_url:
        safe_rpm, has_limit = governor.get_safe_rate(target_url)
        if safe_rpm > 0:
            batch_time = (concurrency / safe_rpm) * 60
            batches = (probe_count + concurrency - 1) // concurrency
            return batches * batch_time * 1.2  # 20% 余量

    base_delay = rate_limit_ms / 1000.0 if rate_limit_ms else 0
    if stealth and base_delay == 0:
        base_delay = 1.0

    batches = (probe_count + concurrency - 1) // concurrency
    time_per_batch = max(timeout, base_delay)
    estimated_time = batches * time_per_batch * 1.5

    return estimated_time


def discover_ai_services(
    target: str,
    auth: AuthContext | None = None,
    concurrency: int = 3,
    timeout: float = 3.0,
    rate_limit_ms: int = 1000,
    enable_fingerprint: bool = True,
    stealth: bool = True,
    governor: "RateLimitGovernor | None" = None,
    layered: bool = True,
    early_exit_threshold: int = 30,
    progress_callback: Callable[[int, int, str], None] | None = None,
) -> list[AIService]:
    """主动 AI 攻击面发现：依次探测已知 AI 端点路径（无痕静默模式）。

    v2.3: 分层探测 + 进度回调 + 早期退出。
    - 分层探测：先 P0 核心路径（~23 个），发现 AI 服务后再扩展 P1/P2
    - 进度回调：实时报告探测进度
    - 早期退出：连续 N 个 404 后跳过剩余路径

    Args:
        target: 目标 URL
        auth: 认证上下文
        concurrency: 并发探测数（默认3，降低被检测风险）
        timeout: 超时时间（默认3.0s，侦察阶段不需要长超时）
        rate_limit_ms: 请求间隔（默认1000ms，governor 优先）
        enable_fingerprint: 是否启用模型指纹探测
        stealth: 是否启用无痕模式（浏览器伪装、随机延迟）
        governor: 自适应速率调速器（可选，优先于 rate_limit_ms）
        layered: 是否启用分层探测（P0 优先，发现 AI 服务后扩展）
        early_exit_threshold: 连续 404 阈值，超过后提前终止
        progress_callback: 进度回调函数 (done, total, phase_label)
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from redteam.recon.fingerprint import fingerprint_model
    from redteam.recon.rag_recon import probe_rag_pipeline

    services: list[AIService] = []
    seen_urls: set[str] = set()

    probes = _build_probe_list()

    # 分层探测：P0 核心路径优先
    if layered:
        p0_probes = [p for p in probes if p[0] in _P0_PATHS]
        p1_probes = [p for p in probes if p[0] not in _P0_PATHS]
        # 确保 P0 路径包含所有硬编码的 P0（即使词表中没有）
        probe_phases: list[tuple[list[tuple[str, str, list[str]]], str]] = [
            (p0_probes, "P0"),
            (p1_probes, "P1"),
        ]
    else:
        probe_phases = [(probes, "all")]

    total_probes = sum(len(phase[0]) for phase in probe_phases)

    # 估算时间（调速器优先）
    estimated_time = _estimate_recon_time(
        total_probes, concurrency, timeout, rate_limit_ms, stealth,
        governor=governor, target_url=target,
    )
    print(f"[info] 端点探测数: {total_probes} (P0: {len(probe_phases[0][0])}), "
          f"预估时间: {estimated_time:.1f} 秒 ({estimated_time/60:.1f} 分钟)")

    # ━━━ 调速器模式：延迟由 governor 在 send_get 中自动处理 ━━━
    use_governor = governor is not None

    # 手动延迟仅在没有 governor 时使用
    delay = rate_limit_ms / 1000.0 if rate_limit_ms and not use_governor else 0
    if stealth and delay == 0 and not use_governor:
        delay = random.uniform(0.5, 2.0)

    try:
        if delay and not use_governor:
            time.sleep(delay)
        resp = send_get(target, auth=auth, timeout=timeout, governor=governor)
        if resp:
            _classify_root_response(resp, target, services)
    except Exception:
        pass

    # ── 分层探测主循环 ──
    total_done = 0
    consecutive_404 = 0
    early_exit = False

    for phase_probes, phase_label in probe_phases:
        if not phase_probes or early_exit:
            continue

        # P1 阶段：如果 P0 未发现 AI 服务，跳过扩展探测
        if phase_label == "P1" and not services:
            print(f"    P0 阶段未发现 AI 服务，跳过 P1 扩展探测")
            continue

        for batch_start in range(0, len(phase_probes), concurrency):
            batch = phase_probes[batch_start:batch_start + concurrency]

            # 进度回调
            if progress_callback:
                current_path = batch[0][0] if batch else ""
                progress_callback(total_done, total_probes, f"{phase_label}: {current_path}")

            with ThreadPoolExecutor(max_workers=len(batch)) as executor:
                futures = {
                    executor.submit(probe_ai_endpoint, target, path, proto, keywords, auth, timeout, governor): (path, proto)
                    for path, proto, keywords in batch
                }
                for f in as_completed(futures):
                    total_done += 1
                    result = f.result()
                    if not result:
                        continue
                    if result["status"] == 404:
                        consecutive_404 += 1
                        if consecutive_404 >= early_exit_threshold:
                            early_exit = True
                            break
                        continue

                    # 非 404 响应，重置计数器
                    consecutive_404 = 0

                    if result["url"] in seen_urls:
                        continue
                    seen_urls.add(result["url"])

                    status = result["status"]
                    auth_required = status in (401, 403)
                    if status == 401:
                        auth_type = "bearer"
                    elif status == 403:
                        auth_type = "forbidden"
                    elif status == 200:
                        auth_type = "none"
                    elif status == 302 or status == 301:
                        auth_type = "redirect"
                    elif 500 <= status < 600:
                        auth_type = "error"
                    else:
                        auth_type = "unknown"

                    svc = AIService(
                        url=result["url"],
                        protocol=result["protocol"],
                        stack_layer=_map_protocol_to_layer(result["protocol"]),
                        auth_required=auth_required,
                        auth_type=auth_type,
                        raw_probe_response=result["body_preview"],
                    )

                    if result["is_json"]:
                        _parse_models_from_response(result["body_preview"], svc)

                    svc.tools = _detect_tools(result["body_preview"])
                    svc.system_prompt_hints = _detect_system_prompt_hints(result["body_preview"])

                    services.append(svc)

            # 早期退出检查
            if early_exit:
                print(f"    连续 {consecutive_404} 个 404，提前终止探测")
                break

            # 仅在无 governor 时手动延迟
            if not use_governor and delay and batch_start + concurrency < len(phase_probes):
                time.sleep(delay)

        # P0 阶段完成后的进度反馈
        if progress_callback and phase_label == "P0" and services:
            progress_callback(total_done, total_probes, f"P0 完成: 发现 {len(services)} 个服务 → P1")

    # 最终进度
    if progress_callback:
        progress_callback(total_done, total_probes, f"完成: 发现 {len(services)} 个服务")

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
        "cors_policy": {},
        "server_headers": {},
        "security_headers": {},
        "ai_plugin_discovery": [],
        "sitemap_entries": [],
        "wappalyzer_tech": [],
    }

    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    try:
        # === 1. robots.txt 分析 ===
        resp = send_get(f"{base}/robots.txt", timeout=timeout)
        if resp and resp["status"] == 200:
            for line in resp["body"].splitlines():
                for ai_path in ["/api/", "/mcp/", "/v1/", "/chat/", "/models/", "/tools/",
                                 "/embeddings", "/generate", "/inference", "/playground",
                                 "/admin", "/management", "/metrics", "/health"]:
                    if ai_path in line:
                        info["ai_endpoints_hint"].append(line.strip())

        # === 2. 主页响应分析 ===
        resp_root = send_get(base, timeout=timeout)
        if resp_root:
            # 技术头提取
            tech_headers = ["x-powered-by", "server", "x-frame-options", "x-gradio-version",
                            "x-vllm-version", "x-transformers-version", "x-openwebui-version",
                            "x-litellm-version", "x-langchain-version", "x-ollama-version"]
            for h in tech_headers:
                h_lower = h.lower()
                for header_name in resp_root["headers"]:
                    if header_name.lower() == h_lower:
                        info["tech_headers"][header_name] = resp_root["headers"][header_name]
                        break

            # CSP 策略分析
            csp = resp_root["headers"].get("content-security-policy", "")
            ai_domains = ["openai.com", "anthropic.com", "huggingface.co", "ollama", "vllm",
                          "langchain", "gradio", "comfyui", "flowise", "litellm", "pinecone",
                          "milvus", "chromadb", "qdrant", "weaviate"]
            for domain in ai_domains:
                if domain in csp:
                    info["csp_ai_hints"].append(domain)

            # CORS 策略分析
            cors_headers = ["access-control-allow-origin", "access-control-allow-methods",
                            "access-control-allow-headers", "access-control-expose-headers"]
            for h in cors_headers:
                h_lower = h.lower()
                for header_name in resp_root["headers"]:
                    if header_name.lower() == h_lower:
                        info["cors_policy"][header_name] = resp_root["headers"][header_name]
                        break

            # 安全头分析
            security_headers_list = ["strict-transport-security", "x-content-type-options",
                                     "x-xss-protection", "content-security-policy",
                                     "x-frame-options", "referrer-policy", "permissions-policy"]
            for h in security_headers_list:
                h_lower = h.lower()
                for header_name in resp_root["headers"]:
                    if header_name.lower() == h_lower:
                        info["security_headers"][header_name] = resp_root["headers"][header_name]
                        break

            # 服务器头分析
            server_headers_list = ["server", "x-powered-by", "x-server"]
            for h in server_headers_list:
                h_lower = h.lower()
                for header_name in resp_root["headers"]:
                    if header_name.lower() == h_lower:
                        info["server_headers"][header_name] = resp_root["headers"][header_name]
                        break

            # 页面内容技术指纹
            body_lower = resp_root["body"].lower()
            tech_patterns = {
                "gradio": "gradio",
                "comfyui": "comfyui",
                "flowise": "flowise",
                "langserve": "langserve",
                "ollama": "ollama",
                "vllm": "vllm",
                "litellm": "litellm",
                "openwebui": "openwebui",
                "streamlit": "streamlit",
                "chainlit": "chainlit",
            }
            for tech, pattern in tech_patterns.items():
                if pattern in body_lower:
                    info["wappalyzer_tech"].append(tech)

        # === 3. AI 插件发现 ===
        plugin_paths = ["/ai-plugin.json", "/.well-known/ai-plugin.json", "/plugins/manifest.json"]
        for plugin_path in plugin_paths:
            resp_plugin = send_get(f"{base}{plugin_path}", timeout=timeout)
            if resp_plugin and resp_plugin["status"] == 200:
                info["ai_plugin_discovery"].append({
                    "path": plugin_path,
                    "status": resp_plugin["status"],
                })

        # === 4. sitemap 分析 ===
        resp_sitemap = send_get(f"{base}/sitemap.xml", timeout=timeout)
        if resp_sitemap and resp_sitemap["status"] == 200:
            sitemap_content = resp_sitemap["body"]
            import re
            url_pattern = re.compile(r"<url><loc>([^<]+)</loc>")
            urls = url_pattern.findall(sitemap_content)
            for url in urls[:20]:
                info["sitemap_entries"].append(url)

        # === 5. .well-known 端点扫描 ===
        well_known_paths = [
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/.well-known/jwks.json",
            "/.well-known/security.txt",
            "/.well-known/mcp",
            "/.well-known/a2a/agent-card",
            "/.well-known/agent.json",           # AI-300 Ch4 考试关键路径
            "/.well-known/agent-card.json",      # 变体
        ]
        for wk_path in well_known_paths:
            resp_wk = send_get(f"{base}{wk_path}", timeout=timeout)
            if resp_wk and resp_wk["status"] == 200:
                info["ai_endpoints_hint"].append(f"{wk_path} (status: {resp_wk['status']})")

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


def probe_realtime_endpoints(
    target: str,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """探测实时通信端点（WebSocket和SSE）。

    Args:
        target: 目标 URL
        timeout: 超时时间

    Returns:
        探测结果字典，包含 websocket 和 sse 探测信息
    """
    from urllib.parse import urlparse

    result = {
        "websocket": [],
        "sse": [],
        "evidence": [],
    }

    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    ws_base = f"ws://{parsed.netloc}"
    wss_base = f"wss://{parsed.netloc}"

    websocket_paths = [
        "/ws",
        "/websocket",
        "/socket.io",
        "/socket.io/",
        "/realtime",
        "/stream",
        "/chat/ws",
        "/v1/chat/completions/ws",
        "/api/ws",
        "/ws/chat",
        "/ws/realtime",
        "/graphql/ws",
    ]

    sse_paths = [
        "/events",
        "/subscribe",
        "/stream",
        "/sse",
        "/v1/chat/completions",
        "/api/events",
        "/api/stream",
    ]

    # === WebSocket 握手探测 ===
    for path in websocket_paths:
        for scheme in [ws_base, wss_base]:
            ws_url = scheme + path
            try:
                import websocket as ws_client
                ws_client.setdefaulttimeout(timeout)
                ws = ws_client.create_connection(ws_url)
                result["websocket"].append({
                    "url": ws_url,
                    "status": "connected",
                    "protocol": ws.get_subprotocol() if hasattr(ws, 'get_subprotocol') else "unknown",
                })
                result["evidence"].append(f"WebSocket connected: {ws_url}")
                ws.close()
                break
            except ImportError:
                try:
                    import httpx
                    upgrade_headers = {
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                        "Sec-WebSocket-Version": "13",
                    }
                    with httpx.Client(timeout=timeout, verify=False) as client:
                        resp = client.get(ws_url.replace("ws://", "http://").replace("wss://", "https://"), headers=upgrade_headers)
                        if resp.status_code == 101:
                            result["websocket"].append({
                                "url": ws_url,
                                "status": "handshake_success",
                                "protocol": resp.headers.get("upgrade", "websocket"),
                            })
                            result["evidence"].append(f"WebSocket handshake: {ws_url}")
                except Exception:
                    pass
            except Exception:
                pass

    # === SSE 连接测试 ===
    for path in sse_paths:
        sse_url = base + path
        try:
            import httpx
            with httpx.Client(timeout=timeout, verify=False) as client:
                resp = client.get(sse_url, headers={"Accept": "text/event-stream"})
                if resp.status_code == 200:
                    content_type = resp.headers.get("content-type", "")
                    if "text/event-stream" in content_type or "stream" in content_type:
                        result["sse"].append({
                            "url": sse_url,
                            "status": "connected",
                            "content_type": content_type,
                            "data_preview": resp.text[:200] if resp.text else "",
                        })
                        result["evidence"].append(f"SSE connected: {sse_url}")
                    else:
                        result["sse"].append({
                            "url": sse_url,
                            "status": "http_200_not_streaming",
                            "content_type": content_type,
                        })
        except Exception:
            pass

    return result


__all__ = [
    "discover_ai_services",
    "probe_ai_endpoint",
    "passive_recon",
    "enum_protected_endpoints",
]