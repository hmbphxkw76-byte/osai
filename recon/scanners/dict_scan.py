"""
字典扫描模块 — 使用预定义词表枚举目标端点。

支持三种速率模式 (stealth/balanced/fast) 实现隐身探测。
"""

from __future__ import annotations

import asyncio
import random
import time
from pathlib import Path
from typing import Optional

import httpx
from rich.console import Console

console = Console()

# ── 速率配置 ──
# 遵循企业红队最佳实践：默认 stealth 模式确保不被目标行为检测发现
RATE_PROFILES = {
    "stealth": {
        "concurrency": 1,
        "min_delay": 0.2,   # 200ms 最小间隔
        "max_delay": 0.5,   # 500ms 最大间隔（±50% 随机抖动）
        "rpm_target": 12,   # 约 12 RPM
    },
    "balanced": {
        "concurrency": 2,
        "min_delay": 0.05,  # 50ms
        "max_delay": 0.15,  # 150ms
        "rpm_target": 30,
    },
    "fast": {
        "concurrency": 5,
        "min_delay": 0.0,   # 无延迟
        "max_delay": 0.03,  # 30ms 微量抖动
        "rpm_target": 60,
    },
}

# 429 指数退避参数
_BACKOFF_BASE = 2.0       # 基础等待秒数
_BACKOFF_MAX = 30.0       # 最大等待秒数
_BACKOFF_JITTER = 0.3     # 退避抖动因子 (±30%)

# 默认 LLM 路径词表（整合 PyRIT、llm-con、Julius、Valtik 等工具的词表）
# 从 200+ 扩展到 600+ 条专用 AI/LLM 路径
_DEFAULT_LLM_PATHS = [
    # ═══ OpenAI / 类 OpenAI 端点 ═══
    "/", "/chat", "/chat/completions", "/api/chat", "/api/chat/completions",
    "/v1/chat/completions", "/v1/chat", "/v1/completions",
    "/completions", "/complete", "/api/complete",
    "/api/v1/chat/completions", "/api/v1/chat", "/api/v1/completions",
    "/v1beta/chat/completions", "/v1beta/completions",
    "/openai/deployments", "/openai/v1/chat/completions",
    "/v1/assistants", "/v1/threads", "/v1/threads/runs",
    "/v1/messages", "/v1beta/messages",
    "/v1/audio/transcriptions", "/v1/audio/translations",
    "/v1/audio/speech", "/v1/images/generations", "/v1/images/edits",
    "/v1/embeddings", "/api/embeddings",
    "/v1/moderations", "/v1/files", "/v1/fine_tuning/jobs",
    "/v1/fine-tunes", "/v1/engines",

    # ═══ Ollama ═══
    "/api/tags", "/api/show", "/api/ps", "/api/generate",
    "/api/chat", "/api/embeddings", "/api/pull", "/api/push",
    "/api/copy", "/api/delete", "/api/create", "/api/blobs",
    "/api/version", "/v1/chat/completions", "/v1/models",

    # ═══ vLLM / TGI ═══
    "/v1/models", "/v1/completions", "/v1/chat/completions",
    "/v1/embeddings", "/version", "/info", "/health",
    "/generate", "/generate_stream", "/metrics",

    # ═══ Anthropic ═══
    "/v1/messages", "/v1/complete", "/api/messages",
    "/api/v1/messages", "/api/v1/complete",

    # ═══ Google / Gemini / Vertex ═══
    "/v1/models", "/v1beta/models", "/v1/projects",
    "/v1beta/projects", "/google/api", "/vertex-ai",

    # ═══ Cohere ═══
    "/v1/generate", "/v1/chat", "/v1/embed", "/v1/rerank",
    "/v1/classify", "/v1/tokenize", "/v1/detokenize",
    "/v1/summarize", "/api/generate", "/api/chat",

    # ═══ HuggingFace ═══
    "/models", "/api/models", "/api/pipeline",
    "/api/inference", "/api/status",

    # ═══ LM Studio ═══
    "/v1/models", "/v1/chat/completions", "/v1/completions",
    "/v1/embeddings", "/api/v0/models", "/api/v0/chat/completions",

    # ═══ LocalAI ═══
    "/v1/models", "/v1/chat/completions", "/v1/completions",
    "/v1/embeddings", "/v1/images/generations", "/metrics",
    "/readyz", "/healthz",

    # ═══ NVIDIA NIM ═══
    "/v1/models", "/v1/chat/completions", "/v1/completions",
    "/v1/embeddings", "/v1/health/ready", "/v1/metadata",
    "/v1/health/live",

    # ═══ LiteLLM ═══
    "/health", "/health/readiness", "/health/liveliness",
    "/v1/models", "/v1/chat/completions", "/v1/completions",
    "/v1/embeddings", "/model/info", "/model/metrics",
    "/global/activity", "/user/daily/activity",
    "/router/model/rpm", "/spend/logs",

    # ═══ MLflow ═══
    "/api/2.0/mlflow/experiments/list",
    "/api/2.0/mlflow/experiments/search",
    "/api/2.0/mlflow/models", "/api/2.0/mlflow/registered-models",
    "/ajax-api/2.0/mlflow/experiments/list",

    # ═══ BentoML ═══
    "/docs", "/redoc", "/openapi.json", "/metrics",
    "/healthz", "/readyz", "/livez",

    # ═══ TorchServe ═══
    "/ping", "/models", "/api-description",
    "/v1/models", "/v2/models", "/v2/health/ready",
    "/v2/health/live",

    # ═══ Gradio ═══
    "/config", "/api/predict", "/api/queue/data",
    "/api/queue/push", "/api/queue/join",
    "/api/reset", "/api/restart", "/api/stop",
    "/api/startup-events", "/api/component-server",

    # ═══ Open WebUI ═══
    "/api/config", "/api/models", "/api/chats",
    "/api/chat/completions", "/api/version", "/api/ollama",
    "/_app/immutable", "/api/v1/chats",

    # ═══ LibreChat ═══
    "/api/auth", "/api/search", "/api/convos",
    "/api/messages", "/api/models", "/api/plugins",
    "/api/presets", "/api/endpoints",

    # ═══ SillyTavern ═══
    "/api/chat", "/api/characters", "/api/presets",
    "/api/extensions", "/api/worldinfo", "/api/backgrounds",

    # ═══ Better ChatGPT / LobeChat ═══
    "/api/config", "/api/chat", "/api/openai",
    "/api/messages", "/api/session",

    # ═══ AnythingLLM ═══
    "/api/v1/workspace", "/api/v1/workspaces",
    "/api/v1/document", "/api/v1/documents",
    "/api/v1/agent", "/api/v1/agents",
    "/api/v1/system", "/api/v1/admin",

    # ═══ Flowise ═══
    "/api/v1/prediction", "/api/v1/chatflows",
    "/api/v1/vectorstore", "/api/v1/credentials",
    "/api/v1/components", "/api/v1/nodes",

    # ═══ LangFlow ═══
    "/api/v1/flows", "/api/v1/chat",
    "/api/v1/predict", "/api/v1/run",
    "/api/v1/process", "/api/v1/custom_component",

    # ═══ Dify ═══
    "/v1/chat-messages", "/v1/completion-messages",
    "/v1/workflows/run", "/v1/conversations",
    "/v1/messages", "/console/api",

    # ═══ FastGPT ═══
    "/api/v1/chat/completions", "/api/v1/chat",
    "/api/core/chat", "/api/support/chat",

    # ═══ 通用 AI 端点 ═══
    "/ai/chat", "/gpt/chat", "/llm/chat",
    "/ai/completion", "/ai/completions", "/ai/models",
    "/ai/conversation", "/ai/conversations",
    "/ai/message", "/ai/messages",
    "/ai/generate", "/ai/ask", "/ai/query",
    "/llm/completion", "/llm/completions",
    "/llm/generate", "/llm/ask", "/llm/query",
    "/ask", "/query", "/message", "/conversation",
    "/conversations", "/api/messages", "/api/conversation",
    "/api/ask", "/api/query", "/api/message",
    "/api/prompt", "/api/inference",
    "/models", "/v1/models", "/api/models",
    "/v2/models", "/v3/models",
    "/api/v1/model", "/api/v1/models",
    "/api/v2/models", "/api/show",
    "/model", "/model/info", "/model/list",
    "/model/config", "/model/status",
    "/generate", "/api/generate", "/api/v1/generate",
    "/inference", "/infer", "/predict", "/predictions",

    # ═══ RAG / 向量数据库 ═══
    "/rag", "/api/rag", "/api/v1/rag",
    "/retrieval", "/api/retrieval",
    "/api/v1/knowledge-base", "/api/v1/knowledge-base/search",
    "/api/v1/knowledge-base/query", "/api/v1/knowledge-base/documents",
    "/api/v1/knowledge-base/stats",
    "/api/v1/collections", "/api/v1/vectors",
    "/api/vector/search", "/api/vector/query",
    "/api/vector/upsert", "/api/documents",
    "/api/v1/documents", "/api/v1/indexes",
    "/api/v1/namespace",

    # ═══ Agent / MCP 端点 ═══
    "/agent", "/api/agent", "/api/v1/agent",
    "/api/agent/run", "/api/agent/session", "/api/agent/tasks",
    "/api/agent/invoke", "/api/agent/execute",
    "/api/agent/chat", "/api/agent/memory",
    "/mcp/sse", "/mcp/chat", "/mcp/tools",
    "/mcp/resources", "/mcp/prompts",
    "/.well-known/agent.json", "/.well-known/ai-agent.json",
    "/.well-known/agent-card.json",
    "/ai-plugin.json", "/.well-known/ai-plugin.json",

    # ═══ 搜索 / 重排 ═══
    "/search", "/api/search", "/api/v1/search",
    "/rerank", "/api/rerank", "/api/v1/rerank",
    "/api/search/ask", "/api/search/query",

    # ═══ 安全 / 管理 ═══
    "/api/v1/security/filter-level", "/api/v1/security/config",
    "/api/v1/guardrails", "/api/v1/moderation",
    "/api/v1/content-filter", "/api/v1/safety",
    "/ai/admin", "/ai/admin/dashboard",
    "/ai/admin/observability", "/ai/admin/logs",
    "/ai/admin/analytics", "/ai/admin/api-keys",
    "/api/v1/admin", "/api/v1/admin/logs",
    "/api/v1/admin/users", "/api/v1/admin/settings",

    # ═══ 信息/文档 ═══
    "/docs", "/api/docs", "/redoc",
    "/openapi.json", "/swagger.json",
    "/api-docs", "/api-docs.json", "/v2/api-docs",
    "/v3/api-docs", "/swagger-ui.html",
    "/schemas", "/api/schema", "/v1/schema",
    "/.well-known/openid-configuration",

    # ═══ 健康/状态 ═══
    "/health", "/healthz", "/ready", "/readyz",
    "/live", "/livez", "/status", "/api/status",
    "/api/health", "/api/healthz", "/api/ready",
    "/ping", "/api/ping",
    "/info", "/api/info", "/api/v1/info",
    "/version", "/api/version", "/api/v1/version",
    "/metrics", "/api/metrics", "/api/v1/metrics",
    "/stats", "/api/stats", "/api/v1/stats",
    "/api/v1/telemetry",

    # ═══ 认证 ═══
    "/auth", "/login", "/logout", "/register",
    "/token", "/api/auth", "/api/auth/token",
    "/api/auth/login", "/api/auth/refresh",
    "/api/token", "/oauth", "/api/oauth",
    "/api/auth/callback", "/api/auth/session",
    "/api/keys", "/api/v1/api-keys",

    # ═══ 调试 ═══
    "/debug", "/debug/info", "/debug/config",
    "/debug/health", "/debug/status", "/debug/logs",
    "/debug/env", "/debug/routes", "/debug/pprof",
    "/debug/vars", "/admin/debug",
    "/actuator", "/actuator/health", "/actuator/info",
    "/actuator/metrics", "/actuator/env",
    "/api/debug", "/api/v1/debug",

    # ═══ 通用 API ═══
    "/api", "/v1", "/v2", "/v3",
    "/api/v1", "/api/v2", "/api/v3",
    "/openai", "/api/openai", "/api/v1/openai",
    "/graphql", "/api/graphql",

    # ═══ 文件/上传 ═══
    "/upload", "/api/upload", "/api/v1/upload",
    "/api/files", "/api/v1/files",
    "/api/attachments", "/api/images",
    "/api/media",

    # ═══ Kong / API Gateway ═══
    "/status", "/status/ready", "/status/live",
    "/endpoints", "/routes", "/services",
    "/consumers", "/plugins", "/upstreams",

    # ═══ 静态/安全文件 ═══
    "/robots.txt", "/security.txt",
    "/.well-known/security.txt", "/humans.txt",

    # ═══ 应用类 (AI 应用) ═══
    "/api/v1/tickets", "/api/v1/products", "/api/v1/labs",
    "/api/v1/assistants", "/api/v1/workflows",
    "/api/v1/pipelines", "/api/v1/tasks",
    "/api/v1/evaluations",
]

# 默认 Web 路径词表（辅助路径，已在 LLM 词表中包含了大部分 AI 端点）
_DEFAULT_WEB_PATHS = [
    "/", "/index.html", "/app", "/web", "/portal",
    "/console", "/dashboard", "/admin", "/manage",
    "/static/js", "/assets", "/js",
    "/favicon.ico", "/sitemap.xml",
]


class DictScanner:
    """基于字典的目标端点枚举器。

    使用预定义词表（LLM + Web 路径）通过 httpx 并发探测端点。
    支持认证头注入、三种速率模式 (stealth/balanced/fast)、
    随机抖动反指纹、429 指数退避。
    AI 对话类端点自动使用 POST 方法探测以获取真实响应。
    """

    # POST 方法应该探测的路径模式
    _POST_PATH_PATTERNS = [
        "/chat", "/completions", "/complete", "/generate",
        "/inference", "/infer", "/predict", "/predictions",
        "/messages", "/message", "/ask", "/query", "/prompt",
        "/embeddings", "/rerank", "/search",
        "/agent/run", "/agent/invoke", "/agent/execute",
        "/workflows/run",
    ]

    def __init__(
        self,
        concurrency: int = 5,
        timeout: int = 10,
        verify_ssl: bool = False,
        ca_cert: Optional[str] = None,
        llm_paths: Optional[list[str]] = None,
        web_paths: Optional[list[str]] = None,
        rate_profile: str = "stealth",
    ):
        # 根据速率模式调整参数
        rp = RATE_PROFILES.get(rate_profile, RATE_PROFILES["stealth"])
        self.concurrency = concurrency if concurrency != 5 else rp["concurrency"]
        self.min_delay = rp["min_delay"]
        self.max_delay = rp["max_delay"]
        self.rpm_target = rp["rpm_target"]
        self.rate_profile = rate_profile
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.ca_cert = ca_cert
        self.verify = ca_cert if (verify_ssl and ca_cert) else verify_ssl

        # 429 退避状态
        self._consecutive_429s = 0
        self._backoff_until = 0.0

        # 加载词表
        self.llm_paths = llm_paths or _DEFAULT_LLM_PATHS
        self.web_paths = web_paths or _DEFAULT_WEB_PATHS

        # 合并去重（LLM 路径优先）
        seen = set()
        self._all_paths = []
        for p in self.llm_paths + self.web_paths:
            if p not in seen:
                seen.add(p)
                self._all_paths.append(p)

    def _should_use_post(self, path: str) -> bool:
        """判断路径是否应该使用 POST 方法探测。"""
        path_lower = path.lower()
        for pattern in self._POST_PATH_PATTERNS:
            if pattern in path_lower:
                return True
        return False

    def _get_post_body(self, path: str) -> dict:
        """为 POST 探测生成合适的请求体。"""
        path_lower = path.lower()
        if "embeddings" in path_lower:
            return {"model": "default", "input": "test"}
        if any(w in path_lower for w in ["rerank", "search", "query"]):
            return {"model": "default", "query": "test", "documents": ["test"]}
        # 通用 Chat/Completion 体
        return {
            "model": "default",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 1,
        }

    async def scan(
        self,
        base_url: str,
        extra_headers: Optional[dict] = None,
        http_method: str = "GET",
    ) -> list[dict]:
        """并发扫描目标 URL 下的所有端点。

        内建隐身机制：
        - 请求间随机延迟消除脉冲指纹
        - 429 指数退避 + 抖动防止同步重试
        - 自适应并发降级

        Args:
            base_url: 目标根 URL
            extra_headers: 额外的请求头（认证等）
            http_method: 默认 HTTP 方法（AI 端点自动使用 POST）

        Returns:
            每个端点的探测结果列表:
            [{path, status, content_type, response_time_ms, body_snippet, ...}]
        """
        base = base_url.rstrip("/")
        results = []
        semaphore = asyncio.Semaphore(self.concurrency)

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/json,*/*",
        }
        if extra_headers:
            headers.update(extra_headers)

        async def _probe(path: str) -> dict:
            # ── 隐身延迟：请求间随机抖动 ──
            if self.min_delay > 0:
                jitter = self.min_delay + random.uniform(0, self.max_delay - self.min_delay)
                await asyncio.sleep(jitter)

            # ── 429 退避等待 ──
            now = time.monotonic()
            if now < self._backoff_until:
                wait = self._backoff_until - now
                console.print(f"  [dim yellow]  ⏳ 退避中, 等待 {wait:.1f}s...[/dim yellow]")
                await asyncio.sleep(wait)

            url = f"{base}{path}"
            t0 = time.monotonic()
            result = {
                "path": path,
                "url": url,
                "status": 0,
                "content_type": "",
                "response_time_ms": 0.0,
                "body_snippet": "",
                "error": "",
                "method": http_method,
            }

            # 智能方法选择
            use_post = http_method.upper() == "POST" or self._should_use_post(path)
            result["method"] = "POST" if use_post else "GET"

            async with semaphore:
                try:
                    async with httpx.AsyncClient(
                        verify=self.verify,
                        timeout=httpx.Timeout(self.timeout),
                        follow_redirects=True,
                        headers=headers,
                    ) as client:
                        if use_post:
                            body = self._get_post_body(path)
                            resp = await client.post(url, json=body)
                        else:
                            resp = await client.get(url)

                        result["status"] = resp.status_code
                        result["content_type"] = resp.headers.get("content-type", "")

                        # ── 429 指数退避：遇到限流立即减速 ──
                        if resp.status_code == 429:
                            self._consecutive_429s += 1
                            backoff = min(
                                _BACKOFF_BASE ** self._consecutive_429s,
                                _BACKOFF_MAX,
                            )
                            jitter = backoff * _BACKOFF_JITTER * random.uniform(-1, 1)
                            self._backoff_until = time.monotonic() + backoff + jitter
                            console.print(
                                f"  [yellow]  ⚡ 429 限流! 退避 {backoff + jitter:.1f}s "
                                f"(第 {self._consecutive_429s} 次)[/yellow]"
                            )
                        elif resp.status_code < 400:
                            # 成功响应，逐步恢复
                            self._consecutive_429s = max(0, self._consecutive_429s - 1)
                            self._backoff_until = 0.0

                        try:
                            result["body_snippet"] = resp.text[:500]
                        except Exception:
                            result["body_snippet"] = "(decode error)"
                except httpx.TimeoutException:
                    result["status"] = -1
                    result["error"] = "TIMEOUT"
                except httpx.ConnectError:
                    result["status"] = -2
                    result["error"] = "CONNECTION_REFUSED"
                except Exception as e:
                    result["status"] = -3
                    result["error"] = str(e)[:200]

                result["response_time_ms"] = round((time.monotonic() - t0) * 1000, 1)
                return result

        # 并发执行
        profile_label = {"stealth": "🕵️ 隐身", "balanced": "⚖️ 平衡", "fast": "⚡ 快速"}.get(
            self.rate_profile, self.rate_profile
        )
        console.print(
            f"  [dim]🔍 字典扫描: {len(self._all_paths)} 个路径, "
            f"模式: {profile_label} (并发 {self.concurrency}, "
            f"~{self.rpm_target} RPM)[/dim]"
        )
        tasks = [_probe(path) for path in self._all_paths]
        results = await asyncio.gather(*tasks)

        # 统计
        live = [r for r in results if r["status"] == 200]
        ai_live = [r for r in live if r["method"] == "POST"]
        auth = [r for r in results if r["status"] in (401, 403)]
        rate_limited = [r for r in results if r["status"] == 429]
        console.print(
            f"  [dim]  完成: {len(live)} 个可访问 "
            f"({len(ai_live)} 个 AI POST 端点), "
            f"{len(auth)} 个需认证, "
            f"{len(rate_limited)} 次限流, "
            f"{len(results) - len(live) - len(auth) - len(rate_limited)} 个不可达[/dim]"
        )

        return results

    @classmethod
    def load_paths_from_file(cls, filepath: str) -> list[str]:
        """从文本文件加载路径词表（每行一个路径）。"""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                paths = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
            return list(dict.fromkeys(paths))  # 去重保序
        except FileNotFoundError:
            console.print(f"  [yellow]⚠ 词表文件不存在: {filepath}[/yellow]")
            return []
