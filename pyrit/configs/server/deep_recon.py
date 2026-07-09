"""
===============================================================================
Config Center — 深度侦察模块 (Deep Recon)
===============================================================================
针对 AI 安全训练靶机（AISecLab 等）的深度侦察能力：

  1. robots.txt 解析 — 提取靶机暴露的内部路径
  2. Debug 端点探测 — 扫描 /debug/* 端点
  3. 安全响应头分析 — CSP/HSTS/CORS/X-Frame-Options 等
  4. 多格式 API 探测 — 同时测试 OpenAI + Anthropic + Gemini 格式
  5. 知识库/向量存储探测 — RAG / ChromaDB / 知识库搜索端点
  6. 多级安全过滤探测 — 测试 AI 过滤器不同等级

设计原则:
  ✅ 异步探测（httpx），与项目整体架构一致
  ✅ 最小化侵入：独立模块，不修改现有探测流程
  ✅ 失败优雅降级：探测失败不阻塞后续流程
  ✅ 结构化输出，前端可直接渲染
===============================================================================
"""
from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import httpx

from utils.http_transport import create_http_client, API_HEADERS
from utils.target_url import normalize_target_url
from .probe_resilience import (
    AdaptiveTimeout,
    RateLimitTracker,
    classify_exception,
)

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class RobotsResult:
    """robots.txt 解析结果"""
    ok: bool
    disallowed_paths: list[str] = field(default_factory=list)
    allowed_paths: list[str] = field(default_factory=list)
    raw_rules: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class DebugEndpointResult:
    """Debug 端点探测结果"""
    url: str
    status: int = 0
    content_type: str = ""
    body_preview: str = ""
    sensitive_info: list[str] = field(default_factory=list)


@dataclass
class SecurityHeadersResult:
    """安全响应头分析结果"""
    headers: dict[str, str] = field(default_factory=dict)
    csp: str | None = None
    hsts: str | None = None
    x_frame_options: str | None = None
    x_content_type_options: str | None = None
    cors_headers: dict[str, str] = field(default_factory=dict)
    server: str = ""
    powered_by: str = ""
    risk_level: str = "info"  # low / medium / high / info
    findings: list[str] = field(default_factory=list)


@dataclass
class MultiFormatResult:
    """多格式 API 探测结果"""
    openai: dict | None = None
    anthropic: dict | None = None
    gemini: dict | None = None
    ollama: dict | None = None
    best_format: str = "unknown"
    suggestion: str = ""
    # 🆕 限流信息（探测过程中触发的 429 次数 / Retry-After）
    rate_limit_info: dict = field(default_factory=dict)


@dataclass
class KnowledgeBaseResult:
    """知识库/向量存储探测结果"""
    found_endpoints: list[dict] = field(default_factory=list)
    chromadb_detected: bool = False
    rag_detected: bool = False
    vector_db_type: str = "unknown"
    document_count: int | None = None
    collection_names: list[str] = field(default_factory=list)


@dataclass
class DeepReconResult:
    """深度侦察聚合结果"""
    ok: bool
    robots: RobotsResult | None = None
    debug_endpoints: list[DebugEndpointResult] = field(default_factory=list)
    security_headers: SecurityHeadersResult | None = None
    multi_format: MultiFormatResult | None = None
    knowledge_base: KnowledgeBaseResult | None = None
    summary: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


# ═══════════════════════════════════════════════════════════════════════════
# 路径字典
# ═══════════════════════════════════════════════════════════════════════════

# Debug 端点（常见于 AI 安全训练平台 / 开发环境）
_DEBUG_PATHS = [
    "/debug",
    "/debug/info",
    "/debug/config",
    "/debug/health",
    "/debug/status",
    "/debug/logs",
    "/debug/trace",
    "/debug/profile",
    "/debug/env",
    "/debug/routes",
    "/debug/endpoints",
    "/debug/tokens",
    "/debug/sessions",
    "/debug/users",
    "/admin/debug",
    "/api/debug",
    "/api/v1/debug",
    "/internal/debug",
    "/.debug",
    "/phpinfo.php",        # 遗留
    "/info.php",
    "/actuator",           # Spring Boot Actuator
    "/actuator/health",
    "/actuator/info",
    "/actuator/env",
    "/actuator/configprops",
    "/actuator/mappings",
]

# RAG / 知识库检索端点
_KNOWLEDGE_BASE_PATHS = [
    "/api/v1/knowledge-base",
    "/api/v1/knowledge-base/search",
    "/api/v1/knowledge-base/query",
    "/api/v1/knowledge-base/documents",
    "/api/v1/knowledge-base/stats",
    "/api/knowledge/search",
    "/api/knowledge/query",
    "/api/rag/search",
    "/api/rag/query",
    "/api/search",
    "/search",
    "/api/v1/search",
    "/query",
    "/api/query",
    "/api/v1/retrieval",
    "/retrieval",
    "/api/v1/semantic-search",
    "/api/v1/hybrid-search",
    # ChromaDB
    "/api/v1/collections",
    "/api/v1/collections/names",
    "/api/v1/heartbeat",
    "/api/v1/version",
    "/api/v1/pre-flight-checks",
    # Weaviate
    "/v1/schema",
    "/v1/meta",
    "/v1/nodes",
    # Qdrant
    "/collections",
    "/dashboard",
    "/telemetry",
]

# Anthropic Messages API 探测路径
_ANTHROPIC_PROBE_PATHS = [
    "/v1/messages",
    "/api/v1/messages",
    "/api/messages",
    "/messages",
]

# Gemini API 探测路径
_GEMINI_PROBE_PATHS = [
    "/v1/models",
    "/v1beta/models",
    "/api/v1/models",
    "/api/v1beta/models",
    "/v1/chat",
    "/api/v1/chat",
]

# 安全级别过滤路径 (AISecLab 特有: filter_level 1-5)
_FILTER_LEVEL_PATHS = [
    "/api/v1/chat/completions?filter_level=1",
    "/api/v1/chat/completions?filter_level=2",
    "/api/v1/chat/completions?filter_level=3",
    "/api/v1/chat/completions?filter_level=4",
    "/api/v1/chat/completions?filter_level=5",
]


# ═══════════════════════════════════════════════════════════════════════════
# robots.txt 解析
# ═══════════════════════════════════════════════════════════════════════════

async def parse_robots_txt(
    base_url: str,
    timeout: float = 8.0,
    verify_ssl: bool = False,
    api_key: str = "",
    extra_headers: dict[str, str] | None = None,
) -> RobotsResult:
    """拉取并解析目标站点的 robots.txt。

    AISecLab 等训练平台常通过 robots.txt 列出内部调试路径，
    红队利用此信息可快速发现隐藏端点。
    """
    try:
        nurl = normalize_target_url(base_url)
        robots_url = urljoin(nurl.full_url, "/robots.txt")

        headers = dict(API_HEADERS)
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        if extra_headers:
            headers.update(extra_headers)

        async with create_http_client(
            verify_ssl=verify_ssl, timeout=timeout, headers=headers,
            follow_redirects=True, max_redirects=3,
        ) as client:
            resp = await client.get(robots_url)

        if resp.status_code != 200:
            return RobotsResult(
                ok=False,
                error=f"robots.txt 不存在或无法访问 (HTTP {resp.status_code})",
            )

        content = resp.text.strip()
        if not content:
            return RobotsResult(ok=False, error="robots.txt 内容为空")

        result = _parse_robots_content(content)
        result.ok = True
        return result

    except httpx.ConnectError as e:
        return RobotsResult(ok=False, error=f"连接失败: {e}")
    except Exception as e:
        logger.exception("robots.txt 解析异常")
        return RobotsResult(ok=False, error=str(e)[:300])


def _parse_robots_content(content: str) -> RobotsResult:
    """解析 robots.txt 内容，提取 Disallow/Allow 规则。"""
    result = RobotsResult(ok=True)

    current_agent = "*"
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # User-agent 声明
        m = re.match(r"^(?i)User-agent\s*:\s*(.+)", line)
        if m:
            current_agent = m.group(1).strip()
            continue

        # 只收集所有 user-agent 的规则
        m = re.match(r"^(?i)Disallow\s*:\s*(.+)", line)
        if m:
            path = m.group(1).strip()
            result.raw_rules.append(f"Disallow: {path}")
            if path and path != "/":
                result.disallowed_paths.append(path)
            continue

        m = re.match(r"^(?i)Allow\s*:\s*(.+)", line)
        if m:
            path = m.group(1).strip()
            result.raw_rules.append(f"Allow: {path}")
            if path:
                result.allowed_paths.append(path)
            continue

        m = re.match(r"^(?i)Sitemap\s*:\s*(.+)", line)
        if m:
            result.raw_rules.append(f"Sitemap: {m.group(1).strip()}")
            continue

    return result


# ═══════════════════════════════════════════════════════════════════════════
# Debug 端点探测
# ═══════════════════════════════════════════════════════════════════════════

async def probe_debug_endpoints(
    base_url: str,
    timeout: float = 5.0,
    verify_ssl: bool = False,
    api_key: str = "",
    extra_headers: dict[str, str] | None = None,
    concurrency: int = 5,
) -> list[DebugEndpointResult]:
    """扫描常见 debug/admin 端点，识别敏感信息泄露。"""
    nurl = normalize_target_url(base_url)
    results: list[DebugEndpointResult] = []

    headers = dict(API_HEADERS)
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    if extra_headers:
        headers.update(extra_headers)

    import asyncio as _asyncio

    async def _probe_one(path: str) -> DebugEndpointResult:
        url = urljoin(nurl.full_url, path)
        try:
            async with create_http_client(
                verify_ssl=verify_ssl,
                timeout=min(timeout, 4.0),
                headers=headers,
                follow_redirects=True,
                max_redirects=3,
            ) as client:
                resp = await client.get(url)
            body = resp.text[:2000]
            sensitive = _detect_sensitive_in_body(body, resp.headers.get("content-type", ""))
            return DebugEndpointResult(
                url=url,
                status=resp.status_code,
                content_type=resp.headers.get("content-type", ""),
                body_preview=body[:300],
                sensitive_info=sensitive,
            )
        except Exception as e:
            return DebugEndpointResult(
                url=url,
                status=0,
                sensitive_info=[f"请求失败: {str(e)[:100]}"],
            )

    sem = _asyncio.Semaphore(concurrency)

    async def _bounded(path: str) -> DebugEndpointResult:
        async with sem:
            return await _probe_one(path)

    tasks = [_bounded(p) for p in _DEBUG_PATHS]
    results = await _asyncio.gather(*tasks)
    return [r for r in results if r.status > 0]


_SENSITIVE_PATTERNS = [
    (r'(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?key)\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,}', "API Key / Secret"),
    (r'(?:password|passwd|pwd)\s*[:=]\s*["\']?[^\s"\'&\n]{4,}', "密码信息"),
    (r'(?:jdbc|mysql|postgresql|mongodb)://[^\s"\']+', "数据库连接字符串"),
    (r'(?:-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----)', "私钥泄露"),
    (r'(?:eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,})', "JWT Token"),
    (r'(?:sk-[a-zA-Z0-9]{20,})', "OpenAI API Key"),
    (r'(?:AIza[0-9A-Za-z\-_]{35})', "Google API Key"),
]


def _detect_sensitive_in_body(body: str, content_type: str) -> list[str]:
    """检测响应体中是否包含敏感信息。"""
    findings: list[str] = []
    # 只检查 text/json/html 类型
    if not body:
        return findings
    for pattern, label in _SENSITIVE_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            findings.append(label)
    # 检查是否暴露了文件路径
    if re.search(r'(?:/home/|/root/|/etc/|C:\\)[^\s"\']+', body):
        findings.append("文件系统路径暴露")
    # 检查是否暴露了环境变量
    if re.search(r'(?:OS_|PATH=|HOME=|USER=|PYTHON_|JAVA_|NODE_)', body):
        findings.append("环境变量暴露")
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# 安全响应头分析
# ═══════════════════════════════════════════════════════════════════════════

_SECURITY_HEADERS = [
    "content-security-policy",
    "content-security-policy-report-only",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-allow-credentials",
    "access-control-expose-headers",
    "access-control-max-age",
    "x-permitted-cross-domain-policies",
    "expect-ct",
    "x-download-options",
    "x-dns-prefetch-control",
]


async def analyze_security_headers(
    base_url: str,
    timeout: float = 8.0,
    verify_ssl: bool = False,
    api_key: str = "",
    extra_headers: dict[str, str] | None = None,
) -> SecurityHeadersResult:
    """分析目标的 HTTP 安全响应头，评估安全配置水平。

    对红队而言，缺失关键安全头意味着：
      - 无 CSP → XSS 攻击面增大
      - 无 HSTS → 中间人降级可能
      - 宽松 CORS → SSRF / CSRF 面增大
      - 暴露 Server → 版本信息泄露
    """
    result = SecurityHeadersResult()

    try:
        nurl = normalize_target_url(base_url)
        headers = dict(API_HEADERS)
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        if extra_headers:
            headers.update(extra_headers)

        async with create_http_client(
            verify_ssl=verify_ssl, timeout=timeout, headers=headers,
            follow_redirects=True, max_redirects=3,
        ) as client:
            resp = await client.get(nurl.full_url)

        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        result.headers = dict(resp.headers)

        # 安全头检测
        result.csp = resp_headers.get("content-security-policy")
        result.hsts = resp_headers.get("strict-transport-security")
        result.x_frame_options = resp_headers.get("x-frame-options")
        result.x_content_type_options = resp_headers.get("x-content-type-options")

        # CORS 配置
        result.cors_headers = {
            h: resp_headers.get(h, "")
            for h in [
                "access-control-allow-origin",
                "access-control-allow-methods",
                "access-control-allow-headers",
                "access-control-allow-credentials",
            ]
        }

        # 服务端信息
        result.server = resp_headers.get("server", "")
        result.powered_by = resp_headers.get("x-powered-by", "")

        # 分析风险
        _assess_security_risk(result)

    except Exception as e:
        logger.exception("安全头分析失败")
        result.findings = [f"请求失败: {str(e)[:200]}"]

    return result


def _assess_security_risk(result: SecurityHeadersResult) -> None:
    """评估安全风险等级并生成发现列表。"""
    risk_score = 0
    findings: list[str] = []

    # CSP
    if not result.csp:
        findings.append("⚠ 缺少 Content-Security-Policy — XSS/数据注入攻击面增大")
        risk_score += 15
    elif "unsafe-inline" in result.csp or "unsafe-eval" in result.csp:
        findings.append("⚠ CSP 包含 'unsafe-inline'/'unsafe-eval' — 削弱防护效果")

    # HSTS
    if not result.hsts:
        findings.append("⚠ 缺少 Strict-Transport-Security — 可能受中间人降级攻击")
        risk_score += 10

    # X-Frame-Options
    if not result.x_frame_options:
        findings.append("⚠ 缺少 X-Frame-Options — Clickjacking 攻击面存在")
        risk_score += 5
    elif result.x_frame_options.upper() == "ALLOWALL":
        findings.append("⚠ X-Frame-Options: ALLOWALL — 允许任意 iframe 嵌入")
        risk_score += 10

    # X-Content-Type-Options
    if not result.x_content_type_options:
        findings.append("⚠ 缺少 X-Content-Type-Options — MIME 嗅探攻击可能")
        risk_score += 5

    # CORS 宽松检查
    acao = result.cors_headers.get("access-control-allow-origin", "")
    acac = result.cors_headers.get("access-control-allow-credentials", "")
    if acao == "*" and acac.lower() == "true":
        findings.append("🔴 Access-Control-Allow-Origin: * 且 Allow-Credentials: true — CSRF 高危")
        risk_score += 20
    elif acao == "*":
        findings.append("⚠ CORS 配置为通配符 * — 接受任意源请求")
        risk_score += 5

    # Server 头暴露
    if result.server:
        findings.append(f"ℹ Server 头暴露: {result.server} — 版本信息泄露")
        risk_score += 2
    if result.powered_by:
        findings.append(f"ℹ X-Powered-By: {result.powered_by} — 技术栈泄露")

    # 风险等级
    if risk_score >= 30:
        result.risk_level = "high"
    elif risk_score >= 15:
        result.risk_level = "medium"
    elif risk_score >= 5:
        result.risk_level = "low"
    else:
        result.risk_level = "info"

    result.findings = findings


# ═══════════════════════════════════════════════════════════════════════════
# 多格式 API 探测
# ═══════════════════════════════════════════════════════════════════════════

async def probe_multi_format(
    base_url: str,
    timeout: float = 10.0,
    verify_ssl: bool = False,
    api_key: str = "",
    extra_headers: dict[str, str] | None = None,
) -> MultiFormatResult:
    """同时探测 OpenAI / Anthropic / Gemini / Ollama 四种 API 格式。

    AISecLab 等高级 AI 平台常同时支持多种 API 格式，仅探 OpenAI
    会遗漏 Anthropic 和 Gemini 端点，导致攻击面发现不全。
    """
    nurl = normalize_target_url(base_url)
    result = MultiFormatResult()
    rate_tracker = RateLimitTracker()
    adaptive = AdaptiveTimeout(base=timeout, max_=max(timeout * 2.5, 20.0))

    headers = dict(API_HEADERS)
    headers["Content-Type"] = "application/json"
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    if extra_headers:
        headers.update(extra_headers)

    import asyncio as _asyncio

    async def _try_openai() -> dict | None:
        """OpenAI /v1/models"""
        for path in ["/v1/models", "/models", "/api/models"]:
            url = urljoin(nurl.full_url, path)
            try:
                async with create_http_client(
                    verify_ssl=verify_ssl, timeout=min(adaptive.current(), 6.0), headers=headers,
                ) as client:
                    resp = await client.get(url)
                # 限流检测
                if rate_tracker.record(resp):
                    adaptive.on_rate_limited(retry_after=rate_tracker.max_retry_after)
                    return {"format": "openai", "status": 429, "rate_limited": True,
                            "retry_after": rate_tracker.max_retry_after}
                adaptive.on_success()
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, dict) and "data" in data:
                            models = [m.get("id", "") for m in data.get("data", []) if isinstance(m, dict)]
                            return {"format": "openai", "source": path, "models": models[:10], "status": 200}
                    except Exception:
                        pass
            except (httpx.ReadError, httpx.RemoteProtocolError, httpx.CloseError,
                    ConnectionResetError, BrokenPipeError) as e:
                adaptive.on_server_crash()
                logger.warning("多格式探测[openai]: 对端崩溃 %s — %s", type(e).__name__, str(e)[:80])
                return None
            except Exception:
                continue
        return None

    async def _try_anthropic() -> dict | None:
        """Anthropic /v1/messages"""
        body = {
            "model": "claude-3-haiku-20240307",
            "max_tokens": 10,
            "messages": [{"role": "user", "content": "Hi"}],
        }
        for path in _ANTHROPIC_PROBE_PATHS:
            url = urljoin(nurl.full_url, path)
            try:
                async with create_http_client(
                    verify_ssl=verify_ssl, timeout=min(adaptive.current(), 6.0), headers=headers,
                ) as client:
                    resp = await client.post(url, json=body)
                if rate_tracker.record(resp):
                    adaptive.on_rate_limited(retry_after=rate_tracker.max_retry_after)
                    return {"format": "anthropic", "status": 429, "rate_limited": True,
                            "retry_after": rate_tracker.max_retry_after}
                adaptive.on_success()
                if resp.status_code in (200, 401, 403):
                    return {"format": "anthropic", "source": path, "status": resp.status_code}
            except (httpx.ReadError, httpx.RemoteProtocolError, httpx.CloseError,
                    ConnectionResetError, BrokenPipeError) as e:
                adaptive.on_server_crash()
                logger.warning("多格式探测[anthropic]: 对端崩溃 %s", type(e).__name__)
                return None
            except Exception:
                continue
        return None

    async def _try_gemini() -> dict | None:
        """Gemini /v1/models 或 /v1beta/models"""
        for path in _GEMINI_PROBE_PATHS:
            url = urljoin(nurl.full_url, path)
            try:
                async with create_http_client(
                    verify_ssl=verify_ssl, timeout=min(adaptive.current(), 6.0), headers=headers,
                ) as client:
                    resp = await client.get(url)
                if rate_tracker.record(resp):
                    adaptive.on_rate_limited(retry_after=rate_tracker.max_retry_after)
                    return {"format": "gemini", "status": 429, "rate_limited": True,
                            "retry_after": rate_tracker.max_retry_after}
                adaptive.on_success()
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, dict) and ("models" in data or "model" in data):
                            return {"format": "gemini", "source": path, "status": 200, "data_preview": str(data)[:200]}
                    except Exception:
                        if "gemini" in resp.text.lower() or "generativelanguage" in resp.text.lower():
                            return {"format": "gemini", "source": path, "status": 200}
            except (httpx.ReadError, httpx.RemoteProtocolError, httpx.CloseError,
                    ConnectionResetError, BrokenPipeError) as e:
                adaptive.on_server_crash()
                logger.warning("多格式探测[gemini]: 对端崩溃 %s", type(e).__name__)
                return None
            except Exception:
                continue
        return None

    async def _try_ollama() -> dict | None:
        """Ollama /api/tags"""
        for path in ["/api/tags", "/api/version"]:
            url = urljoin(nurl.full_url, path)
            try:
                async with create_http_client(
                    verify_ssl=verify_ssl, timeout=min(adaptive.current(), 6.0), headers=headers,
                ) as client:
                    resp = await client.get(url)
                if rate_tracker.record(resp):
                    adaptive.on_rate_limited(retry_after=rate_tracker.max_retry_after)
                    return {"format": "ollama", "status": 429, "rate_limited": True,
                            "retry_after": rate_tracker.max_retry_after}
                adaptive.on_success()
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, dict):
                            return {"format": "ollama", "source": path, "status": 200, "data_preview": str(data)[:200]}
                    except Exception:
                        pass
            except (httpx.ReadError, httpx.RemoteProtocolError, httpx.CloseError,
                    ConnectionResetError, BrokenPipeError) as e:
                adaptive.on_server_crash()
                logger.warning("多格式探测[ollama]: 对端崩溃 %s", type(e).__name__)
                return None
            except Exception:
                continue
        return None

    tasks = [
        _try_openai(),
        _try_anthropic(),
        _try_gemini(),
        _try_ollama(),
    ]
    results = await _asyncio.gather(*tasks)
    result.openai, result.anthropic, result.gemini, result.ollama = results

    # 限流信息汇总
    result.rate_limit_info = rate_tracker.to_dict()

    # 确定最佳格式
    detected = [(k, v) for k, v in [
        ("openai", result.openai),
        ("anthropic", result.anthropic),
        ("gemini", result.gemini),
        ("ollama", result.ollama),
    ] if v and v.get("status") in (200, 401, 403) and not v.get("rate_limited")]

    if detected:
        # 优先 200 响应
        ok_formats = [f for f in detected if f[1].get("status") == 200]
        best = ok_formats[0] if ok_formats else detected[0]
        result.best_format = best[0]

        all_formats = [f[0] for f in detected]
        result.suggestion = (
            f"发现 {len(detected)} 种 API 格式: {', '.join(all_formats)}。"
            f"推荐使用 {result.best_format} 格式进行攻击。"
        )
    else:
        result.best_format = "unknown"
        # 若仅因为限流导致未识别，提示用户
        if rate_tracker.hit_count > 0:
            result.suggestion = (
                f"探测过程中目标触发了 {rate_tracker.hit_count} 次速率限制 (HTTP 429)。"
                f"建议等待 {rate_tracker.max_retry_after:.1f}s 后重试，或降低探测并发。"
            )
        else:
            result.suggestion = "未检测到标准 AI API 端点，目标可能为自定义 Web 应用。"

    return result


# ═══════════════════════════════════════════════════════════════════════════
# 知识库 / 向量存储探测
# ═══════════════════════════════════════════════════════════════════════════

async def probe_knowledge_base(
    base_url: str,
    timeout: float = 6.0,
    verify_ssl: bool = False,
    api_key: str = "",
    extra_headers: dict[str, str] | None = None,
    concurrency: int = 5,
) -> KnowledgeBaseResult:
    """探测知识库/RAG/向量数据库端点。

    AISecLab 使用 ChromaDB 作为向量存储，知识库暴露在 /api/v1/knowledge-base/。
    """
    nurl = normalize_target_url(base_url)
    result = KnowledgeBaseResult()

    headers = dict(API_HEADERS)
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    if extra_headers:
        headers.update(extra_headers)

    import asyncio as _asyncio

    async def _probe_path(path: str) -> dict | None:
        url = urljoin(nurl.full_url, path)
        try:
            async with create_http_client(
                verify_ssl=verify_ssl, timeout=min(timeout, 4.0), headers=headers,
                follow_redirects=True, max_redirects=3,
            ) as client:
                resp = await client.get(url)
            if resp.status_code in (200, 401, 403):
                ct = resp.headers.get("content-type", "")
                is_json = "json" in ct.lower()
                preview = ""
                if resp.status_code == 200:
                    preview = resp.text[:300]
                    if is_json:
                        try:
                            data = resp.json()
                            preview = str(data)[:300]
                        except Exception:
                            pass
                return {
                    "url": url,
                    "path": path,
                    "status": resp.status_code,
                    "content_type": ct,
                    "preview": preview,
                    "is_json": is_json,
                }
        except Exception:
            pass
        return None

    sem = _asyncio.Semaphore(concurrency)

    async def _bounded(path: str) -> dict | None:
        async with sem:
            return await _probe_path(path)

    tasks = [_bounded(p) for p in _KNOWLEDGE_BASE_PATHS]
    results_list = await _asyncio.gather(*tasks)
    result.found_endpoints = [r for r in results_list if r is not None]

    # 分析探测结果
    for ep in result.found_endpoints:
        path = ep["path"]
        if "chroma" in path.lower() or "/api/v1/collections" in path:
            result.chromadb_detected = True
            result.vector_db_type = "chromadb"
        if path in ("/v1/schema", "/v1/nodes", "/v1/meta"):
            result.vector_db_type = "weaviate"
        if path == "/collections":
            result.vector_db_type = result.vector_db_type or "qdrant"
        if "knowledge" in path.lower() or "rag" in path.lower() or "search" in path.lower():
            result.rag_detected = True

        # 尝试从响应中提取文档数量
        preview = ep.get("preview", "")
        if result.document_count is None:
            m = re.search(r'(?:total[_\s]?(?:documents|count|results|items)|num[_\s]?(?:docs|documents|items))\s*[:=]\s*(\d+)', preview, re.IGNORECASE)
            if m:
                result.document_count = int(m.group(1))

        # 提取集合名称
        if ep.get("is_json") and "collections" in preview.lower():
            try:
                data = __import__("json").loads(preview) if isinstance(preview, str) else preview
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and item.get("name"):
                            result.collection_names.append(item["name"])
            except Exception:
                pass

    return result


# ═══════════════════════════════════════════════════════════════════════════
# 聚合深度侦察
# ═══════════════════════════════════════════════════════════════════════════

async def run_deep_recon(
    base_url: str,
    timeout: float = 8.0,
    verify_ssl: bool = False,
    api_key: str = "",
    extra_headers: dict[str, str] | None = None,
) -> DeepReconResult:
    """一键深度侦察：robots.txt + debug 端点 + 安全头 + 多格式 + 知识库。

    并行执行所有子侦察任务，聚合返回结果供前端渲染。
    """
    import asyncio as _asyncio

    results = await _asyncio.gather(
        parse_robots_txt(base_url, timeout=timeout, verify_ssl=verify_ssl, api_key=api_key, extra_headers=extra_headers),
        probe_debug_endpoints(base_url, timeout=timeout, verify_ssl=verify_ssl, api_key=api_key, extra_headers=extra_headers),
        analyze_security_headers(base_url, timeout=timeout, verify_ssl=verify_ssl, api_key=api_key, extra_headers=extra_headers),
        probe_multi_format(base_url, timeout=timeout, verify_ssl=verify_ssl, api_key=api_key, extra_headers=extra_headers),
        probe_knowledge_base(base_url, timeout=timeout, verify_ssl=verify_ssl, api_key=api_key, extra_headers=extra_headers),
        return_exceptions=True,
    )

    robots_raw, debug_raw, sec_raw, multi_raw, kb_raw = results

    recon_result = DeepReconResult(ok=True)

    if isinstance(robots_raw, Exception):
        recon_result.robots = RobotsResult(ok=False, error=str(robots_raw))
    else:
        recon_result.robots = robots_raw

    if isinstance(debug_raw, Exception):
        recon_result.debug_endpoints = []
    else:
        recon_result.debug_endpoints = debug_raw

    if isinstance(sec_raw, Exception):
        recon_result.security_headers = SecurityHeadersResult(findings=[f"分析失败: {sec_raw}"])
    else:
        recon_result.security_headers = sec_raw

    if isinstance(multi_raw, Exception):
        recon_result.multi_format = MultiFormatResult()
    else:
        recon_result.multi_format = multi_raw

    if isinstance(kb_raw, Exception):
        recon_result.knowledge_base = KnowledgeBaseResult()
    else:
        recon_result.knowledge_base = kb_raw

    # 生成汇总
    recon_result.summary = _build_recon_summary(recon_result)

    return recon_result


def _build_recon_summary(result: DeepReconResult) -> dict:
    """生成深度侦察摘要。"""
    summary: dict[str, Any] = {
        "high_findings": 0,
        "medium_findings": 0,
        "low_findings": 0,
        "key_recommendations": [],
    }

    # robots.txt
    if result.robots and result.robots.ok and result.robots.disallowed_paths:
        interesting = [p for p in result.robots.disallowed_paths if any(
            kw in p.lower() for kw in ("admin", "debug", "internal", "api", "config", "secret", "backup", "log")
        )]
        if interesting:
            summary["high_findings"] += 1
            summary["key_recommendations"].append(
                f"robots.txt 暴露了 {len(interesting)} 条敏感路径: {', '.join(interesting[:5])}"
            )

    # debug 端点
    debug_ok = [d for d in result.debug_endpoints if d.status == 200]
    debug_sensitive = [d for d in debug_ok if d.sensitive_info]
    if debug_sensitive:
        summary["high_findings"] += len(debug_sensitive)
        summary["key_recommendations"].append(
            f"发现 {len(debug_sensitive)} 个可访问的 debug 端点并包含敏感信息 (API Key / 密码 / 连接串)"
        )
    elif debug_ok:
        summary["medium_findings"] += 1
        summary["key_recommendations"].append(
            f"发现 {len(debug_ok)} 个可访问的 debug 端点，请检查是否泄露配置信息"
        )

    # 安全头
    if result.security_headers:
        if result.security_headers.risk_level == "high":
            summary["high_findings"] += 1
        elif result.security_headers.risk_level == "medium":
            summary["medium_findings"] += 1
        if result.security_headers.findings:
            summary["key_recommendations"].append(
                f"安全响应头分析: {result.security_headers.risk_level.upper()} 风险 — {len(result.security_headers.findings)} 条发现"
            )

    # 多格式
    if result.multi_format and result.multi_format.best_format != "unknown":
        summary["key_recommendations"].append(
            f"多格式 API 探测: 最佳格式 {result.multi_format.best_format.upper()}"
        )
        if result.multi_format.openai and result.multi_format.anthropic:
            summary["medium_findings"] += 1
            summary["key_recommendations"].append(
                "⚠ 目标同时暴露 OpenAI 和 Anthropic 端点 — 双格式攻击面"
            )

    # 知识库
    if result.knowledge_base and result.knowledge_base.found_endpoints:
        summary["medium_findings"] += 1
        if result.knowledge_base.rag_detected:
            summary["key_recommendations"].append(
                "发现 RAG 知识库端点 — 可能包含敏感训练文档，建议尝试检索查询"
            )
        if result.knowledge_base.chromadb_detected:
            summary["key_recommendations"].append(
                "检测到 ChromaDB 向量数据库 — 可尝试枚举 collections 获取文档列表"
            )
        if result.knowledge_base.collection_names:
            summary["key_recommendations"].append(
                f"ChromaDB collections: {', '.join(result.knowledge_base.collection_names[:5])}"
            )

    return summary
