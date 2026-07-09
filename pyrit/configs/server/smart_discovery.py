"""
===============================================================================
Config Center — 智能端点发现（Smart Discovery）
===============================================================================
针对「前端网关 + 后端 LLM」型 AI 应用（如 AI 安全训练靶机）：

  https://192.168.0.20/            ← 用户看到的前端 SPA
    │
    │  (HTML 内嵌 Base URL / 模型配置输入框)
    ▼
  http://localhost:11434/v1         ← 真正的 LLM (Ollama OpenAI 兼容)

普通端点枚举只扫描字典路径，找不到真实 LLM。智能发现会：
  1. 拉取首页 HTML → beautifulsoup4 + lxml 解析
  2. 提取 <a href> / <form action> / <script src> / <link href>
  3. 嗅探「Base URL」「API Key」「模型配置」表单字段 — 找到内嵌 LLM 地址
  4. 扫描 JS 文件中的 API 路径常量、fetch() 目标
  5. 推导 SPA 路由模式 (如 /ai/chat/<id>)
  6. 对发现的每个候选 URL 探测 /v1/models / /api/tags 等 LLM 特征端点

依赖（均为成熟开源库）:
  - beautifulsoup4 + lxml: HTML 解析（业界标准，Google/Instagram 等在用）
  - httpx: 异步 HTTP（项目已在用）
===============================================================================
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field, asdict
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from utils.http_transport import create_http_client
from .probe_resilience import (
    AdaptiveTimeout,
    RateLimitTracker,
    classify_exception,
    classify_response_for_rate_limit,
)

logger = logging.getLogger(__name__)


# ── 数据结构 ───────────────────────────────────────────────────────────────

@dataclass
class DiscoveredURL:
    """单条发现的 URL/端点。"""
    url: str
    source: str             # href / script / form / embedded / js_extract / llm_probe
    page: str = ""          # 发现于哪个页面
    category: str = ""      # link / static / api / api_base / chat_route / llm_endpoint / unknown
    status: int | None = None
    content_type: str = ""
    is_llm_endpoint: bool = False
    notes: str = ""


@dataclass
class SmartDiscoveryResult:
    """智能发现完整结果。"""
    ok: bool
    base_url: str
    homepage_status: int | None = None
    homepage_title: str = ""
    discovered_urls: list[DiscoveredURL] = field(default_factory=list)
    llm_endpoints: list[DiscoveredURL] = field(default_factory=list)
    embedded_api_bases: list[str] = field(default_factory=list)
    chat_routes: list[str] = field(default_factory=list)
    pages_crawled: list[str] = field(default_factory=list)
    error: str | None = None
    suggestion: str = ""
    # 🆕 异常分类 / 限速 / 自适应超时（前端可据此展示）
    error_type: str = ""              # 失败时的错误类型（与 ProbeErrorInfo.error_type 对齐）
    error_detail: str = ""            # 原始异常（已脱敏）
    rate_limit_info: dict = field(default_factory=dict)  # {"hit_count": N, "max_retry_after": X, ...}
    adaptive_timeout: float = 0.0     # 当前推荐的自适应超时（秒）


# ── 常量和特征模式 ──────────────────────────────────────────────────────────

# 跟 AI/LLM 相关的输入框名称/ID/占位符关键词
_AI_FIELD_KEYWORDS = [
    "base_url", "base-url", "api_base", "api-base", "api_url", "api-url",
    "endpoint_url", "endpoint-url", "server_url", "server-url", "backend_url",
    "openai_base", "ollama_host", "ollama_url", "vllm_url", "model_url",
    "api_endpoint", "api-endpoint", "llm_url", "llm_endpoint",
]

# 非业务/无关域
_SKIP_DOMAINS = {"cdn.", "fonts.", "analytics.", "tracker.", "pixel.", "beacon.",
                 "doubleclick.", "googletagmanager.", "gtag.", "facebook.", "bat.bing."}

# 静态资源后缀
_STATIC_EXTS = ('.css', '.png', '.jpg', '.jpeg', '.svg', '.ico', '.woff', '.woff2', '.wav', '.mp4', '.webp', '.gif')

# LLM 探测路径
_LLM_PROBE_PATHS = [
    "/v1/models",
    "/v1/chat/completions",
    "/api/tags",
    "/api/version",
    "/health",
    "/api/health",
    "/api/models",
    "/models",
    "/v2/models",
    # 🆕 Anthropic 端点
    "/v1/messages",
    "/api/v1/messages",
    "/v1/complete",
    # 🆕 Gemini 端点
    "/v1beta/models",
    "/api/v1beta/models",
]

# 聊天路由模式
_CHAT_ROUTE_PATTERNS = [
    re.compile(r'(/ai/chat/[^/"\s\'<>]+)', re.IGNORECASE),
    re.compile(r'(/chat/[^/"\s\'<>]+)', re.IGNORECASE),
    re.compile(r'(/conversation/[^/"\s\'<>]+)', re.IGNORECASE),
    re.compile(r'(/sessions?/[^/"\s\'<>]+)', re.IGNORECASE),
]


# ── BeautifulSoup 为核心的 HTML 解析 ────────────────────────────────────────

def _classify_url(url: str) -> tuple[str, str]:
    """用 URL 特征分类：link / static / api / api_base / chat_route / auth / page / debug / kb / unknown。"""
    u = url.lower()
    if u.endswith(_STATIC_EXTS):
        if 'api' in u or 'route' in u or 'config' in u:
            return ('api', '静态 API 配置')
        return ('static', '静态资源')
    # 🆕 Debug / 敏感端点
    if '/debug' in u or '/actuator' in u or '/phpinfo' in u or '/.debug' in u:
        return ('debug', 'Debug/诊断端点（高敏感）')
    # 🆕 知识库 / RAG / 向量数据库
    if any(kw in u for kw in ('/knowledge', '/rag/', '/retrieval', '/semantic-search', '/hybrid-search', '/collections', '/vector')):
        return ('kb', '知识库/向量存储端点')
    # 🆕 Admin / 管理端点
    if '/admin' in u or '/observability' in u or '/monitoring' in u:
        return ('admin', '管理/可观测性端点')
    if re.search(r'/v\d+/', u) or '/api/' in u or '/openapi' in u or '/swagger' in u or '/graphql' in u:
        return ('api', 'API 端点')
    if re.search(r'/ai/chat/|/chat/|/conversation/', u):
        return ('chat_route', '聊天会话路由')
    if u.endswith(('/login', '/auth', '/signin', '/signup', '/register')):
        return ('auth', '认证相关')
    if u in ('/', '/index.html', '/home', ''):
        return ('page', '页面入口')
    return ('link', '链接')


def _is_same_origin(url1: str, url2: str) -> bool:
    """判断两个 URL 是否同源（scheme + netloc 相同）。"""
    try:
        p1, p2 = urlparse(url1), urlparse(url2)
        return p1.scheme == p2.scheme and p1.netloc == p2.netloc
    except Exception:
        return False


def _should_skip_url(url: str) -> bool:
    """判断 URL 是否应跳过（CDN、追踪、静态资源等）。"""
    try:
        parsed = urlparse(url)
        if any(d in parsed.netloc for d in _SKIP_DOMAINS):
            return True
        if parsed.path.endswith(_STATIC_EXTS) and not any(
            kw in parsed.path.lower() for kw in ('api', 'config', 'route', 'manifest')
        ):
            return True
    except Exception:
        pass
    return False


def _resolve_url(raw: str, base_url: str) -> str | None:
    """将 HTML 属性中的原始 URL 解析为绝对 URL。"""
    raw = raw.strip()
    if not raw or raw.startswith(('javascript:', 'mailto:', 'tel:', '#', 'data:')):
        return None
    if raw.startswith(('http://', 'https://', 'ws://', 'wss://')):
        return raw
    if raw.startswith('//'):
        scheme = urlparse(base_url).scheme or 'https'
        return f"{scheme}:{raw}"
    return urljoin(base_url, raw)


def _extract_urls_with_bs4(html: str, base_url: str) -> list[tuple[str, str]]:
    """用 beautifulsoup4 + lxml 从 HTML 中提取所有 URL。

    返回 [(absolute_url, source_type), ...]
    source_type: href / script / form / link / iframe / img
    """
    soup = BeautifulSoup(html, 'lxml')
    found: list[tuple[str, str]] = []

    # <a href>
    for tag in soup.find_all('a', href=True):
        resolved = _resolve_url(tag['href'], base_url)
        if resolved and not _should_skip_url(resolved):
            found.append((resolved, 'href'))

    # <script src>
    for tag in soup.find_all('script', src=True):
        resolved = _resolve_url(tag['src'], base_url)
        if resolved and not _should_skip_url(resolved):
            found.append((resolved, 'script'))

    # <link href> (只保留非图标/非纯样式)
    for tag in soup.find_all('link', href=True):
        rel = (tag.get('rel') or [''])[0].lower() if isinstance(tag.get('rel'), list) else (tag.get('rel') or '').lower()
        if rel in ('stylesheet', 'preload', 'prefetch'):
            resolved = _resolve_url(tag['href'], base_url)
            if resolved and not _should_skip_url(resolved) and resolved.endswith(('.js', '.json', '.map')):
                found.append((resolved, 'link'))
            elif resolved and not _should_skip_url(resolved) and rel == 'stylesheet':
                # CSS 也收，可能包含 background-image URL
                found.append((resolved, 'link'))

    # <form action>
    for tag in soup.find_all('form', action=True):
        resolved = _resolve_url(tag['action'], base_url)
        if resolved:
            found.append((resolved, 'form'))

    # <iframe src>
    for tag in soup.find_all('iframe', src=True):
        resolved = _resolve_url(tag['src'], base_url)
        if resolved and not _should_skip_url(resolved):
            found.append((resolved, 'iframe'))

    # <img src> — 只保留可能含 API 信息的（如 /api/qrcode）
    for tag in soup.find_all('img', src=True):
        src = tag['src']
        if any(kw in src.lower() for kw in ('api', 'qrcode', 'captcha', 'chart', 'avatar')):
            resolved = _resolve_url(src, base_url)
            if resolved:
                found.append((resolved, 'img'))

    return found


def _extract_embedded_api_bases(html: str, base_url: str) -> list[str]:
    """嗅探页面中「Base URL / API URL」输入框，提取 API 根地址。

    适用：AI 训练靶机的「模型配置」页面通常有：
      <input name="base_url" value="http://localhost:11434/v1">
      <input placeholder="API Base URL" value="...">
    """
    soup = BeautifulSoup(html, 'lxml')
    bases: list[str] = []

    for tag in soup.find_all('input'):
        name = (tag.get('name') or '').lower().replace('-', '_').replace(' ', '_')
        placeholder = (tag.get('placeholder') or '').lower().replace('-', '_').replace(' ', '_')
        _id = (tag.get('id') or '').lower().replace('-', '_').replace(' ', '_')
        value = (tag.get('value') or '').strip()

        combined = f"{name}|{placeholder}|{_id}"
        if any(kw in combined for kw in _AI_FIELD_KEYWORDS) and value:
            if value.startswith(('http://', 'https://')):
                bases.append(value.rstrip('/'))

    # 也搜 JS 变量/JSON 中的 API Base 定义
    for pattern in [
        r'''(?:api[_\-]?base|base[_\-]?url|api[_\-]?url|api[_\-]?endpoint|backend[_\-]?url|server[_\-]?url)\s*[:=]\s*["']([^"']+)["']''',
        r'''["'](https?://[^"'\s]+(?:/v\d+|/api|/openai|/ollama|/llm)[^"'\s]*)["']''',
    ]:
        for m in re.finditer(pattern, html, re.IGNORECASE):
            url = m.group(1).strip()
            if url.startswith(('http://', 'https://')) and not _should_skip_url(url):
                bases.append(url.rstrip('/'))

    # curl 示例中的 URL
    for m in re.finditer(r'''curl\s+[^\n]*?["'](https?://[^"'\s]+)["']''', html, re.IGNORECASE):
        url = m.group(1).strip()
        if not _should_skip_url(url):
            bases.append(url.rstrip('/'))

    return list(dict.fromkeys(bases))


def _extract_js_api_paths(html_or_js: str) -> list[str]:
    """从 JS 代码文本中提取 API 路径常量、fetch/axios 调用目标。

    示例匹配：
      fetch("/api/chat")
      axios.post("/v1/complete")
      const API = "/internal/api/v1"
    """
    paths: list[str] = []

    # fetch/axios/xhr 调用中的路径
    patterns = [
        r'''fetch\s*\(\s*["']([^"']+)["']''',
        r'''axios\.(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']''',
        r'''\.open\s*\(\s*["'](?:GET|POST|PUT|DELETE|PATCH)\s*["']\s*,\s*["']([^"']+)["']''',
        # 路径常量赋值
        r'''(?:api|path|url|endpoint|base)\s*[:=]\s*["']([/"'][^"'\s]{2,})["']''',
        r'''(?:API|PATH|URL|ENDPOINT|BASE)[_A-Z]*\s*[:=]\s*["']([/"'][^"'\s]{2,})["']''',
    ]
    for pattern in patterns:
        for m in re.finditer(pattern, html_or_js, re.IGNORECASE):
            p = m.group(1).strip()
            if p.startswith('/') and len(p) > 2 and not p.startswith('//'):
                paths.append(p)
            elif p.startswith('http') and not _should_skip_url(p):
                paths.append(p)

    return list(dict.fromkeys(paths))


def _extract_chat_routes(urls: list[str]) -> list[str]:
    """从 URL 列表中识别 /ai/chat/<id> 类聊天会话路由，推导模式。"""
    routes: list[str] = []
    for url in urls:
        for pat in _CHAT_ROUTE_PATTERNS:
            for m in pat.finditer(url):
                p = m.group(1)
                p_generic = re.sub(r'/[a-f0-9]{8,}[a-f0-9]*$', '/<id>', p, flags=re.IGNORECASE)
                p_generic = re.sub(r'/\d{4,}$', '/<id>', p_generic)
                if p_generic != p and p_generic not in routes:
                    routes.append(p_generic)
    return routes


# ── 主流程 ───────────────────────────────────────────────────────────────

async def smart_discover(
    base_url: str,
    verify_ssl: bool = False,
    timeout: float = 8.0,
    max_pages: int = 3,
    api_key: str = "",
    cookies: str = "",
    extra_headers: dict[str, str] | None = None,
) -> SmartDiscoveryResult:
    """智能发现：beautifulsoup4 解析首页 → 提取嵌入 API + 爬取 JS → 探测 LLM。

    Args:
        base_url: 目标根 URL（如 https://192.168.0.20/）
        verify_ssl: SSL 证书验证
        timeout: 单次请求超时（秒）
        max_pages: 最多抓取多少个子页面/JS 文件
        api_key: 可选 Bearer 认证令牌
        cookies: 可选 Cookie 头（如 session=xxx）
        extra_headers: 额外 HTTP 头
    """
    result = SmartDiscoveryResult(ok=True, base_url=base_url)
    adaptive = AdaptiveTimeout(base=timeout, max_=max(timeout * 3, 30.0))
    rate_tracker = RateLimitTracker()
    result.adaptive_timeout = adaptive.current()

    client_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    }
    if api_key:
        client_headers["Authorization"] = f"Bearer {api_key}"
    if extra_headers:
        client_headers.update(extra_headers)

    try:
        async with create_http_client(
            verify_ssl=verify_ssl,
            timeout=timeout,
            connect_timeout=5.0,
            headers=client_headers,
            follow_redirects=True,
            max_redirects=5,
        ) as client:
            # ── 1. 拉取首页 ──
            try:
                req_headers = {}
                if cookies:
                    req_headers["Cookie"] = cookies
                resp = await client.get(base_url, headers=req_headers)
                result.homepage_status = resp.status_code
                ct = resp.headers.get("content-type", "")

                if "text/html" not in ct.lower() and not resp.text.strip().startswith("<"):
                    result.ok = False
                    result.error = f"首页不是 HTML (content-type: {ct})"
                    result.suggestion = "该 URL 可能是纯 API 服务，请直接用「模型枚举」按钮"
                    return result

                html = resp.text
                result.pages_crawled.append(base_url)

                # 提取 <title>
                try:
                    soup_title = BeautifulSoup(html, 'lxml')
                    title_tag = soup_title.find('title')
                    if title_tag and title_tag.string:
                        result.homepage_title = title_tag.string.strip()[:100]
                except Exception:
                    m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
                    if m:
                        result.homepage_title = m.group(1).strip()[:100]

                # ── 2. 嗅探内嵌 API Base URL（关键！）──
                bases = _extract_embedded_api_bases(html, base_url)
                result.embedded_api_bases = bases
                if bases:
                    logger.info("智能发现：嗅探到 %d 个内嵌 API Base: %s", len(bases), bases)

                # ── 3. BeautifulSoup 提取所有 URL ──
                urls_with_source = _extract_urls_with_bs4(html, base_url)
                logger.info("智能发现：BS4 从首页提取到 %d 个 URL", len(urls_with_source))

                # 去重
                seen: set[str] = set()
                unique_urls: list[tuple[str, str]] = []
                for u, src in urls_with_source:
                    if u not in seen:
                        seen.add(u)
                        unique_urls.append((u, src))

                # ── 4. 抓取 JS 文件 + 提取内部路径 ──
                js_candidates = [
                    (u, src) for u, src in unique_urls
                    if (
                        u.endswith('.js') or u.endswith('.mjs')
                        or '/js/' in u or '/static/' in u or '/assets/' in u or '/_next/' in u
                    )
                ][:max_pages * 2]

                for js_url, js_src in js_candidates[:max_pages]:
                    try:
                        js_resp = await client.get(
                            js_url,
                            headers={"Cookie": cookies} if cookies else {},
                            timeout=min(timeout, 6.0),
                        )
                        if js_resp.status_code == 200 and 100 < len(js_resp.text) < 5_000_000:
                            js_paths = _extract_js_api_paths(js_resp.text)
                            for p in js_paths:
                                if p.startswith('http'):
                                    if p not in seen and not _should_skip_url(p):
                                        seen.add(p)
                                        unique_urls.append((p, f'js:{js_url.split("/")[-1][:30]}'))
                                elif p.startswith('/'):
                                    resolved = urljoin(base_url, p)
                                    if resolved not in seen:
                                        seen.add(resolved)
                                        unique_urls.append((resolved, f'js:{js_url.split("/")[-1][:30]}'))
                            if js_url not in result.pages_crawled:
                                result.pages_crawled.append(js_url)
                    except Exception:
                        logger.debug("JS 文件抓取跳过: %s", js_url)

                # ── 5. 构建 DiscoveredURL 列表 ──
                for u, src in unique_urls:
                    category, notes = _classify_url(u)
                    result.discovered_urls.append(DiscoveredURL(
                        url=u, source=src, page=base_url,
                        category=category, notes=notes,
                    ))

                # ── 6. 推导聊天路由 ──
                all_url_strs = [u for u, _ in unique_urls]
                result.chat_routes = _extract_chat_routes(all_url_strs)

                # ── 7. 探测 LLM 端点 ──
                # 候选目标：内嵌 Base + 从 URL 中提取的 API 根
                probe_targets: list[str] = list(result.embedded_api_bases)
                for u, _ in unique_urls:
                    parsed = urlparse(u)
                    if parsed.scheme in ('http', 'https') and (
                        '/v1/' in parsed.path or '/v2/' in parsed.path or '/api/' in parsed.path
                    ):
                        root_path = re.match(r'(/v\d+|/api)', parsed.path)
                        if root_path:
                            root = f"{parsed.scheme}://{parsed.netloc}{root_path.group(1)}"
                            if root not in probe_targets:
                                probe_targets.append(root)

                # 对每个候选探测 LLM 路径
                for target in probe_targets[:5]:
                    target = target.rstrip('/')
                    for sub in _LLM_PROBE_PATHS:
                        try:
                            test_url = f"{target}{sub}"
                            current_timeout = min(adaptive.current(), 5.0)
                            test_resp = await client.get(
                                test_url,
                                headers={"Cookie": cookies} if cookies else {},
                                timeout=current_timeout,
                            )
                            # 检测限流
                            if rate_tracker.record(test_resp):
                                adaptive.on_rate_limited(retry_after=rate_tracker.max_retry_after)
                                logger.warning(
                                    "智能发现: 目标 %s 返回 429，已调整 timeout 至 %.1fs",
                                    target, adaptive.current(),
                                )
                                # 限流时跳过本候选剩余路径，避免持续触发
                                break
                            adaptive.on_success()
                            if test_resp.status_code == 200:
                                test_ct = test_resp.headers.get("content-type", "")
                                body_start = test_resp.text.strip()[:1]
                                is_json = "json" in test_ct.lower() or body_start in ('{', '[')
                                if is_json:
                                    ep = DiscoveredURL(
                                        url=test_url,
                                        source='llm_probe',
                                        page=base_url,
                                        category='llm_endpoint',
                                        status=200,
                                        content_type=test_ct,
                                        is_llm_endpoint=True,
                                        notes=f'在 {target} 上发现 LLM 端点 ({sub})',
                                    )
                                    result.llm_endpoints.append(ep)
                                    if not any(d.url == test_url for d in result.discovered_urls):
                                        result.discovered_urls.append(ep)
                        except (httpx.ReadError, httpx.RemoteProtocolError,
                                httpx.CloseError, ConnectionResetError, BrokenPipeError) as e:
                            # 对端崩溃/中断 — 跳出当前 target 的探测
                            adaptive.on_server_crash()
                            logger.warning(
                                "智能发现: 探测 %s 时对端连接中断 (%s)，跳过剩余路径",
                                target, type(e).__name__,
                            )
                            break
                        except (httpx.TimeoutException, httpx.ConnectError) as e:
                            info = classify_exception(e, context=f"探测 {test_url}")
                            logger.debug("智能发现: %s 失败 (%s)", test_url, info.error_type)
                            # 继续探测其他路径
                            continue
                        except Exception as e:  # noqa: BLE001
                            logger.debug("智能发现: 探测 %s 异常: %s", test_url, type(e).__name__)
                            continue

                # ── 8. 总结建议 ──
                if result.llm_endpoints:
                    ep = result.llm_endpoints[0]
                    result.suggestion = (
                        f"🎯 发现 {len(result.llm_endpoints)} 个 LLM 端点！推荐目标 URL：{ep.url}\n"
                        f"请复制该端点地址到步骤 1 的目标 URL 输入框"
                    )
                elif result.embedded_api_bases:
                    result.suggestion = (
                        f"🔍 从页面嗅探到 {len(result.embedded_api_bases)} 个内嵌 API 地址：\n"
                        + "\n".join(f"  • {b}" for b in result.embedded_api_bases[:3])
                        + "\n请复制其中一个到步骤 1 的目标 URL，然后重新探测"
                    )
                elif result.chat_routes:
                    result.suggestion = (
                        f"💬 发现 {len(result.chat_routes)} 个聊天路由模式（如 {result.chat_routes[0]}）\n"
                        "这通常是 SPA 前端，真实 LLM 端点可能不直接暴露。\n"
                        "建议：浏览器登录后 F12 → Network → 找发往 /api/ 或 /v1/ 的真实请求"
                    )
                else:
                    result.suggestion = (
                        "未发现 LLM 端点。可能原因：\n"
                        "  • 目标不是 AI 应用\n"
                        "  • 真实 LLM 在另一个端口/内网地址，页面未暴露\n"
                        "  • 需要 Cookie/JWT 认证才能访问配置页面"
                    )

            except httpx.TimeoutException as e:
                info = classify_exception(e, context="智能发现首页抓取")
                result.ok = False
                result.error = info.error_message
                result.error_type = info.error_type
                result.error_detail = info.detail
                result.suggestion = info.suggestion
            except httpx.ConnectError as e:
                info = classify_exception(e, context="智能发现首页抓取")
                result.ok = False
                result.error = info.error_message
                result.error_type = info.error_type
                result.error_detail = info.detail
                result.suggestion = info.suggestion
            except (httpx.ReadError, httpx.RemoteProtocolError,
                    httpx.CloseError, ConnectionResetError, BrokenPipeError) as e:
                # 对端服务器在响应过程中崩溃/断开
                info = classify_exception(e, context="智能发现首页抓取")
                result.ok = False
                result.error = info.error_message
                result.error_type = info.error_type
                result.error_detail = info.detail
                result.suggestion = info.suggestion
            except Exception as e:
                logger.exception("智能发现首页抓取异常")
                info = classify_exception(e, context="智能发现首页抓取")
                result.ok = False
                result.error = info.error_message
                result.error_type = info.error_type
                result.error_detail = info.detail
                result.suggestion = info.suggestion

    except Exception as e:
        logger.exception("智能发现整体失败")
        info = classify_exception(e, context="智能发现")
        result.ok = False
        result.error = info.error_message
        result.error_type = info.error_type
        result.error_detail = info.detail
        result.suggestion = info.suggestion

    # 始终输出限流统计 + 自适应超时，供前端展示
    result.rate_limit_info = rate_tracker.to_dict()
    result.adaptive_timeout = adaptive.current()
    if rate_tracker.hit_count > 0 and result.ok:
        # 探测成功但过程中触发了限流，给用户提示
        if not result.suggestion:
            result.suggestion = (
                f"⚠️ 探测过程中目标触发了 {rate_tracker.hit_count} 次限流 (HTTP 429)。"
                f"建议在步骤 1 适当增大「超时」并降低后续探测的并发度。"
            )

    return result


def smart_discovery_to_dict(r: SmartDiscoveryResult) -> dict:
    """转为 JSON 安全 dict（供 Flask jsonify 使用）。"""
    return {
        "ok": r.ok,
        "base_url": r.base_url,
        "homepage_status": r.homepage_status,
        "homepage_title": r.homepage_title,
        "discovered_urls": [
            {
                "url": u.url,
                "source": u.source,
                "category": u.category,
                "status": u.status,
                "content_type": u.content_type,
                "is_llm_endpoint": u.is_llm_endpoint,
                "notes": u.notes,
            }
            for u in r.discovered_urls
        ],
        "llm_endpoints": [
            {
                "url": u.url,
                "source": u.source,
                "category": u.category,
                "status": u.status,
                "content_type": u.content_type,
                "is_llm_endpoint": u.is_llm_endpoint,
                "notes": u.notes,
            }
            for u in r.llm_endpoints
        ],
        "embedded_api_bases": r.embedded_api_bases,
        "chat_routes": r.chat_routes,
        "pages_crawled": r.pages_crawled,
        "error": r.error,
        "suggestion": r.suggestion,
        # 🆕 异常分类 / 限流 / 自适应超时
        "error_type": r.error_type,
        "error_detail": r.error_detail,
        "rate_limit_info": r.rate_limit_info,
        "adaptive_timeout": r.adaptive_timeout,
    }
