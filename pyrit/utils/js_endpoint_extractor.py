"""
===============================================================================
PyRIT Red Team — JS 端点提取器 (LinkFinder-style)
===============================================================================
参照 GerbenJavado/LinkFinder 的 JS 端点发现策略，为 PyRIT 侦查阶段补充
动态 JS 解析能力，发现静态字典爆破无法覆盖的隐藏 API 端点。

LinkFinder 核心思路（已适配 PyRIT 异步架构）:
  1. 从 HTML 响应中提取 <script src="..."> / <link href="..."> 标签
  2. 下载 JS 文件，通过 jsbeautifier 规范化
  3. 用多层正则提取：完整 URL、绝对/相对路径、REST 端点、文件路径
  4. 可选上下文提取（显示端点周围的代码）
  5. 去重 + 噪音过滤（node_modules / jquery / vendors 等）

区别于 LinkFinder 的改进（PyRIT 特性）:
  ✅ 异步 httpx（而非 urllib），与 PyRIT 基础设施一致
  ✅ 集成限流感知（复用 model_probe 的超时/并发配置）
  ✅ AI/LLM 专项模式：额外捕获 fetch/axios/import 中的 API 端点
  ✅ 按 Content-Type 智能判断是否解析（text/html → 提取标签，application/javascript → 直接解析）
  ✅ 最大 JS 文件大小限制（防止下载大 bundle 耗尽内存）
  ✅ 不依赖 jsbeautifier（可选依赖，无安装时不美化但正常提取）

设计原则:
  ✅ 非阻塞：JS 提取为可选增强，失败不影响主探测流程
  ✅ 低噪音：过滤 common libraries、CDN、第三方追踪脚本
  ✅ 互补：结果合并到 model_probe 的 DiscoveredEndpoint，不替代
===============================================================================
"""
from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from .target_url import (
    DEFAULT_OPEN_TIMEOUT,
    DEFAULT_READ_TIMEOUT,
    DEFAULT_MAX_REDIRECTS,
)
from .http_transport import create_http_client


# ═══════════════════════════════════════════════════════════════════════════
# 常量
# ═══════════════════════════════════════════════════════════════════════════

# 最大 JS 文件大小（字节），超过则跳过（防止大 bundle OOM）
_MAX_JS_SIZE_BYTES = 2 * 1024 * 1024  # 2 MB

# 单次 JS 提取最大耗时（秒），超时则终止
_MAX_EXTRACTION_TIMEOUT = 20.0

# JS 源默认 HTTP 请求超时
_DEFAULT_JS_FETCH_TIMEOUT = 10.0

# 最大同时下载 JS 文件数
_MAX_CONCURRENT_JS_DOWNLOADS = 5

# 最多发现 JS 源文件数（从 HTML 中）
_MAX_SCRIPT_SRC_COUNT = 20


# ═══════════════════════════════════════════════════════════════════════════
# 核心正则 — 参照 LinkFinder regex_str 五路匹配
# ═══════════════════════════════════════════════════════════════════════════

# 分支说明（与 LinkFinder 完全等价）:
#   B1 — 完整 URL: scheme://domain.ext/path 或 //domain.ext/path
#   B2 — 绝对/相对路径起点: /path, ../path, ./path
#   B3 — 带扩展名的相对路径: dir/file.ext?query#fragment
#   B4 — REST API 路径（无扩展名，≥3 字符资源名）: /api/v1/users?query
#   B5 — 特定扩展名文件: file.php|asp|aspx|jsp|json|action|html|js|txt|xml

_JS_ENDPOINT_REGEX_STR = r"""
  (?:"|')                                   # 起始引号
  (
    (?:[a-zA-Z]{1,10}://|//)               # B1: scheme:// 或 //
    [^"'/]{1,}\.                            #     域名部分
    [a-zA-Z]{2,}[^"']{0,}                   #     TLD + 路径
    |
    (?:/|\.\./|\./)                         # B2: / | ../ | ./
    [^"'><,;| *()(%$^/\\\[\]                #     下一个字符的限制
    [^"'><,;|()]{1,}                        #     后续字符
    |
    ([a-zA-Z0-9_\-/]{1,}/                  # B3: 路径/
    [a-zA-Z0-9_\-/.]{1,}                   #     文件名
    \.(?:[a-zA-Z]{1,4}|action)             #     .扩展名(1-4字符或action)
    (?:[\?|\#][^"|']{0,}|))                #     ?query 或 #fragment
    |
    ([a-zA-Z0-9_\-/]{1,}/                  # B4: REST API 路径/
    [a-zA-Z0-9_\-/]{3,}                    #     资源名(≥3字符)
    (?:[\?|\#][^"|']{0,}|))                #     ?query 或 #fragment
    |
    ([a-zA-Z0-9_\-]{1,}                    # B5: 文件名
    \.(?:php|asp|aspx|jsp|json|            #     .特定扩展名
        action|html|js|txt|xml)
    (?:[\?|\#][^"|']{0,}|))                #     ?query 或 #fragment
  )
  (?:"|')                                   # 结束引号
"""

_JS_ENDPOINT_REGEX = re.compile(_JS_ENDPOINT_REGEX_STR, re.VERBOSE | re.IGNORECASE)


# ── PyRIT 扩展：AI/LLM 专用提取模式 ──

# fetch() / axios() 调用中的 URL
_FETCH_CALL_REGEX = re.compile(
    r"(?:fetch|axios\.(?:get|post|put|delete|patch|head|options|request))"
    r"\s*\(\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)

# HTTP 方法直接调用（第三方 HTTP client）
_HTTP_METHOD_REGEX = re.compile(
    r"(?:\.(?:get|post|put|delete|patch))\s*\(\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)

# JS 变量定义中的 URL/baseURL/apiURL/endpoint
_BASEURL_VAR_REGEX = re.compile(
    r"(?:baseUrl|baseURL|apiUrl|apiURL|endpoint|api_endpoint|serverUrl|host|apiHost|apiBase)"
    r"\s*[:=]\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)

# import / require 语句中的路径
_IMPORT_REGEX = re.compile(
    r"(?:import\s+.+?\s+from\s+|require\s*\(\s*)[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)

# WebSocket URL
_WEBSOCKET_REGEX = re.compile(
    r"(?:ws|wss)://[^\"'\s]+",
    re.IGNORECASE,
)

# ── HTML 标签提取 ──

# <script src="...">
_SCRIPT_SRC_REGEX = re.compile(
    r'<script[^>]+src\s*=\s*["\']([^"\']+\.js[^"\']*)["\']',
    re.IGNORECASE,
)

# <link href="..." rel="..."> 中的 JS/JSON 资源
_LINK_HREF_REGEX = re.compile(
    r'<link[^>]+href\s*=\s*["\']([^"\']+(?:\.js|\.json|manifest\.json|openapi\.json)[^"\']*)["\']',
    re.IGNORECASE,
)

# <a href="..."> 中的 .js 链接
_A_HREF_JS_REGEX = re.compile(
    r'<a[^>]+href\s*=\s*["\']([^"\']+\.js[^"\']*)["\']',
    re.IGNORECASE,
)

# 内联 importmap / System.import 中的 JS 源
_IMPORTMAP_REGEX = re.compile(
    r'["\']([^"\']+\.js[^"\']*)["\']\s*:',
    re.IGNORECASE,
)


# ═══════════════════════════════════════════════════════════════════════════
# 噪音域名/路径黑名单（避免解析第三方 CDN 脚本）
# ═══════════════════════════════════════════════════════════════════════════

_NOISE_HOSTS = {
    # CDN / 分析
    "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "ajax.googleapis.com", "www.googletagmanager.com", "www.google-analytics.com",
    "connect.facebook.net", "static.cloudflareinsights.com",
    # 常见前端框架（通常不含后端 API）
    "cdn.js",  # 模糊匹配
}

_NOISE_PATH_PARTS = {
    "node_modules", "jquery", "jquery.min", "bootstrap", "react-dom",
    "vue.min", "vue.runtime", "angular.min", "lodash", "moment",
    "popper", "polyfill", "shim", "vendor", "dist/vendor",
    "chunk-", "webpack-runtime", "core-js",
}


# ═══════════════════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class JSEndpoint:
    """从 JS 文件中提取的端点。

    比 DiscoveredEndpoint 更轻量 — 仅表示"代码中发现端点引用"，
    不等同于"端点确实存在"。

    Attributes:
        endpoint: 提取到的端点/URL/路径字符串
        source_file: 来源 JS 文件 URL
        match_type: 匹配类型 (full_url / relative_path / rest_api / file / fetch_call / baseurl_var / import)
        context: 端点周围的代码上下文（可选）
    """
    endpoint: str = ""
    source_file: str = ""
    match_type: str = ""           # full_url | relative_path | rest_api | file | fetch_call | baseurl_var | import | websocket
    context: str = ""              # 代码上下文（可选，用于人工判断）
    line_number: int = 0           # JS 中所在行号（近似）


@dataclass
class JSDiscoveryResult:
    """JS 端点提取的完整结果。

    Attributes:
        endpoints: 提取到的端点列表
        js_sources_found: 发现多少 JS 源文件
        js_sources_parsed: 成功解析多少 JS 源文件
        js_sources_skipped: 跳过多少 JS 源文件（过大/噪音）
        elapsed_ms: 总耗时（毫秒）
        error: 错误信息（如有）
    """
    endpoints: list[JSEndpoint] = field(default_factory=list)
    js_sources_found: int = 0
    js_sources_parsed: int = 0
    js_sources_skipped: int = 0
    elapsed_ms: float = 0.0
    error: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# JS 内容解析
# ═══════════════════════════════════════════════════════════════════════════

def _prettify_js(js_content: str) -> str:
    """尝试美化 JS（可选依赖 jsbeautifier），失败则用简单规则。

    参照 LinkFinder：美化后正则匹配率显著提升（统一换行/缩进）。
    """
    try:
        import jsbeautifier  # noqa: F401 — 可选依赖
        if len(js_content) > 1_000_000:
            # 超大文件：简单分号/逗号换行降级
            return js_content.replace(";", ";\n").replace(",", ",\n")
        return jsbeautifier.beautify(js_content)
    except (ImportError, Exception):
        # 无 jsbeautifier 或美化失败：简单规则降级
        return js_content.replace(";", ";\n").replace("}", "}\n").replace("{", "{\n")


def _extract_endpoints_from_js(
    js_content: str,
    source_url: str = "",
    filter_pattern: Optional[str] = None,
    include_context: bool = True,
) -> list[JSEndpoint]:
    """从 JS 内容中提取所有端点/URL 引用。

    多层正则策略（按优先级）：
      1. LinkFinder 主正则 — 五路匹配（URL/路径/REST/文件/扩展名）
      2. fetch/axios 调用 — HTTP 请求中的目标 URL
      3. baseUrl/endpoint 变量 — 配置中的 API 基础 URL
      4. import/require 语句 — 模块导入路径
      5. WebSocket URL — ws:// 或 wss://

    Args:
        js_content: JS 源代码文本
        source_url: 来源 URL（用于日志和相对路径转换）
        filter_pattern: 可选过滤正则（如 r'^/api/'），只保留匹配的端点
        include_context: 是否提取端点周围的代码上下文

    Returns:
        JSEndpoint 列表（已去重）
    """
    results: list[JSEndpoint] = []
    seen: set[str] = set()

    def _add(endpoint: str, match_type: str, context: str = "", line_number: int = 0):
        """去重添加端点。"""
        key = f"{endpoint}|{match_type}"
        if key in seen:
            return
        seen.add(key)
        results.append(JSEndpoint(
            endpoint=endpoint,
            source_file=source_url,
            match_type=match_type,
            context=context,
            line_number=line_number,
        ))

    # ── 步骤 0: 可选美化 ──
    content = _prettify_js(js_content)

    # ── 步骤 1: LinkFinder 主正则（五路匹配） ──
    for m in _JS_ENDPOINT_REGEX.finditer(content):
        endpoint = m.group(1)
        if not endpoint:
            continue

        # 确定匹配类型
        if endpoint.startswith(("http://", "https://", "//")):
            mtype = "full_url"
        elif endpoint.startswith("/"):
            if "." in endpoint.rsplit("/", 1)[-1]:
                mtype = "file"
            else:
                mtype = "rest_api"
        elif endpoint.startswith(("../", "./")):
            mtype = "relative_path"
        elif "/" in endpoint:
            mtype = "rest_api"
        else:
            mtype = "file"

        ctx = ""
        if include_context:
            # 提取周围 120 字符的代码上下文
            start = max(0, m.start() - 60)
            end = min(len(content), m.end() + 60)
            ctx = content[start:end].replace("\n", " ").replace("\r", " ")

        line_no = content[:m.start()].count("\n") + 1
        _add(endpoint, mtype, ctx, line_no)

    # ── 步骤 2: fetch/axios 调用 ──
    for m in _FETCH_CALL_REGEX.finditer(content):
        _add(m.group(1), "fetch_call", "", content[:m.start()].count("\n") + 1)

    # ── 步骤 3: HTTP 方法简写 (.get/.post 等) ──
    for m in _HTTP_METHOD_REGEX.finditer(content):
        _add(m.group(1), "fetch_call", "", content[:m.start()].count("\n") + 1)

    # ── 步骤 4: baseUrl/endpoint 变量 ──
    for m in _BASEURL_VAR_REGEX.finditer(content):
        val = m.group(1)
        # 跳过明显不是 URL/路径的值（如纯环境变量引用 "process.env.X"）
        if val.startswith("$") or val.startswith("process.") or val.startswith("import."):
            continue
        _add(val, "baseurl_var", "", content[:m.start()].count("\n") + 1)

    # ── 步骤 5: import/require ──
    for m in _IMPORT_REGEX.finditer(content):
        val = m.group(1)
        # 只保留看起来像路径的（含 / 或 .js/.ts 等）
        if "/" in val or val.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs")):
            _add(val, "import", "", content[:m.start()].count("\n") + 1)

    # ── 步骤 6: WebSocket ──
    for m in _WEBSOCKET_REGEX.finditer(content):
        _add(m.group(0), "websocket", "", content[:m.start()].count("\n") + 1)

    # ── 可选过滤 ──
    if filter_pattern:
        try:
            pattern = re.compile(filter_pattern, re.IGNORECASE)
            results = [r for r in results if pattern.search(r.endpoint)]
        except re.error:
            pass  # 无效正则，不过滤

    return results


def _filter_api_endpoints(endpoints: list[JSEndpoint]) -> list[JSEndpoint]:
    """过滤出可能为 API 端点的结果（而非静态资源）。

    规则：
      - 路径中包含 /api/ /v1/ /v2/ /graphql /rest/
      - REST API 类型（rest_api/fetch_call/baseurl_var）
      - 排除 .js/.css/.png/.jpg 等静态资源（除非在 API 路径中）
    """
    static_ext = {".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                  ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map"}

    filtered = []
    for ep in endpoints:
        path = ep.endpoint

        # 排除纯静态资源
        if any(path.lower().endswith(ext) for ext in static_ext):
            # 但如果路径中包含 /api/ 则保留（可能是 API 返回的 js 文件引用）
            if "/api/" not in path.lower():
                continue

        # REST API 类型始终保留
        if ep.match_type in ("rest_api", "fetch_call", "baseurl_var", "websocket"):
            filtered.append(ep)
            continue

        # 路径中包含 API 关键词
        if re.search(r"/(?:api|v[12]|graphql|rest|rpc)/", path, re.IGNORECASE):
            filtered.append(ep)
            continue

        # 完整 URL 中如果包含 API 路径
        if ep.match_type == "full_url":
            parsed = urlparse(path)
            if re.search(r"/(?:api|v[12]|graphql|rest|rpc)/", parsed.path, re.IGNORECASE):
                filtered.append(ep)
                continue

    return filtered


# ═══════════════════════════════════════════════════════════════════════════
# HTML 中提取 JS 源
# ═══════════════════════════════════════════════════════════════════════════

def extract_script_sources(html_content: str, base_url: str = "") -> list[str]:
    """从 HTML 页面中提取所有 JavaScript 源文件 URL。

    参照 LinkFinder 的 domain 模式：递归发现页面中的 JS 文件进而分析。

    提取来源：
      - <script src="...">
      - <link href="..." rel="..."> 中的 JS/JSON 资源
      - <a href="..."> 中的 .js 链接
      - importmap JSON 中的 JS 引用

    Args:
        html_content: HTML 页面文本
        base_url: 页面基 URL（用于将相对路径转为绝对 URL）

    Returns:
        去重后的 JS 文件绝对 URL 列表
    """
    sources: set[str] = set()

    def _to_absolute(href: str) -> str:
        """将相对路径转为绝对 URL。"""
        if href.startswith(("http://", "https://", "//")):
            if href.startswith("//"):
                return f"https:{href}" if base_url.startswith("https") else f"http:{href}"
            return href
        if base_url:
            return urljoin(base_url, href)
        return href

    def _is_noise(url: str) -> bool:
        """判断是否为噪音（第三方 CDN / 公共库）。"""
        lower = url.lower()
        # 域名黑名单
        for host in _NOISE_HOSTS:
            if host in lower:
                return True
        # 路径黑名单
        for part in _NOISE_PATH_PARTS:
            if part in lower:
                return True
        return False

    # 1. <script src="...">
    for m in _SCRIPT_SRC_REGEX.finditer(html_content):
        src = m.group(1)
        abs_url = _to_absolute(src)
        if not _is_noise(abs_url):
            sources.add(abs_url)

    # 2. <link href="...">
    for m in _LINK_HREF_REGEX.finditer(html_content):
        href = m.group(1)
        abs_url = _to_absolute(href)
        if not _is_noise(abs_url):
            sources.add(abs_url)

    # 3. <a href="..."> 中的 .js
    for m in _A_HREF_JS_REGEX.finditer(html_content):
        href = m.group(1)
        abs_url = _to_absolute(href)
        if not _is_noise(abs_url):
            sources.add(abs_url)

    # 4. importmap
    for m in _IMPORTMAP_REGEX.finditer(html_content):
        src = m.group(1)
        abs_url = _to_absolute(src)
        if not _is_noise(abs_url):
            sources.add(abs_url)

    return list(sources)[:_MAX_SCRIPT_SRC_COUNT]


def _should_parse_as_html(content_type: str) -> bool:
    """判断 Content-Type 是否表示 HTML 页面。"""
    ct = content_type.lower()
    return any(k in ct for k in ("text/html", "application/xhtml"))


def _should_parse_as_js(content_type: str, url: str = "") -> bool:
    """判断响应是否应该被当作 JS 解析。

    规则：
      - Content-Type: application/javascript / text/javascript → 是
      - URL 以 .js 结尾 → 是（即使 Content-Type 不准）
      - Content-Type: application/json → 否（除非是 JS 文件伪装）
    """
    ct = content_type.lower()
    if any(k in ct for k in ("javascript", "ecmascript")):
        return True
    if url.endswith((".js", ".mjs", ".jsx")):
        return True
    # .json 文件也可能是 API 文档，但在 JS 上下文中解析
    # 如果 CT 是 application/json 且 URL 以 .js 结尾，按 JS 处理
    return False


# ═══════════════════════════════════════════════════════════════════════════
# 异步核心流程
# ═══════════════════════════════════════════════════════════════════════════

async def _download_js_source(
    client: httpx.AsyncClient,
    url: str,
    timeout: float = _DEFAULT_JS_FETCH_TIMEOUT,
) -> tuple[str, str, int]:
    """下载 JS 源文件。

    Returns:
        (content, content_type, status_code)
    """
    try:
        head = await client.head(url, timeout=timeout)
        content_length = int(head.headers.get("content-length", "0"))
        if content_length > _MAX_JS_SIZE_BYTES:
            return "", "text/javascript; size_exceeded", head.status_code
        if content_length == 0:
            pass  # 无 Content-Length，尝试 GET
    except Exception:
        pass

    try:
        resp = await client.get(url, timeout=timeout)
        content = resp.text
        if len(content) > _MAX_JS_SIZE_BYTES:
            return "", "text/javascript; size_exceeded", resp.status_code
        return content, resp.headers.get("content-type", ""), resp.status_code
    except Exception:
        return "", "", 0


async def crawl_js_endpoints(
    html_pages: list[tuple[str, str]],  # [(html_content, source_url), ...]
    client: Optional[httpx.AsyncClient] = None,
    verify_ssl: bool = False,
    timeout: float = _MAX_EXTRACTION_TIMEOUT,
    filter_pattern: Optional[str] = None,
    api_only: bool = True,
) -> JSDiscoveryResult:
    """异步爬取 HTML 页面中的 JS 源文件并提取端点。

    参照 LinkFinder 的 domain 模式完整流程：
      1. 从每个 HTML 页面提取 <script src>/<link href> 等
      2. 并发下载 JS 源文件（受 _MAX_CONCURRENT_JS_DOWNLOADS 限制）
      3. 对每个 JS 内容运行多层正则提取
      4. 去重、过滤噪音、可选仅保留 API 端点

    Args:
        html_pages: HTML 页面列表，每项为 (html_content, page_url)
        client: 可复用的 httpx.AsyncClient（如不提供则临时创建）
        verify_ssl: SSL 证书验证
        timeout: 整体超时（秒）
        filter_pattern: 可选正则过滤（如 r'^/api/'）
        api_only: 是否仅返回 API 端点（排除静态资源）

    Returns:
        JSDiscoveryResult 包含所有发现的端点
    """
    t0 = time.monotonic()
    result = JSDiscoveryResult()

    # ── 阶段 1: 提取 JS 源 URL ──
    all_js_sources: set[str] = set()
    for html_content, page_url in html_pages:
        if not _should_parse_as_html("text/html") and not html_content.strip():
            continue
        # 即使 CT 不明确，也尝试从内容中提取（可能是无头页面）
        sources = extract_script_sources(html_content, page_url)
        all_js_sources.update(sources)

    result.js_sources_found = len(all_js_sources)
    if not all_js_sources:
        result.elapsed_ms = (time.monotonic() - t0) * 1000
        return result

    # ── 阶段 2: 并发下载 JS 源 ──
    semaphore = asyncio.Semaphore(_MAX_CONCURRENT_JS_DOWNLOADS)
    own_client = client is None

    async def _fetch_and_parse(js_url: str) -> list[JSEndpoint]:
        async with semaphore:
            # 过滤噪音
            if any(part in js_url.lower() for part in _NOISE_PATH_PARTS):
                nonlocal_ns["skipped"] += 1  # type: ignore
                return []
            if any(host in js_url.lower() for host in _NOISE_HOSTS):
                nonlocal_ns["skipped"] += 1  # type: ignore
                return []

            content, ct, status = await _download_js_source(
                _client, js_url, _DEFAULT_JS_FETCH_TIMEOUT,
            )
            if not content:
                nonlocal_ns["skipped"] += 1  # type: ignore
                return []

            nonlocal_ns["parsed"] += 1  # type: ignore
            eps = _extract_endpoints_from_js(
                content, js_url, filter_pattern, include_context=False,
            )
            return eps

    # 使用 namespace object 模拟 nonlocal
    ns: dict = {"skipped": 0, "parsed": 0}

    try:
        async def _run_with_client(_client: httpx.AsyncClient):
            nonlocal_ns = ns
            tasks = [_fetch_and_parse(url) for url in all_js_sources]
            batch_results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=timeout,
            )
            for item in batch_results:
                if isinstance(item, list):
                    result.endpoints.extend(item)
                # 异常静默跳过

        if own_client:
            async with create_http_client(
                verify_ssl=verify_ssl,
                timeout=_DEFAULT_JS_FETCH_TIMEOUT,
                connect_timeout=DEFAULT_OPEN_TIMEOUT,
                follow_redirects=True,
                max_redirects=DEFAULT_MAX_REDIRECTS,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/131.0.0.0 Safari/537.36"
                    ),
                    "Accept": "text/html,application/javascript,*/*",
                },
            ) as new_client:
                # Nonlocal workaround
                _client_local = new_client
                async def _inner():
                    nonlocal_ns = ns
                    tasks = []
                    for url in all_js_sources:
                        # 过滤噪音
                        if any(part in url.lower() for part in _NOISE_PATH_PARTS):
                            ns["skipped"] += 1
                            continue
                        if any(host in url.lower() for host in _NOISE_HOSTS):
                            ns["skipped"] += 1
                            continue
                        tasks.append(_fetch_and_parse_impl(_client_local, url))
                    if not tasks:
                        return
                    batch_results = await asyncio.wait_for(
                        asyncio.gather(*tasks, return_exceptions=True),
                        timeout=timeout,
                    )
                    for item in batch_results:
                        if isinstance(item, list):
                            result.endpoints.extend(item)

                async def _fetch_and_parse_impl(c: httpx.AsyncClient, js_url: str) -> list[JSEndpoint]:
                    async with semaphore:
                        content, ct, status = await _download_js_source(c, js_url, _DEFAULT_JS_FETCH_TIMEOUT)
                        if not content:
                            ns["skipped"] += 1
                            return []
                        ns["parsed"] += 1
                        return _extract_endpoints_from_js(content, js_url, filter_pattern, include_context=False)

                await _inner()
        else:
            # 复用外部 client
            _client_local = client
            async def _inner_shared():
                tasks = []
                for url in all_js_sources:
                    if any(part in url.lower() for part in _NOISE_PATH_PARTS):
                        ns["skipped"] += 1
                        continue
                    if any(host in url.lower() for host in _NOISE_HOSTS):
                        ns["skipped"] += 1
                        continue
                    tasks.append(_fetch_and_parse_impl(_client_local, url))
                if not tasks:
                    return
                batch_results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=timeout,
                )
                for item in batch_results:
                    if isinstance(item, list):
                        result.endpoints.extend(item)
            await _inner_shared()
    except asyncio.TimeoutError:
        result.error = "JS extraction timed out"
    except Exception as e:
        result.error = str(e)[:200]

    result.js_sources_parsed = ns["parsed"]
    result.js_sources_skipped = ns["skipped"]

    # ── 阶段 3: 后处理 ──
    # 去重（通过 endpoint + source_file 组合键）
    seen_keys: set[tuple[str, str]] = set()
    deduped: list[JSEndpoint] = []
    for ep in result.endpoints:
        key = (ep.endpoint, ep.source_file)
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(ep)
    result.endpoints = deduped

    # 可选：仅 API 端点
    if api_only:
        result.endpoints = _filter_api_endpoints(result.endpoints)

    # 排序：rest_api 和 fetch_call 排前面
    priority_order = {"rest_api": 0, "fetch_call": 1, "baseurl_var": 2,
                      "full_url": 3, "websocket": 4, "file": 5,
                      "relative_path": 6, "import": 7}
    result.endpoints.sort(key=lambda e: (priority_order.get(e.match_type, 99), e.endpoint))

    result.elapsed_ms = (time.monotonic() - t0) * 1000
    return result


# ═══════════════════════════════════════════════════════════════════════════
# 便捷函数（供 model_probe / readiness_probe 调用）
# ═══════════════════════════════════════════════════════════════════════════

def normalize_js_endpoint(endpoint: str, base_url: str) -> Optional[str]:
    """将 JS 中提取的端点标准化为绝对路径。

    Args:
        endpoint: 从 JS 中提取的原始端点字符串
        base_url: 目标网站的基础 URL

    Returns:
        绝对路径或 None（无法标准化时）
    """
    ep = endpoint.strip()

    # 完整 URL → 提取路径
    if ep.startswith(("http://", "https://")):
        try:
            parsed = urlparse(ep)
            return parsed.path or "/"
        except Exception:
            return None

    # 协议相对 URL
    if ep.startswith("//"):
        return None  # 跨域引用，跳过

    # 绝对路径
    if ep.startswith("/"):
        return ep.split("?")[0].split("#")[0]

    # 相对路径（以 ../ 或 ./ 开头）
    if ep.startswith(("../", "./")):
        # 无法准确还原，跳过
        return None

    # 纯文件名或相对路径（如 "api/chat"）
    if "/" in ep:
        return f"/{ep}"

    return None


def normalize_js_endpoint_to_paths(
    endpoints: list[JSEndpoint],
    base_url: str,
) -> list[str]:
    """将 JS 端点列表标准化为 API 路径列表（去重）。

    用于合并到 model_probe 的 DiscoveredEndpoint 静态列表中。

    Args:
        endpoints: JS 提取的端点列表
        base_url: 目标基础 URL

    Returns:
        去重后的标准化路径列表
    """
    paths: set[str] = set()
    for js_ep in endpoints:
        normalized = normalize_js_endpoint(js_ep.endpoint, base_url)
        if normalized and len(normalized) > 1 and len(normalized) < 300:
            # 过滤明显不是 API 端点的路径
            if not any(normalized.lower().endswith(ext) for ext in
                       (".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
                        ".svg", ".ico", ".woff", ".woff2", ".ttf")):
                paths.add(normalized)
    return sorted(paths)
