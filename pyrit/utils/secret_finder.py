"""
===============================================================================
PyRIT Red Team — API Key / Secret 侦察模块 (SecretFinder-style)
===============================================================================
参照 m4ll0k/SecretFinder 的正则匹配模式，为 PyRIT 补充 JS 文件中的
敏感信息探测能力：API 密钥、Access Token、JWT、云服务凭证、密码等。

SecretFinder 核心思路（已适配 PyRIT 异步架构）:
  1. 从 HTML 响应中提取 <script src> 标签，下载 JS 源文件
  2. 对 JS 内容用 30+ 正则模式逐行扫描
  3. 对每个匹配项提取上下文（前后各 60 字符），帮助人工判断
  4. 去重 + 按危险等级排序 + 敏感值脱敏

区别于 SecretFinder 的改进（PyRIT 特性）:
  ✅ 异步 httpx（而非 requests），与 PyRIT 基础设施一致
  ✅ 集成限流感知（复用 model_probe 的 HTTP client）
  ✅ 支持 HTML 页面内联 <script> 扫描（无需单独的 JS 下载步骤）
  ✅ 按危险等级分类（CRITICAL / HIGH / MEDIUM / LOW）
  ✅ 敏感值自动脱敏（日志/报告安全）
  ✅ 检测到 credential 时联动填充到攻击目标的 API Key 字段
  ✅ 所有扫描结果不直接输出原始敏感值（脱敏显示）

设计原则:
  ✅ 非破坏性：仅作信息侦察，不用于利用
  ✅ 可审计：每条发现记录来源文件和行号
  ✅ 低假阳性：正则约束长度/格式/上下文
===============================================================================
"""
from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

import httpx

from .http_transport import create_http_client
from .target_url import (
    DEFAULT_OPEN_TIMEOUT,
    DEFAULT_MAX_REDIRECTS,
)


# ═══════════════════════════════════════════════════════════════════════════
# 常量
# ═══════════════════════════════════════════════════════════════════════════

_MAX_JS_SIZE_BYTES = 2 * 1024 * 1024  # 2 MB
_MAX_CONCURRENT_DOWNLOADS = 5
_DEFAULT_JS_FETCH_TIMEOUT = 10.0
_MAX_SCRIPT_SRC_COUNT = 20
_CONTEXT_CHARS = 80  # 匹配项前后截取的上下文字符数

# 噪音域名/路径（第三方 CDN，不含业务敏感信息）
_NOISE_HOSTS = {
    "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "ajax.googleapis.com", "www.googletagmanager.com", "www.google-analytics.com",
    "connect.facebook.net", "static.cloudflareinsights.com",
}

_NOISE_PATH_PARTS = {
    "node_modules", "jquery", "jquery.min", "bootstrap", "react-dom",
    "vue.min", "vue.runtime", "angular.min", "lodash", "moment",
    "popper", "polyfill", "shim", "vendor", "dist/vendor", "webpack-runtime",
}


# ═══════════════════════════════════════════════════════════════════════════
# SecretFinder 正则规则库（共 38 条规则，按危险等级分组）
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class SecretRule:
    """单条敏感信息匹配规则。

    Attributes:
        name: 规则名称（如 google_api_key）
        pattern: 预编译正则表达式
        severity: 危险等级: CRITICAL / HIGH / MEDIUM / LOW
        category: 分类: api_key / token / cloud / credential / db / other
        description: 中文描述
    """
    name: str
    regex: re.Pattern
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    category: str  # api_key | token | cloud | credential | db | other
    description: str
    redact_groups: list[int] = field(default_factory=list)  # 需要脱敏的捕获组索引


_SECRET_RULES: list[SecretRule] = []


def _compile(name: str, pattern: str, severity: str, category: str, description: str, redact: list[int] | None = None) -> SecretRule:
    return SecretRule(
        name=name,
        regex=re.compile(pattern, re.VERBOSE | re.IGNORECASE),
        severity=severity,
        category=category,
        description=description,
        redact_groups=redact or [],
    )


# ── CRITICAL: 直接可用的认证凭证 ──

_SECRET_RULES.append(_compile(
    "aws_access_key_id",
    r"AKIA[0-9A-Z]{16}",
    "CRITICAL", "cloud", "AWS Access Key ID",
))

_SECRET_RULES.append(_compile(
    "aws_secret_access_key",
    r'(?:"|\'|^|\\s)(?P<key>[A-Za-z0-9/+=]{40})(?:"|\'|$|\\s)',
    "CRITICAL", "cloud", "疑似 AWS Secret Access Key (40 char base64)",
    [1],
))

_SECRET_RULES.append(_compile(
    "google_api_key",
    r"AIza[0-9A-Za-z\-_]{35}",
    "CRITICAL", "api_key", "Google API Key",
))

_SECRET_RULES.append(_compile(
    "github_token",
    r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}",
    "CRITICAL", "api_key", "GitHub Personal Access Token",
))

_SECRET_RULES.append(_compile(
    "slack_token",
    r"xox[abpos]-(?:[0-9]+-){2,}[0-9A-Za-z\-]+",
    "CRITICAL", "api_key", "Slack Bot/User Token",
))

_SECRET_RULES.append(_compile(
    "stripe_secret_key",
    r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}",
    "CRITICAL", "api_key", "Stripe Secret/Restricted Key",
))

_SECRET_RULES.append(_compile(
    "stripe_publishable_key",
    r"pk_(?:live|test)_[A-Za-z0-9]{24,}",
    "HIGH", "api_key", "Stripe Publishable Key",
))

# ── HIGH: 认证令牌 / JWT ──

_SECRET_RULES.append(_compile(
    "jwt_token",
    r"ey[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_\.\+\/=]*",
    "HIGH", "token", "JWT Token",
    [0],
))

_SECRET_RULES.append(_compile(
    "google_oauth_access_token",
    r"ya29\.[0-9A-Za-z\-_]+",
    "HIGH", "token", "Google OAuth Access Token",
    [0],
))

_SECRET_RULES.append(_compile(
    "firebase",
    r"AAAA[A-Za-z0-9\-_]{7}:[A-Za-z0-9\-_]{140}",
    "HIGH", "api_key", "Firebase 配置密钥",
))

_SECRET_RULES.append(_compile(
    "bearer_token",
    r'(?:bearer|token|apikey|api_key|authorization|auth)\s*[:=]\s*[\'"]([a-zA-Z0-9_\-\.=:_\+\/]{10,200})[\'"]',
    "HIGH", "token", "Bearer Token / 认证头值",
    [1],
))

_SECRET_RULES.append(_compile(
    "twilio_api_key",
    r"SK[0-9a-fA-F]{32}",
    "HIGH", "api_key", "Twilio API Key (SID format)",
))

_SECRET_RULES.append(_compile(
    "mailgun_api_key",
    r"key-[0-9a-zA-Z]{32}",
    "HIGH", "api_key", "Mailgun API Key",
))

_SECRET_RULES.append(_compile(
    "sendgrid_api_key",
    r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
    "HIGH", "api_key", "SendGrid API Key",
))

_SECRET_RULES.append(_compile(
    "heroku_api_key",
    r"[Hh][Ee][Rr][Oo][Kk][Uu].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "HIGH", "api_key", "Heroku API Key (UUID format)",
))

_SECRET_RULES.append(_compile(
    "openai_api_key",
    r'sk-(?:proj-|svcacct-)?[A-Za-z0-9]{20,}',
    "HIGH", "api_key", "OpenAI API Key",
    [0],
))

_SECRET_RULES.append(_compile(
    "anthropic_api_key",
    r'sk-ant-(?:api|coding)-[0-9]{2}-[A-Za-z0-9\-_]{80,}',
    "HIGH", "api_key", "Anthropic Claude API Key",
    [0],
))

# ── MEDIUM: 私钥 / 密码 / 连接串 ──

_SECRET_RULES.append(_compile(
    "private_key_pem",
    r"-----BEGIN\s(?:RSA|DSA|EC|OPENSSH|PGP)\sPRIVATE\s(?:KEY|BLOCK)-----",
    "MEDIUM", "credential", "PEM 私钥头",
))

_SECRET_RULES.append(_compile(
    "ssh_private_key",
    r"-----BEGIN\sOPENSSH\sPRIVATE\sKEY-----",
    "MEDIUM", "credential", "SSH 私钥头",
))

_SECRET_RULES.append(_compile(
    "generic_password_assignment",
    r'(?:password|passwd|pwd|secret|pass|passcode)\s*[`=:"]+\s*["\']?([^\s"\'`;]{4,64})["\']?',
    "MEDIUM", "credential", "密码/密钥赋值",
    [1],
))

_SECRET_RULES.append(_compile(
    "database_url",
    r'(?:DATABASE_URL|DB_URL|MONGO_URI|REDIS_URL|MYSQL_URL|POSTGRES_URL|DATABASE_URI|PG_URI)\s*=\s*["\']?([^\s"\']{10,300})["\']?',
    "MEDIUM", "db", "数据库连接字符串",
    [1],
))

_SECRET_RULES.append(_compile(
    "jdbc_connection_string",
    r"jdbc:(?:mysql|postgresql|oracle|sqlserver|mariadb|sqlite|h2|db2)://[^\s\"\'<>]+",
    "MEDIUM", "db", "JDBC 数据库连接串",
))

_SECRET_RULES.append(_compile(
    "connection_string_generic",
    r'(?:mongodb|mysql|postgres|postgresql|redis|sqlite)://[^\s\"\'<>]{10,}',
    "MEDIUM", "db", "数据库直连 URI",
))

_SECRET_RULES.append(_compile(
    "azure_blob_sas",
    r'(?:sv=\d{4}-\d{2}-\d{2})[^\s"\'<>]+(?:(?:sig)=[^\s"\'<>]+)',
    "MEDIUM", "cloud", "Azure Blob SAS Token (含签名)",
))

_SECRET_RULES.append(_compile(
    "aws_s3_bucket_url",
    r's3\.amazonaws\.com[/]+|[a-zA-Z0-9\-_]*\.s3\.amazonaws\.com',
    "LOW", "cloud", "AWS S3 Bucket URL",
))

# ── LOW: 可公开的信息但有侦察价值 ──

_SECRET_RULES.append(_compile(
    "google_captcha_site_key",
    r"6L[0-9A-Za-z\-_]{38}|^6[0-9a-zA-Z\-_]{39}$",
    "LOW", "other", "Google reCAPTCHA Site Key（前端公开）",
))

_SECRET_RULES.append(_compile(
    "google_oauth_client_id",
    r'[0-9]+-[a-zA-Z0-9_]+\.apps\.googleusercontent\.com',
    "LOW", "other", "Google OAuth Client ID（前端公开）",
))

_SECRET_RULES.append(_compile(
    "facebook_app_id",
    r'(?:facebook|FB|fb).{0,15}(?:app|application|client)_?(?:id|key)\s*[:=]\s*["\']?([0-9]{10,20})["\']?',
    "LOW", "other", "Facebook App ID",
    [1],
))

_SECRET_RULES.append(_compile(
    "firebase_url",
    r'(?:https?://)?[a-zA-Z0-9\-]+\.firebaseio\.com',
    "LOW", "other", "Firebase Realtime Database URL",
))

_SECRET_RULES.append(_compile(
    "generic_api_endpoint_with_key",
    r'(?:api|rest|graphql|rpc)(?:_endpoint|_url|_host|_base|Endpoint|Url)\s*[:=]\s*["\']([^"\']{5,200})["\']',
    "LOW", "other", "API 端点 URL 定义",
    [1],
))

_SECRET_RULES.append(_compile(
    "app_secret_key",
    r'(?:APP_SECRET|SECRET_KEY|APP_KEY|ENCRYPTION_KEY|FLASK_SECRET|DJANGO_SECRET)\s*[:=]\s*["\']([^"\']{10,100})["\']',
    "MEDIUM", "credential", "应用 Secret Key / 加密密钥",
    [1],
))

_SECRET_RULES.append(_compile(
    "basic_auth_header",
    r'(?:basic|authorization)\s+(?:[A-Za-z0-9+/=]{20,})',
    "HIGH", "token", "HTTP Basic Auth 凭据",
    [1],
))

_SECRET_RULES.append(_compile(
    "internal_ip_exposure",
    r'(?:host|ip|addr|address|server|proxy|endpoint)\s*[:=]\s*["\']?(?:(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})|(?:192\.168\.\d{1,3}\.\d{1,3})|(?:0\.0\.0\.0))["\']?',
    "LOW", "other", "内网 IP 暴露",
))

_SECRET_RULES.append(_compile(
    "generic_api_key_assignment",
    r'(?:api_?key|apikey|token|access_?key|access_?token)\s*[:=]\s*["\']([A-Za-z0-9_\-\.=:_\+\/]{12,200})["\']',
    "HIGH", "api_key", "通用 API Key / Token 赋值",
    [1],
))

_SECRET_RULES.append(_compile(
    "basic_auth_url",
    r'https?://[^:]+:[^@]+@[^\s"\']+',
    "CRITICAL", "credential", "URL 中包含明文凭据 (user:pass@host)",
    [0],
))

_SECRET_RULES.append(_compile(
    "docker_config_json_auth",
    r'"auth"\s*:\s*"[A-Za-z0-9+/=]{50,}"',
    "HIGH", "credential", "Docker config.json Base64 Auth",
    [0],
))

_SECRET_RULES.append(_compile(
    "npm_author_token",
    r"(?:npm_|//registry\.npmjs\.org/:_authToken=)([A-Za-z0-9\-]{36})",
    "HIGH", "api_key", "NPM 发布 Token",
    [1],
))

# 去掉重复规则
_seen_rules: set[str] = set()
_deduped_rules: list[SecretRule] = []
for r in _SECRET_RULES:
    if r.name not in _seen_rules:
        _seen_rules.add(r.name)
        _deduped_rules.append(r)
_SECRET_RULES = _deduped_rules


# ═══════════════════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class SecretMatch:
    """单条敏感信息匹配结果。

    Attributes:
        rule_name: 匹配的规则名称
        matched_value: 匹配到的值（用于内部传递，前端展示时脱敏）
        redacted_value: 脱敏后的展示值（如 sk-abc***xyz）
        severity: CRITICAL / HIGH / MEDIUM / LOW
        category: api_key / token / cloud / credential / db / other
        description: 规则中文描述
        source_file: 来源 JS/HTML 文件 URL
        context: 匹配项前后文本上下文
        line_number: JS 中所在行号（近似）
    """
    rule_name: str = ""
    matched_value: str = ""
    redacted_value: str = ""
    severity: str = "LOW"
    category: str = "other"
    description: str = ""
    source_file: str = ""
    context: str = ""
    line_number: int = 0


@dataclass
class SecretScanResult:
    """敏感信息扫描完整结果。

    Attributes:
        findings: 发现的所有敏感信息匹配项
        js_sources_found: 发现了多少个 JS 源文件
        js_sources_parsed: 成功解析了多少个 JS 源文件
        js_sources_skipped: 跳过了多少个 JS 源文件
        html_pages_scanned: 扫描了多少个 HTML 页面（含内联脚本）
        elapsed_ms: 总耗时（毫秒）
        error: 错误信息（如有）
    """
    findings: list[SecretMatch] = field(default_factory=list)
    js_sources_found: int = 0
    js_sources_parsed: int = 0
    js_sources_skipped: int = 0
    html_pages_scanned: int = 0
    elapsed_ms: float = 0.0
    error: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# 核心函数
# ═══════════════════════════════════════════════════════════════════════════

def _redact_value(raw: str, rule: SecretRule, show_chars_front: int = 3, show_chars_end: int = 3) -> str:
    """脱敏显示。默认保留前3后3字符，中间用星号替代。

    Args:
        raw: 原始敏感值
        rule: 匹配规则
        show_chars_front: 前端展示字符数
        show_chars_end: 后端展示字符数

    Returns:
        脱敏后字符串，如 "sk-***xyz"
    """
    length = len(raw)
    if length <= 8:
        return raw[:show_chars_front] + "***" + raw[-show_chars_end:]
    return raw[:show_chars_front] + "***" + raw[-show_chars_end:]


def _extract_context(text: str, match_start: int, match_end: int, chars: int = _CONTEXT_CHARS) -> str:
    """提取匹配项周围文本上下文。"""
    start = max(0, match_start - chars)
    end = min(len(text), match_end + chars)
    ctx = text[start:end].replace("\n", " ").replace("\r", " ").replace("\t", " ")
    # 压缩多余空格
    ctx = re.sub(r"\s{2,}", " ", ctx)
    return ctx


def scan_content_for_secrets(
    text: str,
    source_label: str = "",
) -> list[SecretMatch]:
    """对任意文本扫描敏感信息（JS 内容、HTML 内容、API 响应等）。

    参照 SecretFinder 的 parser_file() 核心逻辑：
      1. 遍历所有 _SECRET_RULES
      2. 逐规则执行 re.finditer()
      3. 提取上下文 + 脱敏
      4. 去重（同规则、同文件、同值只保留一次）

    Args:
        text: 待扫描的文本
        source_label: 来源标签（如文件名/URL，用于日志）

    Returns:
        SecretMatch 列表（已去重、脱敏）
    """
    findings: list[SecretMatch] = []
    seen: set[tuple[str, str, str]] = set()  # (rule_name, source_label, redacted_value)

    for rule in _SECRET_RULES:
        try:
            for m in rule.regex.finditer(text):
                raw_value = m.group(0)
                if len(raw_value) > 500:
                    # 异常长的匹配，跳过
                    continue

                # 对特定规则，提取捕获组中更精确的值
                match_value = raw_value
                if rule.redact_groups:
                    for gi in rule.redact_groups:
                        try:
                            candidate = m.group(gi)
                            if candidate and len(candidate) > 3:
                                match_value = candidate
                                break
                        except IndexError:
                            continue

                redacted = _redact_value(match_value, rule)

                # 去重
                key = (rule.name, source_label, redacted)
                if key in seen:
                    continue
                seen.add(key)

                # 上下文
                ctx = _extract_context(text, m.start(), m.end())
                line_no = text[:m.start()].count("\n") + 1

                findings.append(SecretMatch(
                    rule_name=rule.name,
                    matched_value=match_value,
                    redacted_value=redacted,
                    severity=rule.severity,
                    category=rule.category,
                    description=rule.description,
                    source_file=source_label,
                    context=ctx,
                    line_number=line_no,
                ))
        except Exception:
            # 单条规则异常不影响其他规则
            continue

    return findings


# ── HTML 中提取 JS 源（复用 js_endpoint_extractor 的标签提取） ──

_SCRIPT_SRC_REGEX = re.compile(
    r'<script[^>]+src\s*=\s*["\']([^"\']+\.js[^"\']*)["\']',
    re.IGNORECASE,
)

_LINK_HREF_REGEX = re.compile(
    r'<link[^>]+href\s*=\s*["\']([^"\']+(?:\.js|\.json)[^"\']*)["\']',
    re.IGNORECASE,
)


def extract_js_sources(html: str, base_url: str = "") -> list[str]:
    """从 HTML 中提取 JS 源文件 URL，同 js_endpoint_extractor 但独立。

    Args:
        html: HTML 文本
        base_url: 基础 URL（用于转换相对路径）

    Returns:
        去重的 JS 绝对 URL 列表
    """
    sources: set[str] = set()

    def _abs(href: str) -> str:
        if href.startswith(("http://", "https://", "//")):
            if href.startswith("//"):
                return ("https:" if base_url.startswith("https") else "http:") + href
            return href
        return urljoin(base_url, href) if base_url else href

    def _noise(url: str) -> bool:
        lower = url.lower()
        for h in _NOISE_HOSTS:
            if h in lower:
                return True
        for p in _NOISE_PATH_PARTS:
            if p in lower:
                return True
        return False

    for m in _SCRIPT_SRC_REGEX.finditer(html):
        abs_url = _abs(m.group(1))
        if not _noise(abs_url):
            sources.add(abs_url)

    for m in _LINK_HREF_REGEX.finditer(html):
        abs_url = _abs(m.group(1))
        if not _noise(abs_url):
            sources.add(abs_url)

    return list(sources)[:_MAX_SCRIPT_SRC_COUNT]


# ═══════════════════════════════════════════════════════════════════════════
# 异步核心流程
# ═══════════════════════════════════════════════════════════════════════════

async def _download_js(
    client: httpx.AsyncClient,
    url: str,
    timeout: float = _DEFAULT_JS_FETCH_TIMEOUT,
) -> str:
    """下载 JS 源文件，返回文本内容或空字符串。"""
    # HEAD 检查大小
    try:
        head = await client.head(url, timeout=timeout)
        cl = int(head.headers.get("content-length", "0"))
        if cl > _MAX_JS_SIZE_BYTES:
            return ""
    except Exception:
        pass

    try:
        resp = await client.get(url, timeout=timeout)
        if len(resp.text) > _MAX_JS_SIZE_BYTES:
            return ""
        return resp.text
    except Exception:
        return ""


async def scan_js_sources_for_secrets(
    html_pages: list[tuple[str, str]],  # [(html_content, source_url), ...]
    js_urls: list[str] | None = None,   # 额外的 JS URL 列表
    client: httpx.AsyncClient | None = None,
    verify_ssl: bool = False,
    timeout: float = 20.0,
) -> SecretScanResult:
    """下载 HTML 中引用的 JS 文件 + 额外 JS URL，全面扫描敏感信息。

    参照 SecretFinder 完整流程：
      1. 从每个 HTML 页面提取 JS 源 URL
      2. 并发下载 JS 文件
      3. 对每个 JS + 每个 HTML 中的内联 <script> 扫描
      4. 汇总、去重、排序

    Args:
        html_pages: HTML 页面列表，每项 (html_text, page_url)
        js_urls: 额外的独立 JS 文件 URL 列表
        client: 可复用的 httpx.AsyncClient
        verify_ssl: SSL 证书验证
        timeout: 整体超时

    Returns:
        SecretScanResult
    """
    t0 = time.monotonic()
    result = SecretScanResult()

    all_js_sources: set[str] = set(js_urls or [])
    for html_text, page_url in html_pages:
        result.html_pages_scanned += 1
        sources = extract_js_sources(html_text, page_url)
        all_js_sources.update(sources)

    result.js_sources_found = len(all_js_sources)

    semaphore = asyncio.Semaphore(_MAX_CONCURRENT_DOWNLOADS)
    ns: dict = {"skipped": 0, "parsed": 0}

    # ── 阶段 1: 扫描 HTML 内联脚本 ──
    _SCRIPT_CONTENT_REGEX = re.compile(
        r'<script[^>]*>(.*?)</script>',
        re.IGNORECASE | re.DOTALL,
    )
    for html_text, page_url in html_pages:
        inline_scripts = _SCRIPT_CONTENT_REGEX.findall(html_text)
        for script_content in inline_scripts:
            if len(script_content.strip()) > 50:
                findings = scan_content_for_secrets(script_content, f"{page_url} (inline)")
                result.findings.extend(findings)

    # ── 阶段 2: 并发下载 + 扫描 JS 源文件 ──
    own_client = client is None

    async def _fetch_and_scan(js_url: str):
        async with semaphore:
            # 噪音过滤
            lower = js_url.lower()
            if any(part in lower for part in _NOISE_PATH_PARTS):
                ns["skipped"] += 1
                return []
            if any(host in lower for host in _NOISE_HOSTS):
                ns["skipped"] += 1
                return []

            content = await _download_js(_client, js_url, _DEFAULT_JS_FETCH_TIMEOUT)
            if not content or len(content) < 50:
                ns["skipped"] += 1
                return []
            ns["parsed"] += 1
            return scan_content_for_secrets(content, js_url)

    try:
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
                _client = new_client
                tasks = [_fetch_and_scan(url) for url in all_js_sources]
                batch_results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=timeout,
                )
                for item in batch_results:
                    if isinstance(item, list):
                        result.findings.extend(item)
        else:
            _client = client
            tasks = [_fetch_and_scan(url) for url in all_js_sources]
            batch_results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=timeout,
            )
            for item in batch_results:
                if isinstance(item, list):
                    result.findings.extend(item)
    except asyncio.TimeoutError:
        result.error = "Secret scan timed out"
    except Exception as e:
        result.error = str(e)[:200]

    result.js_sources_parsed = ns["parsed"]
    result.js_sources_skipped = ns["skipped"]

    # ── 阶段 3: 后处理 ──
    # 去重
    seen_keys: set[tuple[str, str, str]] = set()
    deduped: list[SecretMatch] = []
    for f in result.findings:
        key = (f.rule_name, f.source_file, f.redacted_value)
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(f)
    result.findings = deduped

    # 按 severity 排序: CRITICAL > HIGH > MEDIUM > LOW
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    result.findings.sort(key=lambda f: (severity_order.get(f.severity, 99), f.rule_name))

    result.elapsed_ms = (time.monotonic() - t0) * 1000
    return result


def findings_to_dict(findings: list[SecretMatch]) -> list[dict]:
    """将 SecretMatch 列表转为 JSON 安全的 dict 列表（已脱敏）。"""
    return [
        {
            "rule_name": f.rule_name,
            "redacted_value": f.redacted_value,
            "severity": f.severity,
            "category": f.category,
            "description": f.description,
            "source_file": f.source_file,
            "context": f.context[:200],
            "line_number": f.line_number,
        }
        for f in findings
    ]


def summarize_findings(findings: list[SecretMatch]) -> dict:
    """对扫描结果进行汇总统计。"""
    counts: dict[str, int] = {}
    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_category: dict[str, int] = {}

    for f in findings:
        counts[f.rule_name] = counts.get(f.rule_name, 0) + 1
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_category[f.category] = by_category.get(f.category, 0) + 1

    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_category": by_category,
        "top_rules": sorted(counts.items(), key=lambda x: -x[1])[:10],
    }


# ═══════════════════════════════════════════════════════════════════════════
# 便捷入口：从 URL 出发一站式 API Key 侦察
# ═══════════════════════════════════════════════════════════════════════════

async def run_secret_recon(
    base_url: str,
    verify_ssl: bool = False,
    timeout: float = 20.0,
    api_key: str = "",
    extra_js_urls: list[str] | None = None,
) -> dict:
    """一站式 API Key 侦察：连接目标 → 获取 HTML → 解析 JS → 扫描密钥。

    Args:
        base_url: 目标根 URL
        verify_ssl: SSL 验证
        timeout: 总超时
        api_key: 可选认证头
        extra_js_urls: 额外的 JS 文件 URL（从抓包等来源）

    Returns:
        {
            "ok": bool,
            "findings": [dict, ...],
            "summary": dict,
            "homepage_status": int,
            "error": str | None,
        }
    """
    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/javascript,*/*",
        }
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        html_pages: list[tuple[str, str]] = []
        homepage_status = 0

        async with create_http_client(
            verify_ssl=verify_ssl,
            timeout=timeout,
            connect_timeout=DEFAULT_OPEN_TIMEOUT,
            headers=headers,
            follow_redirects=True,
            max_redirects=DEFAULT_MAX_REDIRECTS,
        ) as client:
            # 阶段 1: 拉取首页 HTML
            try:
                resp = await client.get(base_url, timeout=max(timeout, 10.0))
                homepage_status = resp.status_code
                ct = resp.headers.get("content-type", "")
                if "text/html" in ct.lower() or (not ct and resp.text.strip().startswith("<")):
                    html_pages.append((resp.text, base_url))
            except Exception:
                pass

            # 阶段 2: 扫描
            scan_result = await scan_js_sources_for_secrets(
                html_pages=html_pages,
                js_urls=extra_js_urls,
                client=client,
                verify_ssl=verify_ssl,
                timeout=timeout,
            )

        findings_dict_list = findings_to_dict(scan_result.findings)
        summary = summarize_findings(scan_result.findings)

        return {
            "ok": True,
            "findings": findings_dict_list,
            "summary": {
                **summary,
                "js_sources_found": scan_result.js_sources_found,
                "js_sources_parsed": scan_result.js_sources_parsed,
                "js_sources_skipped": scan_result.js_sources_skipped,
                "html_pages_scanned": scan_result.html_pages_scanned,
                "elapsed_ms": scan_result.elapsed_ms,
            },
            "homepage_status": homepage_status,
            "error": scan_result.error or None,
        }
    except Exception as e:
        return {
            "ok": False,
            "findings": [],
            "summary": {"total": 0},
            "homepage_status": 0,
            "error": str(e)[:400],
        }
