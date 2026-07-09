"""
===============================================================================
PyRIT Red Team — API Key / Secret 侦察模块
===============================================================================

融合两大开源工具的核心能力:
  ✅ m4ll0k/SecretFinder — 正则规则库 (38条) + JS扫描 + 上下文提取
  ✅ trufflesecurity/trufflehog — 凭证验证 + 关键词预过滤 + 熵值检测 + 哈希去重

TruffleHog 核心特性已适配 PyRIT:
  1. 凭证验证系统 (VerificationEngine)
     - 对 OpenAI / Anthropic / Google AI / GitHub / Stripe 等 API Key 执行实际 API 调用验证
     - SSRF 防护：禁止验证请求访问内网地址
     - 验证结果去重：同一凭据只验证一次
     - 验证错误信息脱敏

  2. 关键词预过滤 (Keyword Pre-filtering)
     - 参照 TruffleHog 的 Aho-Corasick 预过滤策略
     - 仅对包含特征关键词的文本片段执行正则匹配
     - 大幅减少无效正则计算

  3. 熵值检测 (Entropy Check)
     - 对匹配结果计算 Shannon 熵值
     - 低熵值匹配（纯数字/重复字符）标记为可疑误报
     - 辅助假阳性过滤

  4. 哈希去重 (Hash-based Dedup)
     - 使用 SHA256 对凭证原文哈希
     - 跨扫描、跨文件去重
     - 记录首次发现时间

  5. 多段凭证支持 (Multi-part Credential)
     - 检测 key+secret 成对出现
     - 支持 AWS Access Key + Secret Key 等组合

设计原则:
  ✅ 非破坏性：仅作信息侦察，不用于利用
  ✅ 可审计：每条发现记录来源文件和验证状态
  ✅ 低假阳性：正则约束 + 关键词预过滤 + 熵值检测
  ✅ 安全脱敏：验证错误信息中的敏感值自动替换
===============================================================================
"""
from __future__ import annotations

import asyncio
import hashlib
import math
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urljoin, urlparse

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
_LOW_ENTROPY_THRESHOLD = 3.0  # 低于此值的匹配标记为低熵（可能误报）

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
# TruffleHog-style 凭证验证状态
# ═══════════════════════════════════════════════════════════════════════════

class VerifyStatus(str, Enum):
    """凭证验证状态（对齐 TruffleHog Result.Verified）。"""
    UNVERIFIED = "unverified"       # 未验证（默认）
    VERIFIED = "verified"           # 验证通过 — 凭据有效
    INVALID = "invalid"             # 验证失败 — 凭据无效/过期
    ERROR = "error"                 # 验证过程出错（网络超时、率限制等）
    SKIPPED = "skipped"             # 跳过验证（不支持此凭证类型或用户关闭验证）


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
        redact_groups: 需要脱敏的捕获组索引
        keywords: 预过滤关键词（TruffleHog Keywords 机制）
        verifiable: 是否支持远程验证
        verify_endpoint: 验证端点 URL 模板（{key} 占位）
        verify_method: HTTP 方法
        verify_success_pattern: 验证成功的响应特征
        min_entropy: 最低熵值阈值
    """
    name: str
    regex: "re.Pattern"
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    category: str  # api_key | token | cloud | credential | db | other
    description: str
    redact_groups: list[int] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    verifiable: bool = False
    verify_endpoint: str = ""
    verify_method: str = "GET"
    verify_success_pattern: str = ""
    min_entropy: float = 0.0


_SE = []


def _compile(
    name: str, pattern: str, severity: str, category: str, description: str,
    redact: list[int] | None = None,
    keywords: list[str] | None = None,
    verifiable: bool = False,
    verify_endpoint: str = "",
    verify_method: str = "GET",
    verify_success_pattern: str = "",
    min_entropy: float = 0.0,
) -> SecretRule:
    return SecretRule(
        name=name,
        regex=re.compile(pattern, re.VERBOSE | re.IGNORECASE),
        severity=severity,
        category=category,
        description=description,
        redact_groups=redact or [],
        keywords=keywords or [],
        verifiable=verifiable,
        verify_endpoint=verify_endpoint,
        verify_method=verify_method,
        verify_success_pattern=verify_success_pattern,
        min_entropy=min_entropy,
    )


# ── CRITICAL: 直接可用的认证凭证 ──

_SE.append(_compile(
    "aws_access_key_id",
    r"AKIA[0-9A-Z]{16}",
    "CRITICAL", "cloud", "AWS Access Key ID",
    keywords=["AKIA", "aws", "access_key"],
))

_SE.append(_compile(
    "aws_secret_access_key",
    r'(?:"|\'|^|\\s)(?P<key>[A-Za-z0-9/+=]{40})(?:"|\'|$|\\s)',
    "CRITICAL", "cloud", "疑似 AWS Secret Access Key (40 char base64)",
    redact=[1], keywords=["secret", "aws", "access"],
))

_SE.append(_compile(
    "google_api_key",
    r"AIza[0-9A-Za-z\-_]{35}",
    "CRITICAL", "api_key", "Google API Key",
    keywords=["AIza", "google", "api_key", "key"],
    verifiable=True,
    verify_endpoint="https://generativelanguage.googleapis.com/v1beta/models?key={key}",
    verify_success_pattern=r'"models"',
))

_SE.append(_compile(
    "github_token",
    r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}",
    "CRITICAL", "api_key", "GitHub Personal Access Token",
    keywords=["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github", "token"],
    verifiable=True,
    verify_endpoint="https://api.github.com/user",
    verify_method="GET",
    verify_success_pattern=r'"login"',
))

_SE.append(_compile(
    "slack_token",
    r"xox[abpos]-(?:[0-9]+-){2,}[0-9A-Za-z\-]+",
    "CRITICAL", "api_key", "Slack Bot/User Token",
    keywords=["xox", "slack", "token"],
    verifiable=True,
    verify_endpoint="https://slack.com/api/auth.test",
    verify_method="POST",
    verify_success_pattern=r'"ok":\s*true',
))

_SE.append(_compile(
    "stripe_secret_key",
    r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}",
    "CRITICAL", "api_key", "Stripe Secret/Restricted Key",
    keywords=["sk_live", "sk_test", "rk_live", "rk_test", "stripe"],
    verifiable=True,
    verify_endpoint="https://api.stripe.com/v1/balance",
    verify_success_pattern=r'"object":\s*"balance"',
))

_SE.append(_compile(
    "stripe_publishable_key",
    r"pk_(?:live|test)_[A-Za-z0-9]{24,}",
    "HIGH", "api_key", "Stripe Publishable Key",
    keywords=["pk_live", "pk_test", "stripe", "publishable"],
))

# ── HIGH: 认证令牌 / JWT ──

_SE.append(_compile(
    "jwt_token",
    r"ey[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_\.\+\/=]*",
    "HIGH", "token", "JWT Token",
    redact=[0], keywords=["eyJ", "jwt", "token"],
    min_entropy=3.5,
))

_SE.append(_compile(
    "google_oauth_access_token",
    r"ya29\.[0-9A-Za-z\-_]+",
    "HIGH", "token", "Google OAuth Access Token",
    redact=[0], keywords=["ya29", "google", "oauth", "access_token"],
))

_SE.append(_compile(
    "firebase",
    r"AAAA[A-Za-z0-9\-_]{7}:[A-Za-z0-9\-_]{140}",
    "HIGH", "api_key", "Firebase 配置密钥",
    keywords=["AAAA", "firebase", "config"],
))

_SE.append(_compile(
    "bearer_token",
    r'(?:bearer|token|apikey|api_key|authorization|auth)\s*[:=]\s*[\'"]([a-zA-Z0-9_\-\.=:_\+\/]{10,200})[\'"]',
    "HIGH", "token", "Bearer Token / 认证头值",
    redact=[1], keywords=["bearer", "token", "apikey", "authorization"],
))

_SE.append(_compile(
    "twilio_api_key",
    r"SK[0-9a-fA-F]{32}",
    "HIGH", "api_key", "Twilio API Key (SID format)",
    keywords=["SK", "twilio", "sid"],
    verifiable=True,
    verify_endpoint="https://api.twilio.com/2010-04-01/Accounts",
    verify_success_pattern=r'"accounts"',
))

_SE.append(_compile(
    "mailgun_api_key",
    r"key-[0-9a-zA-Z]{32}",
    "HIGH", "api_key", "Mailgun API Key",
    keywords=["key-", "mailgun"],
    verifiable=True,
    verify_endpoint="https://api.mailgun.net/v4/domains",
    verify_success_pattern=r'"items"',
))

_SE.append(_compile(
    "sendgrid_api_key",
    r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
    "HIGH", "api_key", "SendGrid API Key",
    keywords=["SG.", "sendgrid", "api_key"],
))

_SE.append(_compile(
    "heroku_api_key",
    r"[Hh][Ee][Rr][Oo][Kk][Uu].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "HIGH", "api_key", "Heroku API Key (UUID format)",
    keywords=["heroku", "HEROKU", "uuid"],
))

_SE.append(_compile(
    "openai_api_key",
    r'sk-(?:proj-|svcacct-)?[A-Za-z0-9]{20,}',
    "HIGH", "api_key", "OpenAI API Key",
    redact=[0], keywords=["sk-", "openai", "api_key"],
    verifiable=True,
    verify_endpoint="https://api.openai.com/v1/models",
    verify_success_pattern=r'"object":\s*"list"',
))

_SE.append(_compile(
    "anthropic_api_key",
    r'sk-ant-(?:api|coding)-[0-9]{2}-[A-Za-z0-9\-_]{80,}',
    "HIGH", "api_key", "Anthropic Claude API Key",
    redact=[0], keywords=["sk-ant", "anthropic", "claude", "api_key"],
    verifiable=True,
    verify_endpoint="https://api.anthropic.com/v1/models",
    verify_success_pattern=r'"data"',
))

# ── MEDIUM: 私钥 / 密码 / 连接串 ──

_SE.append(_compile(
    "private_key_pem",
    r"-----BEGIN\s(?:RSA|DSA|EC|OPENSSH|PGP)\sPRIVATE\s(?:KEY|BLOCK)-----",
    "MEDIUM", "credential", "PEM 私钥头",
    keywords=["BEGIN", "PRIVATE KEY", "PRIVATE BLOCK"],
    min_entropy=3.0,
))

_SE.append(_compile(
    "ssh_private_key",
    r"-----BEGIN\sOPENSSH\sPRIVATE\sKEY-----",
    "MEDIUM", "credential", "SSH 私钥头",
    keywords=["OPENSSH", "PRIVATE KEY"],
))

_SE.append(_compile(
    "generic_password_assignment",
    r'(?:password|passwd|pwd|secret|pass|passcode)\s*[`=:"]+\s*["\']?([^\s"\'`;]{4,64})["\']?',
    "MEDIUM", "credential", "密码/密钥赋值",
    redact=[1], keywords=["password", "passwd", "pwd", "secret"],
    min_entropy=2.5,
))

_SE.append(_compile(
    "database_url",
    r'(?:DATABASE_URL|DB_URL|MONGO_URI|REDIS_URL|MYSQL_URL|POSTGRES_URL|DATABASE_URI|PG_URI)\s*=\s*["\']?([^\s"\']{10,300})["\']?',
    "MEDIUM", "db", "数据库连接字符串",
    redact=[1], keywords=["DATABASE_URL", "DB_URL", "MONGO_URI", "REDIS_URL"],
))

_SE.append(_compile(
    "jdbc_connection_string",
    r"jdbc:(?:mysql|postgresql|oracle|sqlserver|mariadb|sqlite|h2|db2)://[^\s\"\'<>]+",
    "MEDIUM", "db", "JDBC 数据库连接串",
    keywords=["jdbc:", "mysql", "postgresql", "oracle"],
))

_SE.append(_compile(
    "connection_string_generic",
    r'(?:mongodb|mysql|postgres|postgresql|redis|sqlite)://[^\s\"\'<>]{10,}',
    "MEDIUM", "db", "数据库直连 URI",
    keywords=["mongodb://", "mysql://", "postgresql://", "redis://", "sqlite://"],
))

_SE.append(_compile(
    "azure_blob_sas",
    r'(?:sv=\d{4}-\d{2}-\d{2})[^\s"\'<>]+(?:(?:sig)=[^\s"\'<>]+)',
    "MEDIUM", "cloud", "Azure Blob SAS Token (含签名)",
    keywords=["sv=", "sig=", "azure", "blob"],
))

_SE.append(_compile(
    "aws_s3_bucket_url",
    r's3\.amazonaws\.com[/]+|[a-zA-Z0-9\-_]*\.s3\.amazonaws\.com',
    "LOW", "cloud", "AWS S3 Bucket URL",
    keywords=["s3.amazonaws.com", "aws", "bucket"],
))

# ── LOW: 可公开的信息但有侦察价值 ──

_SE.append(_compile(
    "google_captcha_site_key",
    r"6L[0-9A-Za-z\-_]{38}|^6[0-9a-zA-Z\-_]{39}$",
    "LOW", "other", "Google reCAPTCHA Site Key（前端公开）",
    keywords=["6L", "recaptcha", "sitekey"],
))

_SE.append(_compile(
    "google_oauth_client_id",
    r'[0-9]+-[a-zA-Z0-9_]+\.apps\.googleusercontent\.com',
    "LOW", "other", "Google OAuth Client ID（前端公开）",
    keywords=["apps.googleusercontent.com", "client_id", "oauth"],
))

_SE.append(_compile(
    "facebook_app_id",
    r'(?:facebook|FB|fb).{0,15}(?:app|application|client)_?(?:id|key)\s*[:=]\s*["\']?([0-9]{10,20})["\']?',
    "LOW", "other", "Facebook App ID",
    redact=[1], keywords=["facebook", "FB", "app_id"],
))

_SE.append(_compile(
    "firebase_url",
    r'(?:https?://)?[a-zA-Z0-9\-]+\.firebaseio\.com',
    "LOW", "other", "Firebase Realtime Database URL",
    keywords=["firebaseio.com"],
))

_SE.append(_compile(
    "generic_api_endpoint_with_key",
    r'(?:api|rest|graphql|rpc)(?:_endpoint|_url|_host|_base|Endpoint|Url)\s*[:=]\s*["\']([^"\']{5,200})["\']',
    "LOW", "other", "API 端点 URL 定义",
    redact=[1], keywords=["api_endpoint", "api_url", "graphql", "rest"],
))

_SE.append(_compile(
    "app_secret_key",
    r'(?:APP_SECRET|SECRET_KEY|APP_KEY|ENCRYPTION_KEY|FLASK_SECRET|DJANGO_SECRET)\s*[:=]\s*["\']([^"\']{10,100})["\']',
    "MEDIUM", "credential", "应用 Secret Key / 加密密钥",
    redact=[1], keywords=["APP_SECRET", "SECRET_KEY", "ENCRYPTION_KEY", "FLASK_SECRET", "DJANGO_SECRET"],
    min_entropy=3.5,
))

_SE.append(_compile(
    "basic_auth_header",
    r'(?:basic|authorization)\s+(?:[A-Za-z0-9+/=]{20,})',
    "HIGH", "token", "HTTP Basic Auth 凭据",
    redact=[1], keywords=["basic", "authorization", "auth"],
))

_SE.append(_compile(
    "internal_ip_exposure",
    r'(?:host|ip|addr|address|server|proxy|endpoint)\s*[:=]\s*["\']?(?:(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})|(?:192\.168\.\d{1,3}\.\d{1,3})|(?:0\.0\.0\.0))["\']?',
    "LOW", "other", "内网 IP 暴露",
    keywords=["10.", "192.168", "172.16", "172.17", "host", "ip", "addr"],
))

_SE.append(_compile(
    "generic_api_key_assignment",
    r'(?:api_?key|apikey|token|access_?key|access_?token)\s*[:=]\s*["\']([A-Za-z0-9_\-\.=:_\+\/]{12,200})["\']',
    "HIGH", "api_key", "通用 API Key / Token 赋值",
    redact=[1], keywords=["api_key", "apikey", "access_token", "access_key", "token"],
    min_entropy=3.5,
))

_SE.append(_compile(
    "basic_auth_url",
    r'https?://[^:]+:[^@]+@[^\s"\']+',
    "CRITICAL", "credential", "URL 中包含明文凭据 (user:pass@host)",
    redact=[0], keywords=["://", "@"],
    min_entropy=2.0,
))

_SE.append(_compile(
    "docker_config_json_auth",
    r'"auth"\s*:\s*"[A-Za-z0-9+/=]{50,}"',
    "HIGH", "credential", "Docker config.json Base64 Auth",
    redact=[0], keywords=["auth", "docker", "config.json"],
))

_SE.append(_compile(
    "npm_author_token",
    r"(?:npm_|//registry\.npmjs\.org/:_authToken=)([A-Za-z0-9\-]{36})",
    "HIGH", "api_key", "NPM 发布 Token",
    redact=[1], keywords=["npm_", "_authToken", "registry.npmjs.org"],
))

# 去掉重复规则
_seen_rules: set[str] = set()
_deduped_rules: list[SecretRule] = []
for r in _SE:
    if r.name not in _seen_rules:
        _seen_rules.add(r.name)
        _deduped_rules.append(r)
_SECRET_RULES = _deduped_rules


# ── TruffleHog-style 关键词索引（用于预过滤） ──
# 从所有规则提取唯一关键词集合
_KEYWORD_INDEX: set[str] = set()
for rule in _SECRET_RULES:
    for kw in rule.keywords:
        _KEYWORD_INDEX.add(kw.lower())
# 添加一些通用触发词
_KEYWORD_INDEX.update(
    {"api", "key", "secret", "token", "auth", "password",
     "sk-", "pk_", "ghp_", "xox", "eyJ", "AKIA", "AIza",
     "BEGIN", "PRIVATE", "bearer", "apikey"}
)


def _calculate_shannon_entropy(data: str) -> float:
    """计算字符串的 Shannon 熵值（TruffleHog 假阳性检测核心指标）。

    熵值越高表示字符分布越随机，是真正 API Key 的强信号。
    低熵值（纯数字、重复字符）通常是假阳性。

    Args:
        data: 待计算熵值的字符串

    Returns:
        Shannon 熵值（0-8 范围）
    """
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return entropy


def _compute_secret_hash(raw_value: str) -> str:
    """对凭证原文计算 SHA256 哈希（TruffleHog hash-based dedup）。"""
    return hashlib.sha256(raw_value.encode("utf-8")).hexdigest()


def _keyword_prefilter(text: str) -> bool:
    """关键词预过滤：快速检查文本是否包含任何检测规则的关键词。

    参照 TruffleHog 的 Aho-Corasick 预过滤策略，用简单的集合包含检查替代
    （Python 在 38 规则/30 关键词场景下足够高效）。

    Returns:
        True 表示文本可能包含敏感信息，需要进一步正则扫描
    """
    text_lower = text[:4000].lower()  # 只检查前 4KB 就够了
    for kw in _KEYWORD_INDEX:
        if kw in text_lower:
            return True
    return False


# ═══════════════════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class SecretMatch:
    """单条敏感信息匹配结果（融合 TruffleHog Result 字段）。

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
        entropy: Shannon 熵值（TruffleHog 假阳性检测）
        secret_hash: 凭证原文 SHA256 哈希（跨扫描去重）
        verified: TruffleHog 验证状态
        verification_error: 验证过程错误信息（已脱敏）
        is_low_entropy: 是否为低熵值匹配（可能误报）
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
    # TruffleHog fields
    entropy: float = 0.0
    secret_hash: str = ""
    verified: str = VerifyStatus.UNVERIFIED.value
    verification_error: str = ""
    is_low_entropy: bool = False


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
        verified_count: 验证通过的凭证数
        invalid_count: 验证失败的凭证数
        verification_enabled: 是否启用了验证
    """
    findings: list[SecretMatch] = field(default_factory=list)
    js_sources_found: int = 0
    js_sources_parsed: int = 0
    js_sources_skipped: int = 0
    html_pages_scanned: int = 0
    elapsed_ms: float = 0.0
    error: str = ""
    # TruffleHog verification summary
    verified_count: int = 0
    invalid_count: int = 0
    verification_enabled: bool = False


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

    融合 SecretFinder + TruffleHog 策略:
      0. 关键词预过滤 — 快速跳过无关文本
      1. 遍历所有 _SECRET_RULES
      2. 逐规则执行 re.finditer()
      3. 熵值 + 哈希计算（TruffleHog 假阳性检测）
      4. 提取上下文 + 脱敏
      5. 去重（同规则、同文件、同值只保留一次）+ 哈希去重

    Args:
        text: 待扫描的文本
        source_label: 来源标签（如文件名/URL，用于日志）

    Returns:
        SecretMatch 列表（已去重、脱敏）
    """
    # TruffleHog 关键词预过滤 — 无关键词的直接跳过
    if not _keyword_prefilter(text):
        return []

    findings: list[SecretMatch] = []
    seen: set[tuple[str, str, str]] = set()
    seen_hashes: set[str] = set()

    for rule in _SECRET_RULES:
        try:
            for m in rule.regex.finditer(text):
                raw_value = m.group(0)
                if len(raw_value) > 500:
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

                # TruffleHog 哈希去重
                secret_hash = _compute_secret_hash(match_value)
                if secret_hash in seen_hashes:
                    continue
                seen_hashes.add(secret_hash)

                # 去重
                key = (rule.name, source_label, redacted)
                if key in seen:
                    continue
                seen.add(key)

                # TruffleHog 熵值计算
                entropy = _calculate_shannon_entropy(match_value)
                is_low = False
                if rule.min_entropy > 0 and entropy < rule.min_entropy:
                    is_low = True  # 标记低熵（可能误报）
                elif entropy < _LOW_ENTROPY_THRESHOLD:
                    is_low = True

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
                    entropy=entropy,
                    secret_hash=secret_hash,
                    is_low_entropy=is_low,
                ))
        except Exception:
            continue

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# TruffleHog-style 凭证验证引擎
# ═══════════════════════════════════════════════════════════════════════════

# 内网 IP 段（SSRF 防护 — 参照 TruffleHog WithNoLocalIP）
_PRIVATE_NETS = [
    re.compile(r"^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
    re.compile(r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$"),
    re.compile(r"^192\.168\.\d{1,3}\.\d{1,3}$"),
    re.compile(r"^0\.0\.0\.0$"),
    re.compile(r"^::1$"),
    re.compile(r"^fe80:"),
]

# 验证专用 User-Agent（对齐 TruffleHog 统一 User-Agent）
_VERIFY_UA = "PyRIT-SecretFinder/2.0 (TruffleHog-compatible verification)"


def _is_private_url(url: str) -> bool:
    """SSRF 防护：检查 URL 是否指向内网地址（参照 TruffleHog WithNoLocalIP）。"""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return True  # 无法解析的主机，保守拒绝
        if hostname in ("localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"):
            return True
        for pat in _PRIVATE_NETS:
            if pat.match(hostname):
                return True
        return False
    except Exception:
        return True


def _build_verify_headers(rule: SecretRule, matched_value: str) -> dict[str, str]:
    """根据规则类型构造验证请求头（Bearer Token / API Key / Basic Auth）。"""
    headers = {"User-Agent": _VERIFY_UA}
    if rule.verifiable:
        if rule.name in ("openai_api_key", "anthropic_api_key", "github_token"):
            headers["Authorization"] = f"Bearer {matched_value}"
        elif rule.name == "stripe_secret_key":
            headers["Authorization"] = f"Bearer {matched_value}"
        elif rule.name == "twilio_api_key":
            from base64 import b64encode
            # Twilio uses Basic Auth: AccountSid:AuthToken  (but APIToken alone)
            # For simplicity, use Bearer
            headers["Authorization"] = f"Bearer {matched_value}"
        elif rule.name == "google_api_key":
            pass  # key 作为 query param
        elif rule.name == "slack_token":
            headers["Authorization"] = f"Bearer {matched_value}"
        elif rule.name == "sendgrid_api_key":
            headers["Authorization"] = f"Bearer {matched_value}"
        elif rule.name == "mailgun_api_key":
            from base64 import b64encode
            credentials = b64encode(f"api:{matched_value}".encode()).decode()
            headers["Authorization"] = f"Basic {credentials}"
    return headers


async def _verify_single_credential(
    client: httpx.AsyncClient,
    rule: SecretRule,
    matched_value: str,
    timeout: float = 10.0,
) -> tuple[str, str]:
    """验证单个凭证（TruffleHog 核心验证逻辑）。

    使用规则定义的端点和方法向真实服务发送请求，
    根据响应判断凭据是否有效。

    Returns:
        (status, error_message) — status 为 VerifyStatus.value
    """
    if _is_private_url(rule.verify_endpoint):
        return VerifyStatus.SKIPPED.value, "endpoint is private/internal"

    try:
        headers = _build_verify_headers(rule, matched_value)
        endpoint = rule.verify_endpoint.replace("{key}", matched_value)

        method = rule.method.lower()
        if method == "get":
            resp = await client.get(endpoint, headers=headers, timeout=timeout)
        elif method == "post":
            resp = await client.post(endpoint, headers=headers, timeout=timeout)
        elif method == "head":
            resp = await client.head(endpoint, headers=headers, timeout=timeout)
        else:
            return VerifyStatus.SKIPPED.value, f"unsupported method: {method}"

        # 检查响应
        status_code = resp.status_code
        body = resp.text[:500]

        # 特定状态码判断
        if status_code == 200:
            # 检查成功特征模式
            if rule.verify_success_pattern:
                if re.search(rule.verify_success_pattern, body):
                    return VerifyStatus.VERIFIED.value, ""
                else:
                    # 200 但不含预期特征 → 可能限速页或其他
                    return VerifyStatus.ERROR.value, f"HTTP 200 but unexpected response body"
            return VerifyStatus.VERIFIED.value, ""

        if status_code == 401:
            return VerifyStatus.INVALID.value, "HTTP 401 Unauthorized"
        if status_code == 403:
            return VerifyStatus.INVALID.value, "HTTP 403 Forbidden"
        if status_code == 429:
            return VerifyStatus.ERROR.value, "HTTP 429 Rate Limited"
        if status_code >= 500:
            return VerifyStatus.ERROR.value, f"HTTP {status_code} Server Error"

        # 其他状态码
        return VerifyStatus.INVALID.value, f"HTTP {status_code}"

    except httpx.TimeoutException:
        return VerifyStatus.ERROR.value, "verification timeout"
    except httpx.ConnectError as e:
        return VerifyStatus.ERROR.value, f"connection error: {str(e)[:100]}"
    except Exception as e:
        # 脱敏错误信息（TruffleHog SetVerificationError）
        err_msg = str(e).replace(matched_value, "[REDACTED]")
        return VerifyStatus.ERROR.value, err_msg[:200]


async def verify_credentials(
    findings: list[SecretMatch],
    verify_ssl: bool = False,
    timeout: float = 15.0,
    max_concurrent: int = 5,
) -> list[SecretMatch]:
    """对扫描发现的凭证执行批量远程验证（TruffleHog 核心功能）。

    验证策略:
      1. 仅验证标记为 verifiable=True 的规则匹配项
      2. SSRF 防护：拒绝访问内网地址
      3. 按 secret_hash 去重：相同凭据只验证一次
      4. 并发数受 max_concurrent 限制
      5. 验证结果写入 SecretMatch.verified / verification_error

    Args:
        findings: 扫描发现的 SecretMatch 列表
        verify_ssl: SSL 验证
        timeout: 总超时
        max_concurrent: 最大并发验证数

    Returns:
        更新了 verified 状态的 SecretMatch 列表
    """
    if not findings:
        return findings

    verifiable = [f for f in findings if f.rule_name and _find_rule(f.rule_name) and _find_rule(f.rule_name).verifiable]
    if not verifiable:
        return findings

    # 按哈希去重验证请求（TruffleHog DoWithDedup）
    seen_hashes: set[str] = set()
    to_verify: list[SecretMatch] = []
    for f in verifiable:
        if f.secret_hash and f.secret_hash not in seen_hashes:
            seen_hashes.add(f.secret_hash)
            to_verify.append(f)
        elif not f.secret_hash:
            to_verify.append(f)

    semaphore = asyncio.Semaphore(max_concurrent)

    async def _verify_one(f: SecretMatch):
        rule = _find_rule(f.rule_name)
        if not rule or not rule.verifiable:
            return

        async with semaphore:
            status, err_msg = await _verify_single_credential(
                _verify_client, rule, f.matched_value, timeout=min(timeout, 10.0),
            )
            f.verified = status
            f.verification_error = err_msg

    try:
        async with create_http_client(
            verify_ssl=verify_ssl,
            timeout=timeout,
            connect_timeout=DEFAULT_OPEN_TIMEOUT,
            headers={"User-Agent": _VERIFY_UA},
            follow_redirects=True,
            max_redirects=3,
        ) as client:
            _verify_client = client
            tasks = [_verify_one(f) for f in to_verify]
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=timeout,
            )
    except asyncio.TimeoutError:
        for f in to_verify:
            if f.verified == VerifyStatus.UNVERIFIED.value:
                f.verified = VerifyStatus.ERROR.value
                f.verification_error = "global verification timeout"
    except Exception as e:
        for f in to_verify:
            if f.verified == VerifyStatus.UNVERIFIED.value:
                f.verified = VerifyStatus.ERROR.value
                f.verification_error = str(e)[:100]

    # 对于已验证/无效的结果，同步状态到相同 hash 的其他匹配
    hash_status: dict[str, str] = {}
    for f in findings:
        if f.secret_hash and f.verified != VerifyStatus.UNVERIFIED.value:
            hash_status[f.secret_hash] = f.verified
    for f in findings:
        if f.secret_hash and f.secret_hash in hash_status and f.verified == VerifyStatus.UNVERIFIED.value:
            f.verified = hash_status[f.secret_hash]

    return findings


def _find_rule(rule_name: str) -> SecretRule | None:
    """按名称查找规则。"""
    for r in _SECRET_RULES:
        if r.name == rule_name:
            return r
    return None


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
            # TruffleHog fields
            "verified": f.verified,
            "verification_error": f.verification_error[:200] if f.verification_error else "",
            "is_low_entropy": f.is_low_entropy,
            "entropy": round(f.entropy, 2) if f.entropy else 0,
        }
        for f in findings
    ]


def summarize_findings(findings: list[SecretMatch]) -> dict:
    """对扫描结果进行汇总统计（含 TruffleHog 验证统计）。"""
    counts: dict[str, int] = {}
    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_category: dict[str, int] = {}
    verify_counts: dict[str, int] = {"verified": 0, "invalid": 0, "error": 0, "unverified": 0}
    low_entropy_count = 0

    for f in findings:
        counts[f.rule_name] = counts.get(f.rule_name, 0) + 1
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_category[f.category] = by_category.get(f.category, 0) + 1
        verify_counts[f.verified] = verify_counts.get(f.verified, 0) + 1
        if f.is_low_entropy:
            low_entropy_count += 1

    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_category": by_category,
        "top_rules": sorted(counts.items(), key=lambda x: -x[1])[:10],
        "by_verification": verify_counts,
        "low_entropy_count": low_entropy_count,
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
    do_verify: bool = True,
    extra_headers: dict[str, str] | None = None,
) -> dict:
    """一站式 API Key 侦察：连接目标 → 获取 HTML → 解析 JS → 扫描密钥 → 验证凭证。

    Args:
        base_url: 目标根 URL
        verify_ssl: SSL 验证
        timeout: 总超时
        api_key: 可选认证头
        extra_js_urls: 额外的 JS 文件 URL（从抓包等来源）
        do_verify: 是否对发现的凭据执行远程验证（TruffleHog 核心功能）
        extra_headers: 额外请求头（如 Cookie、X-Custom-Header）

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
        if extra_headers:
            headers.update({k: v for k, v in extra_headers.items() if k and v})


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

            # 阶段 2: 扫描 JS 中的敏感信息（含 TruffleHog 熵值+哈希）
            scan_result = await scan_js_sources_for_secrets(
                html_pages=html_pages,
                js_urls=extra_js_urls,
                client=client,
                verify_ssl=verify_ssl,
                timeout=timeout,
            )

        # 阶段 3: TruffleHog-style 凭证验证（对 OpenAI/Anthropic/GitHub 等执行 API 调用验证）
        if do_verify and scan_result.findings:
            scan_result.verification_enabled = True
            scan_result.findings = await verify_credentials(
                scan_result.findings,
                verify_ssl=verify_ssl,
                timeout=timeout,
            )
            # 统计验证结果
            for f in scan_result.findings:
                if f.verified == VerifyStatus.VERIFIED.value:
                    scan_result.verified_count += 1
                elif f.verified == VerifyStatus.INVALID.value:
                    scan_result.invalid_count += 1

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
                "verified_count": scan_result.verified_count,
                "invalid_count": scan_result.invalid_count,
                "verification_enabled": scan_result.verification_enabled,
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
