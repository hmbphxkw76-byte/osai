"""端点发现常量 — 路径词库与数据类。

学术依据:
    - OWASP WSTG-INFO-03 (Fingerprint Web Application Framework)
    - PTES §2: Intelligence Gathering
    - Arbis et al. (arXiv:2306.01943) §4.2 — 关键词覆盖率 >85%
    - OWASP API Security Top 10 (2025) + OWASP Top 10 (2025)
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ══════════════════════════════════════════════════════════════
# Layer 0: API 规范文档路径 (最高优先级)
# 学术依据: arXiv:2306.01943 — OpenAPI/Swagger 文档可一次性揭示全部端点
# ══════════════════════════════════════════════════════════════
_API_SPEC_PATHS: list[str] = [
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/api/v1/openapi.json",
    "/api-docs",
    "/api/docs",
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/api/swagger-ui.html",
    "/v3/api-docs",
    "/graphql",
    "/graphql/schema.json",
    "/api/graphql",
    "/.well-known/security.txt",
]

# ══════════════════════════════════════════════════════════════
# Layer 1: 高价值信息泄露/框架指纹端点
# 学术依据: OWASP WSTG-INFO-03 — 框架指纹识别后针对性探测
# ══════════════════════════════════════════════════════════════
_HIGH_VALUE_PATHS: list[str] = [
    # Spring Boot Actuator (信息泄露)
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/info",
    "/actuator/mappings",
    "/actuator/beans",
    "/actuator/configprops",
    "/actuator/loggers",
    # 环境泄露
    "/.env",
    "/.git/config",
    "/config",
    "/debug",
    "/env",
    # 健康检查 (信息泄露)
    "/health",
    "/status",
    "/info",
    # 版本信息
    "/version",
    "/api/version",
    # robots.txt (路径线索)
    "/robots.txt",
    "/sitemap.xml",
]

# ══════════════════════════════════════════════════════════════
# Layer 2: 端点关键词词库 — 按 OWASP Top 10 (2025) 分级
# 高频高价值关键词优先 (学术依据: arXiv:2306.01943 §4.2
#   — API 端点名称在 top-50 关键词中的覆盖率 >85%)
# ══════════════════════════════════════════════════════════════
# Tier A: 最高频端点名 (CRUD + 认证 + 搜索)
_TIER_A_KEYWORDS: list[str] = [
    "users", "user", "login", "auth", "search", "query",
    "profile", "account", "accounts",
]

# Tier B: 高频端点名 (业务逻辑 + 数据操作)
_TIER_B_KEYWORDS: list[str] = [
    "chat", "ask", "fetch", "proxy", "upload", "data",
    "import", "parse", "order", "checkout", "coupon",
    "comment", "reflect",
]

# Tier C: 中频端点名 (安全相关 + 基础设施)
_TIER_C_KEYWORDS: list[str] = [
    "token", "keys", "cert", "crypto",
    "debug", "env", "config",
    "log", "audit", "events",
    "actuator", "version",
    "health", "status", "info",
    "xml", "url",
]

# 全部关键词 (按 Tier 排序, 高优先级在前)
_ALL_KEYWORDS: list[str] = _TIER_A_KEYWORDS + _TIER_B_KEYWORDS + _TIER_C_KEYWORDS

# ══════════════════════════════════════════════════════════════
# Layer 3: 通用 API 版本前缀 (版本化探测)
# 学术依据: arXiv:2306.01943 §4.3 — /api/v{N}/ 是最常见版本模式
# ══════════════════════════════════════════════════════════════
_API_VERSION_PREFIXES: list[str] = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/api/latest",
    "/v1",
    "/v2",
    "/rest",
    "/rest/v1",
    "/service",
    "/services",
]

# ══════════════════════════════════════════════════════════════
# Layer 5: 通用基线路径 (仅在前面层发现不足时使用)
# ══════════════════════════════════════════════════════════════
_BASELINE_PATHS: list[str] = [
    "/api/users",
    "/api/user",
    "/api/profile",
    "/api/search",
    "/api/query",
    "/api/login",
    "/api/auth",
    "/api/fetch",
    "/api/proxy",
    "/api/debug",
    "/api/env",
    "/api/config",
    "/api/info",
    "/api/status",
    "/api/chat",
    "/api/health",
    "/api/v1/users",
    "/api/v1/search",
    "/api/v1/login",
    "/api/v2/users",
    "/api/v2/search",
]

# 200/301/302/403 → 端点存在, 仅 404 → 不存在
# 学术依据: arXiv:2306.01943 §4.1 — 403 (Forbidden) 表示端点存在但需要认证
_VALID_STATUS_CODES: set[int] = {200, 201, 301, 302, 307, 308, 401, 403, 405, 422}


@dataclass
class DiscoveredEndpoint:
    """发现的端点信息。"""

    path: str
    method: str = "GET"
    status_code: int = 0
    content_type: str = ""
    response_length: int = 0
    response_preview: str = ""
    # 检测到的漏洞类型提示
    vuln_hints: list[str] = field(default_factory=list)
    # 端点是否可用
    available: bool = False
    # 端点接受的参数 (从响应推断)
    expected_params: list[str] = field(default_factory=list)
    # 发现层级 (0=spec, 1=high-value, 2=same-prefix, 3=version, 4=guided, 5=baseline)
    discovery_layer: int = 5
    # 是否来自 OpenAPI 规范
    from_spec: bool = False
