"""响应分析与漏洞推断 — 从端点响应提取路径并检测漏洞提示。

学术依据:
    - arXiv:2306.01943 §5 — API 响应中的路径引用可揭示隐藏端点
    - arXiv:2306.01943 §3.1 — OpenAPI 规范是端点发现的黄金标准
    - OWASP Top 10 (2025) — 端点关键词按漏洞分类分级
"""

from __future__ import annotations

import re

# ══════════════════════════════════════════════════════════════
# 响应引导扩展 (Layer 4)
# ══════════════════════════════════════════════════════════════

def _extract_paths_from_response(
    response_text: str,
) -> list[str]:
    """从响应内容中提取可能的 API 路径。

    学术依据: arXiv:2306.01943 §5
      — API 响应中的路径引用 (links, href, endpoints) 可揭示隐藏端点
      — OpenAPI/Swagger JSON 中的 paths 字段是最高价值来源

    提取模式:
        1. JSON 中的 paths 字段 (OpenAPI 规范)
        2. href/link 字段
        3. 相对路径 (以 / 开头的 URL)
    """
    paths: list[str] = []

    # 模式 1: OpenAPI paths 字段
    # 匹配 "paths": { "/api/xxx": ... }
    path_matches = re.findall(
        r'"paths"\s*:\s*\{[^}]*"(/[a-zA-Z0-9_/\-{}\.]+)"',
        response_text,
    )
    paths.extend(path_matches)

    # 模式 2: href/link 字段
    href_matches = re.findall(
        r'"(?:href|link|url|path|endpoint)"\s*:\s*"(/[a-zA-Z0-9_/\-\.]+)"',
        response_text,
    )
    paths.extend(href_matches)

    # 模式 3: 相对路径 (保守匹配, 避免误报)
    # 仅匹配以 / 开头且长度合理的路径
    rel_matches = re.findall(
        r'"(/[a-zA-Z0-9_/\-]{3,80})"',
        response_text[:5000],  # 仅在前 5000 字符搜索 (性能优化)
    )
    paths.extend(rel_matches)

    # 去重 + 过滤
    seen: set[str] = set()
    unique: list[str] = []
    for p in paths:
        # 过滤掉静态资源路径
        if any(p.endswith(ext) for ext in (".css", ".js", ".png", ".jpg", ".svg", ".ico")):
            continue
        if p not in seen and len(p) > 2:
            seen.add(p)
            unique.append(p)

    return unique


# ══════════════════════════════════════════════════════════════
# OpenAPI 规范解析
# ══════════════════════════════════════════════════════════════

def _parse_openapi_paths(response_text: str) -> list[str]:
    """解析 OpenAPI/Swagger JSON, 提取所有路径。

    学术依据: arXiv:2306.01943 §3.1
      — OpenAPI 规范是 API 端点发现的黄金标准
      — 单次请求可获取全部端点定义, 覆盖率 100%
    """
    paths: list[str] = []
    try:
        import json
        data = json.loads(response_text)
        api_paths = data.get("paths", {})
        for path, methods in api_paths.items():
            if path.startswith("/"):
                paths.append(path)
            # 也探测 path 中的子路径
    except (json.JSONDecodeError, ValueError):
        pass

    return paths


# ══════════════════════════════════════════════════════════════
# 漏洞提示检测
# ══════════════════════════════════════════════════════════════

def _detect_vuln_hints(
    path: str,
    status_code: int,
    response_preview: str,
    content_type: str,
) -> list[str]:
    """从路径和响应推断端点可能的漏洞类型。

    基于路径段关键词 (不依赖硬编码前缀) 和响应内容进行推断。
    增加对 403/401 状态码的推断 (端点存在但需认证 → IDOR/Auth 攻击面)。

    Args:
        path: 端点路径。
        status_code: HTTP 状态码。
        response_preview: 响应预览 (前 500 字符)。
        content_type: 响应 Content-Type。

    Returns:
        漏洞类型提示列表。
    """
    hints: list[str] = []
    path_segments = path.rstrip("/").split("/")
    last_segment = path_segments[-1].lower() if path_segments else ""
    path_lower = path.lower()
    preview_lower = response_preview.lower()

    # ── 基于状态码推断 ──
    # 403 Forbidden → 端点存在但需要认证 → IDOR / 权限绕过攻击面
    if status_code == 403:
        hints.append("idor")
        hints.append("auth_bypass")
    # 401 Unauthorized → 认证绕过 / JWT 攻击面
    elif status_code == 401:
        hints.append("auth_bypass")
        hints.append("sqli_auth")
    # 405 Method Not Allowed → 方法覆盖攻击面
    elif status_code == 405:
        hints.append("method_override")

    # ── 基于路径段推断 ──
    # A01: Broken Access Control
    if last_segment in ("user", "users", "profile", "account", "accounts"):
        hints.append("idor")
        hints.append("path_traversal")

    # A02: Cryptographic Failures
    if last_segment in ("keys", "cert", "crypto") or "crypto" in last_segment:
        hints.append("info_leak")
        hints.append("crypto_failure")

    # A03: Injection (SQLi, NoSQLi, Command Injection, XSS)
    if last_segment in ("search", "query"):
        hints.append("sqli")
        hints.append("xss_reflected")
    if last_segment in ("reflect", "comment"):
        hints.append("xss")
        hints.append("xss_reflected")

    # A04: Insecure Design (Business Logic)
    if last_segment in ("order", "checkout", "coupon"):
        hints.append("business_logic")
        hints.append("mass_assignment")

    # A05: Security Misconfiguration
    if last_segment in ("debug", "env", "config"):
        hints.append("info_leak")
        hints.append("path_traversal")
    if last_segment in ("upload", "xml", "parse"):
        hints.append("xxe")
        hints.append("deserialization")

    # A06: Vulnerable & Outdated Components
    if last_segment in ("actuator", "version"):
        hints.append("vulnerable_component")
        hints.append("info_leak")

    # A07: Identification & Authentication Failures
    if last_segment in ("login", "auth", "token"):
        hints.append("auth_bypass")
        hints.append("sqli_auth")

    # A09: Security Logging & Monitoring Failures
    if last_segment in ("log", "audit", "events"):
        hints.append("log_injection")
        hints.append("info_leak")

    # A10: SSRF
    if last_segment in ("fetch", "proxy", "url"):
        hints.append("ssrf")

    # LLM01: Prompt Injection
    if last_segment in ("chat", "ask"):
        hints.append("llm_injection")
        hints.append("prompt_injection")

    # ── 基于响应内容推断 ──
    if "sql" in preview_lower or "mysql" in preview_lower or "postgresql" in preview_lower:
        hints.append("sqli")
    if "error" in preview_lower and ("syntax" in preview_lower or "query" in preview_lower):
        hints.append("sqli")
    if "stack trace" in preview_lower or "exception" in preview_lower:
        hints.append("info_leak")
    if "application/json" in content_type and ("api_key" in preview_lower or "secret" in preview_lower):
        hints.append("info_leak")
    # Spring Boot Actuator 响应特征
    if "_links" in preview_lower and ("actuator" in path_lower or "health" in path_lower):
        hints.append("vulnerable_component")
        hints.append("info_leak")

    return list(set(hints))


# ══════════════════════════════════════════════════════════════
# 漏洞类型标准化
# ══════════════════════════════════════════════════════════════

def _normalize_vuln_type(vuln_type: str) -> str:
    """标准化漏洞类型名称 — 对齐 OWASP Top 10 (2025) 分类。"""
    vt = vuln_type.lower()
    # 映射到 hint 名称
    # A03: Injection — SQLi
    if "sqli" in vt or "sql_injection" in vt or "auth_bypass_sqli" in vt:
        if "auth" in vt:
            return "sqli_auth"
        return "sqli"
    # A03: Injection — NoSQLi
    if "nosql" in vt:
        return "sqli"  # NoSQLi 归类到 injection 大类
    # A03: Injection — Command Injection
    if "command" in vt:
        return "command_injection"
    # A03: Injection — XSS
    if "xss" in vt:
        if "reflected" in vt:
            return "xss_reflected"
        return "xss"
    # A01: Broken Access Control
    if "idor" in vt:
        return "idor"
    if "path_traversal" in vt:
        return "path_traversal"
    # A10: SSRF
    if "ssrf" in vt:
        return "ssrf"
    # A07: Identification & Authentication Failures
    if "auth" in vt:
        return "auth_bypass"
    if "jwt" in vt:
        return "auth_bypass"
    if "default" in vt or "weak" in vt or "credential" in vt:
        return "auth_bypass"
    # A05: Security Misconfiguration
    if "xxe" in vt:
        return "xxe"
    if "deserialization" in vt or "php_deser" in vt:
        return "deserialization"
    if "info" in vt or "env" in vt or "debug" in vt or "git" in vt:
        return "info_leak"
    # A02: Cryptographic Failures
    if "crypto" in vt or "hash" in vt:
        return "info_leak"
    # A04: Insecure Design (Business Logic)
    if "business" in vt or "mass_assignment" in vt or "coupon" in vt:
        return "business_logic"
    # A06: Vulnerable & Outdated Components
    if "log4shell" in vt or "spring4shell" in vt or "cve_" in vt:
        return "vulnerable_component"
    # A09: Security Logging & Monitoring Failures
    if "log_injection" in vt or "audit" in vt:
        return "log_injection"
    # LLM01: Prompt Injection
    if "llm" in vt or "prompt" in vt or "indirect" in vt:
        return "llm_injection"
    return vt
