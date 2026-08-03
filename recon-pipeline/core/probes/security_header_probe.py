# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Security header analysis probe — CORS, CSP, HSTS, and other security headers.

Analyzes HTTP security headers from discovered endpoints:
  1. CORS configuration (Access-Control-Allow-Origin, credentials, methods)
  2. CSP policy analysis (unsafe-inline, wildcard sources, missing directives)
  3. HSTS configuration
  4. Missing security headers (X-Frame-Options, X-Content-Type-Options, etc.)
  5. Cache-Control for sensitive endpoints
  6. Server header disclosure
  7. Cross-Origin security headers (COOP, COEP, CORP)
  8. Permissions-Policy
  9. Referrer-Policy

Architecture:
  - Input: endpoints from session.report with response headers
  - Output: security_findings (categorized security issues)
  - Browser: False
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from core.probes.base import ReconProbe

if TYPE_CHECKING:
    from core.session import ReconSession

logger = logging.getLogger(__name__)

# Security headers that should be present on all responses
_REQUIRED_SECURITY_HEADERS: dict[str, str] = {
    "x-content-type-options": "Prevents MIME type sniffing",
    "x-frame-options": "Prevents clickjacking",
    "strict-transport-security": "Enforces HTTPS (HSTS)",
    "referrer-policy": "Controls referrer information leakage",
    "permissions-policy": "Controls browser feature access",
}

# CORS misconfiguration patterns
_CORS_MISCONFIG_PATTERNS: list[tuple[str, str, str]] = [
    ("access-control-allow-origin", "*", "CORS: Wildcard allow-origin with credentials"),
    ("access-control-allow-origin", "null", "CORS: 'null' origin allowed (sandboxed iframe bypass)"),
    ("access-control-allow-credentials", "true", "CORS: Credentials allowed (check allow-origin)"),
]

# CSP dangerous directives
_CSP_DANGEROUS_DIRECTIVES: list[tuple[str, str]] = [
    ("unsafe-inline", "CSP: 'unsafe-inline' allows inline scripts (XSS risk)"),
    ("unsafe-eval", "CSP: 'unsafe-eval' allows eval() (code injection risk)"),
    ("*", "CSP: Wildcard source allows loading from any origin"),
    ("data:", "CSP: data: URI allowed (XSS via data URL)"),
    ("blob:", "CSP: blob: URI allowed"),
    ("https:", "CSP: Scheme-only source (allows any HTTPS origin)"),
    ("http:", "CSP: HTTP source allowed (downgrade attack risk)"),
    ("ws:", "CSP: WebSocket allowed from any origin"),
    ("filesystem:", "CSP: filesystem: URI allowed"),
]

# Server headers that should NOT be exposed
_SERVER_DISCLOSURE_HEADERS: list[str] = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-drupal-dynamic-cache",
]

# Sensitive endpoints that should have strict Cache-Control
_SENSITIVE_ENDPOINT_PATTERNS: list[str] = [
    "/api/", "/v1/", "/chat", "/completion", "/auth", "/login", "/token",
    "/user", "/account", "/admin",
]

# Cross-Origin isolation headers
_CROSS_ORIGIN_HEADERS: dict[str, str] = {
    "cross-origin-opener-policy": "COOP: Controls cross-origin window interactions",
    "cross-origin-embedder-policy": "COEP: Controls cross-origin resource embedding",
    "cross-origin-resource-policy": "CORP: Controls cross-origin resource reading",
}


class SecurityHeaderProbe(ReconProbe):
    """Security header analysis probe.

    Analyzes HTTP security headers from discovered endpoints
    for misconfigurations and missing protections.

    Usage::
        probe = SecurityHeaderProbe()
        result = await probe.probe(session)
        # result["security_findings"] -> list of security issues
    """

    @property
    def name(self) -> str:
        return "SecurityHeaderProbe"

    @property
    def requires_browser(self) -> bool:
        return False

    @property
    def requires_auth(self) -> bool:
        return False

    async def probe(self, session: ReconSession) -> dict[str, Any]:
        """Execute security header analysis.

        Args:
            session: Recon session.

        Returns:
            Dict with security_findings and summary.
        """
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()

        for ep in session.report.endpoints:
            headers = ep.request_headers or {}
            if not headers:
                continue

            # Normalize header keys to lowercase
            headers_lower = {k.lower(): v for k, v in headers.items()}

            # 1. Check for missing required security headers
            for header_name, description in _REQUIRED_SECURITY_HEADERS.items():
                if header_name not in headers_lower:
                    finding_key = f"missing:{header_name}:{ep.url}"
                    if finding_key not in seen:
                        seen.add(finding_key)
                        findings.append({
                            "category": "missing_header",
                            "header": header_name,
                            "description": description,
                            "source_url": ep.url,
                            "severity": "medium",
                        })

            # 2. Check CORS configuration
            acao = headers_lower.get("access-control-allow-origin", "")
            acac = headers_lower.get("access-control-allow-credentials", "")
            if acao == "*" and acac == "true":
                finding_key = f"cors:wildcard-credentials:{ep.url}"
                if finding_key not in seen:
                    seen.add(finding_key)
                    findings.append({
                        "category": "cors_misconfig",
                        "issue": "CORS wildcard origin with credentials (credentials will be blocked by browser but header suggests misconfiguration)",
                        "allow_origin": acao,
                        "allow_credentials": acac,
                        "source_url": ep.url,
                        "severity": "high",
                    })
            elif acao == "*":
                finding_key = f"cors:wildcard:{ep.url}"
                if finding_key not in seen:
                    seen.add(finding_key)
                    findings.append({
                        "category": "cors_misconfig",
                        "issue": "CORS wildcard origin (allows any website to make cross-origin requests)",
                        "allow_origin": acao,
                        "source_url": ep.url,
                        "severity": "medium",
                    })
            elif acao == "null":
                finding_key = f"cors:null:{ep.url}"
                if finding_key not in seen:
                    seen.add(finding_key)
                    findings.append({
                        "category": "cors_misconfig",
                        "issue": "CORS 'null' origin allowed (exploitable via sandboxed iframe)",
                        "allow_origin": acao,
                        "source_url": ep.url,
                        "severity": "high",
                    })

            # 3. Analyze CSP if present
            csp = headers_lower.get("content-security-policy", "")
            if csp:
                csp_findings = self._analyze_csp(csp, ep.url, seen)
                findings.extend(csp_findings)
            else:
                finding_key = f"missing:csp:{ep.url}"
                if finding_key not in seen:
                    seen.add(finding_key)
                    findings.append({
                        "category": "missing_header",
                        "header": "content-security-policy",
                        "description": "No CSP header — XSS and data injection attacks are easier",
                        "source_url": ep.url,
                        "severity": "high",
                    })

            # 4. Check server header disclosure
            for server_header in _SERVER_DISCLOSURE_HEADERS:
                if server_header in headers_lower:
                    finding_key = f"server_disclosure:{server_header}:{ep.url}"
                    if finding_key not in seen:
                        seen.add(finding_key)
                        findings.append({
                            "category": "server_disclosure",
                            "header": server_header,
                            "value": headers_lower[server_header],
                            "source_url": ep.url,
                            "severity": "low",
                        })

            # 5. Check Cross-Origin isolation headers
            for co_header, description in _CROSS_ORIGIN_HEADERS.items():
                if co_header not in headers_lower:
                    finding_key = f"missing:{co_header}:{ep.url}"
                    if finding_key not in seen:
                        seen.add(finding_key)
                        findings.append({
                            "category": "missing_header",
                            "header": co_header,
                            "description": description,
                            "source_url": ep.url,
                            "severity": "low",
                        })

            # 6. Check Cache-Control on sensitive endpoints
            if any(pattern in ep.url.lower() for pattern in _SENSITIVE_ENDPOINT_PATTERNS):
                cache_control = headers_lower.get("cache-control", "")
                if not cache_control or "no-store" not in cache_control:
                    finding_key = f"cache:sensitive:{ep.url}"
                    if finding_key not in seen:
                        seen.add(finding_key)
                        findings.append({
                            "category": "cache_misconfig",
                            "issue": "Sensitive endpoint lacks strict Cache-Control (no-store)",
                            "current_cache_control": cache_control or "(none)",
                            "source_url": ep.url,
                            "severity": "medium",
                        })

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings.sort(key=lambda d: severity_order.get(d["severity"], 99))

        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        for f in findings:
            by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
            by_category[f["category"]] = by_category.get(f["category"], 0) + 1

        logger.info(
            "SecurityHeaderProbe: %d security findings (%s)",
            len(findings),
            ", ".join(f"{k}:{v}" for k, v in sorted(by_severity.items())),
        )

        return {
            "security_findings": findings,
            "summary": {
                "total": len(findings),
                "by_severity": by_severity,
                "by_category": by_category,
            },
        }

    def _analyze_csp(self, csp: str, source_url: str, seen: set[str]) -> list[dict[str, Any]]:
        """Analyze CSP policy for dangerous directives."""
        findings: list[dict[str, Any]] = []
        csp_lower = csp.lower()

        for directive, description in _CSP_DANGEROUS_DIRECTIVES:
            if directive in csp_lower:
                finding_key = f"csp:{directive}:{source_url}"
                if finding_key not in seen:
                    seen.add(finding_key)
                    findings.append({
                        "category": "csp_weakness",
                        "directive": directive,
                        "description": description,
                        "source_url": source_url,
                        "severity": "medium" if directive in ("unsafe-inline", "unsafe-eval") else "low",
                    })

        return findings
