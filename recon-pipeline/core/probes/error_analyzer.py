# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Error message analysis probe — detect information disclosure in API errors.

Analyzes API error responses for information leakage:
  1. Stack traces in error messages
  2. Internal paths / file system references
  3. Database error messages (SQL, connection strings)
  4. Framework version disclosure
  5. Server software disclosure (nginx, uvicorn, gunicorn versions)
  6. Debug mode indicators
  7. Internal IP/hostname disclosure
  8. API key / token fragments in error responses
  9. Model architecture hints in error messages
  10. Configuration file paths

Architecture:
  - Input: endpoints from session.report with error responses
  - Output: info_disclosures (categorized findings)
  - Browser: False
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

from core.probes.base import ReconProbe

if TYPE_CHECKING:
    from core.session import ReconSession

logger = logging.getLogger(__name__)

# ── Information disclosure patterns ──

# Stack traces (Python, Node.js, Java, Go, Rust, PHP)
_STACK_TRACE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'File\s+"([^"]+\.py)"\s*,\s*line\s+\d+', re.IGNORECASE), "Python stack trace"),
    (re.compile(r'Traceback\s*\(most recent call last\)', re.IGNORECASE), "Python traceback"),
    (re.compile(r'at\s+\S+\.\S+\s*\([^)]+\.(?:js|ts|jsx|tsx):\d+:\d+\)', re.IGNORECASE), "Node.js stack trace"),
    (re.compile(r'at\s+\S+\.\S+\s*\(Unknown Source\)', re.IGNORECASE), "Java stack trace"),
    (re.compile(r'goroutine\s+\d+\s+\[', re.IGNORECASE), "Go stack trace"),
    (re.compile(r'panicked at\s+', re.IGNORECASE), "Rust panic"),
    (re.compile(r'Fatal error:', re.IGNORECASE), "PHP fatal error"),
    (re.compile(r'Warning:\s+\S+\.php', re.IGNORECASE), "PHP warning"),
]

# Internal paths / file system
_INTERNAL_PATH_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'/(?:home|Users|root)/\w+/', re.IGNORECASE), "Unix home directory path"),
    (re.compile(r'[A-Z]:\\[A-Za-z]+\\', re.IGNORECASE), "Windows path"),
    (re.compile(r'/var/(?:log|www|lib|tmp)/', re.IGNORECASE), "System directory path"),
    (re.compile(r'/opt/', re.IGNORECASE), "Optional software path"),
    (re.compile(r'/etc/(?:nginx|apache|ssl)/', re.IGNORECASE), "Configuration path"),
    (re.compile(r'(?:node_modules|venv|\.venv|site-packages)', re.IGNORECASE), "Dependency path"),
]

# Database error messages
_DB_ERROR_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'SQLSTATE\[\d+\]', re.IGNORECASE), "SQL error code"),
    (re.compile(r'(?:mysql|postgresql|sqlite|mongodb|redis)\s+(?:error|exception)', re.IGNORECASE), "Database error"),
    (re.compile(r'connection\s+(?:refused|timeout|failed)\s+(?:to|at)\s+\S+:\d+', re.IGNORECASE), "Connection string disclosure"),
    (re.compile(r'(?:UNIQUE|FOREIGN KEY|NOT NULL)\s+constraint', re.IGNORECASE), "Database constraint error"),
    (re.compile(r'collection\s+[\'"]?\w+[\'"]?\s+does not exist', re.IGNORECASE), "Vector DB collection error"),
]

# Framework version disclosure
_FRAMEWORK_VERSION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'Django\s+\d+\.\d+', re.IGNORECASE), "Django version"),
    (re.compile(r'Flask\s+\d+\.\d+', re.IGNORECASE), "Flask version"),
    (re.compile(r'FastAPI\s+\d+\.\d+', re.IGNORECASE), "FastAPI version"),
    (re.compile(r'Express\s+\d+\.\d+', re.IGNORECASE), "Express version"),
    (re.compile(r'Spring\s+(?:Boot\s+)?\d+\.\d+', re.IGNORECASE), "Spring version"),
    (re.compile(r'Laravel\s+\d+\.\d+', re.IGNORECASE), "Laravel version"),
    (re.compile(r'Rails\s+\d+\.\d+', re.IGNORECASE), "Rails version"),
    (re.compile(r'langchain[_-]?core\s+\d+\.\d+', re.IGNORECASE), "LangChain version"),
]

# Server software disclosure
_SERVER_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'nginx/\d+\.\d+\.\d+', re.IGNORECASE), "nginx version"),
    (re.compile(r'Apache/\d+\.\d+', re.IGNORECASE), "Apache version"),
    (re.compile(r'uvicorn/\d+\.\d+', re.IGNORECASE), "Uvicorn version"),
    (re.compile(r'gunicorn/\d+\.\d+', re.IGNORECASE), "Gunicorn version"),
    (re.compile(r'hypercorn/\d+\.\d+', re.IGNORECASE), "Hypercorn version"),
    (re.compile(r'PHP/\d+\.\d+', re.IGNORECASE), "PHP version"),
    (re.compile(r'Python/\d+\.\d+', re.IGNORECASE), "Python version"),
]

# Debug mode indicators
_DEBUG_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'debug\s*=\s*(?:true|True|1|on)', re.IGNORECASE), "Debug mode enabled"),
    (re.compile(r'DEBUG\s*=\s*True', re.IGNORECASE), "Django DEBUG=True"),
    (re.compile(r'app\.run\s*\(\s*debug\s*=\s*True', re.IGNORECASE), "Flask debug mode"),
    (re.compile(r'development\s+mode', re.IGNORECASE), "Development mode"),
    (re.compile(r'is not allowed\. Make sure the request is', re.IGNORECASE), "CORS debug message"),
]

# Internal IP/hostname disclosure
_INTERNAL_NETWORK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}', re.IGNORECASE), "Internal IP address"),
    (re.compile(r'hostname[:\s]+([a-zA-Z0-9\-]+)', re.IGNORECASE), "Hostname disclosure"),
    (re.compile(r'container[_\s]?id[:\s]+([a-f0-9]{12,64})', re.IGNORECASE), "Container ID disclosure"),
]

# API key / token fragments
_TOKEN_LEAK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'(?:api[_-]?key|apikey|secret|token|password)\s*[:=]\s*[\'"]?([^\'"&\s]{8,})', re.IGNORECASE), "API key/token in error"),
    (re.compile(r'(?:Authorization|Bearer)\s+([A-Za-z0-9\-_]{20,})', re.IGNORECASE), "Auth token in error"),
]

# Model architecture hints
_MODEL_HINT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'expected\s+(?:dimension|embedding)\s+(?:size|length)\s+(?:of|is)\s+(\d+)', re.IGNORECASE), "Expected embedding dimension"),
    (re.compile(r'model\s+[\'"]?\w+[\'"]?\s+(?:requires|expects|only supports)\s+(\d+)', re.IGNORECASE), "Model dimension requirement"),
    (re.compile(r'max(?:imum)?\s+(?:context|token)\s+(?:length|size|window)\s+(?:of|is)\s+(\d+)', re.IGNORECASE), "Max context length"),
    (re.compile(r'(?:vocab|vocabulary)\s+size\s+(?:of|is)\s+(\d+)', re.IGNORECASE), "Vocabulary size"),
    (re.compile(r'only\s+(?:supports|accepts)\s+(?:models?|inputs?)\s+(?:of|with|like)\s+', re.IGNORECASE), "Model capability constraint"),
]

# All patterns organized by category
_DISCLOSURE_CATEGORIES: dict[str, list[tuple[re.Pattern[str], str]]] = {
    "stack_trace": _STACK_TRACE_PATTERNS,
    "internal_path": _INTERNAL_PATH_PATTERNS,
    "database_error": _DB_ERROR_PATTERNS,
    "framework_version": _FRAMEWORK_VERSION_PATTERNS,
    "server_software": _SERVER_PATTERNS,
    "debug_mode": _DEBUG_PATTERNS,
    "internal_network": _INTERNAL_NETWORK_PATTERNS,
    "token_leak": _TOKEN_LEAK_PATTERNS,
    "model_hint": _MODEL_HINT_PATTERNS,
}

# Category severity mapping
_CATEGORY_SEVERITY: dict[str, str] = {
    "stack_trace": "critical",
    "token_leak": "critical",
    "internal_path": "high",
    "internal_network": "high",
    "database_error": "high",
    "debug_mode": "high",
    "framework_version": "medium",
    "server_software": "medium",
    "model_hint": "low",
}


class ErrorAnalyzerProbe(ReconProbe):
    """Error message analysis probe — detect information disclosure.

    Analyzes error response bodies from discovered endpoints for
    information leakage patterns across 9 categories.

    Usage::
        probe = ErrorAnalyzerProbe()
        result = await probe.probe(session)
        # result["info_disclosures"] -> list of findings
    """

    @property
    def name(self) -> str:
        return "ErrorAnalyzerProbe"

    @property
    def requires_browser(self) -> bool:
        return False

    @property
    def requires_auth(self) -> bool:
        return False

    async def probe(self, session: ReconSession) -> dict[str, Any]:
        """Execute error analysis.

        Args:
            session: Recon session.

        Returns:
            Dict with info_disclosures list.
        """
        # Analyze all endpoints with non-200 status codes or error-like responses
        error_endpoints = [
            e for e in session.report.endpoints
            if e.status_code and e.status_code >= 400
        ]

        # Also analyze endpoints where response body might contain errors
        body_endpoints = [
            e for e in session.report.endpoints
            if e.response_body_preview and self._looks_like_error(e.response_body_preview)
        ]

        all_endpoints = error_endpoints + [
            e for e in body_endpoints if e not in error_endpoints
        ]

        disclosures: list[dict[str, Any]] = []
        seen_hashes: set[str] = set()

        for ep in all_endpoints:
            body = ep.response_body_preview or ""
            if not body:
                continue

            # Also check response headers
            headers_text = json.dumps(ep.request_headers) if ep.request_headers else ""

            # Analyze response body
            findings = self._analyze_response(body, ep.url, "body")
            # Analyze headers
            findings.extend(self._analyze_response(headers_text, ep.url, "headers"))

            for finding in findings:
                finding_hash = f"{finding['category']}:{finding['pattern']}:{ep.url}"
                if finding_hash not in seen_hashes:
                    seen_hashes.add(finding_hash)
                    disclosures.append(finding)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        disclosures.sort(key=lambda d: severity_order.get(d["severity"], 99))

        # Summary
        by_severity: dict[str, int] = {}
        for d in disclosures:
            by_severity[d["severity"]] = by_severity.get(d["severity"], 0) + 1

        logger.info(
            "ErrorAnalyzerProbe: %d info disclosures found (%s)",
            len(disclosures),
            ", ".join(f"{k}:{v}" for k, v in sorted(by_severity.items())),
        )

        return {
            "info_disclosures": disclosures,
            "summary": {
                "total": len(disclosures),
                "by_severity": by_severity,
                "endpoints_analyzed": len(all_endpoints),
            },
        }

    @staticmethod
    def _looks_like_error(body: str) -> bool:
        """Quick check if a response body looks like an error."""
        error_indicators = ["error", "exception", "traceback", "trace", "failed", "invalid", "unauthorized"]
        body_lower = body.lower()
        return any(indicator in body_lower for indicator in error_indicators)

    def _analyze_response(self, text: str, source_url: str, source_type: str) -> list[dict[str, Any]]:
        """Analyze response text for information disclosure patterns."""
        findings: list[dict[str, Any]] = []

        for category, patterns in _DISCLOSURE_CATEGORIES.items():
            for pattern, description in patterns:
                match = pattern.search(text)
                if match:
                    matched_text = match.group(0)
                    findings.append({
                        "category": category,
                        "pattern": description,
                        "matched": matched_text[:200],
                        "source_url": source_url,
                        "source_type": source_type,
                        "severity": _CATEGORY_SEVERITY.get(category, "low"),
                    })

        return findings
