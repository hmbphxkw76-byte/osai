# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""JSReconProbe: JavaScript reconnaissance probe.

Analyzes JavaScript files discovered by NetworkInterceptor for:
  1. AI SDK imports (50+ npm package patterns)
  2. Hardcoded API keys (25+ prefix patterns)
  3. SDK constructor contexts with API key parameters
  4. Browser mode flags (dangerouslyAllowBrowser)
  5. Frontend JS product markers (20+ products)
  6. AI provider base URLs (15+ API endpoints)

Architecture:
  - Input: endpoints from session.report (JS file URLs)
  - Output: js_findings with categorized discoveries
  - Browser: False (analyzes intercepted content)

Academic basis:
  - MITRE ATT&CK T1552: Unsecured Credentials
  - OWASP LLM02: Sensitive Information Disclosure
  - Reference: RedAmon recon/main_recon_modules/js_recon.py (1105 lines)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from core.probes.ai_signal_catalog import (
    match_ai_browser_flag,
    match_ai_frontend_js,
    match_ai_key_constructor,
    match_ai_key_prefix,
    match_ai_provider_url,
    match_ai_sdk,
)
from core.probes.base import ReconProbe

if TYPE_CHECKING:
    from core.session import ReconSession

logger = logging.getLogger(__name__)


class JSReconProbe(ReconProbe):
    """JavaScript reconnaissance probe.

    Analyzes JS file content discovered through network interception
    for AI SDK usage, API keys, and provider configurations.

    Usage::
        probe = JSReconProbe()
        result = await probe.probe(session)
        # result["js_findings"] -> list of finding dicts
    """

    @property
    def name(self) -> str:
        return "JSReconProbe"

    @property
    def requires_browser(self) -> bool:
        return False

    @property
    def requires_auth(self) -> bool:
        return False

    async def probe(self, session: ReconSession) -> dict[str, Any]:
        """Execute JS reconnaissance.

        Args:
            session: Recon session.

        Returns:
            Dict with js_findings containing categorized discoveries.
        """
        # Find JS file endpoints from the report
        js_endpoints = [
            e for e in session.report.endpoints
            if self._is_js_file(e.url, e.content_type or "")
        ]

        findings: list[dict[str, Any]] = []

        for endpoint in js_endpoints:
            body = endpoint.response_body_preview or ""
            if not body or len(body) < 10:
                continue

            endpoint_findings = self._analyze_js_content(body, endpoint.url)
            if endpoint_findings:
                findings.extend(endpoint_findings)

        logger.info(
            "JSReconProbe: analyzed %d JS files, found %d discoveries",
            len(js_endpoints), len(findings),
        )

        # Categorize findings
        sdk_imports = [f for f in findings if f["category"] == "sdk_import"]
        api_keys = [f for f in findings if f["category"] == "api_key"]
        constructors = [f for f in findings if f["category"] == "constructor"]
        browser_flags = [f for f in findings if f["category"] == "browser_flag"]
        frontend = [f for f in findings if f["category"] == "frontend"]
        providers = [f for f in findings if f["category"] == "provider_url"]

        return {
            "js_findings": findings,
            "summary": {
                "sdk_imports": len(sdk_imports),
                "api_keys_found": len(api_keys),
                "constructors": len(constructors),
                "browser_flags": len(browser_flags),
                "frontend_products": len(frontend),
                "provider_urls": len(providers),
                "sdk_names": sorted({f["detail"] for f in sdk_imports}),
                "key_types": sorted({f["detail"] for f in api_keys}),
                "frontend_products_found": sorted({f["detail"] for f in frontend}),
            },
        }

    @staticmethod
    def _is_js_file(url: str, content_type: str) -> bool:
        """Check if an endpoint is a JavaScript file."""
        ct_lower = content_type.lower()
        if any(t in ct_lower for t in ("javascript", "ecmascript", "text/js")):
            return True
        url_lower = url.lower()
        return url_lower.endswith((".js", ".mjs", ".cjs", ".jsx"))

    def _analyze_js_content(self, content: str, source_url: str) -> list[dict[str, Any]]:
        """Analyze JS content for AI-related signals."""
        findings: list[dict[str, Any]] = []

        # 1. SDK imports
        for sdk_name, matched in match_ai_sdk(content):
            findings.append({
                "category": "sdk_import",
                "detail": sdk_name,
                "matched": matched[:100],
                "source_url": source_url,
                "severity": "info",
            })

        # 2. API keys
        for key_type, matched in match_ai_key_prefix(content):
            # Redact the actual key for safety
            redacted = matched[:8] + "..." + matched[-4:] if len(matched) > 12 else matched[:4] + "..."
            findings.append({
                "category": "api_key",
                "detail": key_type,
                "matched": redacted,
                "source_url": source_url,
                "severity": "critical",
            })

        # 3. Constructor contexts
        for constructor, matched in match_ai_key_constructor(content):
            findings.append({
                "category": "constructor",
                "detail": constructor,
                "matched": matched[:100],
                "source_url": source_url,
                "severity": "warning",
            })

        # 4. Browser flags
        for flag_type, matched in match_ai_browser_flag(content):
            findings.append({
                "category": "browser_flag",
                "detail": flag_type,
                "matched": matched[:100],
                "source_url": source_url,
                "severity": "warning",
            })

        # 5. Frontend JS markers
        for product, matched in match_ai_frontend_js(content):
            findings.append({
                "category": "frontend",
                "detail": product,
                "matched": matched[:100],
                "source_url": source_url,
                "severity": "info",
            })

        # 6. Provider URLs
        for provider, matched in match_ai_provider_url(content):
            findings.append({
                "category": "provider_url",
                "detail": provider,
                "matched": matched[:100],
                "source_url": source_url,
                "severity": "info",
            })

        return findings
