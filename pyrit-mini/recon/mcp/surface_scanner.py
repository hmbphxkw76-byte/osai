# -*- coding: utf-8 -*-
"""recon/mcp/surface_scanner.py - MCP Security Surface Scanner.

Scans MCP server security surface for vulnerability indicators:
    1. Authentication requirement detection
    2. Transport security (TLS/SSL) verification
    3. Input validation strength assessment
    4. Error information leakage detection
    5. Rate limiting presence detection

Academic basis:
    - OWASP ASI Top 10 2025 - MCP Security Surface
    - Greshake et al. (arXiv:2302.12173) - Defense surface mapping
    - NIST AI RMF 600-1 - AI system security surface analysis

Constitution compliance:
    - R-SIZE: < 800 lines
    - R-H3: Single responsibility - surface scanning only
    - R-S1: No hardcoded target identifiers
    - R-S4: Tests all mock
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SecuritySurfaceFinding:
    """A single security surface finding."""

    finding_type: str = ""  # auth, tls, validation, info_disclosure, rate_limit
    severity: str = "info"  # info, low, medium, high, critical
    description: str = ""
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_type": self.finding_type,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class SurfaceScanResult:
    """Complete security surface scan result."""

    target_url: str = ""
    findings: list[SecuritySurfaceFinding] = field(default_factory=list)
    auth_required: bool = False
    tls_enabled: bool = False
    input_validation: str = "unknown"  # strong, weak, none, unknown
    info_disclosure_risk: str = "unknown"  # high, medium, low, unknown
    rate_limiting: bool = False
    overall_security_posture: str = "unknown"  # good, moderate, poor, unknown

    @property
    def critical_findings(self) -> list[SecuritySurfaceFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def high_findings(self) -> list[SecuritySurfaceFinding]:
        return [f for f in self.findings if f.severity == "high"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "findings": [f.to_dict() for f in self.findings],
            "auth_required": self.auth_required,
            "tls_enabled": self.tls_enabled,
            "input_validation": self.input_validation,
            "info_disclosure_risk": self.info_disclosure_risk,
            "rate_limiting": self.rate_limiting,
            "overall_security_posture": self.overall_security_posture,
        }


class MCPSecuritySurfaceScanner:
    """MCP security surface scanner.

    Usage:
        scanner = MCPSecuritySurfaceScanner()
        result = await scanner.scan_security_surface(
            target_url="http://mcp-server:8080",
        )
        for finding in result.critical_findings:
            print(f"CRITICAL: {finding.description}")
    """

    def __init__(
        self,
        timeout: float = 10.0,
        stealth_mode: bool = True,
    ):
        self.timeout = timeout
        self.stealth_mode = stealth_mode

    async def scan_security_surface(
        self,
        target_url: str,
    ) -> SurfaceScanResult:
        """Run complete security surface scan.

        Args:
            target_url: MCP server URL

        Returns:
            SurfaceScanResult with findings
        """
        result = SurfaceScanResult(target_url=target_url)

        # 1. Authentication check
        await self._check_authentication(target_url, result)

        # 2. TLS verification
        self._check_transport_security(target_url, result)

        # 3. Input validation probe
        await self._probe_input_validation(target_url, result)

        # 4. Error message analysis
        await self._check_error_disclosure(target_url, result)

        # 5. Rate limiting detection
        await self._detect_rate_limiting(target_url, result)

        # 6. Calculate overall posture
        result.overall_security_posture = self._calculate_posture(result)

        return result

    async def _check_authentication(
        self,
        target_url: str,
        result: SurfaceScanResult,
    ) -> None:
        """Check if server requires authentication."""
        import aiohttp

        url = f"{target_url.rstrip('/')}/tools/list"

        try:
            timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                json_rpc_body = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {},
                }
                async with session.post(url, json=json_rpc_body) as response:
                    if response.status == 401:
                        result.auth_required = True
                        result.findings.append(
                            SecuritySurfaceFinding(
                                finding_type="auth",
                                severity="info",
                                description="Server requires authentication",
                                evidence=f"HTTP 401 on {url}",
                                remediation="None - authentication is good practice",
                            )
                        )
                    elif response.status == 200:
                        result.auth_required = False
                        result.findings.append(
                            SecuritySurfaceFinding(
                                finding_type="auth",
                                severity="medium",
                                description="Server does not require authentication",
                                evidence=f"HTTP 200 on {url} without auth",
                                remediation="Implement authentication for production use",
                            )
                        )
        except Exception as e:
            logger.debug("Auth check failed: %s", e)

    def _check_transport_security(
        self,
        target_url: str,
        result: SurfaceScanResult,
    ) -> None:
        """Verify TLS/SSL usage."""
        if target_url.startswith("https://"):
            result.tls_enabled = True
            result.findings.append(
                SecuritySurfaceFinding(
                    finding_type="tls",
                    severity="info",
                    description="TLS encryption enabled",
                    evidence="URL scheme is https://",
                )
            )
        elif target_url.startswith("http://"):
            result.tls_enabled = False
            result.findings.append(
                SecuritySurfaceFinding(
                    finding_type="tls",
                    severity="high",
                    description="TLS encryption NOT enabled - traffic is plaintext",
                    evidence="URL scheme is http://",
                    remediation="Enable TLS for production deployment",
                )
            )

    async def _probe_input_validation(
        self,
        target_url: str,
        result: SurfaceScanResult,
    ) -> None:
        """Probe input validation strength."""
        import aiohttp

        url = f"{target_url.rstrip('/')}/tools/list"

        # Send malformed JSON-RPC request
        try:
            timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                # Malformed: missing required fields
                malformed_body = {"id": 1}  # Missing jsonrpc and method
                async with session.post(url, json=malformed_body) as response:
                    if response.status == 400:
                        result.input_validation = "strong"
                    elif response.status == 500:
                        result.input_validation = "weak"
                        result.findings.append(
                            SecuritySurfaceFinding(
                                finding_type="validation",
                                severity="medium",
                                description="Server returns 500 on malformed input",
                                evidence="Malformed JSON-RPC produces HTTP 500",
                                remediation="Implement proper input validation",
                            )
                        )
                    elif response.status == 200:
                        result.input_validation = "none"
                        result.findings.append(
                            SecuritySurfaceFinding(
                                finding_type="validation",
                                severity="high",
                                description="Server accepts malformed input without error",
                                evidence="Malformed JSON-RPC still returns 200",
                                remediation="Add strict JSON-RPC schema validation",
                            )
                        )
        except Exception as e:
            logger.debug("Validation probe failed: %s", e)

    async def _check_error_disclosure(
        self,
        target_url: str,
        result: SurfaceScanResult,
    ) -> None:
        """Check if error messages leak sensitive information."""
        import aiohttp

        url = f"{target_url.rstrip('/')}/tools/list"

        try:
            timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                # Send invalid method
                body = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "invalid/method/that/does/not/exist",
                    "params": {},
                }
                async with session.post(url, json=body) as response:
                    if response.status in (200, 500):
                        data = await response.json()
                        error = data.get("error", {})
                        error_msg = error.get("message", "")

                        # Check for information disclosure
                        if any(kw in error_msg.lower() for kw in ["stack", "trace", "internal", "debug", "path"]):
                            result.info_disclosure_risk = "high"
                            result.findings.append(
                                SecuritySurfaceFinding(
                                    finding_type="info_disclosure",
                                    severity="high",
                                    description="Error messages leak internal details",
                                    evidence=f"Error message contains: {error_msg[:100]}",
                                    remediation="Sanitize error messages before returning to client",
                                )
                            )
                        else:
                            result.info_disclosure_risk = "low"
        except Exception as e:
            logger.debug("Error disclosure check failed: %s", e)

    async def _detect_rate_limiting(
        self,
        target_url: str,
        result: SurfaceScanResult,
    ) -> None:
        """Detect rate limiting by sending burst requests."""
        import asyncio

        import aiohttp

        url = f"{target_url.rstrip('/')}/health"

        try:
            timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                # Send 5 rapid requests
                statuses = []
                for _ in range(5):
                    try:
                        async with session.get(url) as response:
                            statuses.append(response.status)
                    except Exception:
                        statuses.append(0)
                    await asyncio.sleep(0.1)

                # Check if any were rate limited (HTTP 429)
                if 429 in statuses:
                    result.rate_limiting = True
                    result.findings.append(
                        SecuritySurfaceFinding(
                            finding_type="rate_limit",
                            severity="info",
                            description="Rate limiting detected (HTTP 429)",
                            evidence=f"Status codes: {statuses}",
                        )
                    )
                else:
                    result.rate_limiting = False
                    result.findings.append(
                        SecuritySurfaceFinding(
                            finding_type="rate_limit",
                            severity="low",
                            description="No rate limiting detected",
                            evidence=f"All {len(statuses)} rapid requests succeeded",
                            remediation="Consider adding rate limiting for production",
                        )
                    )
        except Exception as e:
            logger.debug("Rate limit detection failed: %s", e)

    def _calculate_posture(self, result: SurfaceScanResult) -> str:
        """Calculate overall security posture."""
        if result.critical_findings:
            return "poor"
        if len(result.high_findings) >= 2:
            return "poor"
        if result.high_findings or result.findings:
            has_medium = any(f.severity == "medium" for f in result.findings)
            return "moderate" if has_medium else "good"
        return "unknown"


async def scan_mcp_security_surface(
    target_url: str,
    timeout: float = 10.0,
) -> SurfaceScanResult:
    """Convenience function for MCP security surface scan.

    Args:
        target_url: MCP server URL
        timeout: Request timeout

    Returns:
        SurfaceScanResult
    """
    scanner = MCPSecuritySurfaceScanner(timeout=timeout)
    return await scanner.scan_security_surface(target_url)
