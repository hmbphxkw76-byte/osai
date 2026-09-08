# Trust Chain Probe - Multi-Agent Trust Exploitation Detection
# Reference: Google A2A Protocol - Trust Chain Model
# arXiv:2407.16924 - Eidam et al., A2A trust chain attacks
# OWASP ASI09 - Trust Boundary Violation
"""trust_chain_probe - Multi-agent trust chain vulnerability detection.

Detects and tests trust chain vulnerabilities in multi-agent systems:

    1. Trust Boundary Detection: Identify trust boundaries between agent tiers
    2. Privilege Escalation Paths: Map possible escalation routes
    3. Cross-Agent Trust Exploitation: Test data access across trust domains
    4. Authentication Bypass: Test auth mechanism weaknesses

Academic basis:
    - Eidam et al. (arXiv:2407.16924) - Trust chain attacks, ASR +15-25%
    - OWASP ASI09 - Trust Boundary Violation
    - Google A2A Protocol - Inter-agent trust model

Design principles:
    1. Black-box probing via HTTP (no agent installation required)
    2. Safe degradation when no A2A detected
    3. trust_level_enum for payload definitions
    4. Integration with a2a_discoverer for topology data

R2 (PyRIT Native First): Uses aiohttp for HTTP requests
R6 Sec6.4: Trust chain probing for multi-agent systems
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from recon.trust_level_enum import (
    TrustEscalationPath,
    TrustLevel,
    get_escalation_path,
)

logger = logging.getLogger(__name__)


@dataclass
class TrustBoundary:
    """Detected trust boundary in multi-agent system."""
    boundary_id: str
    source_tier: str
    target_tier: str
    source_level: TrustLevel
    target_level: TrustLevel
    endpoint: str = ""
    authentication: str = "unknown"
    bypass_attempted: bool = False
    bypass_successful: bool = False


@dataclass
class TrustChainResult:
    """Complete trust chain probing result."""
    base_url: str
    trust_boundaries: list[TrustBoundary] = field(default_factory=list)
    escalation_paths: list[TrustEscalationPath] = field(default_factory=list)
    probe_results: list[dict[str, Any]] = field(default_factory=list)
    multi_agent_detected: bool = False
    max_privilege_level: TrustLevel = TrustLevel.UNAUTHENTICATED
    vulnerabilities_found: int = 0

    @property
    def has_vulnerabilities(self) -> bool:
        """Check if any trust chain vulnerabilities were found."""
        return self.vulnerabilities_found > 0

    @property
    def critical_vulnerabilities(self) -> int:
        """Count critical vulnerabilities."""
        count = 0
        for boundary in self.trust_boundaries:
            if boundary.bypass_successful and boundary.target_level.value >= TrustLevel.FULL_ACCESS.value:
                count += 1
        return count


async def detect_trust_boundaries(
    base_url: str,
    agent_topology: Optional[list[Any]] = None,
    timeout: float = 10.0,
) -> list[TrustBoundary]:
    """Detect trust boundaries in multi-agent system.

    Analyzes agent topology and security schemes to identify trust boundaries.

    Args:
        base_url: Base URL of the agent system
        agent_topology: Optional topology nodes from a2a_discoverer
        timeout: Request timeout

    Returns:
        List of detected TrustBoundary objects
    """
    import aiohttp

    from recon.config_loader import get_tls_verify

    verify = get_tls_verify()
    boundaries: list[TrustBoundary] = []

    # If topology available, use it to identify boundaries
    if agent_topology:
        for node in agent_topology:
            level = TrustLevel.from_string(node.trust_level)
            if level.value > TrustLevel.UNAUTHENTICATED.value:
                boundary = TrustBoundary(
                    boundary_id=f"boundary-{node.agent_id}",
                    source_tier="unauthenticated",
                    target_tier=node.name or node.agent_id,
                    source_level=TrustLevel.UNAUTHENTICATED,
                    target_level=level,
                    endpoint=node.url,
                    authentication=node.trust_level,
                )
                boundaries.append(boundary)

    # Probe common trust boundary indicators
    boundary_paths = [
        "/admin",
        "/api/admin",
        "/internal",
        "/api/internal",
        "/system",
        "/api/system",
        "/agent/privileged",
    ]

    base_url = base_url.rstrip("/")

    for path in boundary_paths:
        url = f"{base_url}{path}"
        try:
            timeout_obj = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                async with session.get(url, ssl=verify) as response:
                    # Check if endpoint exists and requires auth
                    if response.status == 401 or response.status == 403:
                        boundary = TrustBoundary(
                            boundary_id=f"boundary-{path.strip('/')}",
                            source_tier="public",
                            target_tier=path,
                            source_level=TrustLevel.UNAUTHENTICATED,
                            target_level=TrustLevel.ELEVATED,
                            endpoint=url,
                            authentication="required",
                        )
                        boundaries.append(boundary)
                    elif response.status == 200:
                        # Endpoint accessible without auth - potential misconfiguration
                        boundary = TrustBoundary(
                            boundary_id=f"boundary-{path.strip('/')}",
                            source_tier="public",
                            target_tier=path,
                            source_level=TrustLevel.UNAUTHENTICATED,
                            target_level=TrustLevel.ELEVATED,
                            endpoint=url,
                            authentication="none",
                        )
                        boundaries.append(boundary)

        except aiohttp.ClientError:
            pass
        except Exception as e:
            logger.debug("Error probing boundary %s: %s", url, e)

    return boundaries


async def test_trust_escalation(
    base_url: str,
    parsed_request: Any,
    source_level: TrustLevel = TrustLevel.UNAUTHENTICATED,
    target_level: TrustLevel = TrustLevel.FULL_ACCESS,
    timeout: float = 15.0,
) -> list[dict[str, Any]]:
    """Test trust escalation paths.

    Sends trust escalation payloads to test if privilege escalation is possible.

    Args:
        base_url: Target base URL
        parsed_request: Original parsed request for context
        source_level: Starting trust level
        target_level: Target trust level
        timeout: Request timeout

    Returns:
        List of probe results with responses
    """
    import aiohttp

    from recon.config_loader import get_tls_verify

    verify = get_tls_verify()
    results: list[dict[str, Any]] = []

    # Get escalation path
    path = get_escalation_path(source_level, target_level)

    if not path.steps:
        logger.debug("No escalation path from %s to %s", source_level.name, target_level.name)
        return results

    base_url = base_url.rstrip("/")

    for step in path.steps:
        try:
            # Build prompt payload
            payload = {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": step.prompt_template}],
                },
            }

            timeout_obj = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                async with session.post(
                    f"{base_url}/v1/chat/completions",
                    json=payload,
                    ssl=verify,
                    headers={"Content-Type": "application/json"},
                ) as response:
                    status = response.status
                    body = await response.text()

                    result = {
                        "payload_name": step.name,
                        "source_level": step.source_level.name,
                        "target_level": step.target_level.name,
                        "status_code": status,
                        "response_length": len(body),
                        "severity": step.severity,
                        "success": status == 200,
                    }

                    # Check if response indicates successful escalation
                    body_lower = body.lower()
                    if any(indicator in body_lower for indicator in [
                        "api_key", "secret", "password", "token", "credential",
                        "sk-", "akia", "bearer",
                    ]):
                        result["potential_success"] = True
                        result["indicators"] = "credentials_exposed"

                    results.append(result)

        except aiohttp.ClientError as e:
            logger.debug("Trust escalation probe error: %s", e)
            results.append({
                "payload_name": step.name,
                "error": str(e),
                "success": False,
            })
        except Exception as e:
            logger.debug("Unexpected error in trust escalation: %s", e)

    return results


async def run_trust_chain_probe(
    base_url: str,
    parsed_request: Any,
    a2a_topology: Optional[list[Any]] = None,
    timeout: float = 20.0,
) -> TrustChainResult:
    """Run complete trust chain probing pipeline.

    Combines boundary detection and escalation testing.

    Args:
        base_url: Target base URL
        parsed_request: Original parsed request
        a2a_topology: Optional topology from a2a_discoverer
        timeout: Overall timeout

    Returns:
        TrustChainResult with complete findings
    """
    result = TrustChainResult(base_url=base_url)

    logger.info("Starting trust chain probe for %s", base_url)

    # Step 1: Detect trust boundaries
    boundaries = await detect_trust_boundaries(
        base_url,
        agent_topology=a2a_topology,
        timeout=timeout,
    )
    result.trust_boundaries = boundaries
    if boundaries:
        logger.info("Detected %d trust boundaries", len(boundaries))

    # Step 2: Test escalation paths
    probe_results = await test_trust_escalation(
        base_url,
        parsed_request,
        source_level=TrustLevel.UNAUTHENTICATED,
        target_level=TrustLevel.FULL_ACCESS,
        timeout=timeout,
    )
    result.probe_results = probe_results

    # Step 3: Analyze results
    for probe in probe_results:
        if probe.get("potential_success"):
            result.vulnerabilities_found += 1

    for boundary in boundaries:
        if boundary.authentication == "none":
            result.vulnerabilities_found += 1

    # Step 4: Determine max privilege level and multi-agent status
    if a2a_topology and len(a2a_topology) > 1:
        result.multi_agent_detected = True
        for node in a2a_topology:
            level = TrustLevel.from_string(getattr(node, "trust_level", "unauthenticated"))
            if level.value > result.max_privilege_level.value:
                result.max_privilege_level = level

    if result.vulnerabilities_found > 0:
        logger.warning(
            "Trust chain probe found %d potential vulnerabilities",
            result.vulnerabilities_found,
        )

    return result
