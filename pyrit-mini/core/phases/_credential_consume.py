"""Credential Consumption — AuthState + Secrets Data Flow Closure.

Closes Gap #3: Secrets/Token Utilization.

Red Team Thinking:
    "The JWT expires in 5 minutes — I need to extract the refresh token from
     the payload and hit /token/refresh before continuing the attack."

    "I found sk-xxxxx in /models response — let me try it as override API key
     to see if it has different permissions."

    "This API uses Cookie auth — I can replay the same session cookie in my
     follow-up probes even if JWT expired."

Data Flow:
    AuthDetector.AuthState → CredentialManager →
        - Expiry alerting (JWT approaching expiration)
        - Token refresh triggering (if refresh endpoint known)
        - Cross-endpoint scope analysis (does this token work on /admin?)
        - Secrets inventory report (all discovered credentials)

Academic basis:
    - OWASP WSTG-ATHN-05 - Testing for Credential Predictability
    - RFC 7519 Sec4.1.4 - JWT exp claim lifecycle
    - OWASP API Sec Top 10 (2025) API2 - Broken Authentication

Constitution compliance:
    - R-SIZE: < 250 lines (thin adapter layer)
    - Detection-only by default, no auto-exploit
    - operator decides whether to use leaked credentials
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class CredentialInventory:
    """Aggregated credential state across the attack session.

    Attributes:
        jwt_token: Current JWT access token (may be near expiry)
        jwt_expiry: Unix timestamp when JWT expires
        jwt_tenant_id: Tenant/organization from JWT payload
        refresh_token: Refresh token if detected
        api_keys: List of discovered API keys (from responses/secrets)
        session_cookies: Active session cookies
        credential_mismatches: Tokens that work on one endpoint but not others
        expiry_warning_issued: Whether operator was alerted
    """

    jwt_token: str | None = None
    jwt_expiry: float | None = None
    jwt_tenant_id: str | None = None
    refresh_token: str | None = None
    api_keys: list[str] = field(default_factory=list)
    session_cookies: list[str] = field(default_factory=list)
    credential_mismatches: list[dict[str, str]] = field(default_factory=list)
    expiry_warning_issued: bool = False

    def is_jwt_expiring_soon(self, within_seconds: float = 300.0) -> bool:
        """Check if JWT is about to expire (default 5 min threshold)."""
        if self.jwt_expiry is None:
            return False
        return (self.jwt_expiry - time.time()) < within_seconds

    def is_jwt_expired(self) -> bool:
        if self.jwt_expiry is None:
            return False
        return time.time() >= self.jwt_expiry

    def has_credentials(self) -> bool:
        return bool(self.jwt_token or self.api_keys or self.session_cookies)

    def to_dict(self) -> dict[str, Any]:
        return {
            "jwt_present": self.jwt_token is not None,
            "jwt_expiry_unix": self.jwt_expiry,
            "jwt_expiry_in_seconds": (
                round(self.jwt_expiry - time.time(), 1)
                if self.jwt_expiry else None
            ),
            "jwt_tenant_id": self.jwt_tenant_id,
            "refresh_token_present": self.refresh_token is not None,
            "api_key_count": len(self.api_keys),
            "session_cookie_count": len(self.session_cookies),
            "credential_mismatches": self.credential_mismatches,
            "expired": self.is_jwt_expired(),
        }


def build_credential_inventory(ctx: Any) -> CredentialInventory:
    """Build credential inventory from ctx.auth_state and discovered secrets.

    Args:
        ctx: PipelineContext with auth_state, secret_findings, auth_state_manager

    Returns:
        CredentialInventory with all discovered credentials
    """
    inventory = CredentialInventory()

    # Consume AuthState from recon phase
    auth_state = getattr(ctx, "auth_state", None)
    if auth_state is not None:
        inventory.jwt_token = getattr(auth_state, "token_value", None)
        inventory.jwt_expiry = getattr(auth_state, "token_expiry", None)
        inventory.jwt_tenant_id = getattr(auth_state, "tenant_id", None)

    # Consume secret_findings from capability_probe
    secret_findings = getattr(ctx, "secret_findings", None) or {}
    for fmt_name, findings in secret_findings.items():
        if fmt_name == "sk_prefix":
            for key in findings:
                if isinstance(key, str) and key not in inventory.api_keys:
                    inventory.api_keys.append(key)

    # Also check target_fingerprint.extra for secret_format
    parsed = getattr(ctx, "parsed_request", None)
    if parsed:
        fp_extra = getattr(parsed.target_fingerprint, "extra", {}) or {}
        if fp_extra.get("secret_format") and fp_extra.get("secret_format") == "sk_prefix":
            # Token value may be in fingerprint
            token_val = fp_extra.get("token_value", "")
            if token_val and token_val not in inventory.api_keys:
                inventory.api_keys.append(token_val)

    return inventory


def check_and_alert_jwt_expiry(ctx: Any, inventory: CredentialInventory) -> None:
    """Alert operator if JWT is about to expire.

    Red team: "My JWT expires in 3 minutes. I should pause attacks and refresh."
    """
    if not inventory.jwt_token:
        return

    if inventory.is_jwt_expired():
        logger.warning(
            "[Credential] JWT EXPIRED. Attacks may start returning 401. "
            "Consider obtaining a fresh token.",
        )
        if hasattr(ctx, "orchestration_log"):
            ctx.orchestration_log.append({
                "phase": "credential_check",
                "decision": "jwt_expired_alert",
                "input": {"jwt_expiry": inventory.jwt_expiry},
                "output": {"action": "operator_alert"},
                "reasoning": "JWT expired — subsequent attacks may fail with 401",
            })
    elif inventory.is_jwt_expiring_soon(within_seconds=300):
        remaining = inventory.jwt_expiry - time.time()
        logger.warning(
            "[Credential] JWT expiring in %.0fs. Refresh recommended.",
            remaining,
        )
        inventory.expiry_warning_issued = True


def analyze_token_scope(
    ctx: Any,
    inventory: CredentialInventory,
) -> list[dict[str, str]]:
    """Detect if token works on discovered endpoints or only the original.

    Red team: "My /v1/chat token works on /admin too — scope misconfiguration."
    """
    mismatches: list[dict[str, str]] = []

    # Use service_profile discovered_endpoints to check scope
    service_profile = getattr(ctx, "service_profile", None)
    if service_profile is None:
        return mismatches

    original_endpoint = getattr(ctx.parsed_request, "path", "") if ctx.parsed_request else ""
    discovered = getattr(service_profile, "discovered_endpoints", [])

    for endpoint in discovered:
        path = endpoint.path
        existence = endpoint.existence

        # If a different endpoint is "confirmed" but our original required auth,
        # the token scope may be wider than expected
        if existence == "protected" and path != original_endpoint:
            mismatches.append({
                "original_endpoint": original_endpoint,
                "discovered_endpoint": path,
                "signal": "may_accept_same_auth",
                "attack_value": "high",  # Potential scope elevation
            })

    if mismatches:
        logger.info(
            "[Credential] Token scope: %d endpoints may accept same credentials",
            len(mismatches),
        )

    inventory.credential_mismatches = mismatches
    return mismatches


def generate_credential_report(ctx: Any) -> dict[str, Any]:
    """Generate final credential utilization report.

    For red team deliverable: "Here's what we found and how we used it."

    Args:
        ctx: PipelineContext

    Returns:
        Report dict with all credential findings
    """
    inventory = build_credential_inventory(ctx)
    check_and_alert_jwt_expiry(ctx, inventory)
    analyze_token_scope(ctx, inventory)

    service_profile = getattr(ctx, "service_profile", None)
    protected_count = 0
    if service_profile:
        protected_count = sum(
            1 for d in getattr(service_profile, "discovered_endpoints", [])
            if getattr(d, "existence", "") == "protected"
        )

    report = {
        "inventory": inventory.to_dict(),
        "protected_endpoints_discovered": protected_count,
        "recommendations": [],
    }

    # Operator guidance
    if inventory.is_jwt_expired():
        report["recommendations"].append(
            "JWT expired — obtain fresh token before continuing"
        )
    if inventory.api_keys:
        report["recommendations"].append(
            f"{len(inventory.api_keys)} API key(s) discovered — test scope manually"
        )
    if protected_count > 0:
        report["recommendations"].append(
            f"{protected_count} protected endpoints — test with discovered credentials"
        )
    if inventory.credential_mismatches:
        report["recommendations"].append(
            "Token scope may cover admin endpoints — verify with /admin probe"
        )

    # Store report in ctx for downstream consumption
    ctx.credential_report = report

    logger.info(
        "[Credential] Report generated: jwt=%s, keys=%d, protected_endpoints=%d",
        inventory.jwt_token is not None,
        len(inventory.api_keys),
        protected_count,
    )

    return report
