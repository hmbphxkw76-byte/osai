"""Auth Detector - Authentication state detection ONLY (no execution).

Academic basis:
    - Heroux et al. (arXiv:2403.04206) Sec3.2 - /:
      , ,
    - OWASP WSTG-ATHN-01 -
    - OWASP API Security Top 10 (2025) API1 (BOLA) / API3 (BOPLA):

    1. detect_auth_type(): imports Burp
    2. extract_tenant_info(): JWT payload tenant_id header
    3. extract_csrf_token(): imports CSRF token

PyRIT  (Rule 2: Layer):

      recon/  ( detection),

     (try_recover_auth/try_relogin)

    2026-09-08  (v1.5):  auth_state_manager.py  ( no execution)

Constitution compliance:
    - R-RECON-1:  recon/  - ,  strike/
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AuthState:
    """- converter(s)

    :
        auth_type:  (cookie / bearer / jwt / api_key / none)
        raw_headers:  header  ()
        token_value:  token  (Bearer xxx  xxx )
        token_expiry:  (Unix timestamp, None = )
        tenant_id:  ID (imports JWT payload )
        tenant_header:  header  header  ( X-Tenant-Id, X-Org-Id)
        csrf_token:  CSRF token
        csrf_header: CSRF header  ( X-CSRF-Token)
    """

    auth_type: str = "none"
    raw_headers: list[tuple[str, str]] = field(default_factory=list)
    token_value: str | None = None
    token_expiry: float | None = None
    tenant_id: str | None = None
    tenant_header: str | None = None
    csrf_token: str | None = None
    csrf_header: str = "X-CSRF-Token"


class AuthDetector:
    """-

    :
          recon/ ,
           ( detection)

    2026-09-08  (v1.5):  AuthStateManager ,  token refresh/relogin
    """

    async def detect_auth_type(self, parsed: Any) -> AuthState:
        """imports Burp

         ():
            1. Authorization: Bearer xxx -> JWT ( exp)  Bearer Token
            2. Cookie: session_id / JSESSIONID / PHPSESSID -> Cookie-based
            3. X-API-Key: xxx -> API Key
            4.  ->

        JWT exp :
             JWT payload (),  exp
             = exp - 60s ( 1 )
            Academic basis: RFC 7519 Sec4.1.4 - exp  JWT

        Args:
            parsed: ParsedBurpRequest

        Returns:
            AuthState
        """
        state = AuthState()

        if not hasattr(parsed, "headers"):
            return state

        headers = parsed.headers
        state.raw_headers = list(getattr(parsed, "raw_headers", []))

        # == 1. Authorization: Bearer ==
        auth_header = headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()
            state.token_value = token
            state.auth_type = "bearer"

            # JWT
            jwt_payload = decode_jwt_payload(token)
            if jwt_payload is not None:
                state.auth_type = "jwt"
                exp = jwt_payload.get("exp")
                if exp and isinstance(exp, (int, float)):
                    # 60 ()
                    state.token_expiry = float(exp) - 60.0
                    logger.info(
                        "JWT detected: exp=%s, expiry_in=%.0fs",
                        exp,
                        state.token_expiry - time.time(),
                    )

                # JWT payload tenant
                tenant = (
                    jwt_payload.get("tenant_id")
                    or jwt_payload.get("org_id")
                    or jwt_payload.get("organization")
                    or jwt_payload.get("workspace")
                )
                if tenant:
                    state.tenant_id = str(tenant)
                    logger.info("JWT tenant detected: %s", state.tenant_id)

        # == 2. Cookie-based ==
        elif "cookie" in headers:
            cookie_str = headers["cookie"]
            state.auth_type = "cookie"

            # session
            if re.search(r"session[_-]?id", cookie_str, re.IGNORECASE):
                logger.info("Cookie auth: session_id detected")
            elif re.search(r"JSESSIONID", cookie_str, re.IGNORECASE):
                logger.info("Cookie auth: JSESSIONID detected")
            elif re.search(r"PHPSESSID", cookie_str, re.IGNORECASE):
                logger.info("Cookie auth: PHPSESSID detected")

            # Cookie ( cookie )
            state.token_value = cookie_str

        # == 3. X-API-Key ==
        elif headers.get("x-api-key"):
            state.auth_type = "api_key"
            state.token_value = headers["x-api-key"]
            logger.info("API Key auth detected")

        else:
            state.auth_type = "none"
            logger.info("No authentication headers detected - anonymous access")

        # == header ==
        for h_name, h_value in state.raw_headers:
            h_lower = h_name.lower()
            if h_lower in ("x-tenant-id", "x-org-id", "x-organization", "x-workspace"):
                state.tenant_header = h_name
                state.tenant_id = h_value
                logger.info("Tenant header detected: %s=%s", h_name, h_value)
                break

        # == CSRF token header ==
        for h_name, h_value in state.raw_headers:
            h_lower = h_name.lower()
            if h_lower in ("x-csrf-token", "x-xsrf-token", "csrf-token"):
                state.csrf_header = h_name
                state.csrf_token = h_value
                logger.info("CSRF token detected in header: %s", h_name)
                break

        return state

    def extract_tenant_info(self, auth_state: AuthState) -> dict[str, str | None]:
        """Extract tenant information from auth state.

        Returns:
            Dict with tenant_id, tenant_header keys
        """
        return {
            "tenant_id": auth_state.tenant_id,
            "tenant_header": auth_state.tenant_header,
        }

    def extract_csrf_token(self, response_headers: dict[str, str], response_body: str = "") -> str | None:
        """Extract CSRF token from response.

        Args:
            response_headers: HTTP response headers
            response_body: HTTP response body

        Returns:
            CSRF token string or None
        """
        # Check headers
        for h_name, h_value in response_headers.items():
            h_lower = h_name.lower()
            if h_lower in ("x-csrf-token", "x-xsrf-token"):
                return h_value

        # Check Set-Cookie
        set_cookie = response_headers.get("set-cookie", "")
        if set_cookie:
            csrf_match = re.search(r"csrf[=:]([^\s;]+)", set_cookie, re.IGNORECASE)
            if csrf_match:
                return csrf_match.group(1)

        # Check JSON body
        if response_body:
            try:
                data = json.loads(response_body)
                if isinstance(data, dict):
                    for key in ("csrf_token", "csrf", "xsrf_token", "_token"):
                        if key in data:
                            return str(data[key])
            except (json.JSONDecodeError, TypeError):
                pass

        return None

    def is_token_expired(self, auth_state: AuthState, *, ahead: float = 0.0) -> bool:
        """Check if token is expired.

        Args:
            auth_state: Auth state
            ahead: Advance warning seconds

        Returns:
            True if token is expired
        """
        if auth_state.token_expiry is None:
            return False
        return time.time() + ahead >= auth_state.token_expiry


def decode_jwt_payload(token: str) -> dict[str, Any] | None:
    """Decode JWT payload without verification.

    Academic basis:
        - RFC 7519 Sec3 - JWT structure: header.payload.signature
        - RFC 7519 Sec4.1.4 - exp (Expiration Time) claim

    Args:
        token: JWT token string

    Returns:
        Decoded payload dict or None if not valid JWT
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None

    try:
        payload_b64 = parts[1]
        padding_needed = 4 - len(payload_b64) % 4
        if padding_needed < 4:
            payload_b64 += "=" * padding_needed

        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_bytes)
        if isinstance(payload, dict):
            return payload
    except (ValueError, json.JSONDecodeError, Exception) as e:
        logger.debug("JWT decode failed: %s", e)

    return None


# Backward compatibility alias
AuthStateManager = AuthDetector
_decode_jwt_payload = decode_jwt_payload
