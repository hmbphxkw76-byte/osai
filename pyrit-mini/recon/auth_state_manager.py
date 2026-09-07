""" — Token  +  +  + CSRF 

Academic basis:
    - Heroux et al. (arXiv:2403.04206) §3.2 — /:
      , , 
    - Greshake et al. (arXiv:2302.12173) §4 — 
       token , 
    - OWASP WSTG-ATHN-01 — 
    - OWASP API Security Top 10 (2025) API1 (BOLA) / API3 (BOPLA):
      

 (Rule 2: Layer, ):
    Layer,  PyRIT 
    - :  Burp  headers
    - :  httpx  HTTP  ( prompt )
    - :  tenant header 
    - CSRF : imports headers  token

PyRIT  (Rule 2):
     httpx  HTTP  (/),
     LLM prompt ,  HTTP Layer
     HTTPTarget ( {PROMPT} )
     MCP JSON-RPC : httpx  PyRIT 
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any

from recon.config_loader import get_tls_verify as _get_tls_verify_from_config

logger = logging.getLogger(__name__)

# P2-06: TLS verify  (SSOT)
_TLS_VERIFY = _get_tls_verify_from_config()

# JWT  base64url padding 
_B64_PAD = "="


@dataclass
class AuthState:
    """ — converter(s)

    :
        auth_type:  (cookie / bearer / jwt / api_key / none)
        raw_headers:  header  ()
        token_value:  token  (Bearer xxx  xxx )
        token_expiry:  (Unix timestamp, None = )
        refresh_endpoint: token  ( /api/auth/refresh)
        refresh_method:  ( POST)
        tenant_id:  ID (imports JWT payload )
        tenant_header:  header  ( X-Tenant-Id, X-Org-Id)
        csrf_token:  CSRF token 
        csrf_header: CSRF header  ( X-CSRF-Token)
        refresh_count: executed
        max_refreshes:  ( 3)
    """

    auth_type: str = "none"
    raw_headers: list[tuple[str, str]] = field(default_factory=list)
    token_value: str | None = None
    token_expiry: float | None = None
    refresh_endpoint: str | None = None
    refresh_method: str = "POST"
    tenant_id: str | None = None
    tenant_header: str | None = None
    csrf_token: str | None = None
    csrf_header: str = "X-CSRF-Token"
    refresh_count: int = 0
    max_refreshes: int = 3
    # P2-4: 
    recovery_history: list[dict[str, str]] = field(default_factory=list)


class AuthStateManager:
    """ — 

    :
        1. detect_auth_type(): imports Burp 
        2. () 401/403  try_recover_auth()
        3. try_recover_auth():  token  /  / 
        4. try_tenant_switch(): 403  ID
        5. update_csrf_token(): imports CSRF token

    Usage:
        manager = AuthStateManager()
        auth_state = await manager.detect_auth_type(parsed)
        # ...  401 ...
        recovered = await manager.try_recover_auth(auth_state)
        if recovered:
            new_headers = await manager.refresh_headers(auth_state)
    """

    def __init__(self, *, max_refreshes: int = 3) -> None:
        """

        Args:
            max_refreshes:  ( 3)
        """
        self._max_refreshes = max_refreshes

    async def detect_auth_type(self, parsed: Any) -> AuthState:
        """imports Burp 

         ():
            1. Authorization: Bearer xxx → JWT ( exp)  Bearer Token
            2. Cookie: session_id / JSESSIONID / PHPSESSID → Cookie-based
            3. X-API-Key: xxx → API Key
            4.  → 

        JWT exp :
             JWT payload (),  exp 
             = exp - 60s ( 1 )
            Academic basis: RFC 7519 §4.1.4 — exp  JWT 

        Args:
            parsed: ParsedBurpRequest 

        Returns:
            AuthState 
        """
        state = AuthState(max_refreshes=self._max_refreshes)

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

            #  JWT
            jwt_payload = _decode_jwt_payload(token)
            if jwt_payload is not None:
                state.auth_type = "jwt"
                exp = jwt_payload.get("exp")
                if exp and isinstance(exp, (int, float)):
                    #  60  ()
                    state.token_expiry = float(exp) - 60.0
                    logger.info(
                        "JWT detected: exp=%s, expiry_in=%.0fs",
                        exp,
                        state.token_expiry - time.time(),
                    )

                #  JWT payload 
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

            #  session 
            if re.search(r"session[_-]?id", cookie_str, re.IGNORECASE):
                logger.info("Cookie auth: session_id detected")
            elif re.search(r"JSESSIONID", cookie_str, re.IGNORECASE):
                logger.info("Cookie auth: JSESSIONID detected")
            elif re.search(r"PHPSESSID", cookie_str, re.IGNORECASE):
                logger.info("Cookie auth: PHPSESSID detected")

            # Cookie  ( cookie )
            state.token_value = cookie_str

        # == 3. X-API-Key ==
        elif headers.get("x-api-key"):
            state.auth_type = "api_key"
            state.token_value = headers["x-api-key"]
            logger.info("API Key auth detected")

        else:
            state.auth_type = "none"
            logger.info("No authentication headers detected — anonymous access")

        # ==  header ==
        for h_name, h_value in state.raw_headers:
            h_lower = h_name.lower()
            if h_lower in ("x-tenant-id", "x-org-id", "x-organization", "x-workspace"):
                state.tenant_header = h_name
                state.tenant_id = h_value
                logger.info("Tenant header detected: %s=%s", h_name, h_value)
                break

        # ==  CSRF token header ==
        for h_name, h_value in state.raw_headers:
            h_lower = h_name.lower()
            if h_lower in ("x-csrf-token", "x-xsrf-token", "csrf-token"):
                state.csrf_header = h_name
                state.csrf_token = h_value
                logger.info("CSRF token detected in header: %s", h_name)
                break

        return state

    async def try_recover_auth(
        self,
        auth_state: AuthState,
        *,
        host: str = "",
        use_tls: bool = True,
    ) -> bool:
        """

         (3 Layer fallback):
            1. Token : POST refresh_endpoint →  token
            2. : 
            3. : , 

        Academic basis:
            - Heroux et al. (arXiv:2403.04206) §3.2 — 
            - RFC 6749 §6 — OAuth 2.0 Token Refresh

        Args:
            auth_state: 
            host:  host ( URL)
            use_tls:  TLS

        Returns:
            True , False all
        """
        if auth_state.refresh_count >= auth_state.max_refreshes:
            logger.warning(
                "Auth recovery exhausted (max=%d), giving up",
                auth_state.max_refreshes,
            )
            return False

        auth_state.refresh_count += 1

        # P2-4:  — 
        # Academic basis: Heroux et al. (arXiv:2403.04206) §3.2 — 
        recovery_log: list[dict[str, str]] = []

        # ==  1: Token  ==
        if auth_state.refresh_endpoint:
            success = await self._try_token_refresh(auth_state, host, use_tls)
            recovery_log.append({
                "strategy": "token_refresh",
                "endpoint": auth_state.refresh_endpoint,
                "result": "success" if success else "failed",
            })
            if success:
                logger.info("Auth recovered via token refresh")
                auth_state.recovery_history = recovery_log
                return True

        # ==  2:  ==
        login_endpoint = os.environ.get("TARGET_LOGIN_ENDPOINT")
        login_user = os.environ.get("TARGET_LOGIN_USER")
        login_pass = os.environ.get("TARGET_LOGIN_PASS")
        if login_endpoint and login_user and login_pass:
            success = await self._try_relogin(
                auth_state, login_endpoint, login_user, login_pass, host, use_tls
            )
            recovery_log.append({
                "strategy": "relogin",
                "endpoint": login_endpoint,
                "result": "success" if success else "failed",
            })
            if success:
                logger.info("Auth recovered via re-login")
                auth_state.recovery_history = recovery_log
                return True

        # ==  3:  ==
        #  Agent  ( API)
        logger.info("Auth recovery failed, trying anonymous access")
        auth_state.auth_type = "none"
        auth_state.token_value = None
        auth_state.raw_headers = [
            (k, v) for k, v in auth_state.raw_headers
            if k.lower() not in ("authorization", "cookie", "x-api-key")
        ]
        recovery_log.append({
            "strategy": "anonymous_degradation",
            "endpoint": "N/A",
            "result": "degraded",
        })
        auth_state.recovery_history = recovery_log
        return True  # , 

    async def try_tenant_switch(
        self,
        auth_state: AuthState,
        *,
        new_tenant_id: str | None = None,
    ) -> AuthState | None:
        """ —  ID  403

        Academic basis:
            - OWASP API1 (BOLA) —  tenant_id 
            - OWASP API3 (BOPLA) — 

        :
            1. imports JWT payload  header  tenant_id
            2.  tenant_id ( / )
            3.  tenant_header, 

        Args:
            auth_state: 
            new_tenant_id:  ID (None = )

        Returns:
             AuthState ,  None 
        """
        if not auth_state.tenant_header:
            logger.debug("No tenant header found, cannot switch tenant")
            return None

        #  auth_state 
        import copy
        new_state = copy.deepcopy(auth_state)

        if new_tenant_id:
            #  ID
            new_state.tenant_id = new_tenant_id
        elif auth_state.tenant_id:
            #  ( org_001 → org_002)
            num_match = re.search(r"(\d+)", auth_state.tenant_id)
            if num_match:
                current_num = int(num_match.group(1))
                prefix = auth_state.tenant_id[: num_match.start()]
                suffix = auth_state.tenant_id[num_match.end() :]
                num_width = len(num_match.group(1))

                new_num = current_num + 1
                new_state.tenant_id = f"{prefix}{new_num:0{num_width}d}{suffix}"
                logger.info(
                    "Tenant switch: %s → %s",
                    auth_state.tenant_id,
                    new_state.tenant_id,
                )
            else:
                logger.debug("Tenant ID has no numeric part, cannot enumerate")
                return None
        else:
            return None

        #  raw_headers  tenant header
        new_headers: list[tuple[str, str]] = []
        for k, v in new_state.raw_headers:
            if k.lower() == new_state.tenant_header.lower():
                new_headers.append((k, new_state.tenant_id))
            else:
                new_headers.append((k, v))
        new_state.raw_headers = new_headers

        return new_state

    def update_csrf_token(
        self,
        auth_state: AuthState,
        response_headers: dict[str, str],
        response_body: str = "",
    ) -> AuthState:
        """imports CSRF token,  auth_state

         Agent  CSRF token:
            - Set-Cookie: csrf=xxx
            - X-CSRF-Token: xxx ( header)
            -  JSON: {"csrf_token": "xxx"}

        Args:
            auth_state: 
            response_headers: HTTP  headers
            response_body: HTTP  (, imports JSON )

        Returns:
             AuthState ( + )
        """
        #  header 
        for h_name, h_value in response_headers.items():
            h_lower = h_name.lower()
            if h_lower in ("x-csrf-token", "x-xsrf-token"):
                auth_state.csrf_token = h_value
                auth_state.csrf_header = h_name
                logger.info("CSRF token updated from response header: %s", h_name)
                return auth_state

        #  Set-Cookie 
        set_cookie = response_headers.get("set-cookie", "")
        if set_cookie:
            csrf_match = re.search(r"csrf[=:]([^\s;]+)", set_cookie, re.IGNORECASE)
            if csrf_match:
                auth_state.csrf_token = csrf_match.group(1)
                logger.info("CSRF token updated from Set-Cookie")
                return auth_state

        #  JSON 
        if response_body:
            try:
                data = json.loads(response_body)
                if isinstance(data, dict):
                    for key in ("csrf_token", "csrf", "xsrf_token", "_token"):
                        if key in data:
                            auth_state.csrf_token = str(data[key])
                            logger.info("CSRF token updated from response body: %s", key)
                            return auth_state
            except (json.JSONDecodeError, TypeError):
                pass

        return auth_state

    def build_auth_headers(self, auth_state: AuthState) -> list[tuple[str, str]]:
        """ auth_state  headers

        :
            1.  raw_headers 
            2.  token_value  →  Authorization header
            3.  tenant_id  →  tenant header
            4.  csrf_token  →  CSRF header

        Args:
            auth_state: 

        Returns:
             header 
        """
        headers: list[tuple[str, str]] = []
        seen_keys: set[str] = set()

        for k, v in auth_state.raw_headers:
            k_lower = k.lower()

            #  Authorization
            if k_lower == "authorization" and auth_state.token_value:
                if auth_state.auth_type in ("bearer", "jwt"):
                    headers.append((k, f"Bearer {auth_state.token_value}"))
                else:
                    headers.append((k, v))
                seen_keys.add(k_lower)
                continue

            #  Cookie
            if k_lower == "cookie" and auth_state.auth_type == "cookie" and auth_state.token_value:
                headers.append((k, auth_state.token_value))
                seen_keys.add(k_lower)
                continue

            #  API Key
            if k_lower == "x-api-key" and auth_state.token_value:
                headers.append((k, auth_state.token_value))
                seen_keys.add(k_lower)
                continue

            #  Tenant
            if (
                auth_state.tenant_header
                and k_lower == auth_state.tenant_header.lower()
                and auth_state.tenant_id
            ):
                headers.append((auth_state.tenant_header, auth_state.tenant_id))
                seen_keys.add(k_lower)
                continue

            #  CSRF
            if (
                auth_state.csrf_header
                and k_lower == auth_state.csrf_header.lower()
                and auth_state.csrf_token
            ):
                headers.append((auth_state.csrf_header, auth_state.csrf_token))
                seen_keys.add(k_lower)
                continue

            #  header
            headers.append((k, v))
            seen_keys.add(k_lower)

        #  raw_headers  header
        if auth_state.csrf_header and auth_state.csrf_token and auth_state.csrf_header.lower() not in seen_keys:
            headers.append((auth_state.csrf_header, auth_state.csrf_token))

        if auth_state.tenant_header and auth_state.tenant_id and auth_state.tenant_header.lower() not in seen_keys:
            headers.append((auth_state.tenant_header, auth_state.tenant_id))

        return headers

    def is_token_expired(self, auth_state: AuthState, *, ahead: float = 0.0) -> bool:
        """ token 

        Args:
            auth_state: 
            ahead:  (),  60 =  60 

        Returns:
            True  token 
        """
        if auth_state.token_expiry is None:
            return False
        return time.time() + ahead >= auth_state.token_expiry

    async def _try_token_refresh(
        self,
        auth_state: AuthState,
        host: str,
        use_tls: bool,
    ) -> bool:
        """ token 

        Academic basis:
            - RFC 6749 §6 — OAuth 2.0 Token Refresh grant type

        :
            1. POST refresh_endpoint with current token
            2.  token
            3.  auth_state.token_value
        """
        import httpx

        if not host or not auth_state.refresh_endpoint:
            return False

        scheme = "https" if use_tls else "http"
        url = f"{scheme}://{host}{auth_state.refresh_endpoint}"

        #  headers
        headers: dict[str, str] = {}
        for k, v in auth_state.raw_headers:
            if k.lower() not in ("content-length", "host", "content-type"):
                headers[k] = v
        headers["Content-Type"] = "application/json"

        #  body
        refresh_body = json.dumps({"refresh_token": auth_state.token_value}, ensure_ascii=False)

        try:
            async with httpx.AsyncClient(
                timeout=10.0, follow_redirects=True, verify=_TLS_VERIFY
            ) as client:
                response = await client.request(
                    method=auth_state.refresh_method,
                    url=url,
                    headers=headers,
                    content=refresh_body,
                )

                if response.status_code >= 400:
                    logger.debug(
                        "Token refresh failed: HTTP %d",
                        response.status_code,
                    )
                    return False

                #  token
                try:
                    data = response.json()
                    new_token = (
                        data.get("access_token")
                        or data.get("token")
                        or data.get("accessToken")
                    )
                    if new_token:
                        auth_state.token_value = new_token
                        #  JWT expiry ( token  JWT)
                        jwt_payload = _decode_jwt_payload(new_token)
                        if jwt_payload and jwt_payload.get("exp"):
                            auth_state.token_expiry = float(jwt_payload["exp"]) - 60.0
                        logger.info("Token refreshed successfully")
                        return True
                except (json.JSONDecodeError, TypeError):
                    pass

        except Exception as e:
            logger.debug("Token refresh error: %s", e)

        return False

    async def _try_relogin(
        self,
        auth_state: AuthState,
        login_endpoint: str,
        username: str,
        password: str,
        host: str,
        use_tls: bool,
    ) -> bool:
        """ token

        Academic basis:
            - OWASP WSTG-ATHN-02 — 

        :
            1. POST login_endpoint with credentials
            2.  token
            3.  auth_state
        """
        import httpx

        scheme = "https" if use_tls else "http"
        url = f"{scheme}://{host}{login_endpoint}"

        headers = {"Content-Type": "application/json"}
        #  headers ( User-Agent)
        for k, v in auth_state.raw_headers:
            if k.lower() not in (
                "authorization", "cookie", "x-api-key",
                "content-length", "host", "content-type",
            ):
                headers[k] = v

        login_body = json.dumps(
            {"username": username, "password": password},
            ensure_ascii=False,
        )

        try:
            async with httpx.AsyncClient(
                timeout=10.0, follow_redirects=True, verify=_TLS_VERIFY
            ) as client:
                response = await client.post(
                    url=url,
                    headers=headers,
                    content=login_body,
                )

                if response.status_code >= 400:
                    logger.debug("Re-login failed: HTTP %d", response.status_code)
                    return False

                try:
                    data = response.json()
                    new_token = (
                        data.get("access_token")
                        or data.get("token")
                        or data.get("accessToken")
                    )
                    if new_token:
                        auth_state.token_value = new_token
                        auth_state.auth_type = "bearer"
                        jwt_payload = _decode_jwt_payload(new_token)
                        if jwt_payload:
                            auth_state.auth_type = "jwt"
                            exp = jwt_payload.get("exp")
                            if exp:
                                auth_state.token_expiry = float(exp) - 60.0
                        logger.info("Re-login successful, new token acquired")
                        return True
                except (json.JSONDecodeError, TypeError):
                    pass

        except Exception as e:
            logger.debug("Re-login error: %s", e)

        return False


def _decode_jwt_payload(token: str) -> dict[str, Any] | None:
    """ JWT payload ()

    Academic basis:
        - RFC 7519 §3 — JWT : header.payload.signature
        - RFC 7519 §4.1.4 — exp (Expiration Time) claim
        - RFC 7515 §2 —  payload 

    Args:
        token: JWT token 

    Returns:
        payload ,  None  JWT
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None

    try:
        # JWT payload 
        payload_b64 = parts[1]
        # base64url padding 
        padding_needed = 4 - len(payload_b64) % 4
        if padding_needed < 4:
            payload_b64 += _B64_PAD * padding_needed

        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_bytes)
        if isinstance(payload, dict):
            return payload
    except (ValueError, json.JSONDecodeError, Exception) as e:
        logger.debug("JWT decode failed: %s", e)

    return None
