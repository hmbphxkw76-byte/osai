"""认证状态管理器 — Token 刷新 + 会话保活 + 多租户探测 + CSRF 轮换。
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

logger = logging.getLogger(__name__)

# JWT 解码所需的 base64url padding 补齐
_B64_PAD = "="

@dataclass
class AuthState:
    """认证状态快照 — 贯穿整个攻击生命周期的认证信息。
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

class AuthStateManager:
    """认证状态管理 — 检测、恢复、保活、多租户探测。
    """

    def __init__(self, *, max_refreshes: int = 3) -> None:
        """初始化认证状态管理器。
        """
        self._max_refreshes = max_refreshes

    async def detect_auth_type(self, parsed: Any) -> AuthState:
        """从 Burp 请求静态分析认证类型和参数。
        """
        state = AuthState(max_refreshes=self._max_refreshes)

        if not hasattr(parsed, "headers"):
            return state

        headers = parsed.headers
        state.raw_headers = list(getattr(parsed, "raw_headers", []))

        auth_header = headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()
            state.token_value = token
            state.auth_type = "bearer"

            # 尝试解码为 JWT
            jwt_payload = _decode_jwt_payload(token)
            if jwt_payload is not None:
                state.auth_type = "jwt"
                exp = jwt_payload.get("exp")
                if exp and isinstance(exp, (int, float)):
                    # 提前 60 秒刷新 (避免攻击过程中过期)
                    state.token_expiry = float(exp) - 60.0
                    logger.info(
                        "JWT detected: exp=%s, expiry_in=%.0fs",
                        exp,
                        state.token_expiry - time.time(),
                    )

                # 从 JWT payload 提取租户信息
                tenant = (
                    jwt_payload.get("tenant_id")
                    or jwt_payload.get("org_id")
                    or jwt_payload.get("organization")
                    or jwt_payload.get("workspace")
                )
                if tenant:
                    state.tenant_id = str(tenant)
                    logger.info("JWT tenant detected: %s", state.tenant_id)

        elif "cookie" in headers:
            cookie_str = headers["cookie"]
            state.auth_type = "cookie"

            # 检测 session 类型
            if re.search(r"session[_-]?id", cookie_str, re.IGNORECASE):
                logger.info("Cookie auth: session_id detected")
            elif re.search(r"JSESSIONID", cookie_str, re.IGNORECASE):
                logger.info("Cookie auth: JSESSIONID detected")
            elif re.search(r"PHPSESSID", cookie_str, re.IGNORECASE):
                logger.info("Cookie auth: PHPSESSID detected")

            # Cookie 过期时间未知 (无法从 cookie 值推断)
            state.token_value = cookie_str

        elif headers.get("x-api-key"):
            state.auth_type = "api_key"
            state.token_value = headers["x-api-key"]
            logger.info("API Key auth detected")

        else:
            state.auth_type = "none"
            logger.info("No authentication headers detected — anonymous access")

        for h_name, h_value in state.raw_headers:
            h_lower = h_name.lower()
            if h_lower in ("x-tenant-id", "x-org-id", "x-organization", "x-workspace"):
                state.tenant_header = h_name
                state.tenant_id = h_value
                logger.info("Tenant header detected: %s=%s", h_name, h_value)
                break

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
        """认证失效后尝试恢复。
        """
        if auth_state.refresh_count >= auth_state.max_refreshes:
            logger.warning(
                "Auth recovery exhausted (max=%d), giving up",
                auth_state.max_refreshes,
            )
            return False

        auth_state.refresh_count += 1

        if auth_state.refresh_endpoint:
            success = await self._try_token_refresh(auth_state, host, use_tls)
            if success:
                logger.info("Auth recovered via token refresh")
                return True

        login_endpoint = os.environ.get("TARGET_LOGIN_ENDPOINT")
        login_user = os.environ.get("TARGET_LOGIN_USER")
        login_pass = os.environ.get("TARGET_LOGIN_PASS")
        if login_endpoint and login_user and login_pass:
            success = await self._try_relogin(
                auth_state, login_endpoint, login_user, login_pass, host, use_tls
            )
            if success:
                logger.info("Auth recovered via re-login")
                return True

        # 某些 Agent 端点可能不需要认证 (如公开 API)
        logger.info("Auth recovery failed, trying anonymous access")
        auth_state.auth_type = "none"
        auth_state.token_value = None
        auth_state.raw_headers = [
            (k, v) for k, v in auth_state.raw_headers
            if k.lower() not in ("authorization", "cookie", "x-api-key")
        ]
        return True  # 匿名降级不是真正的恢复, 但允许继续尝试

    async def try_tenant_switch(
        self,
        auth_state: AuthState,
        *,
        new_tenant_id: str | None = None,
    ) -> AuthState | None:
        """多租户探测 — 尝试切换租户 ID 绕过 403。
        """
        if not auth_state.tenant_header:
            logger.debug("No tenant header found, cannot switch tenant")
            return None

        # 创建 auth_state 副本
        import copy
        new_state = copy.deepcopy(auth_state)

        if new_tenant_id:
            # 使用指定的新租户 ID
            new_state.tenant_id = new_tenant_id
        elif auth_state.tenant_id:
            # 尝试数字递增 (如 org_001 → org_002)
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

        # 更新 raw_headers 中的 tenant header
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
        """从响应中提取新 CSRF token, 更新到 auth_state。
        """
        # 从响应 header 提取
        for h_name, h_value in response_headers.items():
            h_lower = h_name.lower()
            if h_lower in ("x-csrf-token", "x-xsrf-token"):
                auth_state.csrf_token = h_value
                auth_state.csrf_header = h_name
                logger.info("CSRF token updated from response header: %s", h_name)
                return auth_state

        # 从 Set-Cookie 提取
        set_cookie = response_headers.get("set-cookie", "")
        if set_cookie:
            csrf_match = re.search(r"csrf[=:]([^\s;]+)", set_cookie, re.IGNORECASE)
            if csrf_match:
                auth_state.csrf_token = csrf_match.group(1)
                logger.info("CSRF token updated from Set-Cookie")
                return auth_state

        # 从 JSON 响应体提取
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
        """根据当前 auth_state 重建认证 headers。
        """
        headers: list[tuple[str, str]] = []
        seen_keys: set[str] = set()

        for k, v in auth_state.raw_headers:
            k_lower = k.lower()

            # 替换 Authorization
            if k_lower == "authorization" and auth_state.token_value:
                if auth_state.auth_type in ("bearer", "jwt"):
                    headers.append((k, f"Bearer {auth_state.token_value}"))
                else:
                    headers.append((k, v))
                seen_keys.add(k_lower)
                continue

            # 替换 Cookie
            if k_lower == "cookie" and auth_state.auth_type == "cookie" and auth_state.token_value:
                headers.append((k, auth_state.token_value))
                seen_keys.add(k_lower)
                continue

            # 替换 API Key
            if k_lower == "x-api-key" and auth_state.token_value:
                headers.append((k, auth_state.token_value))
                seen_keys.add(k_lower)
                continue

            # 替换 Tenant
            if (
                auth_state.tenant_header
                and k_lower == auth_state.tenant_header.lower()
                and auth_state.tenant_id
            ):
                headers.append((auth_state.tenant_header, auth_state.tenant_id))
                seen_keys.add(k_lower)
                continue

            # 替换 CSRF
            if (
                auth_state.csrf_header
                and k_lower == auth_state.csrf_header.lower()
                and auth_state.csrf_token
            ):
                headers.append((auth_state.csrf_header, auth_state.csrf_token))
                seen_keys.add(k_lower)
                continue

            # 保留原始 header
            headers.append((k, v))
            seen_keys.add(k_lower)

        # 补充未在 raw_headers 中的新 header
        if auth_state.csrf_header and auth_state.csrf_token and auth_state.csrf_header.lower() not in seen_keys:
            headers.append((auth_state.csrf_header, auth_state.csrf_token))

        if auth_state.tenant_header and auth_state.tenant_id and auth_state.tenant_header.lower() not in seen_keys:
            headers.append((auth_state.tenant_header, auth_state.tenant_id))

        return headers

    def is_token_expired(self, auth_state: AuthState, *, ahead: float = 0.0) -> bool:
        """检查 token 是否已过期或即将过期。
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
        """尝试 token 刷新。
        """
        import httpx

        if not host or not auth_state.refresh_endpoint:
            return False

        scheme = "https" if use_tls else "http"
        url = f"{scheme}://{host}{auth_state.refresh_endpoint}"

        # 构建刷新请求 headers
        headers: dict[str, str] = {}
        for k, v in auth_state.raw_headers:
            if k.lower() not in ("content-length", "host", "content-type"):
                headers[k] = v
        headers["Content-Type"] = "application/json"

        # 刷新请求 body
        refresh_body = json.dumps({"refresh_token": auth_state.token_value}, ensure_ascii=False)

        try:
            async with httpx.AsyncClient(
                timeout=10.0, follow_redirects=True, verify=False
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

                # 解析新 token
                try:
                    data = response.json()
                    new_token = (
                        data.get("access_token")
                        or data.get("token")
                        or data.get("accessToken")
                    )
                    if new_token:
                        auth_state.token_value = new_token
                        # 更新 JWT expiry (如果新 token 是 JWT)
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
        """尝试重新登录获取新 token。
        """
        import httpx

        scheme = "https" if use_tls else "http"
        url = f"{scheme}://{host}{login_endpoint}"

        headers = {"Content-Type": "application/json"}
        # 保留非认证 headers (如 User-Agent)
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
                timeout=10.0, follow_redirects=True, verify=False
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
    """解码 JWT payload (不验签)。
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None

    try:
        # JWT payload 是第二段
        payload_b64 = parts[1]
        # base64url padding 补齐
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
