"""认证状态管理器 — Token 刷新 + 会话保活 + 多租户探测 + CSRF 轮换。

学术依据:
    - Heroux et al. (arXiv:2403.04206) §3.2 — 超时/认证失效恢复策略:
      认证失效不应终止攻击, 应尝试恢复后继续, 恢复失败才降级。
    - Greshake et al. (arXiv:2302.12173) §4 — 信任链利用
      认证 token 是信任链的一环, 可通过间接注入获取或刷新。
    - OWASP WSTG-ATHN-01 — 认证绕过测试标准。
    - OWASP API Security Top 10 (2025) API1 (BOLA) / API3 (BOPLA):
      多租户场景下的权限边界探测。

设计原则 (Rule 2: 增强层, 不替换):
    本模块是胶水层增强, 不替换任何 PyRIT 原生组件。
    - 认证检测: 静态分析 Burp 请求 headers
    - 认证恢复: 使用 httpx 直接发送 HTTP 请求 (非 prompt 交互)
    - 多租户探测: 修改 tenant header 后重新发送请求
    - CSRF 轮换: 从响应 headers 中提取新 token

PyRIT 设计域边界 (Rule 2):
    认证恢复使用 httpx 直接发送 HTTP 请求 (登录/刷新端点),
    这不是 LLM prompt 交互, 属于 HTTP 协议层操作。
    不使用 HTTPTarget (不需要 {PROMPT} 占位符)。
    类似 MCP JSON-RPC 枚举的例外: httpx 是 PyRIT 已有依赖。
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

# P2-06: TLS verify 配置化 (SSOT)
_TLS_VERIFY = _get_tls_verify_from_config()

# JWT 解码所需的 base64url padding 补齐
_B64_PAD = "="


@dataclass
class AuthState:
    """认证状态快照 — 贯穿整个攻击生命周期的认证信息。

    属性:
        auth_type: 认证类型 (cookie / bearer / jwt / api_key / none)。
        raw_headers: 原始认证 header 列表 (保持顺序)。
        token_value: 提取的 token 值 (Bearer xxx 中的 xxx 部分)。
        token_expiry: 预估过期间间 (Unix timestamp, None = 未知)。
        refresh_endpoint: token 刷新端点 (如 /api/auth/refresh)。
        refresh_method: 刷新请求方法 (默认 POST)。
        tenant_id: 当前租户 ID (如从 JWT payload 或路径中提取)。
        tenant_header: 租户 header 名 (如 X-Tenant-Id, X-Org-Id)。
        csrf_token: 当前 CSRF token 值。
        csrf_header: CSRF header 名 (默认 X-CSRF-Token)。
        refresh_count: 已执行认证恢复次数。
        max_refreshes: 最大恢复次数 (默认 3)。
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
    # P2-4: 认证恢复历史记录
    recovery_history: list[dict[str, str]] = field(default_factory=list)


class AuthStateManager:
    """认证状态管理 — 检测、恢复、保活、多租户探测。

    生命周期:
        1. detect_auth_type(): 从 Burp 请求静态分析认证类型
        2. (攻击执行中) 401/403 触发 try_recover_auth()
        3. try_recover_auth(): 尝试 token 刷新 / 重新登录 / 匿名降级
        4. try_tenant_switch(): 403 时尝试切换租户 ID
        5. update_csrf_token(): 从响应中提取新 CSRF token

    使用方式:
        manager = AuthStateManager()
        auth_state = await manager.detect_auth_type(parsed)
        # ... 攻击执行中 401 ...
        recovered = await manager.try_recover_auth(auth_state)
        if recovered:
            new_headers = await manager.refresh_headers(auth_state)
    """

    def __init__(self, *, max_refreshes: int = 3) -> None:
        """初始化认证状态管理器。

        Args:
            max_refreshes: 最大认证恢复次数 (默认 3)。
        """
        self._max_refreshes = max_refreshes

    async def detect_auth_type(self, parsed: Any) -> AuthState:
        """从 Burp 请求静态分析认证类型和参数。

        检测策略 (按优先级):
            1. Authorization: Bearer xxx → JWT (解码 exp) 或 Bearer Token
            2. Cookie: session_id / JSESSIONID / PHPSESSID → Cookie-based
            3. X-API-Key: xxx → API Key
            4. 无认证头 → 尝试匿名访问

        JWT exp 解码:
            解码 JWT payload (不验签), 提取 exp 字段。
            预估过期间间 = exp - 60s (提前 1 分钟刷新)。
            学术依据: RFC 7519 §4.1.4 — exp 是 JWT 标准声明。

        Args:
            parsed: ParsedBurpRequest 实例。

        Returns:
            AuthState 认证状态快照。
        """
        state = AuthState(max_refreshes=self._max_refreshes)

        if not hasattr(parsed, "headers"):
            return state

        headers = parsed.headers
        state.raw_headers = list(getattr(parsed, "raw_headers", []))

        # ── 1. Authorization: Bearer ──
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

        # ── 2. Cookie-based ──
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

            # Cookie 过期间间未知 (无法从 cookie 值推断)
            state.token_value = cookie_str

        # ── 3. X-API-Key ──
        elif headers.get("x-api-key"):
            state.auth_type = "api_key"
            state.token_value = headers["x-api-key"]
            logger.info("API Key auth detected")

        else:
            state.auth_type = "none"
            logger.info("No authentication headers detected — anonymous access")

        # ── 检测租户 header ──
        for h_name, h_value in state.raw_headers:
            h_lower = h_name.lower()
            if h_lower in ("x-tenant-id", "x-org-id", "x-organization", "x-workspace"):
                state.tenant_header = h_name
                state.tenant_id = h_value
                logger.info("Tenant header detected: %s=%s", h_name, h_value)
                break

        # ── 检测 CSRF token header ──
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

        恢复策略 (3 层 fallback):
            1. Token 刷新: POST refresh_endpoint → 获取新 token
            2. 重新登录: 使用环境变量中的凭证重新登录
            3. 匿名降级: 去掉认证头, 尝试匿名访问

        学术依据:
            - Heroux et al. (arXiv:2403.04206) §3.2 — 恢复策略
            - RFC 6749 §6 — OAuth 2.0 Token Refresh

        Args:
            auth_state: 当前认证状态。
            host: 目标 host (用于构建刷新请求 URL)。
            use_tls: 是否使用 TLS。

        Returns:
            True 如果恢复成功, False 如果所有策略失败。
        """
        if auth_state.refresh_count >= auth_state.max_refreshes:
            logger.warning(
                "Auth recovery exhausted (max=%d), giving up",
                auth_state.max_refreshes,
            )
            return False

        auth_state.refresh_count += 1

        # P2-4: 细化恢复策略 — 记录每步结果
        # 学术依据: Heroux et al. (arXiv:2403.04206) §3.2 — 分级恢复
        recovery_log: list[dict[str, str]] = []

        # ── 策略 1: Token 刷新 ──
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

        # ── 策略 2: 重新登录 ──
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

        # ── 策略 3: 匿名降级 ──
        # 某些 Agent 端点可能不需要认证 (如公开 API)
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
        return True  # 匿名降级不是真正的恢复, 但允许继续尝试

    async def try_tenant_switch(
        self,
        auth_state: AuthState,
        *,
        new_tenant_id: str | None = None,
    ) -> AuthState | None:
        """多租户探测 — 尝试切换租户 ID 绕过 403。

        学术依据:
            - OWASP API1 (BOLA) — 路径中的 tenant_id 可枚举
            - OWASP API3 (BOPLA) — 权限边界探测

        策略:
            1. 从 JWT payload 或 header 中提取当前 tenant_id
            2. 尝试枚举其他 tenant_id (数字递增 / 常见名称)
            3. 替换 tenant_header, 重新发送请求

        Args:
            auth_state: 当前认证状态。
            new_tenant_id: 指定的新租户 ID (None = 自动枚举)。

        Returns:
            切换后的 AuthState 副本, 或 None 如果无法切换。
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

        某些 Agent 应用每次响应都轮换 CSRF token:
            - Set-Cookie: csrf=xxx
            - X-CSRF-Token: xxx (响应 header)
            - 响应 JSON: {"csrf_token": "xxx"}

        Args:
            auth_state: 当前认证状态。
            response_headers: HTTP 响应 headers。
            response_body: HTTP 响应体 (可选, 用于从 JSON 提取)。

        Returns:
            更新后的 AuthState (就地修改 + 返回引用)。
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

        策略:
            1. 以 raw_headers 为基础
            2. 如果 token_value 更新了 → 替换 Authorization header
            3. 如果 tenant_id 更新了 → 替换 tenant header
            4. 如果 csrf_token 更新了 → 替换 CSRF header

        Args:
            auth_state: 当前认证状态。

        Returns:
            重建后的 header 列表。
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

        # 补充不在 raw_headers 中的新 header
        if auth_state.csrf_header and auth_state.csrf_token and auth_state.csrf_header.lower() not in seen_keys:
            headers.append((auth_state.csrf_header, auth_state.csrf_token))

        if auth_state.tenant_header and auth_state.tenant_id and auth_state.tenant_header.lower() not in seen_keys:
            headers.append((auth_state.tenant_header, auth_state.tenant_id))

        return headers

    def is_token_expired(self, auth_state: AuthState, *, ahead: float = 0.0) -> bool:
        """检查 token 是否已过期或即将过期。

        Args:
            auth_state: 认证状态。
            ahead: 提前量 (秒), 如 60 = 提前 60 秒判定为过期。

        Returns:
            True 如果 token 已过期或即将过期。
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

        学术依据:
            - RFC 6749 §6 — OAuth 2.0 Token Refresh grant type

        策略:
            1. POST refresh_endpoint with current token
            2. 解析响应中的新 token
            3. 更新 auth_state.token_value
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

        学术依据:
            - OWASP WSTG-ATHN-02 — 认证机制测试

        策略:
            1. POST login_endpoint with credentials
            2. 解析响应中的 token
            3. 更新 auth_state
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
    """解码 JWT payload (不验签)。

    学术依据:
        - RFC 7519 §3 — JWT 结构: header.payload.signature
        - RFC 7519 §4.1.4 — exp (Expiration Time) claim
        - RFC 7515 §2 — 不验签仅解码 payload 用于信息提取

    Args:
        token: JWT token 字符串。

    Returns:
        payload 字典, 或 None 如果不是有效 JWT。
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
