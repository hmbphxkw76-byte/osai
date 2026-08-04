# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""API 认证统一入口 — 统一管理 Basic / Bearer / Cookie / OAuth2 认证。

**设计原则** (R-022: PyRIT 原生优先):
  - 纯数据层模块, 不覆盖原生认证
  - 提供 HTTP header / cookie 注入接口供 Target 适配器使用

**认证类型**:
  - ``none``:   无认证
  - ``basic``:  HTTP Basic auth
  - ``bearer``: Bearer token (OpenAI API)
  - ``cookie``: Session cookie
  - ``oauth2``: OAuth2 client_credentials (企业 API)

学术依据:
  - RFC 7617: HTTP Basic Authentication
  - RFC 6750: OAuth 2.0 Bearer Token
  - RFC 6749 Section 4.4: Client Credentials Grant

> **日期**: 2026-8-4
"""

from __future__ import annotations

import base64
import logging
import os
from dataclasses import dataclass, field
from typing import Any

from web_redteam.auth.credential_store import CredentialStore

logger = logging.getLogger(__name__)

# OAuth2 token 进程级缓存 (避免重复获取)
_oauth2_token_cache: dict[str, str] = {}


@dataclass
class APIAuthConfig:
    """API 认证配置 — 统一所有 API 级认证类型。

    Attributes:
        auth_type: 认证类型 (``none`` / ``basic`` / ``bearer`` / ``cookie`` / ``oauth2``)。
        username: 用户名 (Basic auth)。
        password: 密码 (Basic auth)。
        token: Bearer token。
        cookie_name: Cookie 名称。
        cookie_value: Cookie 值。
        oauth_token_url: OAuth2 token endpoint URL。
        oauth_client_id: OAuth2 client ID。
        oauth_client_secret: OAuth2 client secret。
        extra_headers: 额外 header 字典。
    """

    auth_type: str = "none"
    username: str = ""
    password: str = ""
    token: str = ""
    cookie_name: str = ""
    cookie_value: str = ""
    oauth_token_url: str = ""
    oauth_client_id: str = ""
    oauth_client_secret: str = ""
    extra_headers: dict[str, str] = field(default_factory=dict)


class APIAuthenticator:
    """API 认证器 — 生成 headers / cookies 供 Target 使用。

    使用方式::

        from web_redteam.auth.api_auth import APIAuthenticator

        # Bearer token
        auth = APIAuthenticator(APIAuthConfig(
            auth_type="bearer",
            token="sk-...",
        ))
        headers = auth.get_headers()

        # Cookie auth
        auth = APIAuthenticator(APIAuthConfig(auth_type="cookie"))
        auth.set_cookie("session_id", "abc123...")
        cookies = auth.get_cookies()

        # Basic auth
        auth = APIAuthenticator(APIAuthConfig(
            auth_type="basic",
            username="user",
            password="pass",
        ))
        headers = auth.get_headers()
    """

    def __init__(self, config: APIAuthConfig | None = None) -> None:
        """初始化 API 认证器。

        Args:
            config: 认证配置 (None=无认证)。
        """
        self._config = config or APIAuthConfig()
        self._is_authenticated = False

    @property
    def config(self) -> APIAuthConfig:
        """认证配置。."""
        return self._config

    @property
    def is_authenticated(self) -> bool:
        """是否已认证。."""
        return self._is_authenticated

    def get_headers(self) -> dict[str, str]:
        """获取认证 HTTP headers。

        Returns:
            headers 字典 (可能为空)。
        """
        headers: dict[str, str] = {}

        if self._config.auth_type == "basic":
            if self._config.username:
                credentials = base64.b64encode(
                    f"{self._config.username}:{self._config.password}".encode()
                ).decode()
                headers["Authorization"] = f"Basic {credentials}"
                self._is_authenticated = True

        elif self._config.auth_type == "bearer":
            if self._config.token:
                headers["Authorization"] = f"Bearer {self._config.token}"
                self._is_authenticated = True

        elif self._config.auth_type == "cookie":
            if self._config.cookie_value:
                headers["Cookie"] = f"{self._config.cookie_name}={self._config.cookie_value}"
                self._is_authenticated = True

        elif self._config.auth_type == "oauth2":
            token = self._get_oauth2_token()
            if token:
                headers["Authorization"] = f"Bearer {token}"
                self._is_authenticated = True

        # 额外 headers
        if self._config.extra_headers:
            headers.update(self._config.extra_headers)

        return headers

    def get_cookies(self) -> dict[str, str]:
        """获取认证 cookies。

        Returns:
            cookies 字典 (可能为空)。
        """
        if self._config.auth_type == "cookie" and self._config.cookie_value:
            return {self._config.cookie_name: self._config.cookie_value}
        return {}

    def set_cookie(self, name: str, value: str) -> None:
        """设置 cookie (自动获取后调用)。."""
        self._config.cookie_name = name
        self._config.cookie_value = value
        self._config.auth_type = "cookie"
        self._is_authenticated = True
        logger.info(f"APIAuthenticator: cookie set ({name}={value[:8]}...)")

    def switch_user(self, username: str, password: str, user_id: int | None = None) -> None:
        """切换用户 (多身份)。."""
        self._config.username = username
        self._config.password = password
        self._config.auth_type = "basic"
        self._is_authenticated = True
        if user_id is not None:
            self._config.extra_headers = self._config.extra_headers or {}
            self._config.extra_headers["X-User-ID"] = str(user_id)
        logger.info(f"APIAuthenticator: switched to user '{username}'")

    def _get_oauth2_token(self) -> str | None:
        """获取 OAuth2 client_credentials token (内部方法)。."""
        if not self._config.oauth_token_url or not self._config.oauth_client_id:
            logger.error("APIAuthenticator: OAuth2 requires token_url + client_id + client_secret")
            return None

        cache_key = f"{self._config.oauth_token_url}:{self._config.oauth_client_id}"
        if cache_key in _oauth2_token_cache:
            logger.debug("APIAuthenticator: OAuth2 token from cache")
            return _oauth2_token_cache[cache_key]

        token = _fetch_oauth2_token(
            token_url=self._config.oauth_token_url,
            client_id=self._config.oauth_client_id,
            client_secret=self._config.oauth_client_secret,
        )
        if token:
            _oauth2_token_cache[cache_key] = token
            logger.info("APIAuthenticator: OAuth2 token acquired")
        else:
            logger.error("APIAuthenticator: OAuth2 token acquisition failed")
        return token

    # ── 工厂方法 ──

    @classmethod
    def from_env(cls) -> APIAuthenticator:
        """从环境变量创建认证器。

        支持的变量:
          - ``TARGET_AUTH_TYPE``: basic/cookie/bearer/none
          - ``TARGET_USERNAME`` / ``TARGET_PASSWORD``: Basic auth
          - ``TARGET_COOKIE_NAME`` / ``TARGET_COOKIE_VALUE``: Cookie
          - ``API_KEY``: Bearer token
        """
        auth_type = os.getenv("TARGET_AUTH_TYPE", "none")

        # 如果 auth_type 为 none 但 API_KEY 存在, 自动切换为 bearer
        if auth_type == "none":
            api_key = CredentialStore.get_credential("API_KEY", "")
            if api_key:
                auth_type = "bearer"

        config = APIAuthConfig(
            auth_type=auth_type,
            username=CredentialStore.get_credential("TARGET_USERNAME"),
            password=CredentialStore.get_credential("TARGET_PASSWORD"),
            token=CredentialStore.get_credential("API_KEY"),
            cookie_name=CredentialStore.get_credential("TARGET_COOKIE_NAME"),
            cookie_value=CredentialStore.get_credential("TARGET_COOKIE_VALUE"),
        )
        return cls(config)

    @classmethod
    def from_args(cls, args: Any) -> APIAuthenticator:
        """从 CLI 参数创建认证器。

        Args:
            args: argparse.Namespace。

        Returns:
            APIAuthenticator 实例。
        """
        auth_type = getattr(args, "api_auth_type", "bearer")

        config = APIAuthConfig(
            auth_type=auth_type,
            token=CredentialStore.get_credential("API_KEY", ""),
            oauth_token_url=getattr(args, "api_oauth_token_url", "") or "",
            oauth_client_id=getattr(args, "api_oauth_client_id", "") or "",
            oauth_client_secret=getattr(args, "api_oauth_client_secret", "") or "",
        )
        return cls(config)

    @classmethod
    def from_url(cls, url: str, api_key: str = "") -> APIAuthenticator:
        """根据 URL 自动判别认证方式。

        判别规则:
          - URL 包含 /v1/chat/completions 或 /v1/completions → OpenAI 兼容 (Bearer)
          - URL 包含 localhost:11434 → Ollama (通常无认证或 Bearer)
          - 其他 + api_key 非空 → Bearer
          - 其他 + api_key 为空 → 无认证

        Args:
            url: 目标 URL。
            api_key: API Key (可选, 用于 Bearer 认证)。

        Returns:
            APIAuthenticator 实例 (未认证, 等待认证数据注入)。
        """
        url_lower = url.lower()

        # Ollama 本地服务
        if "localhost:11434" in url_lower or "127.0.0.1:11434" in url_lower:
            return cls.for_ollama(url, api_key)

        # OpenAI 兼容 API 平台
        if any(p in url_lower for p in ("/v1/chat/completions", "/v1/completions", "/v1/responses")):
            return cls.for_openai_compatible(url, api_key)

        # 通用: 有 api_key → Bearer, 无 → none
        if api_key:
            return cls(APIAuthConfig(auth_type="bearer", token=api_key))
        return cls(APIAuthConfig(auth_type="none"))

    @classmethod
    def for_openai_compatible(cls, endpoint: str, api_key: str = "") -> APIAuthenticator:
        """创建 OpenAI 兼容平台认证器 (LongCat / SiliconFlow / OpenRouter 等)。

        自动判别:
          - api_key 非空 → Bearer token 认证
          - api_key 为空 → 无认证

        Args:
            endpoint: API 端点 URL。
            api_key: API Key (可选)。

        Returns:
            APIAuthenticator 实例。
        """
        if api_key:
            logger.info(f"APIAuthenticator: OpenAI-compatible (Bearer) for {endpoint}")
            return cls(APIAuthConfig(auth_type="bearer", token=api_key))
        logger.info(f"APIAuthenticator: OpenAI-compatible (no auth) for {endpoint}")
        return cls(APIAuthConfig(auth_type="none"))

    @classmethod
    def for_ollama(
        cls,
        endpoint: str = "http://localhost:11434",
        api_key: str = "",
    ) -> APIAuthenticator:
        """创建 Ollama 平台认证器。

        Ollama 默认无认证; 如配置了 OLLAMA_API_KEY 环境变量,
        则使用 Bearer token。

        Args:
            endpoint: Ollama API 端点 URL (默认 http://localhost:11434)。
            api_key: API Key (可选, 从 OLLAMA_API_KEY 环境变量获取)。

        Returns:
            APIAuthenticator 实例。
        """
        if not api_key:
            api_key = CredentialStore.get_credential("OLLAMA_API_KEY", "")
        if api_key:
            logger.info(f"APIAuthenticator: Ollama (Bearer) for {endpoint}")
            return cls(APIAuthConfig(auth_type="bearer", token=api_key))
        logger.info(f"APIAuthenticator: Ollama (no auth) for {endpoint}")
        return cls(APIAuthConfig(auth_type="none"))


# ── 模块级 OAuth2 辅助函数 ──


def _fetch_oauth2_token(
    *,
    token_url: str,
    client_id: str,
    client_secret: str,
    scope: str = "",
) -> str | None:
    """获取 OAuth2 client_credentials token。

    使用 client_credentials grant type 向 token endpoint 发送 POST 请求,
    获取 access_token (RFC 6749 Section 4.4)。

    Args:
        token_url: OAuth2 token endpoint URL。
        client_id: Client ID。
        client_secret: Client Secret。
        scope: 请求的 scope (可选)。

    Returns:
        access_token 字符串, 失败返回 None。
    """
    import json as _json
    import urllib.error

    body_data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    if scope:
        body_data["scope"] = scope

    body_str = "&".join(f"{k}={v}" for k, v in body_data.items())
    body_bytes = body_str.encode("utf-8")

    req = urllib.request.Request(
        token_url,
        data=body_bytes,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            token_data = _json.loads(resp.read().decode("utf-8"))
            token = token_data.get("access_token")
            if token:
                logger.info("OAuth2 token acquired successfully")
                return token
            logger.error(f"OAuth2 response missing access_token: {token_data}")
            return None
    except Exception as e:
        logger.error(f"OAuth2 token acquisition failed: {e}")
        return None
