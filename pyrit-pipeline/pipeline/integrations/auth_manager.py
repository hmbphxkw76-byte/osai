# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""统一认证管理器 — 管理两个 OWASP 靶机的认证。

支持两种认证模式:
  1. **HTTP Basic auth** — DonkAI 使用 (alice/password123, admin/admin123)
  2. **Session cookie** — AIVP 使用 (自动获取 aivp_sid)

配置化:
  通过 ``.env`` 或构造函数参数配置认证信息。

设计原则 (R-022: PyRIT 原生优先):
  - 纯数据层模块, 不覆盖原生认证
  - 提供 HTTP header 注入接口供 Target 适配器使用

> **日期**: 2026-8-4
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AuthConfig:
    """认证配置。.

    Attributes:
        auth_type: 认证类型 (``basic``/``cookie``/``none``)。
        username: 用户名 (Basic auth)。
        password: 密码 (Basic auth)。
        cookie_name: Cookie 名称 (如 ``aivp_sid``)。
        cookie_value: Cookie 值。
        token: Bearer token (可选)。
        extra_headers: 额外 header 字典。
    """

    auth_type: str = "none"
    username: str = ""
    password: str = ""
    cookie_name: str = ""
    cookie_value: str = ""
    token: str = ""
    extra_headers: dict[str, str] | None = None


# ── 预定义认证配置 ──

# DonkAI 默认用户
_DONKAI_USERS: dict[str, tuple[str, str, int]] = {
    "alice": ("alice", "password123", 1),
    "bob": ("bob", "password123", 2),
    "admin": ("admin", "admin123", 3),
}


class AuthManager:
    """统一认证管理器。

    使用方式::

        from pipeline.integrations.auth_manager import AuthManager, AuthConfig

        # DonkAI Basic auth
        auth = AuthManager(AuthConfig(
            auth_type="basic",
            username="alice",
            password="password123",
        ))

        # 获取 HTTP headers
        headers = auth.get_headers()
        # → {"Authorization": "Basic YWxpY2U6cGFzc3dvcmQxMjM="}

        # AIVP Session cookie
        auth = AuthManager(AuthConfig(
            auth_type="cookie",
            cookie_name="aivp_sid",
            cookie_value="abc123...",
        ))
    """

    def __init__(self, config: AuthConfig | None = None) -> None:
        """初始化认证管理器。

        Args:
            config: 认证配置 (None=无认证)。
        """
        self._config = config or AuthConfig()
        self._is_authenticated = False

    @property
    def config(self) -> AuthConfig:
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
        """设置 cookie (AIVP 自动获取后调用)。."""
        self._config.cookie_name = name
        self._config.cookie_value = value
        self._config.auth_type = "cookie"
        self._is_authenticated = True
        logger.info(f"AuthManager: cookie set ({name}={value[:8]}...)")

    def switch_user(self, username: str, password: str, user_id: int | None = None) -> None:
        """切换用户 (DonkAI 多身份)。."""
        self._config.username = username
        self._config.password = password
        self._config.auth_type = "basic"
        self._is_authenticated = True
        if user_id is not None:
            self._config.extra_headers = self._config.extra_headers or {}
            self._config.extra_headers["X-User-ID"] = str(user_id)
        logger.info(f"AuthManager: switched to user '{username}'")

    def switch_to_donkai_user(self, username: str) -> tuple[str, str, int]:
        """切换到预定义的 DonkAI 用户。

        Args:
            username: 用户名 (``alice``/``bob``/``admin``)。

        Returns:
            (username, password, user_id) 元组。

        Raises:
            ValueError: 未知用户名。
        """
        if username not in _DONKAI_USERS:
            raise ValueError(f"Unknown DonkAI user: {username}. Available: {list(_DONKAI_USERS.keys())}")

        user, pwd, uid = _DONKAI_USERS[username]
        self.switch_user(user, pwd, uid)
        return user, pwd, uid

    @classmethod
    def from_env(cls) -> AuthManager:
        """从环境变量创建认证管理器。

        支持的变量:
          - ``TARGET_AUTH_TYPE``: basic/cookie/none
          - ``TARGET_USERNAME``: 用户名
          - ``TARGET_PASSWORD``: 密码
          - ``TARGET_COOKIE_NAME``: Cookie 名称
          - ``TARGET_COOKIE_VALUE``: Cookie 值
        """
        import os

        auth_type = os.getenv("TARGET_AUTH_TYPE", "none")
        config = AuthConfig(
            auth_type=auth_type,
            username=os.getenv("TARGET_USERNAME", ""),
            password=os.getenv("TARGET_PASSWORD", ""),
            cookie_name=os.getenv("TARGET_COOKIE_NAME", ""),
            cookie_value=os.getenv("TARGET_COOKIE_VALUE", ""),
        )
        return cls(config)

    @classmethod
    def for_aivp(cls, base_url: str) -> AuthManager:
        """创建 AIVP 认证管理器 (cookie 自动获取)。."""
        config = AuthConfig(
            auth_type="cookie",
            cookie_name="aivp_sid",
        )
        manager = cls(config)
        manager._config.extra_headers = {"Accept": "text/event-stream"}
        return manager

    @classmethod
    def for_donkai(cls, username: str = "alice") -> AuthManager:
        """创建 DonkAI 认证管理器 (HTTP Basic)。

        Args:
            username: DonkAI 用户名 (默认 ``alice``)。
        """
        if username not in _DONKAI_USERS:
            raise ValueError(f"Unknown DonkAI user: {username}")
        user, pwd, uid = _DONKAI_USERS[username]
        config = AuthConfig(
            auth_type="basic",
            username=user,
            password=pwd,
            extra_headers={"X-User-ID": str(uid)},
        )
        return cls(config)
