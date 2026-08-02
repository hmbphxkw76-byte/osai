# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""AuthProvider 抽象基类 — 统一认证接口。

所有认证策略 (Playwright / Cookie / APIKey / OAuth) 继承此基类。
下游探针只依赖 AuthProvider.authenticate() 返回的 AuthState, 不关心具体认证类型。

学术依据:
  - MITRE ATT&CK T1078 (Valid Accounts): 认证态复用
  - OWASP Top 10 for LLM 2025: LLM05 供应链 / LLM07 插件设计
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from core.models.auth_state import AuthState

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class AuthProvider(ABC):
    """认证提供方抽象基类。

    子类实现 authenticate() 方法, 返回 AuthState。
    AuthState 在所有探针和下游消费者间共享。
    """

    @abstractmethod
    async def authenticate(self, target_url: str, **kwargs: object) -> AuthState:
        """执行认证, 返回 AuthState。

        Args:
            target_url: 目标 URL。
            **kwargs: 额外参数 (如 credentials, browser_page 等)。

        Returns:
            AuthState 实例 (包含 cookies, tokens, headers 等)。
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """认证提供方名称。"""
        ...

    def describe(self) -> str:
        """人类可读描述。"""
        return f"{self.__class__.__name__} (name={self.name})"


class NoAuthProvider(AuthProvider):
    """无需认证。"""

    @property
    def name(self) -> str:
        return "none"

    async def authenticate(self, target_url: str, **kwargs: object) -> AuthState:
        return AuthState(auth_type="none")


class APIKeyAuthProvider(AuthProvider):
    """API Key 认证。

    支持两种放置位置:
      - Header: X-API-Key / Authorization: Bearer
      - Query parameter: ?key=xxx
    """

    def __init__(self, api_key: str, header_name: str = "X-API-Key", use_bearer: bool = False) -> None:
        self._api_key = api_key
        self._header_name = header_name
        self._use_bearer = use_bearer

    @property
    def name(self) -> str:
        return "apikey"

    async def authenticate(self, target_url: str, **kwargs: object) -> AuthState:
        if self._use_bearer:
            return AuthState(
                auth_type="bearer",
                tokens={"bearer": self._api_key},
            )
        return AuthState(
            auth_type="apikey",
            headers={self._header_name: self._api_key},
            tokens={"api_key": self._api_key},
        )
