# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""认证数据提取器 — 从浏览器上下文提取认证数据转为 API 可用格式。

**职责**:
  - 从 Playwright BrowserContext 提取 cookies / localStorage
  - 将浏览器 cookies 转为 auth_headers (Authorization: Bearer ...)
  - 将浏览器 cookies 转为 auth_cookies 字典
  - 提取 NetworkTokenStrategy 捕获的 token
  - 生成 AuthState 实例供 pipeline 使用

设计原则 (R-022: PyRIT 原生优先):
  - 纯数据层模块, 不执行认证操作
  - 不修改原生 Playwright/PyRIT 组件
  - 使用 Playwright 原生 context.cookies() API

学术依据:
  - OWASP ASVS V2.4: 认证验证要求
  - NIST SP 800-63B: 多因素认证分类
  - RFC 6265: HTTP State Management (Cookie)

> **日期**: 2026-8-4
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from playwright.async_api import BrowserContext

logger = logging.getLogger(__name__)

# Cookie 名称中的认证关键字 (用于识别认证相关 cookie)
_AUTH_COOKIE_KEYWORDS = (
    "token",
    "auth",
    "session",
    "jwt",
    "sid",
    "phpsessid",
    "jsessionid",
    "access_token",
    "refresh_token",
    "bearer",
)

# 认证 token 相关的 localStorage 键
_AUTH_STORAGE_KEYS = (
    "access_token",
    "refresh_token",
    "token",
    "authToken",
    "auth_token",
    "jwt",
    "jwt_token",
    "Authorization",
)


class AuthDataExtractor:
    """认证数据提取器 — 从浏览器上下文提取认证数据。

    用法::

        from web_redteam.auth.auth_data_extractor import AuthDataExtractor

        auth_state = await AuthDataExtractor.extract_from_browser_context(
            context=page.context,
            target_url="https://chat.example.com",
            auth_type="same_domain",
        )
        # auth_state.headers → {"Authorization": "Bearer xxx", "Cookie": "..."}
        # auth_state.cookies → [{"name": "session", "value": "...", ...}]
    """

    @staticmethod
    async def extract_from_browser_context(
        *,
        context: BrowserContext,
        target_url: str,
        auth_type: str = "same_domain",
        login_url: str = "",
        mfa_types: list[str] | None = None,
    ) -> Any:
        """从 Playwright BrowserContext 提取认证数据。

        提取流程:
          1. context.cookies() → 获取所有 cookies
          2. 筛选认证相关 cookies → 转 auth_headers
          3. context.storage_state() → 获取 localStorage
          4. 从 localStorage 提取 token → 转 auth_headers
          5. 构建 AuthState 实例

        Args:
            context: Playwright BrowserContext (已认证)。
            target_url: 目标 URL。
            auth_type: 认证类型 (same_domain / cross_domain / none)。
            login_url: 登录页 URL (可选)。
            mfa_types: MFA 类型列表 (可选)。

        Returns:
            AuthState 实例 (包含 headers, cookies, tokens)。
        """
        from datetime import datetime, timezone

        from pipeline.integrations.auth_state_bridge import AuthState

        headers: dict[str, str] = {}
        tokens: dict[str, str] = {}
        cookies_list: list[dict[str, Any]] = []

        # Step 1: 提取 cookies
        try:
            cookies = await context.cookies()
            cookies_list = cookies
            logger.info(f"AuthDataExtractor: extracted {len(cookies)} cookies from browser context")

            # 筛选认证相关 cookies → headers
            headers.update(AuthDataExtractor._cookies_to_headers(cookies, target_url))
        except Exception as e:
            logger.warning(f"AuthDataExtractor: failed to extract cookies: {e}")

        # Step 2: 提取 localStorage (通过 storage_state)
        try:
            storage = await context.storage_state()
            origins = storage.get("origins", [])
            for origin in origins:
                local_storage = origin.get("localStorage", [])
                for entry in local_storage:
                    key = entry.get("name", "")
                    value = entry.get("value", "")
                    if key.lower() in _AUTH_STORAGE_KEYS or any(
                        kw in key.lower() for kw in _AUTH_STORAGE_KEYS
                    ):
                        tokens[key] = value
                        # 如果是 access_token, 设置 Authorization header
                        if "access_token" in key.lower() or key.lower() == "token":
                            headers["Authorization"] = f"Bearer {value}"
                            logger.info(f"AuthDataExtractor: token from localStorage key '{key}'")
        except Exception as e:
            logger.debug(f"AuthDataExtractor: localStorage extraction skipped: {e}")

        # Step 3: 构建 Cookie header (如果有多 cookies)
        if cookies_list and "Cookie" not in headers:
            cookie_str = "; ".join(
                f"{c['name']}={c['value']}" for c in cookies_list if c.get("name") and c.get("value")
            )
            if cookie_str:
                headers["Cookie"] = cookie_str

        auth_state = AuthState(
            auth_type=auth_type,
            target_url=target_url,
            login_url=login_url,
            cookies=cookies_list,
            headers=headers,
            tokens=tokens,
            mfa_required=bool(mfa_types),
            mfa_types=mfa_types or [],
            authenticated_at=datetime.now(timezone.utc).isoformat(),
            source="pyrit_browser",
        )

        logger.info(
            f"AuthDataExtractor: auth_state built "
            f"(type={auth_type}, cookies={len(cookies_list)}, "
            f"headers={len(headers)}, tokens={len(tokens)})"
        )
        return auth_state

    @staticmethod
    def _cookies_to_headers(
        cookies: list[dict[str, Any]],
        target_url: str = "",
    ) -> dict[str, str]:
        """将 cookies 转换为认证 headers。

        转换规则:
          1. Cookie 名称包含 token/auth/jwt → Authorization: Bearer <value>
          2. Cookie 名称包含 session/sid → Cookie header
          3. 所有 cookies 拼接为 Cookie header (fallback)

        Args:
            cookies: Playwright cookies 列表。
            target_url: 目标 URL (用于域名过滤, 可选)。

        Returns:
            headers 字典。
        """
        headers: dict[str, str] = {}

        # 尝试从 cookies 中提取 Bearer token
        for cookie in cookies:
            name = cookie.get("name", "").lower()
            value = cookie.get("value", "")
            if not value:
                continue

            # 认证 token cookie → Authorization header
            if any(kw in name for kw in ("access_token", "bearer", "jwt_token", "auth_token")):
                headers["Authorization"] = f"Bearer {value}"
                logger.debug(f"AuthDataExtractor: Bearer token from cookie '{cookie.get('name')}'")
                break

        return headers

    @staticmethod
    def extract_auth_cookies(
        cookies: list[dict[str, Any]],
    ) -> dict[str, str]:
        """从 cookies 列表提取认证相关 cookies 为 {name: value} 字典。

        Args:
            cookies: Playwright cookies 列表。

        Returns:
            认证 cookies 字典。
        """
        auth_cookies: dict[str, str] = {}
        for cookie in cookies:
            name = cookie.get("name", "")
            value = cookie.get("value", "")
            if not name or not value:
                continue
            name_lower = name.lower()
            if any(kw in name_lower for kw in _AUTH_COOKIE_KEYWORDS):
                auth_cookies[name] = value
        return auth_cookies

    @staticmethod
    async def extract_from_network_token_strategy(
        *,
        strategy: Any,
        target_url: str,
        auth_type: str = "same_domain",
    ) -> Any:
        """从 NetworkTokenStrategy 提取捕获的 token。

        当 AuthDetector 使用 NetworkTokenStrategy 时,
        在认证完成后可从中提取捕获的 token。

        Args:
            strategy: NetworkTokenStrategy 实例。
            target_url: 目标 URL。
            auth_type: 认证类型。

        Returns:
            AuthState 实例 (仅包含 token)。
        """
        from datetime import datetime, timezone

        from pipeline.integrations.auth_state_bridge import AuthState

        token = getattr(strategy, "captured_token", None)
        if not token:
            logger.warning("AuthDataExtractor: NetworkTokenStrategy has no captured token")
            return AuthState(
                auth_type=auth_type,
                target_url=target_url,
                source="pyrit_browser",
                authenticated_at=datetime.now(timezone.utc).isoformat(),
            )

        headers = {"Authorization": f"Bearer {token}"}
        tokens = {"access_token": token}

        logger.info(f"AuthDataExtractor: token from NetworkTokenStrategy ({token[:8]}...)")

        return AuthState(
            auth_type=auth_type,
            target_url=target_url,
            headers=headers,
            tokens=tokens,
            source="pyrit_browser",
            authenticated_at=datetime.now(timezone.utc).isoformat(),
        )
