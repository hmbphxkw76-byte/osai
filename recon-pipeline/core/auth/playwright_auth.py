# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Playwright Auth Provider — browser-based authentication via AuthProvider ABC.

Wraps BrowserSession and AuthStrategy to provide a unified AuthProvider interface
for all browser-based authentication scenarios (same-domain, cross-domain, OTP, etc.).

This makes Playwright-based auth available through session.authenticate(),
alongside APIKeyAuthProvider and NoAuthProvider.

Architecture:
  session.authenticate(PlaywrightAuthProvider(...))
    → AuthState(browser_context=..., cookies=..., storage_state=...)
    → All probes share the same browser page + auth headers
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from core.auth.auth_strategy import AuthStrategy, AuthStrategyFactory
from core.auth.browser_session import BrowserSession
from core.auth.provider import AuthProvider
from core.models.auth_state import AuthState

if TYPE_CHECKING:
    from playwright.async_api import Page

logger = logging.getLogger(__name__)


class PlaywrightAuthProvider(AuthProvider):
    """Playwright-based authentication provider.

    Uses BrowserSession for browser lifecycle management and
    AuthStrategy for the actual authentication flow.

    Usage::
        # Auto-detect auth type
        provider = PlaywrightAuthProvider(auth_type="auto")
        auth_state = await session.authenticate(provider)

        # Specific auth strategy
        provider = PlaywrightAuthProvider(auth_type="same_domain")
        auth_state = await session.authenticate(provider)

        # Cross-domain SSO
        provider = PlaywrightAuthProvider(auth_type="cross_domain")
        auth_state = await session.authenticate(provider)
    """

    def __init__(
        self,
        auth_type: str = "auto",
        headless: bool = False,
        cdp_port: int = 9222,
        browser_path: str | None = None,
        storage_state_path: str | None = None,
    ) -> None:
        """Initialize PlaywrightAuthProvider.

        Args:
            auth_type: Auth strategy type — "auto", "none", "same_domain",
                "cross_domain", "otp", "sliding", "sms", "qr".
            headless: Run browser in headless mode (not recommended for auth).
            cdp_port: Chrome DevTools Protocol port.
            browser_path: Path to browser executable (auto-detect if None).
            storage_state_path: Path to restore saved auth state (skip re-auth).
        """
        self._auth_type = auth_type
        self._headless = headless
        self._cdp_port = cdp_port
        self._browser_path = browser_path
        self._storage_state_path = storage_state_path
        self._browser_session: BrowserSession | None = None
        self._page: Page | None = None

    @property
    def name(self) -> str:
        return f"playwright:{self._auth_type}"

    @property
    def page(self) -> Page | None:
        """Get the Playwright Page (for browser-requiring probes)."""
        return self._page

    async def authenticate(self, target_url: str, **kwargs: object) -> AuthState:
        """Execute Playwright-based authentication.

        Flow:
          1. Launch or restore browser session
          2. Navigate to target URL
          3. Execute auth strategy (auto-detect or specific)
          4. Extract cookies, headers, tokens
          5. Return AuthState

        Args:
            target_url: Target URL to authenticate against.
            **kwargs: Additional auth parameters.

        Returns:
            AuthState with browser context, cookies, and headers.
        """
        self._browser_session = BrowserSession()

        # Restore saved state if available (skip re-auth)
        if self._storage_state_path:
            try:
                self._page = await self._browser_session.restore_storage_state(
                    self._storage_state_path
                )
                logger.info("PlaywrightAuthProvider: restored storage state, skipping auth")
                return await self._build_auth_state(target_url)
            except FileNotFoundError:
                logger.info("PlaywrightAuthProvider: no saved state found, performing auth")

        # Launch browser
        if self._auth_type in ("none", "auto") and not self._headless:
            self._page = await self._browser_session.launch_with_debug_port(
                port=self._cdp_port,
                headless=self._headless,
                browser_path=self._browser_path,
            )
        else:
            self._page = await self._browser_session.launch_with_debug_port(
                port=self._cdp_port,
                headless=True,
                browser_path=self._browser_path,
            )

        # Execute auth strategy
        strategy = AuthStrategyFactory.create(self._auth_type)
        logger.info(
            "PlaywrightAuthProvider: executing auth strategy '%s' (type=%s)",
            strategy.name, self._auth_type,
        )

        # Build a minimal TargetProfile-like object for strategy execution
        from core.auth.models import CrossDomainAuthConfig, SameDomainAuthConfig

        class _MinimalAuthConfig:
            type: str = self._auth_type
            target_url: str = target_url
            login_url: str = kwargs.get("login_url", target_url)  # type: ignore[assignment]
            auto_fill: dict[str, str] | None = kwargs.get("auto_fill", None)  # type: ignore[assignment]
            human_assisted_steps: list[str] | None = kwargs.get("human_steps", None)  # type: ignore[assignment]
            same_domain = SameDomainAuthConfig()
            cross_domain = CrossDomainAuthConfig()

        class _MinimalProfile:
            auth = _MinimalAuthConfig()

            def get_detection_configs(self) -> list:  # type: ignore[no-untyped-def]
                return []

        self._page = await strategy.execute(self._page, _MinimalProfile())

        # Build and return AuthState
        return await self._build_auth_state(target_url)

    async def _build_auth_state(self, target_url: str) -> AuthState:
        """Build AuthState from the current browser session."""
        cookies: list[dict[str, Any]] = []
        storage_state: dict[str, Any] = {}

        if self._page and self._browser_session and self._browser_session.context:
            context = self._browser_session.context
            # Extract cookies
            try:
                raw_cookies = await context.cookies()
                cookies = [
                    {
                        "name": c.get("name", ""),
                        "value": c.get("value", ""),
                        "domain": c.get("domain", ""),
                        "path": c.get("path", "/"),
                    }
                    for c in raw_cookies
                ]
            except Exception as e:
                logger.debug("PlaywrightAuthProvider: error extracting cookies: %s", e)

            # Get storage state for persistence
            try:
                import tempfile
                with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
                    tmp_path = f.name
                await context.storage_state(path=tmp_path)
                import json
                with open(tmp_path, encoding="utf-8") as f:
                    storage_state = json.load(f)
                import os
                os.unlink(tmp_path)
            except Exception as e:
                logger.debug("PlaywrightAuthProvider: error extracting storage state: %s", e)

        return AuthState(
            auth_type=f"playwright:{self._auth_type}",
            cookies=cookies,
            headers={},
            tokens={},
            storage_state=storage_state,
            browser_context=self._browser_session.context if self._browser_session else None,
        )

    async def close(self) -> None:
        """Close the browser session."""
        if self._browser_session:
            await self._browser_session.close()
