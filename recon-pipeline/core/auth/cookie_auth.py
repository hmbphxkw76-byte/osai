# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Cookie Auth Provider — file-based cookie authentication via AuthProvider ABC.

Loads cookies from a JSON/Netscape cookie file and provides them as AuthState.
Compatible with Garak's CookieFileProvider pattern.

Usage::
    provider = CookieAuthProvider(cookie_file="cookies.json")
    auth_state = await session.authenticate(provider)

    # Or from raw cookie data
    provider = CookieAuthProvider(cookies=[{"name": "session", "value": "xxx"}])
    auth_state = await session.authenticate(provider)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from core.auth.provider import AuthProvider
from core.models.auth_state import AuthState

logger = logging.getLogger(__name__)


class CookieAuthProvider(AuthProvider):
    """File-based cookie authentication provider.

    Loads cookies from a JSON or Netscape-format cookie file.
    Provides cookies as AuthState.headers (Cookie header).

    Usage::
        # From JSON file
        provider = CookieAuthProvider(cookie_file="cookies.json")
        auth_state = await session.authenticate(provider)

        # From raw list
        provider = CookieAuthProvider(cookies=[
            {"name": "session", "value": "abc123", "domain": "example.com"},
        ])
        auth_state = await session.authenticate(provider)
    """

    def __init__(
        self,
        cookie_file: str | None = None,
        cookies: list[dict[str, str]] | None = None,
        domain: str = "",
    ) -> None:
        """Initialize CookieAuthProvider.

        Args:
            cookie_file: Path to cookie file (JSON or Netscape format).
            cookies: Raw cookie list (alternative to cookie_file).
            domain: Domain for cookie filtering.
        """
        self._cookie_file = cookie_file
        self._raw_cookies = cookies or []
        self._domain = domain

    @property
    def name(self) -> str:
        return "cookie"

    async def authenticate(self, target_url: str, **kwargs: object) -> AuthState:
        """Load cookies and return AuthState.

        Args:
            target_url: Target URL (used for domain extraction if domain not set).
            **kwargs: Additional parameters.

        Returns:
            AuthState with cookies and Cookie header.
        """
        cookies: list[dict[str, str]] = []

        if self._cookie_file:
            path = Path(self._cookie_file)
            if not path.exists():
                raise FileNotFoundError(f"Cookie file not found: {self._cookie_file}")

            content = path.read_text(encoding="utf-8")
            if path.suffix == ".json":
                cookies = self._parse_json_cookies(content)
            else:
                cookies = self._parse_netscape_cookies(content)
        elif self._raw_cookies:
            cookies = self._raw_cookies

        # Filter by domain if specified
        if self._domain and cookies:
            cookies = [c for c in cookies if self._domain in c.get("domain", "")]

        # Build Cookie header
        cookie_header = "; ".join(
            f"{c['name']}={c['value']}" for c in cookies
        )

        logger.info(
            "CookieAuthProvider: loaded %d cookies%s",
            len(cookies),
            f" (domain={self._domain})" if self._domain else "",
        )

        return AuthState(
            auth_type="cookie",
            cookies=[{"name": c["name"], "value": c["value"], "domain": c.get("domain", "")} for c in cookies],
            headers={"Cookie": cookie_header} if cookie_header else {},
        )

    @staticmethod
    def _parse_json_cookies(content: str) -> list[dict[str, str]]:
        """Parse cookies from JSON format.

        Supports formats:
          - [{"name": "...", "value": "...", "domain": "..."}]
          - {"cookies": [...]}
        """
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            logger.warning("CookieAuthProvider: invalid JSON cookie file")
            return []

        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("cookies", [])
        return []

    @staticmethod
    def _parse_netscape_cookies(content: str) -> list[dict[str, str]]:
        """Parse cookies from Netscape cookie file format.

        Format: domain flag path secure expiration name value
        Lines starting with # are comments.
        """
        cookies: list[dict[str, str]] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 7:
                cookies.append({
                    "domain": parts[0],
                    "name": parts[5],
                    "value": parts[6],
                    "path": parts[2],
                })
        return cookies
