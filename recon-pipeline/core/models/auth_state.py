# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""AuthState: 认证态数据模型 — 跨组件传递的认证上下文。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AuthState:
    """认证态: 在所有探针和下游消费者间共享。"""

    auth_type: str = "none"
    cookies: list[dict[str, Any]] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    tokens: dict[str, str] = field(default_factory=dict)
    storage_state: dict[str, Any] | None = None
    browser_context: Any | None = None

    def to_cookie_header(self) -> str:
        return "; ".join(f"{c['name']}={c['value']}" for c in self.cookies if c.get("name") and c.get("value"))

    def to_headers(self) -> dict[str, str]:
        result: dict[str, str] = dict(self.headers)
        bearer = self.tokens.get("bearer")
        api_key = self.tokens.get("api_key")
        if bearer:
            result["Authorization"] = f"Bearer {bearer}"
        elif api_key:
            result.setdefault("X-API-Key", api_key)
        if self.cookies:
            cookie_header = self.to_cookie_header()
            if cookie_header:
                result["Cookie"] = cookie_header
        return result

    def is_authenticated(self) -> bool:
        if self.auth_type == "none":
            return True
        return bool(self.cookies or self.tokens or self.headers or self.browser_context)

    def to_dict(self) -> dict[str, Any]:
        return {
            "auth_type": self.auth_type,
            "cookies": self.cookies,
            "headers": _sanitize(self.headers),
            "tokens": _sanitize(self.tokens),
            "storage_state": self.storage_state,
            "authenticated": self.is_authenticated(),
        }


def _sanitize(data: dict[str, str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for k, v in data.items():
        if len(v) > 8:
            result[k] = f"{v[:4]}...{v[-4:]}"
        else:
            result[k] = "***"
    return result
