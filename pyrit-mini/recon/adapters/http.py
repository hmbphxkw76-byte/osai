"""recon/adapters/http.py — HTTP/JSON 协议适配器（REQ-149 ②）。

最通用的 REST/JSON 通道：`Content-Type: application/json`，Bearer/Cookie/API Key
认证由 `AuthState` 闭合，`chat_id`/`thread_id` 占位符由 `SessionState` 替换。
"""

from __future__ import annotations

import logging
from typing import Any

from recon.adapters.base import AuthState, BaseAdapter, SessionState

logger = logging.getLogger(__name__)


class HTTPAdapter(BaseAdapter):
    """JSON over HTTP(S) adapter（默认请求成形即基类行为）。"""

    name = "http"

    @classmethod
    def from_target(
        cls,
        *,
        url: str,
        method: str = "POST",
        raw_headers: Any = None,
        headers: dict[str, str] | None = None,
        body_template: str = "",
        response_json_path: str | None = None,
        timeout: float = 30.0,
        verify: bool = False,
    ) -> "HTTPAdapter":
        """Build an adapter from Burp-style artefacts (auth closed inside)."""
        return cls(
            url=url,
            method=method,
            auth=AuthState.from_raw_headers(raw_headers),
            session=SessionState(),
            headers=headers,
            body_template=body_template,
            response_json_path=response_json_path,
            timeout=timeout,
            verify=verify,
        )
