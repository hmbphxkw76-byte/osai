"""认证状态获取和复用。
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

def load_auth_state(file_path: str | None) -> dict[str, Any] | None:
    """加载认证状态文件。
    """
    if not file_path:
        return None
    path = Path(file_path)
    if not path.exists():
        logger.warning("Auth state file not found: %s", file_path)
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        logger.error("Failed to parse auth state file: %s", e)
        return None

def inject_auth_headers(raw_request: str, auth_state: dict[str, Any] | None) -> str:
    """将认证 headers 注入到原始 HTTP 请求。
    """
    if not auth_state:
        return raw_request

    # 提取认证信息
    cookies = auth_state.get("cookies", {})
    token = auth_state.get("token") or auth_state.get("bearer_token")
    headers = auth_state.get("headers", {})

    # 构建 Cookie header
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        headers["Cookie"] = cookie_str

    # Bearer token
    if token:
        headers["Authorization"] = f"Bearer {token}"

    if not headers:
        return raw_request

    # 解析请求并注入 headers
    normalized = raw_request.replace("\r\n", "\n")
    parts = normalized.split("\n\n", 1)

    header_lines = parts[0].split("\n")
    body = parts[1] if len(parts) > 1 else ""

    existing_headers: dict[str, str] = {}
    for line in header_lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            existing_headers[key.strip().lower()] = value.strip()

    # 合并认证 headers (不覆盖已有 headers)
    for key, value in headers.items():
        if key.lower() not in existing_headers:
            header_lines.append(f"{key}: {value}")

    # 重建请求
    if body:
        # 更新 Content-Length
        header_lines = [h for h in header_lines if not h.lower().startswith("content-length:")]
        header_lines.append(f"Content-Length: {len(body)}")
        result = "\r\n".join(header_lines) + "\r\n\r\n" + body
    else:
        result = "\r\n".join(header_lines) + "\r\n\r\n"

    logger.info("Auth headers injected: %s", list(headers.keys()))
    return result
