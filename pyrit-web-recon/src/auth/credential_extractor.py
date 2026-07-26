# -*- coding: utf-8 -*-
"""
Credential Extractor
====================

从浏览器登录后的状态自动提取凭据，保存为与 header_parser 兼容的
credentials/{domain}.txt 文件，供后续侦察流程复用。

提取来源：
  1. Playwright browser_context.cookies()
  2. HTTP 拦截器中捕获的 Authorization / X-Api-Key 等请求头
  3. 请求体中的 api_key / token 字段（仅记录 Bearer/APIKey 类长期凭证）

输出格式：
  与浏览器 F12 "Copy as cURL (bash)" 的 Request Headers 一致，
  header_parser.parse_header_text() 可直接解析。
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from src.auth import AuthProfile, normalize_domain

logger = logging.getLogger(__name__)

# 需要提取并保存的请求头
AUTH_HEADER_NAMES = [
    "authorization",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-access-token",
]

# 请求体中可能包含长期凭证的字段名
API_KEY_BODY_KEYS = ["api_key", "apikey", "x-api-key", "api-key", "token"]


class CredentialExtractor:
    """凭据自动提取器"""

    def __init__(self, credentials_dir: str = "credentials"):
        self.credentials_dir = credentials_dir
        os.makedirs(self.credentials_dir, exist_ok=True)

    async def extract_from_browser(
        self,
        context: Any,
        target_url: str,
        captured_entries: Optional[List[Dict[str, Any]]] = None,
    ) -> Optional[str]:
        """
        从浏览器状态和已拦截流量中提取凭据并保存。

        Returns:
            保存的凭据文件路径，若无可提取凭据则返回 None
        """
        domain = normalize_domain(target_url)
        if not domain:
            logger.warning("Cannot extract domain from %s", target_url)
            return None

        # 1. 从 Playwright context 提取 cookies
        cookies = await context.cookies() if context else []

        # 2. 从拦截流量中提取认证头
        headers: Dict[str, str] = {}
        extracted_keys: List[Dict[str, Any]] = []
        entries = captured_entries or []

        for entry in entries:
            req_headers = entry.get("request_headers", {})
            for name in AUTH_HEADER_NAMES:
                value = req_headers.get(name) or req_headers.get(name.title())
                if value and name.lower() not in {k.lower() for k in headers}:
                    headers[name] = value

            # 提取请求体中的 api_key
            body = entry.get("request_body", "")
            key_info = self._extract_api_key_from_body(body)
            if key_info:
                extracted_keys.append({**key_info, "source_url": entry.get("url", "")})

        if not cookies and not headers:
            logger.info("No credentials extracted for %s", domain)
            return None

        # 3. 组装 header 格式文本
        header_text = self._build_header_text(domain, cookies, headers)

        # 4. 保存文件
        file_path = os.path.join(self.credentials_dir, f"{domain}.txt")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(header_text)
        logger.info("Credentials saved to %s", file_path)

        return os.path.abspath(file_path)

    def _build_header_text(
        self,
        domain: str,
        cookies: List[Dict[str, str]],
        headers: Dict[str, str],
    ) -> str:
        """构造与 header_parser 兼容的原始 header 文本"""
        lines: List[str] = [f"GET / HTTP/1.1", f"Host: {domain}"]

        if cookies:
            cookie_pairs = []
            for cookie in cookies:
                name = cookie.get("name", "")
                value = cookie.get("value", "")
                if name:
                    cookie_pairs.append(f"{name}={value}")
            if cookie_pairs:
                lines.append(f"Cookie: {'; '.join(cookie_pairs)}")

        # 按原始大小写保留重要头
        for name, value in headers.items():
            if name.lower() == "authorization":
                lines.append(f"Authorization: {value}")
            elif name.lower() == "x-api-key":
                lines.append(f"X-Api-Key: {value}")
            elif name.lower() == "api-key":
                lines.append(f"Api-Key: {value}")
            elif name.lower() == "x-auth-token":
                lines.append(f"X-Auth-Token: {value}")
            elif name.lower() == "x-access-token":
                lines.append(f"X-Access-Token: {value}")

        # 添加 UA，提高复用兼容性
        lines.append(
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        )
        lines.append(f"X-Extracted-At: {time.strftime('%Y-%m-%dT%H:%M:%S')}")
        lines.append("X-Extraction-Source: playwright_auto")

        return "\n".join(lines) + "\n"

    def _extract_api_key_from_body(self, body: str) -> Optional[Dict[str, Any]]:
        """从请求体中提取可能的 API key"""
        if not body or len(body) > 5000:
            return None
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                for key in API_KEY_BODY_KEYS:
                    if key in data and data[key]:
                        return {"type": "body_api_key", "key_name": key, "hint": str(data[key])[:8]}
        except json.JSONDecodeError:
            pass
        return None

    def parse_saved_profile(self, target_url: str) -> Optional[AuthProfile]:
        """读取已保存的凭据文件并解析为 AuthProfile"""
        from src.auth import find_credential_file, parse_header_file

        domain = normalize_domain(target_url)
        file_path = find_credential_file(domain, self.credentials_dir)
        if not file_path:
            return None
        try:
            return parse_header_file(file_path)
        except Exception as e:
            logger.warning("Failed to parse saved credentials: %s", str(e))
            return None
