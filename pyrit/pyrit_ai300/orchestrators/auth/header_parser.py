# -*- coding: utf-8 -*-
"""
AI-300 Framework - Header Parser
解析 F12 复制的原始 HTTP Request Headers → 结构化 AuthProfile

支持格式：
- 标准 HTTP Request Headers（从浏览器 DevTools 复制）
- 包含 Authorization (Bearer/Basic)、Cookie、自定义头
- 自动提取 Cookie 域名、解析 JWT Token 过期时间

设计原则：
- 输入格式保持 F12 原始文本，用户无需转换
- 运行时实时解析，确保 token 最新
- 纯函数式设计，无副作用，便于测试

PyRIT 0.14.0 兼容
"""

from __future__ import annotations

import os
import sys
import json
import logging
import base64
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

logger = logging.getLogger(__name__)


@dataclass
class AuthProfile:
    """
    认证配置文件：从原始 HTTP Headers 解析的结构化认证信息

    Attributes:
        cookies: Cookie 列表，每项包含 name/value/domain/path
        headers: HTTP 头字典（Authorization、User-Agent 等）
        auth_type: 认证类型 (none/cookie/bearer/basic/cookie+bearer)
        host: 目标主机
        path: 请求路径
        method: HTTP 方法
        token_expiry: JWT Token 过期时间戳（仅 Bearer Token 时）
        raw_cookies: 原始 Cookie 字符串
    """
    cookies: List[Dict[str, str]] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    auth_type: str = "none"
    host: str = ""
    path: str = "/"
    method: str = "GET"
    token_expiry: Optional[int] = None
    raw_cookies: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """导出为字典"""
        return {
            "cookies": self.cookies,
            "headers": self.headers,
            "auth_type": self.auth_type,
            "host": self.host,
            "path": self.path,
            "method": self.method,
            "token_expiry": self.token_expiry,
            "raw_cookies": self.raw_cookies,
        }

    def has_auth(self) -> bool:
        """是否有认证信息"""
        return self.auth_type != "none"

    def summary(self) -> str:
        """摘要信息"""
        parts = []
        if self.host:
            parts.append(f"host={self.host}")
        parts.append(f"auth={self.auth_type}")
        if self.cookies:
            parts.append(f"cookies={len(self.cookies)}")
        if self.token_expiry:
            parts.append(f"expiry={self.token_expiry}")
        return ", ".join(parts)


def extract_domain_from_url(url: str) -> str:
    """从 URL 提取域名"""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return parsed.netloc or ""


def parse_header_file(file_path: str) -> AuthProfile:
    """
    从文件解析 HTTP Request Headers

    Args:
        file_path: 原始 HTTP Request Headers 文件路径

    Returns:
        AuthProfile 实例

    Raises:
        FileNotFoundError: 文件不存在
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Header file not found: {file_path}")

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        raw_text = f.read()

    return parse_header_text(raw_text)


def parse_header_text(raw_text: str) -> AuthProfile:
    """
    从原始文本解析 HTTP Request Headers

    支持格式：
        GET /api/xxx HTTP/1.1
        Host: example.com
        Authorization: Bearer <token>
        Cookie: key1=val1; key2=val2
        ...

    Args:
        raw_text: 原始 HTTP Request Headers 文本

    Returns:
        AuthProfile 实例
    """
    profile = AuthProfile()
    lines = raw_text.strip().splitlines()

    if not lines:
        return profile

    # 解析请求行
    request_line = lines[0].strip()
    _parse_request_line(request_line, profile)

    # 解析头部
    for line in lines[1:]:
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        key_lower = key.lower()

        if key_lower == "host":
            profile.host = value
        elif key_lower == "cookie":
            profile.raw_cookies = value
            profile.cookies = _parse_cookies(value, profile.host)
        elif key_lower == "authorization":
            profile.headers["Authorization"] = value
        elif key_lower == "user-agent":
            profile.headers["User-Agent"] = value
        elif key_lower in ("accept", "accept-language", "accept-encoding"):
            profile.headers[key] = value
        elif key_lower == "content-type":
            profile.headers["Content-Type"] = value
        elif key_lower == "referer":
            profile.headers["Referer"] = value
        elif key_lower == "origin":
            profile.headers["Origin"] = value

    # 确定认证类型
    _determine_auth_type(profile)

    # 解析 JWT Token 过期时间
    if "Authorization" in profile.headers:
        auth_val = profile.headers["Authorization"]
        if auth_val.lower().startswith("bearer "):
            token = auth_val[7:].strip()
            profile.token_expiry = _parse_jwt_expiry(token)

    logger.debug("Parsed AuthProfile: %s", profile.summary())
    return profile


def _parse_request_line(line: str, profile: AuthProfile) -> None:
    """解析 HTTP 请求行"""
    parts = line.split()
    if len(parts) >= 1:
        profile.method = parts[0].upper()
    if len(parts) >= 2:
        profile.path = parts[1]


def _parse_cookies(cookie_str: str, host: str) -> List[Dict[str, str]]:
    """
    解析 Cookie 字符串为结构化列表

    Args:
        cookie_str: "key1=val1; key2=val2" 格式
        host: 目标主机（用于设置 domain）

    Returns:
        Cookie 字典列表
    """
    cookies = []
    for pair in cookie_str.split(";"):
        pair = pair.strip()
        if "=" not in pair:
            continue
        name, _, value = pair.partition("=")
        name = name.strip()
        value = value.strip()
        if not name:
            continue

        cookie = {
            "name": name,
            "value": value,
            "path": "/",
        }

        # 设置 domain
        if host:
            # 移除端口号
            domain = host.split(":")[0]
            if domain:
                # 如果 domain 是 IP 地址，不设置 domain
                if not _is_ip_address(domain):
                    cookie["domain"] = f".{domain}" if not domain.startswith(".") else domain
                else:
                    cookie["domain"] = domain

        cookies.append(cookie)

    return cookies


def _is_ip_address(host: str) -> bool:
    """检查是否为 IP 地址"""
    import re
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host))


def _determine_auth_type(profile: AuthProfile) -> None:
    """确定认证类型"""
    has_cookie = bool(profile.cookies)
    has_auth_header = "Authorization" in profile.headers

    if has_cookie and has_auth_header:
        auth_val = profile.headers["Authorization"].lower()
        if auth_val.startswith("bearer "):
            profile.auth_type = "cookie+bearer"
        elif auth_val.startswith("basic "):
            profile.auth_type = "cookie+basic"
        else:
            profile.auth_type = "cookie+other"
    elif has_cookie:
        profile.auth_type = "cookie"
    elif has_auth_header:
        auth_val = profile.headers["Authorization"].lower()
        if auth_val.startswith("bearer "):
            profile.auth_type = "bearer"
        elif auth_val.startswith("basic "):
            profile.auth_type = "basic"
        else:
            profile.auth_type = "other"
    else:
        profile.auth_type = "none"


def _parse_jwt_expiry(token: str) -> Optional[int]:
    """
    解析 JWT Token 的过期时间

    Args:
        token: JWT Token 字符串

    Returns:
        过期时间戳，或 None（解析失败时）
    """
    try:
        # JWT 格式: header.payload.signature
        parts = token.split(".")
        if len(parts) != 3:
            return None

        # 解码 payload
        payload = parts[1]
        # 补齐 base64 padding
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding

        decoded = base64.urlsafe_b64decode(payload)
        claims = json.loads(decoded)

        return claims.get("exp")
    except Exception:
        return None
