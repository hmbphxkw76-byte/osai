# -*- coding: utf-8 -*-
"""
Header Parser
=============

解析浏览器 F12 复制的原始 HTTP Request Headers → 结构化 AuthProfile。

支持：
  - Cookie / Bearer / Basic 认证提取
  - JWT Token 过期时间解析
  - 按域名精准匹配凭据文件
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class AuthProfile:
    """
    认证配置文件

    Attributes:
        cookies: 结构化 Cookie 列表
        headers: HTTP 头字典
        auth_type: 认证类型 none/cookie/bearer/basic/cookie+bearer
        host: 目标主机
        path: 请求路径
        method: HTTP 方法
        token_expiry: JWT 过期时间戳
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

    def is_token_expired(self) -> bool:
        """检查 JWT 是否已过期（预留 5 分钟缓冲）"""
        if not self.token_expiry:
            return False
        import time

        return int(time.time()) >= (self.token_expiry - 300)

    def get_domain(self) -> str:
        """获取凭据对应域名"""
        if self.host:
            return self.host.split(":")[0]
        for cookie in self.cookies:
            domain = cookie.get("domain", "")
            if domain:
                return domain.lstrip(".")
        return ""

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
    return urlparse(url).netloc or ""


def parse_header_file(file_path: str) -> AuthProfile:
    """从文件解析 HTTP Request Headers"""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Header file not found: {file_path}")
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        return parse_header_text(f.read())


def parse_header_text(raw_text: str) -> AuthProfile:
    """从原始文本解析 HTTP Request Headers"""
    profile = AuthProfile()
    lines = raw_text.strip().splitlines()
    if not lines:
        return profile

    _parse_request_line(lines[0].strip(), profile)

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

    _determine_auth_type(profile)

    auth_val = profile.headers.get("Authorization", "")
    if auth_val.lower().startswith("bearer "):
        profile.token_expiry = _parse_jwt_expiry(auth_val[7:].strip())

    logger.debug("Parsed AuthProfile: %s", profile.summary())
    return profile


def _parse_request_line(line: str, profile: AuthProfile) -> None:
    """解析请求行"""
    parts = line.split()
    if parts:
        profile.method = parts[0].upper()
    if len(parts) >= 2:
        profile.path = parts[1]


def _parse_cookies(cookie_str: str, host: str) -> List[Dict[str, str]]:
    """解析 Cookie 字符串"""
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

        cookie = {"name": name, "value": value, "path": "/"}
        if host:
            domain = host.split(":")[0]
            if domain and not _is_ip_address(domain):
                cookie["domain"] = f".{domain}" if not domain.startswith(".") else domain
            else:
                cookie["domain"] = domain
        cookies.append(cookie)
    return cookies


def _is_ip_address(host: str) -> bool:
    """检查是否为 IP 地址"""
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
    """解析 JWT 过期时间"""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        decoded = base64.urlsafe_b64decode(payload)
        claims = json.loads(decoded)
        return claims.get("exp")
    except Exception:
        return None


def normalize_domain(url_or_domain: str) -> str:
    """规范化域名（去掉协议、端口、路径）"""
    domain = url_or_domain.strip().lower()
    if "://" in domain:
        domain = extract_domain_from_url(domain)
    if ":" in domain:
        domain = domain.split(":")[0]
    domain = domain.split("/")[0].split("?")[0].split("#")[0]
    return domain.strip()


def find_credential_file(
    target_domain: str,
    credentials_dir: str = "credentials",
) -> Optional[str]:
    """按域名精准匹配凭据文件"""
    if not target_domain or not os.path.isdir(credentials_dir):
        return None

    target_domain = normalize_domain(target_domain)
    exact_path = os.path.join(credentials_dir, f"{target_domain}.txt")
    if os.path.isfile(exact_path):
        return os.path.abspath(exact_path)

    for fname in os.listdir(credentials_dir):
        if not fname.endswith(".txt"):
            continue
        fpath = os.path.join(credentials_dir, fname)
        try:
            profile = parse_header_file(fpath)
            file_domain = normalize_domain(profile.get_domain())
            if file_domain and file_domain == target_domain:
                return os.path.abspath(fpath)
        except Exception:
            continue

    return None
