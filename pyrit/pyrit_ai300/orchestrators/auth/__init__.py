# -*- coding: utf-8 -*-
"""
AI-300 Framework - Auth Module
认证解析模块：解析 F12 复制的 Request Headers，注入 Playwright 浏览器

子模块：
- header_parser: 解析原始 HTTP Request Headers → AuthProfile
- playwright_injector: AuthProfile → Playwright 认证注入
"""

from .header_parser import AuthProfile, parse_header_file, parse_header_text, extract_domain_from_url
from .playwright_injector import inject_auth

__all__ = [
    "AuthProfile",
    "parse_header_file",
    "parse_header_text",
    "inject_auth",
    "extract_domain_from_url",
]
