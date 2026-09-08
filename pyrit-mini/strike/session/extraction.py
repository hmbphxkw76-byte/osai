# -*- coding: utf-8 -*-
"""SessionExtractor - 通用会话状态提取器

支持从任意 HTTP 响应中提取会话状态 token。
多方法支持: JSONPath、正则表达式、Header、Cookie。

提取优先级:
    1. 主方法 (primary)
    2. 备用方法列表 (fallbacks，按顺序尝试)
    3. 返回 None 如果所有方法失败

Academic basis:
    - Gao et al. (arXiv:2311.10536) — Response structure taxonomy
    - Karpukhin et al. (arXiv:2004.04906) — Structured response parsing
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


class SessionExtractor:
    """通用会话状态提取器

    从 HTTP 响应中提取一个或多个会话状态 token。
    支持多种提取方法，按优先级回退。

    使用示例:
        extractor = SessionExtractor(config.extraction_rules)
        tokens = extractor.extract_all(response_text, response_headers)
        # tokens = {"session_id": "abc123", "csrf_token": "xyz789"}
    """

    def __init__(self, rules: list[Any]) -> None:
        """
        Args:
            rules: ExtractionRule 列表
        """
        self._rules = rules

    def extract_all(
        self,
        response_text: str,
        response_headers: dict[str, str] | None = None,
        response_cookies: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """从响应中提取所有配置的 token

        Args:
            response_text: HTTP 响应文本
            response_headers: HTTP 响应headers (可选)
            response_cookies: HTTP 响应cookies (可选)

        Returns:
            {token_name: token_value} 提取到的状态字典
        """
        result: dict[str, str] = {}
        for rule in self._rules:
            token = self._extract_with_rule(rule, response_text, response_headers, response_cookies)
            if token:
                result[rule.name] = token
        return result

    def extract_single(
        self,
        rule: Any,
        response_text: str,
        response_headers: dict[str, str] | None = None,
        response_cookies: dict[str, str] | None = None,
    ) -> str | None:
        """从响应中提取单个 token

        Args:
            rule: ExtractionRule
            response_text: HTTP 响应文本
            response_headers: HTTP 响应 headers
            response_cookies: HTTP 响应 cookies

        Returns:
            token value 或 None
        """
        return self._extract_with_rule(rule, response_text, response_headers, response_cookies)

    def _extract_with_rule(
        self,
        rule: Any,
        response_text: str,
        response_headers: dict[str, str] | None = None,
        response_cookies: dict[str, str] | None = None,
    ) -> str | None:
        """使用单个规则提取 token (含 fallback)"""
        # 尝试主方法
        primary = rule.primary
        token = self._try_extract(primary, response_text, response_headers, response_cookies)
        if token:
            return token

        # 尝试 fallback
        for fallback in rule.fallbacks:
            token = self._try_extract(fallback, response_text, response_headers, response_cookies)
            if token:
                logger.debug(
                    "Token '%s' extracted via fallback: %s",
                    rule.name, fallback.get("method", "unknown"),
                )
                return token

        return None

    def _try_extract(
        self,
        method_config: dict[str, Any],
        response_text: str,
        response_headers: dict[str, str] | None = None,
        response_cookies: dict[str, str] | None = None,
    ) -> str | None:
        """尝试使用指定方法提取"""
        method = method_config.get("method", "")

        if method == "json_path":
            return self._extract_json_path(method_config, response_text)
        elif method == "regex":
            return self._extract_regex(method_config, response_text)
        elif method == "header":
            return self._extract_header(method_config, response_headers or {})
        elif method == "cookie":
            return self._extract_cookie(method_config, response_cookies or {})
        else:
            logger.debug("Unknown extraction method: %s", method)
            return None

    @staticmethod
    def _extract_json_path(config: dict[str, Any], text: str) -> str | None:
        """JSONPath 提取 (简化版，支持 $.field 和 $.field.subfield)"""
        path = config.get("path", "")
        if not path or not text:
            return None

        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return None

        # 简化 JSONPath: $.field -> ["field"]
        if not path.startswith("$."):
            return None

        fields = path[2:].split(".")
        current = data
        for field in fields:
            if isinstance(current, dict) and field in current:
                current = current[field]
            else:
                return None

        if isinstance(current, str) and current.strip():
            return current.strip()
        elif current is not None:
            return str(current)
        return None

    @staticmethod
    def _extract_regex(config: dict[str, Any], text: str) -> str | None:
        """正则表达式提取"""
        pattern = config.get("pattern", "")
        if not pattern or not text:
            return None

        match = re.search(pattern, text)
        if match:
            try:
                return match.group(1).strip()
            except IndexError:
                return match.group(0).strip()
        return None

    @staticmethod
    def _extract_header(config: dict[str, Any], headers: dict[str, str]) -> str | None:
        """Header 提取"""
        name = config.get("name", "")
        if not name:
            return None

        # Case-insensitive header lookup
        for key, value in headers.items():
            if key.lower() == name.lower():
                return value.strip() if value else None
        return None

    @staticmethod
    def _extract_cookie(config: dict[str, Any], cookies: dict[str, str]) -> str | None:
        """Cookie 提取"""
        name = config.get("name", "")
        if not name:
            return None

        return cookies.get(name)
