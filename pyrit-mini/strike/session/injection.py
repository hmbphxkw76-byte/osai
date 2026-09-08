# -*- coding: utf-8 -*-
"""SessionInjector - 通用会话状态注入器

支持向 HTTP 请求注入会话状态 token。
多目标支持: Body (JSON)、Header、Query、Cookie。

注入流程:
    1. 根据规则确定注入目标位置
    2. 使用模板格式化 token 值
    3. 修改请求 (返回新请求，不修改原始请求)

Academic basis:
    - Perez et al. (arXiv:2202.03286) — Injection-based attack persistence
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


class SessionInjector:
    """通用会话状态注入器

    向 HTTP 请求中注入会话状态 token。
    支持多种注入位置和模板格式化。

    使用示例:
        injector = SessionInjector(config.injection_rules)
        modified_request = injector.inject(request_text, session_tokens)
    """

    def __init__(self, rules: list[Any]) -> None:
        """
        Args:
            rules: InjectionRule 列表
        """
        self._rules = rules

    def inject(
        self,
        request_text: str,
        tokens: dict[str, str],
    ) -> str:
        """向请求注入所有配置的 token

        Args:
            request_text: HTTP 请求文本
            tokens: {token_name: token_value} 要注入的 token

        Returns:
            修改后的请求文本
        """
        result = request_text
        for rule in self._rules:
            token_value = tokens.get(rule.name)
            if token_value is None:
                continue
            result = self._inject_single(rule, result, token_value)
        return result

    def inject_single(
        self,
        rule: Any,
        request_text: str,
        token_value: str,
    ) -> str:
        """向请求注入单个 token

        Args:
            rule: InjectionRule
            request_text: HTTP 请求文本
            token_value: token 值

        Returns:
            修改后的请求文本
        """
        return self._inject_single(rule, request_text, token_value)

    def _inject_single(
        self,
        rule: Any,
        request_text: str,
        token_value: str,
    ) -> str:
        """单个 token 注入"""
        target = rule.target
        if hasattr(target, "value"):
            target = target.value

        if target == "body":
            return self._inject_body(rule, request_text, token_value)
        elif target == "header":
            return self._inject_header(rule, request_text, token_value)
        elif target == "query":
            return self._inject_query(rule, request_text, token_value)
        elif target == "cookie":
            return self._inject_cookie(rule, request_text, token_value)
        else:
            logger.debug("Unknown injection target: %s", target)
            return request_text

    @staticmethod
    def _inject_body(rule: Any, request: str, value: str) -> str:
        """注入到 JSON Body"""
        field = rule.field
        formatted = rule.template.replace("{value}", value)

        # 分割 body
        parts = request.split("\r\n\r\n", 1)
        if len(parts) < 2:
            parts = request.split("\n\n", 1)
        if len(parts) < 2:
            return request

        header_section = parts[0]
        body = parts[1]

        if not body.strip():
            return request

        # 尝试解析并修改 JSON
        try:
            body_obj = json.loads(body)
            body_obj[field] = formatted
            new_body = json.dumps(body_obj, ensure_ascii=False)
        except (json.JSONDecodeError, TypeError):
            # JSON 解析失败，使用正则替换
            pattern = rf'"{re.escape(field)}"\s*:\s*"[^"]*"'
            replacement = f'"{field}": "{formatted}"'
            if re.search(pattern, body):
                new_body = re.sub(pattern, replacement, body)
            else:
                # 字段不存在，添加到末尾 (简单场景)
                new_body = body.rstrip()
                if new_body.endswith("}"):
                    new_body = new_body[:-1] + f', "{field}": "{formatted}"' + "}"
                else:
                    new_body = body

        return header_section + "\r\n\r\n" + new_body

    @staticmethod
    def _inject_header(rule: Any, request: str, value: str) -> str:
        """注入到 HTTP Header"""
        field = rule.field
        formatted = rule.template.replace("{value}", value)

        lines = request.split("\r\n")
        if len(lines) < 2:
            lines = request.split("\n")

        # 查找并替换已有 header
        header_found = False
        for i, line in enumerate(lines):
            if line.lower().startswith(field.lower() + ":"):
                lines[i] = f"{field}: {formatted}"
                header_found = True
                break

        if not header_found:
            # 插入到 header 区域末尾 (第一个空行前)
            if len(lines) > 1:
                lines.insert(1, f"{field}: {formatted}")
            else:
                lines.append(f"{field}: {formatted}")

        return "\r\n".join(lines)

    @staticmethod
    def _inject_query(rule: Any, request: str, value: str) -> str:
        """注入到 URL Query Parameter"""
        field = rule.field
        formatted = rule.template.replace("{value}", value)

        # 从 request line 提取 URL
        lines = request.split("\r\n")
        if not lines:
            return request

        request_line = lines[0]
        parts = request_line.split(" ", 2)
        if len(parts) < 2:
            return request

        url = parts[1]
        if "?" in url:
            separator = "&"
        else:
            separator = "?"

        parts[1] = f"{url}{separator}{field}={formatted}"
        lines[0] = " ".join(parts)
        return "\r\n".join(lines)

    @staticmethod
    def _inject_cookie(rule: Any, request: str, value: str) -> str:
        """注入到 Cookie Header"""
        field = rule.field
        formatted = rule.template.replace("{value}", value)

        lines = request.split("\r\n")
        cookie_found = False

        for i, line in enumerate(lines):
            if line.lower().startswith("cookie:"):
                # 在已有 cookie 中添加
                lines[i] = f"{line}; {field}={formatted}"
                cookie_found = True
                break

        if not cookie_found:
            # 插入新 Cookie header
            if len(lines) > 1:
                lines.insert(1, f"Cookie: {field}={formatted}")
            else:
                lines.append(f"Cookie: {field}={formatted}")

        return "\r\n".join(lines)
