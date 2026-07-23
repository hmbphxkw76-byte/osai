# -*- coding: utf-8 -*-
"""
AI-300 Framework - Response Parser
HTTP 响应解析器：JSON / SSE / 纯文本

支持两种靶机响应格式：
1. REST JSON 响应（如 OWASP DonkAI /chat 端点）
   - 响应体：{"response": "...", "session_id": 1, "vulnerability_detected": null}
   - 解析：提取 response 字段作为攻击响应文本

2. SSE 流式响应（如 AIVP /api/labs/{lab_id}/chat 端点）
   - 响应体：data: {"content": "chunk1"}\n\ndata: {"content": "chunk2"}\n\n
   - 解析：拼接所有 content 字段为完整响应文本

3. 纯文本响应（直通模式，不解析）
   - 响应体：原始文本
   - 解析：直接返回

使用方式：
    parser = ResponseParser.create("json", field="response")
    text = parser.parse(raw_response_body)

    parser = ResponseParser.create("sse")
    text = parser.parse(raw_sse_body)

PyRIT 0.14.0 兼容
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)


class ResponseParser:
    """
    HTTP 响应解析基类

    子类实现 parse() 方法将原始响应体转换为评分器可用的纯文本。
    """

    def parse(self, raw_body: str) -> str:
        """将原始响应体解析为纯文本"""
        raise NotImplementedError

    @staticmethod
    def create(
        format: str = "text",
        field: Optional[str] = None,
    ) -> "ResponseParser":
        """
        工厂方法：根据格式创建解析器

        Args:
            format: 响应格式 ("json" / "sse" / "text")
            field: JSON 响应中要提取的字段名（仅 format="json" 时有效）

        Returns:
            ResponseParser 实例
        """
        format_lower = (format or "text").lower().strip()
        if format_lower == "json":
            return JsonResponseParser(field=field or "response")
        elif format_lower == "sse":
            return SSEResponseParser()
        else:
            return TextResponseParser()


class TextResponseParser(ResponseParser):
    """纯文本响应解析器（直通模式）"""

    def parse(self, raw_body: str) -> str:
        return raw_body


class JsonResponseParser(ResponseParser):
    """
    JSON 响应解析器

    从 JSON 响应体中提取指定字段。
    支持嵌套字段访问（如 "data.response"）。
    如果字段不存在或解析失败，返回原始响应体。
    """

    def __init__(self, field: str = "response"):
        self.field = field

    def parse(self, raw_body: str) -> str:
        if not raw_body or not raw_body.strip():
            return ""

        # 尝试 JSON 解析
        try:
            data = json.loads(raw_body)
        except json.JSONDecodeError:
            # 可能是 JSON 行或多行文本
            # 尝试提取第一个 JSON 对象
            match = re.search(r'\{.*\}', raw_body, re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group(0))
                except json.JSONDecodeError:
                    logger.debug("JSON parse failed, returning raw body")
                    return raw_body
            else:
                return raw_body

        # 支持嵌套字段访问
        parts = self.field.split(".")
        value: Any = data
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                break

        if value is None:
            # 字段不存在，返回原始响应体（包含完整 JSON 文本）
            logger.debug("Field '%s' not found in JSON response, returning raw body", self.field)
            return raw_body

        if isinstance(value, str):
            return value
        elif isinstance(value, (int, float, bool)):
            return str(value)
        else:
            return json.dumps(value, ensure_ascii=False)


class SSEResponseParser(ResponseParser):
    """
    SSE (Server-Sent Events) 响应解析器

    解析 SSE 格式响应体，提取所有 data 事件中的内容。

    支持格式：
    - data: {"content": "text"} → 提取 content
    - data: {"message": {"content": "text"}} → 提取 message.content（Ollama 风格）
    - data: {"choices": [{"delta": {"content": "text"}}]} → OpenAI 流式格式
    - data: plain text → 直接使用
    - event: meta\ndata: {...} → 跳过 meta 事件
    """

    # SSE 数据行正则
    _DATA_LINE_RE = re.compile(r'^data:\s*(.*)$', re.MULTILINE)
    # event 行正则（用于跳过非 content 事件）
    _EVENT_LINE_RE = re.compile(r'^event:\s*(.*)$', re.MULTILINE)

    def parse(self, raw_body: str) -> str:
        if not raw_body or not raw_body.strip():
            return ""

        # 提取所有 data: 行的内容
        data_lines = self._DATA_LINE_RE.findall(raw_body)
        if not data_lines:
            # 不是 SSE 格式，返回原始文本
            return raw_body

        # 按事件分组处理（跳过 meta / mcp_result 等非内容事件）
        events = self._split_events(raw_body)
        content_parts: list[str] = []

        for event_type, event_data in events:
            # 跳过非内容事件
            if event_type in ("meta", "mcp_result", "error"):
                continue

            text = self._extract_content_from_data(event_data)
            if text:
                content_parts.append(text)

        result = "".join(content_parts)
        if not result:
            # 回退：尝试从所有 data 行提取
            for line in data_lines:
                text = self._extract_content_from_data(line)
                if text:
                    content_parts.append(text)
            result = "".join(content_parts)

        return result

    def _split_events(self, raw_body: str) -> list[tuple[str, str]]:
        """
        将 SSE 响应体按事件分组

        Returns:
            [(event_type, data_content), ...]
        """
        events: list[tuple[str, str]] = []
        current_event = "message"  # SSE 默认事件类型
        current_data: list[str] = []

        for line in raw_body.split("\n"):
            line = line.rstrip("\r")
            if not line:
                # 空行 = 事件分隔符
                if current_data:
                    events.append((current_event, "\n".join(current_data)))
                    current_data = []
                    current_event = "message"
                continue

            if line.startswith("event:"):
                current_event = line[6:].strip()
            elif line.startswith("data:"):
                current_data.append(line[5:].strip())

        # 处理最后未分隔的事件
        if current_data:
            events.append((current_event, "\n".join(current_data)))

        return events

    def _extract_content_from_data(self, data_str: str) -> str:
        """
        从 SSE data 行提取内容

        支持多种 JSON 格式：
        - {"content": "text"}
        - {"message": {"content": "text"}}
        - {"choices": [{"delta": {"content": "text"}}]}
        - {"choices": [{"message": {"content": "text"}}]}

        如果不是 JSON，返回原始文本。
        """
        data_str = data_str.strip()
        if not data_str or data_str == "[DONE]":
            return ""

        # 尝试 JSON 解析
        try:
            data = json.loads(data_str)
        except json.JSONDecodeError:
            # 纯文本内容
            return data_str

        if not isinstance(data, dict):
            return str(data)

        # 格式 1: {"content": "text"}
        content = data.get("content")
        if isinstance(content, str):
            return content

        # 格式 2: {"message": {"content": "text"}}（Ollama 风格）
        message = data.get("message")
        if isinstance(message, dict):
            content = message.get("content")
            if isinstance(content, str):
                return content

        # 格式 3: {"choices": [{"delta": {"content": "text"}}]}（OpenAI 流式）
        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            choice = choices[0]
            if isinstance(choice, dict):
                delta = choice.get("delta")
                if isinstance(delta, dict):
                    content = delta.get("content")
                    if isinstance(content, str):
                        return content
                msg = choice.get("message")
                if isinstance(msg, dict):
                    content = msg.get("content")
                    if isinstance(content, str):
                        return content

        # 格式 4: {"response": "text"}
        response = data.get("response")
        if isinstance(response, str):
            return response

        # 无法识别的格式，返回空
        return ""


class ResponseParserRegistry:
    """
    响应解析器注册表

    根据目标配置自动选择合适的解析器。
    """

    @staticmethod
    def from_config(config: dict) -> ResponseParser:
        """
        从目标配置创建响应解析器

        Args:
            config: 目标配置字典（包含 response_format 和 response_field 字段）

        Returns:
            ResponseParser 实例
        """
        response_config = config.get("response", {})
        fmt = response_config.get("format", "text")
        field = response_config.get("field", "response")
        return ResponseParser.create(format=fmt, field=field)
