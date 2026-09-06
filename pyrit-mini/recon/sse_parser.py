"""SSE (Server-Sent Events) 流式响应解析器。

支持多种 SSE 格式的 content 片段提取与拼接:
    - 标准 SSE (event:, data:)
    - OpenAI 兼容 (choices[0].delta.content)
    - DeepSeek JSON Patch (RFC 6902 变体)
    - Qwen 纯值片段 ({"v":"..."})
"""

from __future__ import annotations

import json
import re
from typing import Any


def _extract_nested_ci(obj: Any, *keys: Any) -> Any:
    """从嵌套 dict/list 中提取值 (大小写不敏感)。

    适配不同 API 的 JSON key 命名风格:
        - snake_case: "choices", "delta", "content"
        - PascalCase: "Choices", "Delta", "Content"
    """
    current = obj
    for key in keys:
        if current is None:
            return None
        if isinstance(key, int):
            if isinstance(current, list) and 0 <= key < len(current):
                current = current[key]
            else:
                return None
        else:
            if isinstance(current, dict):
                # 大小写不敏感查找
                if key in current:
                    current = current[key]
                else:
                    key_lower = key.lower()
                    found = False
                    for k, v in current.items():
                        if k.lower() == key_lower:
                            current = v
                            found = True
                            break
                    if not found:
                        return None
            else:
                return None
    return current


def _extract_nested(obj: Any, *keys: Any) -> Any:
    """从嵌套 dict/list 中提取值 (大小写敏感)。"""
    current = obj
    for key in keys:
        if current is None:
            return None
        if isinstance(key, int):
            if isinstance(current, list) and 0 <= key < len(current):
                current = current[key]
            else:
                return None
        else:
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return None
    return current


def make_sse_callback() -> Any:
    """创建 SSE 流式响应解析 callback。

    策略 (4层 fallback):
        1. 逐行解析 SSE data: 行，提取 content/delta.content/v 字段
        2. 如果逐行解析失败，用正则全局匹配 content 字段
        3. 如果 content 正则也失败，用正则全局匹配 "v":"..." 片段
        4. 如果都失败，返回原始文本 (去掉 SSE 前缀)
    """

    def parse_sse_response(response: Any) -> str:
        """解析 SSE 流式响应，拼接所有 content 片段。"""
        # 获取响应文本
        text = None
        if hasattr(response, "text") and response.text is not None:
            text = response.text
        elif hasattr(response, "content"):
            if isinstance(response.content, bytes):
                text = response.content.decode("utf-8", errors="replace")
            else:
                text = str(response.content)
        else:
            text = str(response)

        if not text or not text.strip():
            return ""

        # 策略1: 逐行解析 SSE data: 行 (最准确)
        content_parts: list[str] = []
        for line in text.split("\n"):
            line = line.strip()
            if not line.startswith("data:"):
                continue

            data_content = line[5:].strip()
            if data_content in ("[DONE]", "[STOP]"):
                continue

            try:
                data_obj = json.loads(data_content)

                # ── DeepSeek JSON Patch 格式 ──
                if isinstance(data_obj, dict) and "v" in data_obj:
                    v_val = data_obj["v"]
                    if "p" in data_obj and "o" in data_obj:
                        p_val = str(data_obj.get("p", ""))
                        o_val = str(data_obj.get("o", ""))
                        if o_val == "APPEND" and "content" in p_val:
                            if isinstance(v_val, str):
                                content_parts.append(v_val)
                            elif isinstance(v_val, list):
                                for item in v_val:
                                    if isinstance(item, dict):
                                        c = item.get("content") or item.get("v")
                                        if c and isinstance(c, str):
                                            content_parts.append(c)
                                    elif isinstance(item, str):
                                        content_parts.append(item)
                        continue
                    else:
                        # 纯值片段 {"v":"片段"} — 直接提取
                        if isinstance(v_val, str):
                            content_parts.append(v_val)
                        elif isinstance(v_val, dict):
                            inner = _extract_nested_ci(v_val, "content")
                            if inner and isinstance(inner, str):
                                content_parts.append(inner)
                        continue

                # ── 标准 SSE / OpenAI / 通用 JSON ──
                content_val = (
                    _extract_nested_ci(data_obj, "content")
                    or _extract_nested_ci(data_obj, "delta", "content")
                    or _extract_nested_ci(data_obj, "choices", 0, "delta", "content")
                    or _extract_nested_ci(data_obj, "choices", 0, "message", "content")
                    or _extract_nested_ci(data_obj, "answer")
                    or _extract_nested_ci(data_obj, "response")
                    or _extract_nested_ci(data_obj, "text")
                )
                if content_val and isinstance(content_val, str):
                    content_parts.append(content_val)
            except (json.JSONDecodeError, ValueError):
                # 非 JSON 格式，尝试正则 (大小写不敏感)
                pattern = re.compile(r'"content"\s*:\s*"((?:[^"\\]|\\.)*)"', re.I)
                match = pattern.search(data_content)
                if match:
                    content_parts.append(match.group(1))

        if content_parts:
            full_content = "".join(content_parts)
            full_content = full_content.replace("\\n", "\n").replace("\\\"", "\"").replace("\\t", "\t")
            return full_content

        # 策略2: 正则全局匹配 content 字段
        pattern = re.compile(r'"content"\s*:\s*"((?:[^"\\]|\\.)*)"', re.I)
        matches = pattern.findall(text)
        if matches:
            full_content = "".join(matches)
            full_content = full_content.replace("\\n", "\n").replace("\\\"", "\"").replace("\\t", "\t")
            return full_content

        # 策略3: 正则全局匹配 "v":"..." 片段
        v_pattern = re.compile(r'"v"\s*:\s*"((?:[^"\\]|\\.)*)"', re.I)
        v_matches = v_pattern.findall(text)
        if v_matches:
            full_content = "".join(v_matches)
            full_content = full_content.replace("\\n", "\n").replace("\\\"", "\"").replace("\\t", "\t")
            return full_content

        # 策略4: 返回原始文本 (清理 SSE 前缀)
        cleaned = re.sub(r"^(event:|data:)\s*", "", text, flags=re.MULTILINE)
        cleaned = cleaned.replace("[DONE]", "").replace("[STOP]", "")
        return cleaned.strip()

    return parse_sse_response
