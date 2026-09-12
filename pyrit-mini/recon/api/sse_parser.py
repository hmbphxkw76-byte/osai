"""SSE (Server-Sent Events) Response Parser

Parses SSE stream content from various AI APIs:
    - OpenAI format (choices[0].delta.content)
    - DeepSeek JSON Patch (RFC 6902)
    - Qwen format ({"v":"..."})


Usage:
    Import make_sse_callback into burp_parser.py for SSE response parsing
"""

from __future__ import annotations

import json
import re
from typing import Any


def _extract_nested_ci(obj: Any, *keys: Any) -> Any:
    """Extract nested value from dict with case-insensitive key matching.

    Supports both snake_case and PascalCase keys.
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
        elif isinstance(current, dict):
            # Try exact match first, then case-insensitive
            if key in current:
                current = current[key]
            else:
                # Case-insensitive search
                found = False
                for k, v in current.items():
                    if isinstance(k, str) and k.lower() == str(key).lower():
                        current = v
                        found = True
                        break
                if not found:
                    return None
        else:
            return None
    return current


def _extract_nested(obj: Any, *keys: Any) -> Any:
    """Extract nested value from dict (case-sensitive)."""
    current = obj
    for key in keys:
        if current is None:
            return None
        if isinstance(key, int):
            if isinstance(current, list) and 0 <= key < len(current):
                current = current[key]
            else:
                return None
        elif isinstance(current, dict):
            current = current.get(key)
        else:
            return None
    return current


def make_sse_callback() -> Any:
    """Create SSE response parser callback.

    Uses 4-layer fallback:
        1. Parse SSE data: lines and extract content
        2. Regex content extraction from full text
        3. Regex "v":"..." extraction (DeepSeek format)
        4. Fallback (return raw SSE text)
    """

    def parse_sse_response(response: Any) -> str:
        """Parse SSE response and extract all content."""
        text: str | None = None
        if hasattr(response, "text") and response.text is not None:
            text = response.text
        elif hasattr(response, "content"):
            if isinstance(response.content, bytes):
                text = response.content.decode("utf-8", errors="replace")
            else:
                text = str(response.content)
        else:
            return ""

        if not text or not text.strip():
            return ""

        # Layer 1: SSE data: lines
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
            except json.JSONDecodeError:
                continue

            # DeepSeek JSON Patch format
            if isinstance(data_obj, dict) and "v" in data_obj:
                v_val = data_obj["v"]
                if "p" in data_obj and "o" in data_obj:
                    p_val = data_obj.get("p", {})
                    o_val = str(data_obj.get("o", ""))
                    if o_val == "APPEND" and "content" in p_val:
                        content_parts.append(str(v_val))
                    elif isinstance(v_val, list):
                        for item in v_val:
                            if isinstance(item, dict):
                                c = item.get("c")
                                if c and isinstance(c, str):
                                    content_parts.append(c)
                            elif isinstance(item, str):
                                content_parts.append(item)
                else:
                    if isinstance(v_val, str):
                        content_parts.append(v_val)
                    elif isinstance(v_val, dict):
                        inner = v_val.get("content") or v_val.get("c")
                        if inner and isinstance(inner, str):
                            content_parts.append(inner)
                continue

            # Standard SSE / OpenAI / JSON
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

        if content_parts:
            full_content = "".join(content_parts)
            return full_content.replace("\\n", "\n").replace('\\"', '"').replace("\\t", "\t")

        # Layer 2: Regex content extraction
        pattern = re.compile(r'"content"\s*:\s*"((?:[^"\\]|\\.)*)"', re.I)
        matches = pattern.findall(text)
        if matches:
            full_content = "".join(matches)
            return full_content.replace("\\n", "\n").replace('\\"', '"').replace("\\t", "\t")

        # Layer 3: "v":"..." format
        v_pattern = re.compile(r'"v"\s*:\s*"((?:[^"\\]|\\.)*)"', re.I)
        v_matches = v_pattern.findall(text)
        if v_matches:
            full_content = "".join(v_matches)
            return full_content.replace("\\n", "\n").replace('\\"', '"').replace("\\t", "\t")

        # Layer 4: Fallback
        cleaned = re.sub(r"^(event:|data:)\s*", "", text, flags=re.MULTILINE)
        cleaned = cleaned.replace("[DONE]", "").replace("[STOP]", "")
        return cleaned.strip()

    return parse_sse_response
