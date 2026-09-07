"""SSE (Server-Sent Events) 

 SSE  content :
    -  SSE (event:, data:)
    - OpenAI  (choices[0].delta.content)
    - DeepSeek JSON Patch (RFC 6902 )
    - Qwen  ({"v":"..."})

⚠️ DEPRECATED (2026-09-06):
     import  (SSE  burp_parser.py)
    :  SSE 
    :  burp_parser.py  'from recon.sse_parser import make_sse_callback'
"""

from __future__ import annotations

import json
import re
from typing import Any


def _extract_nested_ci(obj: Any, *keys: Any) -> Any:
 """imports dict/list ()

     API  JSON key :
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
 # 
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
 """imports dict/list ()"""
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
 """ SSE callback

     (4Layer fallback):
        1.  SSE data:  content/delta.content/v 
        2.  content 
        3.  content  "v":"..." 
        4.  ( SSE )
 """

    def parse_sse_response(response: Any) -> str:
 """ SSE all content """
 # 
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

 # 1: SSE data: ()
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

 # == DeepSeek JSON Patch ==
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
 # {"v":""} - 
                        if isinstance(v_val, str):
                            content_parts.append(v_val)
                        elif isinstance(v_val, dict):
                            inner = _extract_nested_ci(v_val, "content")
                            if inner and isinstance(inner, str):
                                content_parts.append(inner)
                        continue

 # == SSE / OpenAI / JSON ==
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
 # JSON ()
                pattern = re.compile(r'"content"\s*:\s*"((?:[^"\\]|\\.)*)"', re.I)
                match = pattern.search(data_content)
                if match:
                    content_parts.append(match.group(1))

        if content_parts:
            full_content = "".join(content_parts)
            full_content = full_content.replace("\\n", "\n").replace("\\\"", "\"").replace("\\t", "\t")
            return full_content

 # 2: content 
        pattern = re.compile(r'"content"\s*:\s*"((?:[^"\\]|\\.)*)"', re.I)
        matches = pattern.findall(text)
        if matches:
            full_content = "".join(matches)
            full_content = full_content.replace("\\n", "\n").replace("\\\"", "\"").replace("\\t", "\t")
            return full_content

 # 3: "v":"..." 
        v_pattern = re.compile(r'"v"\s*:\s*"((?:[^"\\]|\\.)*)"', re.I)
        v_matches = v_pattern.findall(text)
        if v_matches:
            full_content = "".join(v_matches)
            full_content = full_content.replace("\\n", "\n").replace("\\\"", "\"").replace("\\t", "\t")
            return full_content

 # 4: ( SSE )
        cleaned = re.sub(r"^(event:|data:)\s*", "", text, flags=re.MULTILINE)
        cleaned = cleaned.replace("[DONE]", "").replace("[STOP]", "")
        return cleaned.strip()

    return parse_sse_response
