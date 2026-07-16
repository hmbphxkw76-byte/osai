# -*- coding: utf-8 -*-
"""
AI-300 Framework - Payload Normalizer
归一化预处理：尝试解码已知编码，返回最可能的原始文本

PyRIT 0.14.0 兼容
"""

import base64
import html
import os
import re
import sys
from typing import List, Tuple

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"


def normalize_payload(text: str) -> Tuple[str, List[str]]:
    """
    归一化载荷：尝试解码已知编码，返回最可能的原始文本

    支持的解码：
    - HTML entities
    - Unicode escape (\\uXXXX)
    - Hex escape (\\xXX)
    - URL encoding (%XX)
    - Base64
    - ROT13

    Args:
        text: 原始载荷文本

    Returns:
        (normalized_text, detected_encodings)
    """
    if not text or not isinstance(text, str):
        return text, []

    text_stripped = text.strip()
    detected_encodings: List[str] = []
    current = text_stripped

    # 尝试 HTML entities 解码
    decoded_html = html.unescape(current)
    if decoded_html != current:
        detected_encodings.append("html_entities")
        current = decoded_html

    # 尝试 Unicode escape 解码（仅当文本包含 \uXXXX 模式时）
    if re.search(r'\\u[0-9a-fA-F]{4}', current):
        try:
            decoded_unicode = current.encode().decode("unicode_escape")
            if decoded_unicode != current:
                detected_encodings.append("unicode_escape")
                current = decoded_unicode
        except (UnicodeDecodeError, UnicodeError):
            pass

    # 尝试 Hex escape 解码（仅当文本包含 \xXX 模式时）
    hex_escape_pattern = re.compile(r'\\x([0-9a-fA-F]{2})')
    if hex_escape_pattern.search(current):
        try:
            decoded_hex = hex_escape_pattern.sub(
                lambda m: chr(int(m.group(1), 16)), current
            )
            if decoded_hex != current and all(c.isprintable() or c.isspace() for c in decoded_hex):
                detected_encodings.append("hex_escape")
                current = decoded_hex
        except (ValueError, UnicodeError):
            pass

    # 尝试 URL decoding
    try:
        from urllib.parse import unquote
        decoded_url = unquote(current)
        if decoded_url != current:
            detected_encodings.append("url_encoding")
            current = decoded_url
    except Exception:
        pass

    # 尝试 Base64 解码（仅当整个文本看起来是 Base64）
    try:
        if len(current) >= 20 and re.match(r'^[A-Za-z0-9+/]+=*$', current):
            # 补齐 padding
            padded = current + '=' * (4 - len(current) % 4) if len(current) % 4 else current
            decoded_b64 = base64.b64decode(padded).decode("utf-8", errors="strict")
            if all(c.isprintable() or c.isspace() for c in decoded_b64):
                detected_encodings.append("base64")
                current = decoded_b64
    except Exception:
        pass

    # 尝试 ROT13 解码（仅当文本看起来是 ROT13 编码的）
    try:
        decoded_rot13 = current.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
        ))
        # 如果解码后包含常见英文单词，可能是 ROT13
        common_words = ["the", "and", "for", "are", "but", "not", "you", "all"]
        if decoded_rot13 != current:
            word_count = sum(1 for w in common_words if w in decoded_rot13.lower())
            if word_count >= 2:
                detected_encodings.append("rot13")
                current = decoded_rot13
    except Exception:
        pass

    return current, detected_encodings
