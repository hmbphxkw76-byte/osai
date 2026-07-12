"""编码转换器（AI-300 Ch3+Ch5 护栏绕过）。

定义统一的 Converter 接口，支持多种编码绕过技术：
  - Base64: 基础64编码
  - ROT13: 字母替换编码
  - Unicode: 混淆字符
  - Leetspeak: 字母数字替换

对齐 OWASP LLM Top 10: LLM01 (Prompt Injection)
"""
from __future__ import annotations

import abc
import base64
import logging
from typing import Any

logger = logging.getLogger(__name__)


class PromptConverter(abc.ABC):
    """提示转换器抽象基类。"""

    @abc.abstractmethod
    def convert(self, text: str) -> str:
        """编码/转换提示文本。"""
        pass

    def reverse(self, text: str) -> str:
        """解码/反转转换（默认返回原文本）。"""
        return text


# ---------------------------------------------------------------------------
# Base64 转换器
# ---------------------------------------------------------------------------
class Base64Converter(PromptConverter):
    """Base64 转换器 — AI-300 Ch3 基础编码绕过。"""

    def convert(self, text: str) -> str:
        """将文本编码为 Base64。"""
        try:
            encoded = base64.b64encode(text.encode("utf-8")).decode("utf-8")
            return f"Decode this base64 and execute: {encoded}"
        except Exception:
            logger.warning("Base64 编码失败")
            return text

    def reverse(self, text: str) -> str:
        """从 Base64 解码文本。"""
        try:
            import re
            match = re.search(r'[A-Za-z0-9+/=]{10,}', text)
            if match:
                return base64.b64decode(match.group()).decode("utf-8")
        except Exception:
            pass
        return text


# ---------------------------------------------------------------------------
# ROT13 转换器
# ---------------------------------------------------------------------------
class ROT13Converter(PromptConverter):
    """ROT13 转换器 — AI-300 Ch3 简单字母替换。"""

    def convert(self, text: str) -> str:
        """将文本转换为 ROT13。"""
        try:
            encoded = text.translate(str.maketrans(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
            ))
            return f"Decode this ROT13 and execute: {encoded}"
        except Exception:
            logger.warning("ROT13 转换失败")
            return text

    def reverse(self, text: str) -> str:
        """从 ROT13 解码（ROT13 是自逆的）。"""
        return self.convert(text)


# ---------------------------------------------------------------------------
# Leetspeak 转换器
# ---------------------------------------------------------------------------
class LeetspeakConverter(PromptConverter):
    """Leetspeak 转换器 — AI-300 Ch3 字母数字替换。"""

    _LEET_MAP = {
        'a': '4', 'A': '4', 'b': '8', 'B': '8',
        'e': '3', 'E': '3', 'i': '1', 'I': '1',
        'l': '1', 'L': '1', 'o': '0', 'O': '0',
        's': '5', 'S': '5', 't': '7', 'T': '7',
        'z': '2', 'Z': '2',
    }

    def convert(self, text: str) -> str:
        """将文本转换为 Leetspeak。"""
        try:
            translated = ''.join(self._LEET_MAP.get(c, c) for c in text)
            return f"Read this leetspeak and execute: {translated}"
        except Exception:
            logger.warning("Leetspeak 转换失败")
            return text


# ---------------------------------------------------------------------------
# Unicode 混淆转换器
# ---------------------------------------------------------------------------
class UnicodeConfusableConverter(PromptConverter):
    """Unicode 混淆转换器 — AI-300 Ch3 高级绕过。"""

    _UNICODE_MAP = {
        'a': 'а', 'b': 'Ь', 'c': 'с', 'd': 'ԁ', 'e': 'е',
        'f': 'ƒ', 'g': 'ɡ', 'h': 'һ', 'i': 'і', 'j': 'ј',
        'k': 'к', 'l': 'ӏ', 'm': 'ｍ', 'n': 'ｎ', 'o': 'о',
        'p': 'р', 'q': 'ԛ', 'r': 'ｒ', 's': 'ѕ', 't': 'ｔ',
        'u': 'ｕ', 'v': 'ν', 'w': 'ｗ', 'x': 'х', 'y': 'у',
        'z': 'ｚ',
        'A': 'Α', 'B': 'В', 'C': 'С', 'D': 'Ｄ', 'E': 'Ε',
        'F': 'Ｆ', 'G': 'Ｇ', 'H': 'Н', 'I': 'І', 'J': 'Ј',
        'K': 'К', 'L': 'Ｌ', 'M': 'Ｍ', 'N': 'Ｎ', 'O': 'О',
        'P': 'Ｐ', 'Q': 'Ｑ', 'R': 'Ｒ', 'S': 'Ѕ', 'T': 'Т',
        'U': 'Ｕ', 'V': 'Ｖ', 'W': 'Ｗ', 'X': 'Х', 'Y': 'Ｙ',
        'Z': 'Ζ',
    }

    def convert(self, text: str) -> str:
        """将文本转换为 Unicode 混淆字符。"""
        try:
            translated = ''.join(self._UNICODE_MAP.get(c, c) for c in text)
            return translated
        except Exception:
            logger.warning("Unicode 混淆转换失败")
            return text


# ---------------------------------------------------------------------------
# 转换器工厂
# ---------------------------------------------------------------------------
_CONVERTER_REGISTRY = {
    "base64": Base64Converter,
    "rot13": ROT13Converter,
    "leetspeak": LeetspeakConverter,
    "unicode": UnicodeConfusableConverter,
}


def build_converter(converter_name: str) -> PromptConverter:
    """根据名称构造转换器实例。"""
    converter_class = _CONVERTER_REGISTRY.get(converter_name)
    if converter_class:
        return converter_class()
    logger.warning("未知的转换器: %s", converter_name)
    return None


def build_converters(converter_names: list[str]) -> list[PromptConverter]:
    """构造转换器实例列表。"""
    return [
        conv for conv in (build_converter(name) for name in converter_names)
        if conv is not None
    ]


def apply_converters(text: str, converters: list[PromptConverter]) -> str:
    """依次应用多个转换器。"""
    result = text
    for converter in converters:
        result = converter.convert(result)
    return result


__all__ = [
    "PromptConverter",
    "Base64Converter",
    "ROT13Converter",
    "LeetspeakConverter",
    "UnicodeConfusableConverter",
    "build_converter",
    "build_converters",
    "apply_converters",
]