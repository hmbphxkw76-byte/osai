"""编码转换器（AI-300 Ch3+Ch5 护栏绕过）。

模块职责：
  - ConverterCategory: 转换器分类枚举
  - ConverterRegistry: 转换器注册表（分类体系、动态注册、懒加载）
  - 工厂函数：build_converter / build_converters / apply_converters

子模块：
  - encoding_converters.py: 11 种纯 Python 编码转换器
  - jailbreak_converters.py: 8 种越狱提示词转换器

从大型单文件（726 行）拆分为 3 个独立模块。
"""
from __future__ import annotations

import logging
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)

# 从 encoding_converters 导入 PromptConverter ABC 和全部编码转换器
from redteam.attack.core.encoding_converters import (  # noqa: F401, E402
    AtbashConverter,
    Base32Converter,
    Base64Converter,
    CaesarConverter,
    HexConverter,
    LeetspeakConverter,
    MorseConverter,
    PromptConverter,
    ReverseConverter,
    ROT13Converter,
    UnicodeConfusableConverter,
    URLConverter,
)
# 从 jailbreak_converters 导入全部越狱转换器
from redteam.attack.core.jailbreak_converters import (  # noqa: F401, E402
    AcademicJailbreakConverter,
    AIMConverter,
    DAN6Converter,
    FlipAttackConverter,
    ManyShotJailbreakConverter,
    PAIRJailbreakConverter,
    RoleplayJailbreakConverter,
    TranslationBypassConverter,
)


# ---------------------------------------------------------------------------
# 转换器分类枚举
# ---------------------------------------------------------------------------
class ConverterCategory(Enum):
    """转换器分类。"""
    ENCODING = "encoding"
    JAILBREAK = "jailbreak"
    INJECTION = "injection"
    REASONING = "reasoning"
    STEGANOGRAPHY = "steganography"


# ---------------------------------------------------------------------------
# 转换器注册表（PyRIT 融合）
# ---------------------------------------------------------------------------
class ConverterRegistry:
    """转换器注册表。

    提供分类体系、动态注册、懒加载功能。
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def _initialize(self):
        if self._initialized:
            return
        self._registry: dict[str, dict] = {}
        self._category_map: dict[str, list[str]] = {}
        self._initialized = True
        self._populate_default_converters()

    def _populate_default_converters(self):
        encoding_converters = [
            ("base64", Base64Converter, ConverterCategory.ENCODING),
            ("rot13", ROT13Converter, ConverterCategory.ENCODING),
            ("leetspeak", LeetspeakConverter, ConverterCategory.ENCODING),
            ("unicode", UnicodeConfusableConverter, ConverterCategory.STEGANOGRAPHY),
            ("hex", HexConverter, ConverterCategory.ENCODING),
            ("url", URLConverter, ConverterCategory.ENCODING),
            ("base32", Base32Converter, ConverterCategory.ENCODING),
            ("morse", MorseConverter, ConverterCategory.ENCODING),
            ("caesar", CaesarConverter, ConverterCategory.ENCODING),
            ("atbash", AtbashConverter, ConverterCategory.ENCODING),
            ("reverse", ReverseConverter, ConverterCategory.STEGANOGRAPHY),
        ]

        jailbreak_converters = [
            ("pair", PAIRJailbreakConverter, ConverterCategory.JAILBREAK),
            ("dan6", DAN6Converter, ConverterCategory.JAILBREAK),
            ("aim", AIMConverter, ConverterCategory.JAILBREAK),
            ("academic", AcademicJailbreakConverter, ConverterCategory.JAILBREAK),
            ("many_shot", ManyShotJailbreakConverter, ConverterCategory.JAILBREAK),
            ("flip_attack", FlipAttackConverter, ConverterCategory.JAILBREAK),
            ("roleplay", RoleplayJailbreakConverter, ConverterCategory.JAILBREAK),
            ("translation", TranslationBypassConverter, ConverterCategory.JAILBREAK),
        ]

        for name, cls_, category in encoding_converters + jailbreak_converters:
            self.register(name, cls_, category)

    def register(
        self,
        name: str,
        converter_class: type,
        category: Optional[ConverterCategory] = None,
    ):
        """注册转换器。"""
        self._initialize()
        self._registry[name] = {
            "class": converter_class,
            "category": category or ConverterCategory.INJECTION,
        }
        if category:
            cat_name = category.value
            if cat_name not in self._category_map:
                self._category_map[cat_name] = []
            if name not in self._category_map[cat_name]:
                self._category_map[cat_name].append(name)

    def get(self, name: str) -> Optional[PromptConverter]:
        """获取转换器实例。

        支持三类查找（按优先级）：
        1. 精确匹配注册键（如 "roleplay"）
        2. 类名精确匹配（如 "RoleplayJailbreakConverter"）
        3. 类名大小写不敏感匹配
        """
        self._initialize()
        entry = self._registry.get(name)
        if entry:
            return entry["class"]()

        name_lower = name.lower()
        for key, entry in self._registry.items():
            cls_name = entry["class"].__name__
            if cls_name == name or cls_name.lower() == name_lower:
                return entry["class"]()

        return None

    def list_converters(self) -> list[str]:
        """列出所有转换器名称。"""
        self._initialize()
        return list(self._registry.keys())

    def list_by_category(self, category: ConverterCategory) -> list[str]:
        """按分类列出转换器。"""
        self._initialize()
        return self._category_map.get(category.value, [])

    def get_by_category(self, category: ConverterCategory) -> list[PromptConverter]:
        """按分类获取转换器实例。"""
        names = self.list_by_category(category)
        return [self.get(name) for name in names if self.get(name) is not None]


_converter_registry = ConverterRegistry()


# ---------------------------------------------------------------------------
# 转换器工厂
# ---------------------------------------------------------------------------
def build_converter(converter_name: str) -> Optional[PromptConverter]:
    """根据名称构造转换器实例。"""
    converter = _converter_registry.get(converter_name)
    if converter:
        return converter
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


def get_converter_registry() -> ConverterRegistry:
    """获取转换器注册表单例。"""
    return _converter_registry


__all__ = [
    # ABC
    "PromptConverter",
    # 编码转换器
    "Base64Converter",
    "ROT13Converter",
    "LeetspeakConverter",
    "UnicodeConfusableConverter",
    "HexConverter",
    "URLConverter",
    "Base32Converter",
    "MorseConverter",
    "CaesarConverter",
    "AtbashConverter",
    "ReverseConverter",
    # 越狱转换器
    "PAIRJailbreakConverter",
    "DAN6Converter",
    "AIMConverter",
    "AcademicJailbreakConverter",
    "ManyShotJailbreakConverter",
    "FlipAttackConverter",
    "RoleplayJailbreakConverter",
    "TranslationBypassConverter",
    # 注册表 + 工厂
    "ConverterCategory",
    "ConverterRegistry",
    "build_converter",
    "build_converters",
    "apply_converters",
    "get_converter_registry",
]
