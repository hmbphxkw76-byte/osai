# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Converter 变体链定义 — 使用 PyRIT 原生 ``extra_request_converters`` API。.

PyRIT 原生 ``AttackTechniqueFactory.create(extra_request_converters=...)`` 支持在
已有 Converter 基础上追加（additive），实现渐进式 Converter 升级链:
  attempt 1: prompt_sending (无 Converter)
  attempt 2: prompt_sending + stealth_evasion (追加 Converter)
  attempt 3: prompt_sending + encoding_bypass (追加不同 Converter)

原生 ``AdaptiveTechniqueDispatcher`` 的 ``SequentialAttack(FIRST_SUCCESS)``
能按 selector 排序尝试 Converter 变体，成功即停止。

本模块定义预设 Converter 链元数据（纯数据层，不干扰原生执行）。

学术依据:
- Russinovich et al. (arXiv:2402.12109): Crescendo + encoding 协同 3-5x
- Zeng et al. (arXiv:2402.19181): 说服策略 ASR 30-40%
- Wei et al. (arXiv:2307.15043): 编码攻击表示级变换

> **日期**: 2026-8-1
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from pyrit.converter import (
    AsciiArtConverter,
    AsciiSmugglerConverter,
    AtbashConverter,
    Base64Converter,
    Base2048Converter,
    BidiConverter,
    BinaryConverter,
    BrailleConverter,
    CaesarConverter,
    CharacterSpaceConverter,
    CharSwapConverter,
    DecompositionConverter,
    DiacriticConverter,
    EcojiConverter,
    EmojiConverter,
    FirstLetterConverter,
    InsertPunctuationConverter,
    LeetspeakConverter,
    MathObfuscationConverter,
    MorseConverter,
    NatoConverter,
    NoiseConverter,
    PersuasionConverter,
    PolicyPuppetryConverter,
    RandomCapitalLettersConverter,
    RepeatTokenConverter,
    ROT13Converter,
    ScientificTranslationConverter,
    SearchReplaceConverter,
    SneakyBitsSmugglerConverter,
    StringJoinConverter,
    SuffixAppendConverter,
    SuperscriptConverter,
    TaskFramingConverter,
    TatweelConverter,
    TenseConverter,
    ToneConverter,
    TranslationConverter,
    UnicodeConfusableConverter,
    UnicodeReplacementConverter,
    UnicodeSubstitutionConverter,
    UrlConverter,
    VariationConverter,
    ZalgoConverter,
    ZeroWidthConverter,
)
from pyrit.prompt_normalizer import ConverterConfiguration

logger = logging.getLogger(__name__)


# ============================================================
# Converter 变体链配置 — P2-10: 从 data/converter_chains.yaml 加载
# ============================================================

_CHAINS_YAML = Path(__file__).parent.parent.parent / "data" / "config" / "converter_chains.yaml"


def _load_chain_config() -> tuple[dict[str, dict[str, Any]], dict[str, list[str]]]:
    """从 ``data/converter_chains.yaml`` 加载链配置和基础技术映射。.

    YAML 是唯一数据源, 链元数据和映射不再硬编码在 Python 中。
    链实例化函数 (``_build_*_chain()``) 仍保留在代码中,
    因为它们需要导入和构造 PyRIT Converter 类。
    """
    if not _CHAINS_YAML.exists():
        raise FileNotFoundError(f"Converter chains YAML not found at {_CHAINS_YAML}. This is the required data source.")
    import yaml as _yaml

    with open(_CHAINS_YAML, encoding="utf-8") as f:
        data = _yaml.safe_load(f)

    chains: dict[str, dict[str, Any]] = {}
    for name, meta in (data.get("chains") or {}).items():
        chains[name] = {
            "requires_llm": bool(meta.get("requires_llm", False)),
            "priority": int(meta.get("priority", 3)),
            "modality": meta.get("modality", "text"),
            "description": meta.get("description", ""),
        }

    base_map: dict[str, list[str]] = {}
    for tech, chain_list in (data.get("base_techniques_for_variants") or {}).items():
        base_map[tech] = list(chain_list)

    logger.info(f"Converter chains loaded from YAML: {len(chains)} chains, {len(base_map)} base technique mappings")
    return chains, base_map


CONVERTER_VARIANT_CHAINS, BASE_TECHNIQUES_FOR_VARIANTS = _load_chain_config()


# ============================================================
# 链构建函数
# ============================================================


def _build_stealth_evasion_chain() -> list:
    """Unicode 混淆 + Base64 + 后缀追加."""
    return [
        UnicodeConfusableConverter(),
        Base64Converter(),
        SuffixAppendConverter(suffix="!!"),
    ]


def _build_multi_encoding_v2_chain() -> list:
    """四层编码: Base64 + ROT13 + Caesar(5) + Atbash."""
    return [
        Base64Converter(),
        ROT13Converter(),
        CaesarConverter(caesar_offset=5),
        AtbashConverter(),
    ]


def _build_encoding_bypass_chain() -> list:
    """Base64 + ROT13 + Caesar 编码绕过."""
    return [
        Base64Converter(),
        ROT13Converter(),
        CaesarConverter(caesar_offset=3),
    ]


def _build_unicode_attack_chain() -> list:
    """Unicode 混淆 + 双向文本 + 零宽字符."""
    return [
        UnicodeSubstitutionConverter(),
        BidiConverter(),
        ZeroWidthConverter(),
    ]


def _build_random_case_chain() -> list:
    """随机大写字符绕过关键词检测."""
    return [
        RandomCapitalLettersConverter(),
    ]


def _build_format_injection_chain() -> list:
    """ASCII 艺术格式注入."""
    return [
        AsciiArtConverter(),
    ]


def _build_noise_bypass_chain(converter_target=None) -> list:
    """NoiseConverter 噪声注入 (LLM 辅助).

    NoiseConverter 需要 converter_target 来生成噪声变体。
    """
    if converter_target is None:
        return []
    return [
        NoiseConverter(converter_target=converter_target),
    ]


def _build_special_chars_chain() -> list:
    """特殊字符注入."""
    return [
        UnicodeConfusableConverter(),
        StringJoinConverter(),
    ]


def _build_persuasion_authority_chain(converter_target=None) -> list:
    """权威说服 (LLM 辅助)."""
    if converter_target is None:
        return []
    return [
        PersuasionConverter(
            converter_target=converter_target,
            persuasion_template="authority_endorsement",
        ),
    ]


def _build_decomposition_chain(converter_target=None) -> list:
    """分解重构."""
    if converter_target is None:
        return []
    return [
        DecompositionConverter(
            converter_target=converter_target,
        ),
    ]


def _build_llm_assisted_chain(converter_target=None) -> list:
    """说服 + 语气 + 翻译 (LLM 辅助)."""
    if converter_target is None:
        return []
    return [
        PersuasionConverter(
            converter_target=converter_target,
            persuasion_template="authority_endorsement",
        ),
        ToneConverter(converter_target=converter_target),
        TranslationConverter(converter_target=converter_target, languages=["en"]),
    ]


def _build_task_framing_chain(converter_target=None) -> list:
    """任务框架重构."""
    if converter_target is None:
        return []
    return [
        TaskFramingConverter(converter_target=converter_target),
    ]


# ── 补全: 非 LLM 链构建函数 ──


def _build_binary_morse_chain() -> list:
    """Binary + Morse 双层编码."""
    return [BinaryConverter(), MorseConverter()]


def _build_braille_nato_chain() -> list:
    """Braille + Nato 字母表替换."""
    return [BrailleConverter(), NatoConverter()]


def _build_leetspeak_zalgo_chain() -> list:
    """Leetspeak + Zalgo 文本变形."""
    return [LeetspeakConverter(), ZalgoConverter()]


def _build_emoji_superscript_chain() -> list:
    """Emoji + Superscript 字符替换."""
    return [EmojiConverter(), SuperscriptConverter()]


def _build_char_swap_diacritic_chain() -> list:
    """CharSwap + Diacritic 字符变形."""
    return [CharSwapConverter(), DiacriticConverter()]


def _build_character_space_chain() -> list:
    """CharacterSpace 字符间距混淆."""
    return [CharacterSpaceConverter()]


def _build_punctuation_insert_chain() -> list:
    """InsertPunctuation 标点注入绕过."""
    return [InsertPunctuationConverter()]


def _build_repeat_token_chain() -> list:
    """RepeatToken 重复令牌注入."""
    return [RepeatTokenConverter()]


def _build_token_smuggling_chain() -> list:
    """AsciiSmuggler + SneakyBits 令牌走私."""
    return [AsciiSmugglerConverter(), SneakyBitsSmugglerConverter()]


def _build_url_encoding_chain() -> list:
    """Url + Base64 URL 编码绕过."""
    return [UrlConverter(), Base64Converter()]


def _build_base2048_ecoji_chain() -> list:
    """Base2048 + Ecoji 高基数编码."""
    return [Base2048Converter(), EcojiConverter()]


def _build_unicode_replacement_chain() -> list:
    """UnicodeReplacement + Tatweel Unicode 替换."""
    return [UnicodeReplacementConverter(), TatweelConverter()]


def _build_search_replace_chain() -> list:
    """SearchReplace 关键词替换绕过."""
    return [SearchReplaceConverter(old_value="test", new_value="exam")]


def _build_first_letter_chain() -> list:
    """FirstLetter 首字母提取编码."""
    return [FirstLetterConverter()]


# ── 补全: LLM 链构建函数 ──


def _build_tense_variation_chain(converter_target=None) -> list:
    """Tense + Variation 时态变换+变体 (LLM 辅助)."""
    if converter_target is None:
        return []
    return [
        TenseConverter(converter_target=converter_target),
        VariationConverter(converter_target=converter_target),
    ]


def _build_persuasion_policy_chain(converter_target=None) -> list:
    """Persuasion + PolicyPuppetry 说服+策略模仿."""
    if converter_target is None:
        return []
    return [
        PersuasionConverter(
            converter_target=converter_target,
            persuasion_template="authority_endorsement",
        ),
        PolicyPuppetryConverter(converter_target=converter_target),
    ]


def _build_math_obfuscation_chain(converter_target=None) -> list:
    """MathObfuscation 数学表达式混淆 (LLM 辅助)."""
    if converter_target is None:
        return []
    return [MathObfuscationConverter(converter_target=converter_target)]


def _build_scientific_translation_chain(converter_target=None) -> list:
    """ScientificTranslation 科学翻译变换."""
    if converter_target is None:
        return []
    return [ScientificTranslationConverter(converter_target=converter_target)]


# 链名 → 构建函数映射
_CHAIN_BUILDERS = {
    "stealth_evasion": lambda target=None: _build_stealth_evasion_chain(),
    "multi_encoding_v2": lambda target=None: _build_multi_encoding_v2_chain(),
    "encoding_bypass": lambda target=None: _build_encoding_bypass_chain(),
    "unicode_attack": lambda target=None: _build_unicode_attack_chain(),
    "random_case": lambda target=None: _build_random_case_chain(),
    "format_injection": lambda target=None: _build_format_injection_chain(),
    "noise_bypass": lambda target=None: _build_noise_bypass_chain(),
    "special_chars": lambda target=None: _build_special_chars_chain(),
    "persuasion_authority": lambda target=None: _build_persuasion_authority_chain(target),
    "decomposition_chain": lambda target=None: _build_decomposition_chain(target),
    "llm_assisted": lambda target=None: _build_llm_assisted_chain(target),
    "task_framing_chain": lambda target=None: _build_task_framing_chain(target),
    # 补全链
    "binary_morse_chain": lambda target=None: _build_binary_morse_chain(),
    "braille_nato_chain": lambda target=None: _build_braille_nato_chain(),
    "leetspeak_zalgo_chain": lambda target=None: _build_leetspeak_zalgo_chain(),
    "emoji_superscript_chain": lambda target=None: _build_emoji_superscript_chain(),
    "char_swap_diacritic_chain": lambda target=None: _build_char_swap_diacritic_chain(),
    "character_space_chain": lambda target=None: _build_character_space_chain(),
    "punctuation_insert_chain": lambda target=None: _build_punctuation_insert_chain(),
    "repeat_token_chain": lambda target=None: _build_repeat_token_chain(),
    "token_smuggling_chain": lambda target=None: _build_token_smuggling_chain(),
    "url_encoding_chain": lambda target=None: _build_url_encoding_chain(),
    "base2048_ecoji_chain": lambda target=None: _build_base2048_ecoji_chain(),
    "unicode_replacement_chain": lambda target=None: _build_unicode_replacement_chain(),
    "search_replace_chain": lambda target=None: _build_search_replace_chain(),
    "first_letter_chain": lambda target=None: _build_first_letter_chain(),
    "tense_variation_chain": lambda target=None: _build_tense_variation_chain(target),
    "persuasion_policy_chain": lambda target=None: _build_persuasion_policy_chain(target),
    "math_obfuscation_chain": lambda target=None: _build_math_obfuscation_chain(target),
    "scientific_translation_chain": lambda target=None: _build_scientific_translation_chain(target),
}


def load_preset_converter_chain(
    chain_name: str,
    converter_target=None,
) -> ConverterConfiguration | None:
    """从预设链名构建 ConverterConfiguration。.

    使用 PyRIT 原生 ``ConverterConfiguration`` 包装 Converter 列表，
    供 ``AttackTechniqueFactory.create(extra_request_converters=...)`` 使用。

    Args:
        chain_name: 链名
        converter_target: LLM 链所需的 Converter Target

    Returns:
        ConverterConfiguration 实例，或 None（链不存在/无法构建）
    """
    chain_info = CONVERTER_VARIANT_CHAINS.get(chain_name)
    if chain_info is None:
        return None

    builder = _CHAIN_BUILDERS.get(chain_name)
    if builder is None:
        return None

    # LLM 链需要 converter_target
    if chain_info.get("requires_llm", False) and converter_target is None:
        return None

    try:
        converters = builder(converter_target)
    except Exception as e:
        logger.warning(f"Failed to build converter chain '{chain_name}': {e}")
        return None

    if not converters:
        return None

    return ConverterConfiguration(converters=converters)


# ============================================================
# 辅助函数
# ============================================================


def is_converter_variant(technique_name: str) -> bool:
    """判断是否是 Converter 变体名（如 'prompt_sending+stealth_evasion'）。."""
    return "+" in technique_name


def get_converter_chain_from_variant(technique_name: str) -> str | None:
    """从变体名提取 Converter 链名。."""
    if "+" not in technique_name:
        return None
    return technique_name.split("+", 1)[1]


def get_base_technique_from_variant(technique_name: str) -> str:
    """从变体名提取基础技术名。."""
    if "+" not in technique_name:
        return technique_name
    return technique_name.split("+", 1)[0]


def get_dynamic_chain_mapping(
    target_type: str | None,
    converter_target_available: bool,
) -> dict[str, list[str]] | None:
    """根据 target_type 返回动态链映射。.

    当 target_type 为 None 时返回 None（使用静态映射 BASE_TECHNIQUES_FOR_VARIANTS）。
    """
    from pipeline.converters.target_aware_router import get_chains_for_target_type

    if not target_type:
        return None

    return get_chains_for_target_type(
        target_type=target_type,
        converter_target_available=converter_target_available,
    )


def build_converters_from_chain_names(
    chain_names: list[str],
    converter_target=None,
) -> list:
    """从多个链名构建扁平化的 Converter 实例列表。.

    将多个预设 Converter 链的构建结果合并为一个扁平列表,
    供原生 ``technique_converters`` 参数使用。

    - 非 LLM 链直接构建
    - LLM 链需要 converter_target, 若为 None 则跳过该链
    - 自动去重 (同名 Converter 类只保留第一个实例)

    Args:
        chain_names: 链名列表 (如 ["stealth_evasion", "encoding_bypass"])
        converter_target: LLM 链所需的 Converter Target

    Returns:
        合并后的 Converter 实例列表 (可能为空)
    """
    result: list = []
    seen_types: set[str] = set()

    for chain_name in chain_names:
        chain_info = CONVERTER_VARIANT_CHAINS.get(chain_name)
        if chain_info is None:
            logger.debug(f"Chain '{chain_name}' not found in CONVERTER_VARIANT_CHAINS, skipping")
            continue

        builder = _CHAIN_BUILDERS.get(chain_name)
        if builder is None:
            logger.debug(f"No builder for chain '{chain_name}', skipping")
            continue

        # LLM 链需要 converter_target
        if chain_info.get("requires_llm", False) and converter_target is None:
            logger.debug(f"Chain '{chain_name}' requires LLM but no converter_target, skipping")
            continue

        try:
            converters = builder(converter_target)
        except Exception as e:
            logger.warning(f"Failed to build converter chain '{chain_name}': {e}")
            continue

        if not converters:
            continue

        # 去重: 同名 Converter 类只保留第一个实例
        for conv in converters:
            conv_type_name = type(conv).__name__
            if conv_type_name not in seen_types:
                seen_types.add(conv_type_name)
                result.append(conv)

    return result
