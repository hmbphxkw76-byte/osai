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

import importlib
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# P3-1: 惰性导入 Converter 类 — 避免 PyRIT 版本变更时整个模块导入失败
_converter_mod = None


def _conv(name: str) -> type:
    """惰性获取 PyRIT Converter 类 (首次调用时导入整个模块, 后续从缓存返回).

    如果类不存在, 抛出 AttributeError 并记录警告.
    """
    global _converter_mod
    if _converter_mod is None:
        _converter_mod = importlib.import_module("pyrit.converter")
    cls = getattr(_converter_mod, name, None)
    if cls is None:
        raise AttributeError(f"PyRIT Converter '{name}' not found in pyrit.converter. Check PyRIT version.")
    return cls


# P3-1: 模块级 __getattr__ — 函数体内引用 Converter 类名时自动惰性解析
# 无需修改任何 _build_*_chain() 函数体, Python 会在全局命名空间未找到时自动调用
_CONVERSION_CONFIG_IMPORTED = False


def _get_converter_configuration() -> Any:
    """惰性导入 ConverterConfiguration (仅在使用时导入)."""
    global _CONVERSION_CONFIG_IMPORTED
    if not _CONVERSION_CONFIG_IMPORTED:
        from pyrit.prompt_normalizer import ConverterConfiguration
        globals()["ConverterConfiguration"] = ConverterConfiguration
        _CONVERSION_CONFIG_IMPORTED = True
    return globals().get("ConverterConfiguration")


def __getattr__(name: str) -> Any:
    """模块级惰性导入 (P3-1): Converter 类名在首次引用时从 pyrit.converter 导入.

    支持: UnicodeConfusableConverter, Base64Converter, ROT13Converter, ...
    以及: ConverterConfiguration (从 pyrit.prompt_normalizer)
    """
    if name == "ConverterConfiguration":
        return _get_converter_configuration()
    # 尝试从 pyrit.converter 惰性获取
    try:
        return _conv(name)
    except AttributeError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None


# ============================================================
# Converter 变体链配置 — P2-10: 从 data/converter_chains.yaml 加载
# ============================================================

_CHAINS_YAML = Path(__file__).parent.parent.parent / "data" / "setting" / "converter_chains.yaml"


def _load_chain_config() -> tuple[dict[str, dict[str, Any]], dict[str, list[str]], list[dict[str, Any]]]:
    """从 ``data/converter_chains.yaml`` 加载链配置、基础技术映射和组合乘数。.

    YAML 是唯一数据源, 链元数据和映射不再硬编码在 Python 中。
    链实例化函数 (``_build_*_chain()``) 仍保留在代码中,
    因为它们需要导入和构造 PyRIT Converter 类。

    Returns:
        (chains, base_technique_map, combo_multipliers) 三元组
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
            "cost_tier": meta.get("cost_tier", "cheap"),
        }

    base_map: dict[str, list[str]] = {}
    for tech, chain_list in (data.get("base_techniques_for_variants") or {}).items():
        base_map[tech] = list(chain_list)

    # D13: combo_multipliers — 链组合协同效应乘数
    combo_data = data.get("combo_multipliers") or {}
    combo_multipliers: list[dict[str, Any]] = combo_data.get("combos", []) or []

    logger.info(
        f"Converter chains loaded from YAML: {len(chains)} chains, "
        f"{len(base_map)} base technique mappings, {len(combo_multipliers)} combo multipliers"
    )
    return chains, base_map, combo_multipliers


CONVERTER_VARIANT_CHAINS, BASE_TECHNIQUES_FOR_VARIANTS, COMBO_MULTIPLIERS = _load_chain_config()


# ============================================================
# 链构建函数
# ============================================================


def _build_stealth_evasion_chain() -> list:
    """ROT13 + Base64 + 后缀追加.

    v45.4 修复: 移除 UnicodeConfusableConverter — 导致目标模型无法理解 prompt.
    替换为 ROT13Converter — 保持 ASCII 字符集, 目标模型仍可解码.
    """
    return [
        _conv("ROT13Converter")(),
        _conv("Base64Converter")(),
        _conv("SuffixAppendConverter")(suffix="!!"),
    ]


def _build_multi_encoding_v2_chain() -> list:
    """四层编码: Base64 + ROT13 + Caesar(5) + Atbash."""
    return [
        _conv("Base64Converter")(),
        _conv("ROT13Converter")(),
        _conv("CaesarConverter")(caesar_offset=5),
        _conv("AtbashConverter")(),
    ]


def _build_encoding_bypass_chain() -> list:
    """Base64 + ROT13 + Caesar 编码绕过."""
    return [
        _conv("Base64Converter")(),
        _conv("ROT13Converter")(),
        _conv("CaesarConverter")(caesar_offset=3),
    ]


def _build_unicode_attack_chain() -> list:
    """Unicode 混淆 + 双向文本 + 零宽字符."""
    return [
        _conv("UnicodeSubstitutionConverter")(),
        _conv("BidiConverter")(),
        _conv("ZeroWidthConverter")(),
    ]


def _build_random_case_chain() -> list:
    """随机大写字符绕过关键词检测."""
    return [
        _conv("RandomCapitalLettersConverter")(),
    ]


def _build_format_injection_chain() -> list:
    """ASCII 艺术格式注入."""
    return [
        _conv("AsciiArtConverter")(),
    ]


def _build_noise_bypass_chain(converter_target: Any = None) -> list:
    """NoiseConverter 噪声注入 (LLM 辅助).

    NoiseConverter 需要 converter_target 来生成噪声变体。
    """
    if converter_target is None:
        return []
    return [
        _conv("NoiseConverter")(converter_target=converter_target),
    ]


def _build_special_chars_chain() -> list:
    """特殊字符注入 (v45.4: 移除 UnicodeConfusable, 改用 Diacritic)."""
    return [
        _conv("DiacriticConverter")(),
        _conv("StringJoinConverter")(),
    ]


def _build_persuasion_authority_chain(converter_target: Any = None) -> list:
    """权威说服 (LLM 辅助)."""
    if converter_target is None:
        return []
    return [
        _conv("PersuasionConverter")(
            converter_target=converter_target,
            persuasion_technique="authority_endorsement",
        ),
    ]


def _build_decomposition_chain(converter_target: Any = None) -> list:
    """分解重构."""
    if converter_target is None:
        return []
    return [
        _conv("DecompositionConverter")(
            converter_target=converter_target,
        ),
    ]


def _build_llm_assisted_chain(converter_target: Any = None) -> list:
    """说服 + 语气 + 翻译 (LLM 辅助)."""
    if converter_target is None:
        return []
    return [
        _conv("PersuasionConverter")(
            converter_target=converter_target,
            persuasion_technique="authority_endorsement",
        ),
        _conv("ToneConverter")(converter_target=converter_target),
        _conv("TranslationConverter")(converter_target=converter_target, languages=["en"]),
    ]


def _build_task_framing_chain(converter_target: Any = None) -> list:
    """任务框架重构."""
    if converter_target is None:
        return []
    return [
        _conv("TaskFramingConverter")(converter_target=converter_target),
    ]


# ── 补全: 非 LLM 链构建函数 ──


def _build_binary_morse_chain() -> list:
    """Binary + Morse 双层编码."""
    return [_conv("BinaryConverter")(), _conv("MorseConverter")()]


def _build_braille_nato_chain() -> list:
    """Braille + Nato 字母表替换."""
    return [_conv("BrailleConverter")(), _conv("NatoConverter")()]


def _build_leetspeak_zalgo_chain() -> list:
    """Leetspeak + Zalgo 文本变形."""
    return [_conv("LeetspeakConverter")(), _conv("ZalgoConverter")()]


def _build_emoji_superscript_chain() -> list:
    """Emoji + Superscript 字符替换."""
    return [_conv("EmojiConverter")(), _conv("SuperscriptConverter")()]


def _build_char_swap_diacritic_chain() -> list:
    """CharSwap + Diacritic 字符变形."""
    return [_conv("CharSwapConverter")(), _conv("DiacriticConverter")()]


def _build_character_space_chain() -> list:
    """CharacterSpace 字符间距混淆."""
    return [_conv("CharacterSpaceConverter")()]


def _build_punctuation_insert_chain() -> list:
    """InsertPunctuation 标点注入绕过."""
    return [_conv("InsertPunctuationConverter")()]


def _build_repeat_token_chain() -> list:
    """RepeatToken 重复令牌注入."""
    return [_conv("RepeatTokenConverter")()]


def _build_token_smuggling_chain() -> list:
    """AsciiSmuggler + SneakyBits 令牌走私."""
    return [_conv("AsciiSmugglerConverter")(), _conv("SneakyBitsSmugglerConverter")()]


def _build_url_encoding_chain() -> list:
    """Url + Base64 URL 编码绕过."""
    return [_conv("UrlConverter")(), _conv("Base64Converter")()]


def _build_base2048_ecoji_chain() -> list:
    """Base2048 + Ecoji 高基数编码."""
    return [_conv("Base2048Converter")(), _conv("EcojiConverter")()]


def _build_unicode_replacement_chain() -> list:
    """UnicodeReplacement + Tatweel Unicode 替换."""
    return [_conv("UnicodeReplacementConverter")(), _conv("TatweelConverter")()]


def _build_search_replace_chain() -> list:
    """SearchReplace 关键词替换绕过."""
    return [_conv("SearchReplaceConverter")(old_value="test", new_value="exam")]


def _build_first_letter_chain() -> list:
    """FirstLetter 首字母提取编码."""
    return [_conv("FirstLetterConverter")()]


# ── P2: 跨范式短链 (2-3 层, 学术最优组合) ──
# 学术依据:
#   - HarmBench (arXiv:2402.04249): 同范式叠加边际递减, 跨范式协同最优
#   - Russinovich et al. (arXiv:2402.12109): 编码+混淆 1.5-1.6x ASR
#   - Zeng et al. (arXiv:2402.19181): 语义层 ASR 30-40% >> 表示层 8-12%
#   - Wei et al. (arXiv:2307.15043): 编码攻击绕过表示级安全过滤


def _build_cross_paradigm_2layer_chain() -> list:
    """P2: 跨范式 2 层 — Base64 (编码) + ROT13 (混淆).

    v45.4 修复: 移除 UnicodeConfusableConverter — 导致目标模型无法理解 prompt.
    替换为 ROT13Converter — 保持 ASCII 字符集, 目标模型仍可解码.

    学术依据: encoding + rotation 组合乘数 1.6x (converter_chains.yaml)
    非 LLM 链: 本地计算, 无额外 API 调用, 极速执行.
    注意: Base64 完全编码 prompt, 目标模型无法解码, 仅适用于 many_shot
    """
    return [
        _conv("Base64Converter")(),
        _conv("ROT13Converter")(),
    ]


def _build_semantic_evasion_chain() -> list:
    """P3: 语义保持混淆链 — ROT13 + 随机大写.

    v45.4 修复: 移除 UnicodeConfusable + Leetspeak — 这两个 Converter
    将攻击 prompt 变换为 Unicode 混淆文本 (如西里尔字母替换),
    导致目标模型无法理解 prompt 内容, 直接回复"消息包含特殊字符",
    ASR 降为 0%. 对于无关键词级安全过滤的 API 目标 (如 Burp 模式)
    尤其有害.

    替换为 ROT13 + RandomCapitalLetters — 经典替换密码 + 随机大写,
    保持 ASCII 字符集, 目标模型仍可理解 prompt 语义,
    同时绕过简单的关键词级安全过滤.

    学术依据:
      - Zeng et al. (arXiv:2402.19181): 语义层 ASR 30-40% >> 表示层 8-12%
      - Wei et al. (arXiv:2307.15043): 编码攻击绕过表示级安全过滤
      - HarmBench (arXiv:2402.04249): 保持可读性的变换比完全编码更有效
    """
    return [
        _conv("ROT13Converter")(),
        _conv("RandomCapitalLettersConverter")(),
    ]


def _build_cross_paradigm_3layer_chain(converter_target: Any = None) -> list:
    """P2: 跨范式 3 层 — Base64 (编码) + ROT13 (混淆) + Persuasion (语义).

    v45.4 修复: 移除 UnicodeConfusableConverter — 导致目标模型无法理解 prompt.
    替换为 ROT13Converter — 保持 ASCII 字符集, 目标模型仍可解码.

    学术依据:
      - encoding + stealth 1.5x (arXiv:2402.12109)
      - 语义层 ASR 30-40% >> 表示层 (arXiv:2402.19181)
      - 3 层跨范式 = 理论最优平衡点

    LLM 链: 需要 converter_target, 无则降级为 2 层.
    """
    base = [
        _conv("Base64Converter")(),
        _conv("ROT13Converter")(),
    ]
    if converter_target is None:
        return base
    base.append(
        _conv("PersuasionConverter")(
            converter_target=converter_target,
            persuasion_technique="authority_endorsement",
        ),
    )
    return base


# ── P4: 多模态 Converter 链 (image/audio/video/file, PyRIT 原生 Converter) ──
# 学术依据:
#   - Shayegani et al. (arXiv:2306.13254): 多模态组合攻击, 图像嵌入绕过文本过滤
#   - FigStep (arXiv:2307.14400): 图像编码绕过 OCR 检测
#   - PyRIT 官方多模态 Converter: AddImageText, QRCode, ImageRotation, 等


def _build_image_text_embed_chain(converter_target: Any = None) -> list:
    """P4: 将攻击指令嵌入图像 (text→image_path).

    学术依据: Shayegani et al. (arXiv:2306.13254) —
      组合攻击多模态 LLM, 将文本指令嵌入图像绕过文本过滤.
    """
    if converter_target is None:
        return []
    return [_conv("AddImageTextConverter")(converter_target=converter_target)]


def _build_image_qr_encode_chain() -> list:
    """P4: QR 编码攻击 prompt (text→image_path).

    学术依据: FigStep (arXiv:2307.14400) —
      将攻击 prompt 编码为图像绕过文本检测.
    """
    return [_conv("QRCodeConverter")()]


def _build_image_rotate_ocr_chain() -> list:
    """P4: 旋转图像绕过 OCR 检测 (image_path→image_path)."""
    return [_conv("ImageRotationConverter")()]


def _build_image_overlay_hide_chain(converter_target: Any = None) -> list:
    """P4: 图像叠加隐藏攻击指令 (image_path→image_path)."""
    if converter_target is None:
        return []
    return [_conv("ImageOverlayConverter")(converter_target=converter_target)]


def _build_image_text_rotate_chain(converter_target: Any = None) -> list:
    """P4: 嵌入文本 + 旋转 2 层组合 (text→image→image).

    跨模态 2 层: 先嵌入文本到图像, 再旋转绕过 OCR.
    """
    if converter_target is None:
        return _build_image_rotate_ocr_chain()
    return [
        _conv("AddImageTextConverter")(converter_target=converter_target),
        _conv("ImageRotationConverter")(),
    ]


def _build_image_transparency_chain() -> list:
    """P4: 透明层隐藏文本 (image_path→image_path)."""
    return [_conv("TransparencyAttackConverter")()]


def _build_audio_stego_chain() -> list:
    """P4: 文本转语音 + 白噪声注入 (text→audio→audio)."""
    return [
        _conv("AzureSpeechTextToAudioConverter")(),
        _conv("AudioWhiteNoiseConverter")(),
    ]


def _build_audio_freq_chain() -> list:
    """P4: 文本转语音 + 频移混淆 (text→audio→audio)."""
    return [
        _conv("AzureSpeechTextToAudioConverter")(),
        _conv("AudioFrequencyConverter")(),
    ]


def _build_audio_echo_chain() -> list:
    """P4: 文本转语音 + 回声隐藏 (text→audio→audio)."""
    return [
        _conv("AzureSpeechTextToAudioConverter")(),
        _conv("AudioEchoConverter")(),
    ]


def _build_video_embed_chain(converter_target: Any = None) -> list:
    """P4: 文本嵌入图像再转视频 (text→image→video)."""
    if converter_target is None:
        return []
    return [
        _conv("AddImageTextConverter")(converter_target=converter_target),
        _conv("AddImageVideoConverter")(),
    ]


#: 全局变量: 存储用户传入的已有 PDF 文件路径 (通过 --pdf-file 设置)
_existing_pdf_path: Path | None = None

#: 全局变量: 存储 PDF 注入项列表
_pdf_injection_items: list[dict[str, Any]] | None = None

#: 全局变量: 存储用户传入的已有 Word 文件路径 (通过 --word-file 设置)
_existing_docx_path: Path | None = None

#: 全局变量: 存储 Word 占位符
_word_placeholder: str = "{{INJECTION_PLACEHOLDER}}"


def register_pdf_file_path(pdf_path: Path | None, injection_items: list[dict] | None = None) -> None:
    """注册用户传入的已有 PDF 文件路径和注入项.

    使 ``pdf`` 链构建时使用 ``PDFConverter(existing_pdf=..., injection_items=...)``
    而非无参数构造。

    学术依据: Greshake et al. (arXiv:2302.12173) — XPIA 间接注入需载体隐蔽,
    在已有合法 PDF 中注入隐藏文本是最隐蔽的注入方式。

    Args:
        pdf_path: 已有 PDF 文件路径 (None 则使用默认生成模式)
        injection_items: 注入项列表 [{page, x, y, text}, ...]
    """
    global _existing_pdf_path, _pdf_injection_items
    _existing_pdf_path = pdf_path
    _pdf_injection_items = injection_items
    if pdf_path:
        logger.info(f"Existing PDF registered for injection: {pdf_path}")


def register_word_file_path(docx_path: Path | None, placeholder: str = "{{INJECTION_PLACEHOLDER}}") -> None:
    """注册用户传入的已有 Word 文件路径和占位符.

    使 ``word_doc`` 链构建时使用 ``WordDocConverter(existing_docx=..., placeholder=...)``
    而非无参数构造。

    Args:
        docx_path: 已有 .docx 文件路径 (None 则使用默认生成模式)
        placeholder: 占位符字符串 (默认 {{INJECTION_PLACEHOLDER}})
    """
    global _existing_docx_path, _word_placeholder
    _existing_docx_path = docx_path
    _word_placeholder = placeholder
    if docx_path:
        logger.info(f"Existing Word doc registered for injection: {docx_path}")


def _build_file_pdf_injection_chain() -> list:
    """生成恶意 PDF 用于 XPIA/RAG (text→binary_path).

    三种模式:
    1. 已有 PDF + 注入项: 在已有 PDF 指定坐标注入隐藏文本 (最隐蔽)
    2. 已有 PDF 无注入项: 覆盖模式 (整页覆盖)
    3. 无已有 PDF: 生成全新 PDF (白色文本隐蔽)
    """
    kwargs: dict[str, Any] = {"font_color": (255, 255, 255), "font_size": 8}
    if _existing_pdf_path is not None:
        kwargs["existing_pdf"] = _existing_pdf_path
    if _pdf_injection_items is not None:
        kwargs["injection_items"] = _pdf_injection_items
    return [_conv("PDFConverter")(**kwargs)]


def _build_file_worddoc_injection_chain() -> list:
    """生成恶意 Word 文档 (text→binary_path).

    两种模式:
    1. 已有 .docx + 占位符: 在占位符位置替换为注入文本 (最隐蔽)
    2. 无已有 .docx: 生成全新 .docx
    """
    kwargs: dict[str, Any] = {}
    if _existing_docx_path is not None:
        kwargs["existing_docx"] = _existing_docx_path
        kwargs["placeholder"] = _word_placeholder
    return [_conv("WordDocConverter")(**kwargs)]


# ── 补全: LLM 链构建函数 ──


def _build_tense_variation_chain(converter_target: Any = None) -> list:
    """Tense + Variation 时态变换+变体 (LLM 辅助)."""
    if converter_target is None:
        return []
    return [
        _conv("TenseConverter")(converter_target=converter_target),
        _conv("VariationConverter")(converter_target=converter_target),
    ]


def _build_persuasion_policy_chain(converter_target: Any = None) -> list:
    """Persuasion + PolicyPuppetry 说服+策略模仿."""
    if converter_target is None:
        return []
    return [
        _conv("PersuasionConverter")(
            converter_target=converter_target,
            persuasion_technique="authority_endorsement",
        ),
        _conv("PolicyPuppetryConverter")(converter_target=converter_target),
    ]


def _build_math_obfuscation_chain(converter_target: Any = None) -> list:
    """MathObfuscation 数学表达式混淆 (LLM 辅助)."""
    if converter_target is None:
        return []
    return [_conv("MathObfuscationConverter")(converter_target=converter_target)]


def _build_scientific_translation_chain(converter_target: Any = None) -> list:
    """ScientificTranslation 科学翻译变换."""
    if converter_target is None:
        return []
    return [_conv("ScientificTranslationConverter")(converter_target=converter_target)]


# ============================================================
# P0-2: 新增 11 个 PyRIT 原生 Converter 链构建函数
# ============================================================

def _build_ansi_attack_chain() -> list:
    """ANSI 转义序列注入攻击."""
    return [_conv("AnsiAttackConverter")()]


def _build_arabizi_chain() -> list:
    """阿拉伯语拉丁转写 (Arabizi) 编码."""
    return [_conv("ArabiziConverter")()]


def _build_bidi_chain() -> list:
    """双向文本覆盖 (Bidi) 攻击."""
    return [_conv("BidiConverter")()]


def _build_code_chameleon_chain(converter_target: Any = None) -> list:
    """代码伪装 (Code Chameleon) 编码."""
    if converter_target is None:
        return []
    return [_conv("CodeChameleonConverter")(converter_target=converter_target)]


def _build_negation_trap_chain() -> list:
    """否定陷阱 (Negation Trap) 攻击."""
    return [_conv("NegationTrapConverter")()]


def _build_tone_chain(converter_target: Any = None) -> list:
    """语气变换 (Tone) 说服链."""
    if converter_target is None:
        return []
    return [_conv("ToneConverter")(converter_target=converter_target)]


def _build_variation_chain() -> list:
    """变体选择 (Variation) 混淆."""
    return [_conv("VariationConverter")()]


def _build_malicious_question_chain(converter_target: Any = None) -> list:
    """LLM 生成恶意问题."""
    if converter_target is None:
        return []
    return [_conv("MaliciousQuestionGeneratorConverter")(converter_target=converter_target)]


def _build_toxic_sentence_chain(converter_target: Any = None) -> list:
    """LLM 生成毒性句子."""
    if converter_target is None:
        return []
    return [_conv("ToxicSentenceGeneratorConverter")(converter_target=converter_target)]


def _build_image_saturation_chain() -> list:
    """图像饱和度操纵."""
    return [_conv("ImageColorSaturationConverter")()]


def _build_add_image_video_chain(converter_target: Any = None) -> list:
    """图像+视频注入链."""
    if converter_target is None:
        return []
    return [_conv("AddImageVideoConverter")(converter_target=converter_target)]


# ============================================================
# v44: P3-1 TextJailbreakConverter (XPIA HTML 模板注入)
# ============================================================


def _build_text_jailbreak_chain() -> list:
    """TextJailbreakConverter — 将注入内容包装到 HTML 模板中.

    PyRIT 原生 ``TextJailbreakConverter`` 将 jailbreak prompt 包装到
    HTML 模板中, 隐藏指令在 HTML 注释/属性/脚本中。

    用于 XPIA / RAG 注入场景 — 注入内容被嵌入到合法外观的文档中。

    学术依据: Greshake et al. (arXiv:2302.12173) — 间接注入通过外部文档投递
    """
    return [_conv("TextJailbreakConverter")()]


# v44 P1-3: GCG 后缀链构建函数 (使用动态注册的后缀)


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
    # P2: 跨范式短链
    "cross_paradigm_2layer": lambda target=None: _build_cross_paradigm_2layer_chain(),
    "cross_paradigm_3layer": lambda target=None: _build_cross_paradigm_3layer_chain(target),
    # P3: 语义保持混淆链 (保持可读性, 替代 Base64 编码)
    "semantic_evasion": lambda target=None: _build_semantic_evasion_chain(),
    # P4: 多模态链 (PyRIT 原生 Converter, 按模态选择)
    "image_text_embed": lambda target=None: _build_image_text_embed_chain(target),
    "image_qr_encode": lambda target=None: _build_image_qr_encode_chain(),
    "image_rotate_ocr": lambda target=None: _build_image_rotate_ocr_chain(),
    "image_overlay_hide": lambda target=None: _build_image_overlay_hide_chain(target),
    "image_text_rotate_chain": lambda target=None: _build_image_text_rotate_chain(target),
    "image_transparency": lambda target=None: _build_image_transparency_chain(),
    "audio_stego_chain": lambda target=None: _build_audio_stego_chain(),
    "audio_freq_chain": lambda target=None: _build_audio_freq_chain(),
    "audio_echo_chain": lambda target=None: _build_audio_echo_chain(),
    "video_embed_chain": lambda target=None: _build_video_embed_chain(target),
    "file_pdf_injection": lambda target=None: _build_file_pdf_injection_chain(),
    "file_worddoc_injection": lambda target=None: _build_file_worddoc_injection_chain(),
    # P0-2: 新增 11 个 Converter 链
    "ansi_attack": lambda target=None: _build_ansi_attack_chain(),
    "arabizi": lambda target=None: _build_arabizi_chain(),
    "bidi": lambda target=None: _build_bidi_chain(),
    "code_chameleon": lambda target=None: _build_code_chameleon_chain(target),
    "negation_trap": lambda target=None: _build_negation_trap_chain(),
    "tone": lambda target=None: _build_tone_chain(target),
    "variation": lambda target=None: _build_variation_chain(),
    "malicious_question": lambda target=None: _build_malicious_question_chain(target),
    "toxic_sentence": lambda target=None: _build_toxic_sentence_chain(target),
    "image_saturation": lambda target=None: _build_image_saturation_chain(),
    "add_image_video": lambda target=None: _build_add_image_video_chain(target),
    # v44 P3-1: TextJailbreakConverter (XPIA HTML 模板注入)
    "text_jailbreak": lambda target=None: _build_text_jailbreak_chain(),
    # v44 P1-3: gcg_suffix (动态注册, 初始为空)
    "gcg_suffix": lambda target=None: _build_gcg_suffix_chain(),
    # v44.1: 补全 48 个 Converter 链 (无 LLM 依赖的用单Converter链, LLM依赖的用空链占位)
    "ascii_smuggler": lambda target=None: [_conv("AsciiSmugglerConverter")()],
    "base2048": lambda target=None: [_conv("Base2048Converter")()],
    "bin_ascii": lambda target=None: [
        _conv("BinAsciiConverter")(
            encoding_func="binary",
            word_selection_strategy="all",
            word_split_separator=" ",
        )
    ],
    "char_swap": lambda target=None: [_conv("CharSwapConverter")()],
    "colloquial_wordswap": lambda target=None: [_conv("ColloquialWordswapConverter")()],
    "ecoji": lambda target=None: [_conv("EcojiConverter")()],
    "first_letter": lambda target=None: [_conv("FirstLetterConverter")()],
    "insert_punctuation": lambda target=None: [_conv("InsertPunctuationConverter")()],
    "qr_code": lambda target=None: [_conv("QRCodeConverter")()],
    "random_capital": lambda target=None: [_conv("RandomCapitalLettersConverter")()],
    "repeat_token": lambda target=None: [_conv("RepeatTokenConverter")()],
    "search_replace": lambda target=None: [_conv("SearchReplaceConverter")(pattern=" ", replace=" ")],
    "suffix_append": lambda target=None: [_conv("SuffixAppendConverter")(suffix="!!")],
    "tatweel": lambda target=None: [_conv("TatweelConverter")()],
    "template_segment": lambda target=None: [_conv("TemplateSegmentConverter")()],
    "unicode_confusable": lambda target=None: [_conv("UnicodeConfusableConverter")()],
    "unicode_replacement": lambda target=None: [_conv("UnicodeReplacementConverter")()],
    "variation_selector_smuggler": lambda target=None: [_conv("VariationSelectorSmugglerConverter")()],
    "transparency_attack": lambda target=None: [_conv("TransparencyAttackConverter")()],
    "image_rotation": lambda target=None: [_conv("ImageRotationConverter")()],
    "image_resizing": lambda target=None: [_conv("ImageResizingConverter")()],
    "image_compression": lambda target=None: [_conv("ImageCompressionConverter")()],
    "image_overlay": lambda target=None: [_conv("ImageOverlayConverter")()],
    "add_text_image": lambda target=None: [_conv("AddTextImageConverter")()],
    "add_image_text": lambda target=None: [_conv("AddImageTextConverter")()],
    "pdf": lambda target=None: _build_file_pdf_injection_chain(),
    "word_doc": lambda target=None: _build_file_worddoc_injection_chain(),
    "task_framing": lambda target=None: [_conv("TaskFramingConverter")()],
    "selective_text": lambda target=None: [_conv("SelectiveTextConverter")()],
    "policy_puppetry": lambda target=None: [_conv("PolicyPuppetryConverter")()],
    "math_obfuscation": lambda target=None: [_conv("MathObfuscationConverter")()],
    "ask_to_decode": lambda target=None: [_conv("AskToDecodeConverter")()],
    "sneaky_bits_smuggler": lambda target=None: [_conv("SneakyBitsSmugglerConverter")()],
    # LLM 依赖的 Converter (需要 converter_target)
    "denylist": lambda target=None: [_conv("DenylistConverter")(converter_target=target)] if target else [],
    "character_space": lambda target=None: [
        _conv("CharacterSpaceConverter")(converter_target=target)
    ] if target else [],
    "diacritic": lambda target=None: [_conv("DiacriticConverter")()],
    "noise": lambda target=None: [_conv("NoiseConverter")(converter_target=target)] if target else [],
    "image_prompt_style": lambda target=None: [
        _conv("ImagePromptStyleConverter")(converter_target=target)
    ] if target else [],
    "translation": lambda target=None: [_conv("TranslationConverter")(converter_target=target)] if target else [],
    "random_translation": lambda target=None: [
        _conv("RandomTranslationConverter")(converter_target=target)
    ] if target else [],
    "tense": lambda target=None: [_conv("TenseConverter")(converter_target=target)] if target else [],
    "persuasion": lambda target=None: [_conv("PersuasionConverter")(converter_target=target)] if target else [],
    "math_prompt": lambda target=None: [_conv("MathPromptConverter")(converter_target=target)] if target else [],
    "llm_generic_text": lambda target=None: [
        _conv("LLMGenericTextConverter")(converter_target=target)
    ] if target else [],
    "scientific_translation": lambda target=None: [
        _conv("ScientificTranslationConverter")(converter_target=target)
    ] if target else [],
    "arabic_presentation_form": lambda target=None: [
        _conv("ArabicPresentationFormConverter")(converter_target=target)
    ] if target else [],
    "json_string": lambda target=None: [_conv("JsonStringConverter")(converter_target=target)] if target else [],
}


# ============================================================
# v44: 动态链注册 (GCG 后缀)
# ============================================================


# 全局变量: 存储 GCG 动态生成的后缀
_dynamic_gcg_suffix: str | None = None


def register_dynamic_gcg_chain(suffix: str) -> None:
    """v44 P1-3: 注册 GCG 动态生成的后缀为 gcg_suffix 链.

    GCG 生成后缀后, 调用此函数将后缀注册到全局变量,
    使 ``load_preset_converter_chain("gcg_suffix")`` 能构建
    ``SuffixAppendConverter(suffix=<gcg_generated>)``.

    学术依据: Zou et al. (arXiv:2307.15043) — GCG 后缀具有迁移性,
    可用于黑盒攻击的种子生成.

    Args:
        suffix: GCG 生成的对抗后缀字符串
    """
    global _dynamic_gcg_suffix
    _dynamic_gcg_suffix = suffix
    logger.info(f"Dynamic GCG suffix registered (length={len(suffix)})")


def _build_gcg_suffix_chain() -> list:
    """构建 GCG 后缀附加链 (使用动态注册的后缀)."""
    if _dynamic_gcg_suffix is None:
        return []
    return [_conv("SuffixAppendConverter")(suffix=_dynamic_gcg_suffix)]


def load_preset_converter_chain(
    chain_name: str,
    converter_target: Any = None,
) -> Any:
    """从预设链名构建 ConverterConfiguration.

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

    return _get_converter_configuration()(converters=converters)


# ============================================================
# 辅助函数
# ============================================================


# ============================================================
# D13: 链组合协同评分
# ============================================================


def score_chain_combo(chain_names: list[str]) -> float:
    """D13: 计算链组合的协同效应分数.

    基于 ``converter_chains.yaml`` 的 ``combo_multipliers`` 段,
    检查链列表中是否存在已知的高效组合.

    PyRIT 原生优先: 本函数仅用于选择层 (Stage 2),
    不修改 PyRIT 原生 ``extra_request_converters`` API.

    学术依据: Russinovich et al. (arXiv:2402.12109) —
      Crescendo + encoding = 3-5x ASR

    Args:
        chain_names: 链名列表

    Returns:
        协同效应分数 (1.0 = 无协同, >1.0 = 有协同加成)
    """
    if not chain_names or not COMBO_MULTIPLIERS:
        return 1.0

    chain_set = set(chain_names)
    best_multiplier = 1.0

    for combo in COMBO_MULTIPLIERS:
        combo_chains = set(combo.get("chains", []))
        if combo_chains.issubset(chain_set):
            multiplier = float(combo.get("multiplier", 1.0))
            if multiplier > best_multiplier:
                best_multiplier = multiplier

    return best_multiplier


#: D14: cost_tier → 预算权重映射
_COST_TIER_WEIGHT: dict[str, float] = {
    "cheap": 1.0,  # 非 LLM 链: 快速, 无 API 调用
    "moderate": 0.7,  # 混合链
    "expensive": 0.4,  # LLM 链: 慢, 每次 API 调用 2-5s
}


def get_chain_cost_weight(chain_name: str) -> float:
    """D14: 获取链的成本权重 (用于预算感知分配).

    非 LLM 链 (cheap) 权重高 (优先选择),
    LLM 链 (expensive) 权重低 (预算有限时减少).

    PyRIT 原生优先: 本函数仅用于选择层,
    PyRIT 原生 ``max_attempts_per_objective`` 不变.

    Args:
        chain_name: 链名

    Returns:
        成本权重 (0.0-1.0, 越高越优先)
    """
    chain_info = CONVERTER_VARIANT_CHAINS.get(chain_name, {})
    cost_tier = chain_info.get("cost_tier", "cheap")
    return _COST_TIER_WEIGHT.get(cost_tier, 1.0)


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


#: P0: Converter 链深度上限 — 防止同范式叠加导致 prompt 膨胀和 API 超时.
#:
#: 学术依据:
#:   - HarmBench (arXiv:2402.04249): 3+ 层同类型编码不提升 ASR, 边际递减
#:   - Russinovich et al. (arXiv:2402.12109): 跨范式 2-3 层协同 3-5x ASR
#:   - Zeng et al. (arXiv:2402.19181): 语义层 ASR 30-40% >> 表示层 8-12%
#:
#: 超过此值的 Converter 会被截断, 保留按链顺序排列的前 N 个.
#: 3 层 = 1 编码 + 1 混淆 + 1 语义 (跨范式最优).
MAX_CONVERTER_CHAIN_DEPTH: int = 3


def build_converters_from_chain_names(
    chain_names: list[str],
    converter_target: Any = None,
    *,
    max_depth: int | None = None,
) -> list:
    """从多个链名构建扁平化的 Converter 实例列表。.

    将多个预设 Converter 链的构建结果合并为一个扁平列表,
    供原生 ``technique_converters`` 参数使用。

    - 非 LLM 链直接构建
    - LLM 链需要 converter_target, 若为 None 则跳过该链
    - 自动去重 (同名 Converter 类只保留第一个实例)
    - P0: 链深度截断 — 最多保留 ``max_depth`` 个 Converter, 防止
      同范式叠加导致 prompt 膨胀和 API 超时

    Args:
        chain_names: 链名列表 (如 ["stealth_evasion", "encoding_bypass"])
        converter_target: LLM 链所需的 Converter Target
        max_depth: Converter 链深度上限, None 则使用模块级
            ``MAX_CONVERTER_CHAIN_DEPTH`` (默认 3).

    Returns:
        合并后的 Converter 实例列表 (可能为空)
    """
    effective_max = max_depth if max_depth is not None else MAX_CONVERTER_CHAIN_DEPTH

    result: list = []
    seen_types: set[str] = set()

    for chain_name in chain_names:
        # P0: 已达深度上限, 提前终止
        if len(result) >= effective_max:
            break

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
                # P0: 达到深度上限即停止
                if len(result) >= effective_max:
                    break

    if len(result) > effective_max:
        logger.info(
            f"Converter chain truncated: {len(result)} → {effective_max} "
            f"(max depth limit, academic: HarmBench arXiv:2402.04249)"
        )
        result = result[:effective_max]

    return result


# ============================================================
# 模态感知链路由 (v44.2)
# ============================================================

#: 模态兼容性映射 — 定义哪些模态的链可以在哪种目标模态下使用
#:
#: 策略依据:
#:   - text 目标: 仅接受 text 模态链 (纯文本编码/混淆/语义)
#:   - image 目标: 接受 text + image + multimodal 链
#:   - multimodal 目标: 接受所有模态链 (text + image + audio + video + file + multimodal)
#:   - audio 目标: 接受 text + audio 链
#:   - video 目标: 接受 text + video + multimodal 链
#:   - file 目标: 接受 text + file 链
#:
#: 学术依据: Owens et al. (arXiv:2302.07087) — 跨模态攻击在多模态模型上
#: 具有更高的迁移性, 但需要目标模型支持对应模态输入
_MODALITY_COMPAT: dict[str, frozenset[str]] = {
    "text": frozenset({"text"}),
    "image": frozenset({"text", "image", "multimodal"}),
    "audio": frozenset({"text", "audio"}),
    "video": frozenset({"text", "video", "multimodal"}),
    "file": frozenset({"text", "file"}),
    "multimodal": frozenset({"text", "image", "audio", "video", "file", "multimodal"}),
}


def get_chain_modality(chain_name: str) -> str:
    """返回指定链的模态类型。

    Args:
        chain_name: 链名 (如 "stealth_evasion", "image_text_embed")

    Returns:
        str: 模态类型 — "text" | "image" | "audio" | "video" | "file" | "multimodal"。
        如果链未找到则返回 "text" (安全默认值)。
    """
    chain_info = CONVERTER_VARIANT_CHAINS.get(chain_name, {})
    return chain_info.get("modality", "text")


def get_chains_by_modality(modality: str) -> list[str]:
    """返回指定模态的所有链名列表。

    Args:
        modality: 模态类型 — "text" | "image" | "audio" | "video" | "file" | "multimodal"

    Returns:
        list[str]: 该模态下所有已注册的链名
    """
    return [
        name
        for name, info in CONVERTER_VARIANT_CHAINS.items()
        if info.get("modality", "text") == modality
    ]


def filter_chains_by_target_modality(
    chain_names: list[str],
    target_modality: str,
) -> list[str]:
    """根据目标模态过滤链列表，跳过不兼容的链。

    Args:
        chain_names: 用户指定的链名列表
        target_modality: 目标模型的模态类型

    Returns:
        list[str]: 过滤后与目标模态兼容的链名列表
    """
    accepted = _MODALITY_COMPAT.get(target_modality, frozenset({"text"}))
    filtered: list[str] = []
    for name in chain_names:
        chain_mod = get_chain_modality(name)
        if chain_mod in accepted:
            filtered.append(name)
        else:
            logger.info(
                f"Skipping chain '{name}' (modality={chain_mod}) "
                f"— incompatible with target modality '{target_modality}'"
            )
    return filtered


def auto_select_chains_by_modality(
    target_modality: str,
    *,
    converter_target_available: bool = False,
) -> list[str]:
    """根据目标模态自动选择所有兼容的链名。

    Args:
        target_modality: 目标模型的模态类型
        converter_target_available: 是否有 LLM converter_target 可用。
            若为 False，则跳过 requires_llm=True 的链。

    Returns:
        list[str]: 所有与目标模态兼容且可构建的链名列表
    """
    accepted = _MODALITY_COMPAT.get(target_modality, frozenset({"text"}))
    result: list[str] = []
    for name, info in CONVERTER_VARIANT_CHAINS.items():
        chain_mod = info.get("modality", "text")
        if chain_mod not in accepted:
            continue
        if info.get("requires_llm", False) and not converter_target_available:
            continue
        result.append(name)
    return result
