"""
Converters Module
=================

本模块负责 Converter 链的配置和注册（遵循开发规则 1.4.1）。

Converter 用于对提示词进行编码、混淆、转换等操作，以绕过 AI 安全检测。
Converter 链可以组合多个 Converter，形成复杂的转换序列。

PyRIT 1.0.0 对齐说明（L5 专家级）：
  - pyrit.prompt_converter → pyrit.converter（模块重命名）
  - PromptConverterConfiguration → ConverterConfiguration（类重命名）
  - 新增 1.0.0 Converter：NoiseConverter / DecompositionConverter /
    PolicyPuppetryConverter / RandomCapitalLettersConverter / TaskFramingConverter
  - 补全多模态 Converter：Image / Audio / Video 全系列
  - 接入 Selective Converting 子系统：TextSelectionStrategy 全层级 + WordLevelConverter
  - 对齐 @apply_defaults 全局默认值注入机制
  - 模态感知链路验证：基于 SUPPORTED_INPUT_TYPES / SUPPORTED_OUTPUT_TYPES
  - 导出 PolicyPuppetryTemplate 枚举
  - ConverterConfiguration 高级字段：indexes_to_apply / prompt_data_types_to_apply
"""

import inspect
import logging
from typing import Any, Dict, List, Optional, Tuple

from pyrit.converter import (
    # 编码类 Converter (text → text)
    Base64Converter,
    ROT13Converter,
    CaesarConverter,
    AtbashConverter,
    BinaryConverter,
    MorseConverter,
    NatoConverter,
    BrailleConverter,
    Base2048Converter,
    EcojiConverter,
    BinAsciiConverter,
    # Unicode 类 Converter (text → text)
    UnicodeConfusableConverter,
    UnicodeReplacementConverter,
    UnicodeSubstitutionConverter,
    BidiConverter,
    ZeroWidthConverter,
    VariationSelectorSmugglerConverter,
    SneakyBitsSmugglerConverter,
    AsciiSmugglerConverter,
    ArabicPresentationFormConverter,
    ArabiziConverter,
    DiacriticConverter,
    TatweelConverter,
    SuperscriptConverter,
    CharacterSpaceConverter,
    CharSwapConverter,
    # 语义类 Converter (text → text)
    TranslationConverter,
    ScientificTranslationConverter,
    RandomTranslationConverter,
    ToneConverter,
    TenseConverter,
    VariationConverter,
    ColloquialWordswapConverter,
    LeetspeakConverter,
    EmojiConverter,
    FirstLetterConverter,
    NegationTrapConverter,
    InsertPunctuationConverter,
    StringJoinConverter,
    SearchReplaceConverter,
    MathObfuscationConverter,
    MathPromptConverter,
    # 格式/文件类 Converter (text → text / binary_path / image_path)
    AsciiArtConverter,
    QRCodeConverter,
    PDFConverter,
    WordDocConverter,
    JsonStringConverter,
    TemplateSegmentConverter,
    UrlConverter,
    DenylistConverter,
    # Selective Converting 子系统
    SelectiveTextConverter,
    TextSelectionStrategy,
    TokenSelectionStrategy,
    WordSelectionStrategy,
    AllWordsSelectionStrategy,
    IndexSelectionStrategy,
    RegexSelectionStrategy,
    KeywordSelectionStrategy,
    PositionSelectionStrategy,
    ProportionSelectionStrategy,
    RangeSelectionStrategy,
    WordIndexSelectionStrategy,
    WordKeywordSelectionStrategy,
    WordProportionSelectionStrategy,
    WordRegexSelectionStrategy,
    WordPositionSelectionStrategy,
    # LLM 辅助类 Converter (text → text, 需要 converter_target)
    PersuasionConverter,
    LLMGenericTextConverter,
    MaliciousQuestionGeneratorConverter,
    ToxicSentenceGeneratorConverter,
    TextJailbreakConverter,
    AskToDecodeConverter,
    CodeChameleonConverter,
    # 特殊类 Converter (text → text)
    AnsiAttackConverter,
    FlipConverter,
    RepeatTokenConverter,
    SuffixAppendConverter,
    ZalgoConverter,
    TransparencyAttackConverter,
    # PyRIT 1.0.0 新增 Converter
    NoiseConverter,
    DecompositionConverter,
    PolicyPuppetryConverter,
    PolicyPuppetryTemplate,
    RandomCapitalLettersConverter,
    TaskFramingConverter,
    # 多模态 Converter — Image (text → image_path / image_path → image_path)
    AddImageTextConverter,
    AddTextImageConverter,
    ImageOverlayConverter,
    ImageColorSaturationConverter,
    ImageCompressionConverter,
    ImageResizingConverter,
    ImageRotationConverter,
    ImagePromptStyleConverter,
    # 多模态 Converter — Audio (text → audio_path / audio_path → text / audio_path → audio_path)
    AzureSpeechTextToAudioConverter,
    AzureSpeechAudioToTextConverter,
    AudioEchoConverter,
    AudioFrequencyConverter,
    AudioSpeedConverter,
    AudioVolumeConverter,
    AudioWhiteNoiseConverter,
    # 多模态 Converter — Video (image_path → video_path)
    AddImageVideoConverter,
    # 工具函数
    get_converter_modalities,
)
from pyrit.converter.converter import Converter, ConverterResult

from pyrit.prompt_normalizer import ConverterConfiguration

from pyrit.executor.attack import AttackConverterConfig

from src.core.config_loader import get_config_loader

logger = logging.getLogger(__name__)


# ============================================================
# 模态分类常量
# ============================================================

# 按 PyRIT 1.0.0 模态转换矩阵分组的 Converter 名称集合
# 用于模态感知过滤和链路验证

TEXT_TO_TEXT_CONVERTERS: frozenset[str] = frozenset({
    # 编码类
    "base64", "rot13", "caesar", "atbash", "binary", "morse", "nato",
    "braille", "base2048", "ecoji", "bin_ascii",
    # Unicode 类
    "unicode_confusable", "unicode_replacement", "unicode_substitution",
    "bidi", "zero_width", "variation_selector_smuggler", "sneaky_bits_smuggler",
    "ascii_smuggler", "arabic_presentation_form", "arabizi", "diacritic",
    "tatweel", "superscript", "character_space", "char_swap",
    # 语义类
    "translation", "scientific_translation", "random_translation",
    "tone", "tense", "variation", "colloquial_wordswap", "leetspeak",
    "emoji", "first_letter", "negation_trap", "insert_punctuation",
    "string_join", "search_replace", "math_obfuscation", "math_prompt",
    # 格式类 (text → text)
    "ascii_art", "json_string", "template_segment", "url",
    "denylist", "selective_text",
    # LLM 辅助类
    "persuasion", "llm_generic_text", "malicious_question_generator",
    "toxic_sentence_generator", "text_jailbreak", "ask_to_decode", "code_chameleon",
    # 特殊类
    "ansi_attack", "flip", "repeat_token", "suffix_append", "zalgo",
    "transparency_attack",
    # PyRIT 1.0.0 新增
    "noise", "decomposition", "policy_puppetry",
    "random_capital_letters", "task_framing",
})

TEXT_TO_FILE_CONVERTERS: frozenset[str] = frozenset({
    # text → binary_path
    "pdf", "word_doc",
    # text → image_path
    "qr_code", "add_image_text",
})

IMAGE_CONVERTERS: frozenset[str] = frozenset({
    # text → image_path
    "add_image_text", "image_prompt_style",
    # image_path → image_path
    "add_text_image", "image_overlay", "image_color_saturation",
    "image_compression", "image_resizing", "image_rotation",
})

AUDIO_CONVERTERS: frozenset[str] = frozenset({
    # text → audio_path
    "azure_speech_text_to_audio",
    # audio_path → text
    "azure_speech_audio_to_text",
    # audio_path → audio_path
    "audio_echo", "audio_frequency", "audio_speed",
    "audio_volume", "audio_white_noise",
})

VIDEO_CONVERTERS: frozenset[str] = frozenset({
    # image_path → video_path
    "add_image_video",
})

MULTIMODAL_CONVERTERS: frozenset[str] = (
    IMAGE_CONVERTERS | AUDIO_CONVERTERS | VIDEO_CONVERTERS
)


# ============================================================
# Converter 类名到 Converter 类的映射
# ============================================================

def _build_converter_map() -> Dict[str, Any]:
    """构建 Converter 映射表，同时支持 snake_case 和类名两种风格"""

    raw = {
        # === 编码类 (text → text) ===
        "base64": Base64Converter,
        "rot13": ROT13Converter,
        "caesar": CaesarConverter,
        "atbash": AtbashConverter,
        "binary": BinaryConverter,
        "morse": MorseConverter,
        "nato": NatoConverter,
        "braille": BrailleConverter,
        "base2048": Base2048Converter,
        "ecoji": EcojiConverter,
        "bin_ascii": BinAsciiConverter,
        # === Unicode 类 (text → text) ===
        "unicode_confusable": UnicodeConfusableConverter,
        "unicode_replacement": UnicodeReplacementConverter,
        "unicode_substitution": UnicodeSubstitutionConverter,
        "bidi": BidiConverter,
        "zero_width": ZeroWidthConverter,
        "variation_selector_smuggler": VariationSelectorSmugglerConverter,
        "sneaky_bits_smuggler": SneakyBitsSmugglerConverter,
        "ascii_smuggler": AsciiSmugglerConverter,
        "arabic_presentation_form": ArabicPresentationFormConverter,
        "arabizi": ArabiziConverter,
        "diacritic": DiacriticConverter,
        "tatweel": TatweelConverter,
        "superscript": SuperscriptConverter,
        "character_space": CharacterSpaceConverter,
        "char_swap": CharSwapConverter,
        # === 语义类 (text → text) ===
        "translation": TranslationConverter,
        "scientific_translation": ScientificTranslationConverter,
        "random_translation": RandomTranslationConverter,
        "tone": ToneConverter,
        "tense": TenseConverter,
        "variation": VariationConverter,
        "colloquial_wordswap": ColloquialWordswapConverter,
        "leetspeak": LeetspeakConverter,
        "emoji": EmojiConverter,
        "first_letter": FirstLetterConverter,
        "negation_trap": NegationTrapConverter,
        "insert_punctuation": InsertPunctuationConverter,
        "string_join": StringJoinConverter,
        "search_replace": SearchReplaceConverter,
        "math_obfuscation": MathObfuscationConverter,
        "math_prompt": MathPromptConverter,
        # === 格式/文件类 ===
        "ascii_art": AsciiArtConverter,           # text → text
        "qr_code": QRCodeConverter,               # text → image_path
        "pdf": PDFConverter,                      # text → binary_path
        "word_doc": WordDocConverter,             # text → binary_path
        "json_string": JsonStringConverter,       # text → text
        "template_segment": TemplateSegmentConverter,  # text → text
        "url": UrlConverter,                      # text → text
        "denylist": DenylistConverter,             # text → text (LLM 辅助)
        "selective_text": SelectiveTextConverter,  # text → text (组合包装器)
        # === LLM 辅助类 (text → text, 需要 converter_target) ===
        "persuasion": PersuasionConverter,
        "llm_generic_text": LLMGenericTextConverter,
        "malicious_question_generator": MaliciousQuestionGeneratorConverter,
        "toxic_sentence_generator": ToxicSentenceGeneratorConverter,
        "text_jailbreak": TextJailbreakConverter,
        "ask_to_decode": AskToDecodeConverter,
        "code_chameleon": CodeChameleonConverter,
        # === 特殊类 (text → text) ===
        "ansi_attack": AnsiAttackConverter,
        "flip": FlipConverter,
        "repeat_token": RepeatTokenConverter,
        "suffix_append": SuffixAppendConverter,
        "zalgo": ZalgoConverter,
        "transparency_attack": TransparencyAttackConverter,
        # === PyRIT 1.0.0 新增 (text → text) ===
        "noise": NoiseConverter,                   # LLM 辅助
        "decomposition": DecompositionConverter,   # LLM 辅助
        "policy_puppetry": PolicyPuppetryConverter,
        "random_capital_letters": RandomCapitalLettersConverter,
        "task_framing": TaskFramingConverter,
        # === 多模态 Converter — Image ===
        # text → image_path
        "add_image_text": AddImageTextConverter,
        "image_prompt_style": ImagePromptStyleConverter,
        # image_path → image_path
        "add_text_image": AddTextImageConverter,
        "image_overlay": ImageOverlayConverter,
        "image_color_saturation": ImageColorSaturationConverter,
        "image_compression": ImageCompressionConverter,
        "image_resizing": ImageResizingConverter,
        "image_rotation": ImageRotationConverter,
        # === 多模态 Converter — Audio ===
        # text → audio_path
        "azure_speech_text_to_audio": AzureSpeechTextToAudioConverter,
        # audio_path → text
        "azure_speech_audio_to_text": AzureSpeechAudioToTextConverter,
        # audio_path → audio_path
        "audio_echo": AudioEchoConverter,
        "audio_frequency": AudioFrequencyConverter,
        "audio_speed": AudioSpeedConverter,
        "audio_volume": AudioVolumeConverter,
        "audio_white_noise": AudioWhiteNoiseConverter,
        # === 多模态 Converter — Video ===
        # image_path → video_path
        "add_image_video": AddImageVideoConverter,
    }

    # 自动添加类名别名（如 "Base64Converter" → Base64Converter）
    result = dict(raw)
    for cls in raw.values():
        result[cls.__name__] = cls

    return result


CONVERTER_CLASS_MAP: Dict[str, Any] = _build_converter_map()


# ============================================================
# 模态感知工具
# ============================================================

def get_all_converter_modalities() -> List[Tuple[str, List[str], List[str]]]:
    """
    获取所有 Converter 的模态转换矩阵

    封装 PyRIT 的 get_converter_modalities()，同时包含项目映射表中的 Converter。

    Returns:
        list[tuple[str, list[str], list[str]]]: (类名, 支持的输入模态, 支持的输出模态)
    """
    return get_converter_modalities()


def get_converter_supported_types(converter_name: str) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    """
    获取指定 Converter 的支持输入/输出模态

    Args:
        converter_name: Converter 名称

    Returns:
        tuple: (supported_input_types, supported_output_types)

    Raises:
        ValueError: 如果 Converter 名称不存在
    """
    converter_class = CONVERTER_CLASS_MAP.get(converter_name)
    if converter_class is None:
        raise ValueError(f"未知的 Converter 名称: {converter_name}")

    input_types = tuple(converter_class.SUPPORTED_INPUT_TYPES)
    output_types = tuple(converter_class.SUPPORTED_OUTPUT_TYPES)
    return (input_types, output_types)


def validate_converter_chain_modality(converter_names: List[str]) -> List[str]:
    """
    验证 Converter 链的模态兼容性

    检查链中每个 Converter 的输出模态是否与下一个 Converter 的输入模态匹配。
    链中第一个 Converter 的输入默认为 "text"（攻击 prompt 的标准模态）。

    Args:
        converter_names: Converter 名称列表，按执行顺序排列

    Returns:
        list[str]: 警告消息列表（空列表表示无模态冲突）

    Raises:
        ValueError: 如果链中存在未知的 Converter 名称
    """
    if not converter_names:
        return []

    warnings = []
    current_output_type = "text"  # 链的输入默认为 text

    for i, name in enumerate(converter_names):
        converter_class = CONVERTER_CLASS_MAP.get(name)
        if converter_class is None:
            raise ValueError(f"未知的 Converter 名称: {name}")

        input_types = tuple(converter_class.SUPPORTED_INPUT_TYPES)
        output_types = tuple(converter_class.SUPPORTED_OUTPUT_TYPES)

        # 检查当前 Converter 是否接受前一个的输出
        if current_output_type not in input_types:
            warnings.append(
                f"模态不匹配: Converter '{name}' (位置 {i}) 的输入类型 {input_types} "
                f"不接受前驱输出类型 '{current_output_type}'"
            )

        # 链路中后续 Converter 接收的输入类型为当前 Converter 的第一个输出类型
        if output_types:
            current_output_type = output_types[0]

    return warnings


def filter_converters_by_input_type(
    converters: Optional[Dict[str, Any]] = None,
    input_type: str = "text",
) -> Dict[str, Any]:
    """
    按输入模态过滤 Converter

    Args:
        converters: 待过滤的 Converter 映射表（None 表示使用 CONVERTER_CLASS_MAP）
        input_type: 目标输入模态

    Returns:
        dict: 过滤后的 Converter 映射表
    """
    source = converters if converters is not None else CONVERTER_CLASS_MAP
    return {
        name: cls for name, cls in source.items()
        if input_type in tuple(cls.SUPPORTED_INPUT_TYPES)
    }


# ============================================================
# @apply_defaults 对齐：反射检测 converter_target 需求
# ============================================================

# 缓存：Converter 类名 → 是否需要 converter_target 参数
_target_requirement_cache: Dict[str, bool] = {}


def _requires_converter_target(converter_class: type) -> bool:
    """
    通过反射检测 Converter 类的构造函数是否接受 converter_target 参数

    对齐 PyRIT 1.0.0 的 @apply_defaults 机制：
    - 使用 inspect.signature 反射获取构造函数参数
    - 检测参数名是否包含 "converter_target"
    - 结果缓存以避免重复反射开销

    Args:
        converter_class: Converter 类

    Returns:
        bool: 如果构造函数接受 converter_target 参数则返回 True
    """
    cls_name = converter_class.__name__
    if cls_name in _target_requirement_cache:
        return _target_requirement_cache[cls_name]

    try:
        sig = inspect.signature(converter_class.__init__)
        requires = "converter_target" in sig.parameters
    except (ValueError, TypeError):
        requires = False

    _target_requirement_cache[cls_name] = requires
    return requires


def _query_global_default_target() -> Any:
    """
    查询 PyRIT 全局默认值注册表中是否注册了 converter_target

    对齐 PyRIT 1.0.0 的 GlobalDefaultValues 机制：
    - 如果用户通过 PyRIT 初始化注册了默认 converter_target，
      则此处自动获取
    - 如果未注册，返回 None

    Returns:
        全局注册的 converter_target 实例，或 None
    """
    try:
        from pyrit.common.apply_defaults import get_global_default_values
        from pyrit.converter.converter import Converter

        registry = get_global_default_values()
        found, value = registry.get_default_value(
            class_type=Converter,
            parameter_name="converter_target",
        )
        return value if found else None
    except Exception:
        return None


def get_converters_requiring_target() -> List[str]:
    """
    获取所有需要 converter_target 参数的 Converter 名称列表

    使用反射自动检测，无需手动维护列表。

    Returns:
        list[str]: 需要 converter_target 的 Converter 名称列表
    """
    result = []
    seen_classes = set()
    for name, cls in CONVERTER_CLASS_MAP.items():
        # 只检查每个类一次（跳过类名别名）
        if cls in seen_classes:
            continue
        seen_classes.add(cls)
        if _requires_converter_target(cls):
            result.append(name)
    return result


# ============================================================
# Converter 链构建器
# ============================================================


def create_converter_instance(
    converter_name: str,
    converter_target: Any = None,
    **kwargs: Any,
) -> Any:
    """
    创建 Converter 实例

    PyRIT 1.0.0 对齐：
    - 使用反射自动检测构造函数是否需要 converter_target
    - 支持 @apply_defaults 全局默认值注入：
      如果 converter_target 未显式提供，尝试从全局注册表获取
    - LLM 辅助 Converter（NoiseConverter / DecompositionConverter /
      PersuasionConverter / TranslationConverter 等）会自动注入 converter_target

    Args:
        converter_name: Converter 名称（来自 CONVERTER_CLASS_MAP 的键）
        converter_target: LLM 辅助转换用的 PromptTarget（可选）
        **kwargs: Converter 构造参数

    Returns:
        Converter 实例

    Raises:
        ValueError: 如果 Converter 名称不存在
    """
    converter_class = CONVERTER_CLASS_MAP.get(converter_name)
    if converter_class is None:
        raise ValueError(f"未知的 Converter 名称: {converter_name}")

    # 反射检测是否需要 converter_target
    if _requires_converter_target(converter_class):
        # 优先使用显式传入的 converter_target
        if converter_target is not None:
            kwargs["converter_target"] = converter_target
        elif "converter_target" not in kwargs:
            # 尝试从 PyRIT 全局默认值注册表获取
            global_target = _query_global_default_target()
            if global_target is not None:
                kwargs["converter_target"] = global_target
            # 如果全局也没有，让 PyRIT 的 @apply_defaults 处理（会抛出明确错误）

    return converter_class(**kwargs)


def create_converter_chain_config(
    converter_names: List[str],
    converter_params: Optional[Dict[str, Dict[str, Any]]] = None,
    converter_target: Any = None,
    indexes_to_apply: Optional[List[int]] = None,
    prompt_data_types_to_apply: Optional[List[str]] = None,
    validate_modality: bool = True,
) -> ConverterConfiguration:
    """
    创建 Converter 链配置

    PyRIT 1.0.0: PromptConverterConfiguration → ConverterConfiguration

    新增功能：
    - 模态感知链路验证（validate_modality=True 时自动检查模态兼容性）
    - ConverterConfiguration 高级字段支持（indexes_to_apply / prompt_data_types_to_apply）

    Args:
        converter_names: Converter 名称列表，按执行顺序排列
        converter_params: Converter 参数字典，key 为 Converter 名称，value 为参数字典
        converter_target: LLM 辅助转换用的 PromptTarget（可选，用于 NoiseConverter 等）
        indexes_to_apply: 指定应用到哪些响应片段的索引（None 表示全部）
        prompt_data_types_to_apply: 按数据类型过滤（None 表示全部）
        validate_modality: 是否执行模态兼容性验证

    Returns:
        ConverterConfiguration 实例

    Raises:
        ValueError: 如果 Converter 名称不存在
        ValueError: 如果模态验证发现不可恢复的冲突
    """
    converter_params = converter_params or {}

    # 模态感知链路验证
    if validate_modality and converter_names:
        warnings = validate_converter_chain_modality(converter_names)
        for w in warnings:
            logger.warning(f"Converter 链模态验证: {w}")

    converters = []
    for converter_name in converter_names:
        params = converter_params.get(converter_name, {})
        converter_instance = create_converter_instance(
            converter_name, converter_target=converter_target, **params
        )
        converters.append(converter_instance)

    return ConverterConfiguration(
        converters=converters,
        indexes_to_apply=indexes_to_apply,
        prompt_data_types_to_apply=prompt_data_types_to_apply,
    )


def create_attack_converter_config(
    converter_names: List[str],
    converter_params: Optional[Dict[str, Dict[str, Any]]] = None,
    apply_to_request: bool = True,
    apply_to_response: bool = False,
    converter_target: Any = None,
    indexes_to_apply: Optional[List[int]] = None,
    prompt_data_types_to_apply: Optional[List[str]] = None,
) -> AttackConverterConfig:
    """
    创建 AttackConverterConfig

    Args:
        converter_names: Converter 名称列表，按执行顺序排列
        converter_params: Converter 参数字典，key 为 Converter 名称，value 为参数字典
        apply_to_request: 是否应用到请求
        apply_to_response: 是否应用到响应
        converter_target: LLM 辅助转换用的 PromptTarget（可选）
        indexes_to_apply: 指定应用到哪些响应片段的索引（None 表示全部）
        prompt_data_types_to_apply: 按数据类型过滤（None 表示全部）

    Returns:
        AttackConverterConfig 实例
    """
    if apply_to_request and apply_to_response:
        # 如果都应用，需要创建两个独立的 chain
        converter_chain_req = create_converter_chain_config(
            converter_names, converter_params, converter_target=converter_target,
            indexes_to_apply=indexes_to_apply,
            prompt_data_types_to_apply=prompt_data_types_to_apply,
            validate_modality=True,
        )
        converter_chain_resp = create_converter_chain_config(
            converter_names, converter_params, converter_target=converter_target,
            indexes_to_apply=indexes_to_apply,
            prompt_data_types_to_apply=prompt_data_types_to_apply,
            validate_modality=True,
        )
        return AttackConverterConfig(
            request_converters=[converter_chain_req],
            response_converters=[converter_chain_resp],
        )
    elif apply_to_request:
        converter_chain = create_converter_chain_config(
            converter_names, converter_params, converter_target=converter_target,
            indexes_to_apply=indexes_to_apply,
            prompt_data_types_to_apply=prompt_data_types_to_apply,
            validate_modality=True,
        )
        return AttackConverterConfig(request_converters=[converter_chain])
    else:
        converter_chain = create_converter_chain_config(
            converter_names, converter_params, converter_target=converter_target,
            indexes_to_apply=indexes_to_apply,
            prompt_data_types_to_apply=prompt_data_types_to_apply,
            validate_modality=True,
        )
        return AttackConverterConfig(response_converters=[converter_chain])


# ============================================================
# Selective Converting 辅助
# ============================================================

# 选择策略名称到类的映射
SELECTION_STRATEGY_MAP: Dict[str, Any] = {
    # 字符级策略
    "index": IndexSelectionStrategy,
    "regex": RegexSelectionStrategy,
    "keyword": KeywordSelectionStrategy,
    "position": PositionSelectionStrategy,
    "proportion": ProportionSelectionStrategy,
    "range": RangeSelectionStrategy,
    # 词级策略
    "all_words": AllWordsSelectionStrategy,
    "word_index": WordIndexSelectionStrategy,
    "word_keyword": WordKeywordSelectionStrategy,
    "word_proportion": WordProportionSelectionStrategy,
    "word_regex": WordRegexSelectionStrategy,
    "word_position": WordPositionSelectionStrategy,
    # Token 策略
    "token": TokenSelectionStrategy,
}


def create_selection_strategy(
    strategy_name: str,
    **kwargs: Any,
) -> TextSelectionStrategy:
    """
    创建文本选择策略实例

    用于 SelectiveTextConverter 的 selection_strategy 参数。

    Args:
        strategy_name: 策略名称（见 SELECTION_STRATEGY_MAP 的键）
        **kwargs: 策略构造参数

    Returns:
        TextSelectionStrategy 实例

    Raises:
        ValueError: 如果策略名称不存在
    """
    strategy_class = SELECTION_STRATEGY_MAP.get(strategy_name)
    if strategy_class is None:
        raise ValueError(
            f"未知的文本选择策略: {strategy_name}。"
            f"可用策略: {', '.join(sorted(SELECTION_STRATEGY_MAP.keys()))}"
        )
    return strategy_class(**kwargs)


def create_selective_text_converter(
    sub_converter_name: str,
    selection_strategy_name: str = "all_words",
    preserve_tokens: bool = False,
    start_token: str = "⟪",
    end_token: str = "⟫",
    word_separator: str = " ",
    sub_converter_params: Optional[Dict[str, Any]] = None,
    selection_strategy_params: Optional[Dict[str, Any]] = None,
    converter_target: Any = None,
) -> SelectiveTextConverter:
    """
    创建 SelectiveTextConverter 实例（组合包装器）

    SelectiveTextConverter 将另一个 Converter 应用到文本的选定部分，
    支持 preserve_tokens 链式选择转换。

    Args:
        sub_converter_name: 被包装的 Converter 名称
        selection_strategy_name: 选择策略名称
        preserve_tokens: 是否用 ⟪⟫ 标记包裹转换结果（用于链式选择转换）
        start_token: 起始标记
        end_token: 结束标记
        word_separator: 词分隔符
        sub_converter_params: 被包装 Converter 的构造参数
        selection_strategy_params: 选择策略的构造参数
        converter_target: LLM 辅助转换用的 PromptTarget（可选）

    Returns:
        SelectiveTextConverter 实例

    Example:
        >>> # 链式选择转换：Base64 编码文本的后半部分，再用 ROT13 转换标记内的内容
        >>> first = create_selective_text_converter(
        ...     "base64",
        ...     selection_strategy_name="position",
        ...     selection_strategy_params={"start_proportion": 0.5, "end_proportion": 1.0},
        ...     preserve_tokens=True,
        ... )
        >>> second = create_selective_text_converter(
        ...     "rot13",
        ...     selection_strategy_name="token",  # 自动检测 ⟪⟫ 标记
        ...     preserve_tokens=True,
        ... )
    """
    sub_converter_params = sub_converter_params or {}
    selection_strategy_params = selection_strategy_params or {}

    # 创建子 Converter
    sub_converter = create_converter_instance(
        sub_converter_name, converter_target=converter_target, **sub_converter_params
    )

    # 创建选择策略
    strategy = create_selection_strategy(
        selection_strategy_name, **selection_strategy_params
    )

    return SelectiveTextConverter(
        sub_converter=sub_converter,
        selection_strategy=strategy,
        preserve_tokens=preserve_tokens,
        start_token=start_token,
        end_token=end_token,
        word_separator=word_separator,
    )


# ============================================================
# 预置 Converter 链加载
# ============================================================


def load_preset_converter_chain(
    chain_name: str,
    converter_target: Any = None,
) -> Optional[AttackConverterConfig]:
    """
    从配置文件加载预置 Converter 链

    支持标准 Converter 链和 SelectiveTextConverter 组合链。
    YAML 配置中的 converter 条目可以是：
    1. 简单名称字符串：如 "base64"
    2. SelectiveTextConverter 组合字典：包含 selective + sub_converter + strategy 等字段

    Args:
        chain_name: 链名称，如 "stealth_evasion"
        converter_target: LLM 辅助转换用的 PromptTarget（可选，用于 NoiseConverter 等）

    Returns:
        AttackConverterConfig 实例，如果链不存在则返回 None
    """
    config_loader = get_config_loader()
    chain_config = config_loader.get_converter_chain_config(chain_name)

    if chain_config is None:
        return None

    raw_converters = chain_config.get("converters", [])
    converter_params = chain_config.get("params", {})

    # 处理可能包含 SelectiveTextConverter 组合的 converter 列表
    converter_names = []
    expanded_params = dict(converter_params)

    for item in raw_converters:
        if isinstance(item, dict):
            # SelectiveTextConverter 组合配置
            if item.get("selective"):
                sub_name = item.get("sub_converter", "")
                strategy_name = item.get("strategy", "all_words")
                selective_params = item.get("params", {})

                # 构建 SelectiveTextConverter 实例并注入到参数中
                selective_converter = create_selective_text_converter(
                    sub_converter_name=sub_name,
                    selection_strategy_name=strategy_name,
                    preserve_tokens=item.get("preserve_tokens", False),
                    start_token=item.get("start_token", "⟪"),
                    end_token=item.get("end_token", "⟫"),
                    sub_converter_params=selective_params.get("sub_converter", {}),
                    selection_strategy_params=selective_params.get("strategy", {}),
                    converter_target=converter_target,
                )

                # 使用一个唯一键标识此组合实例
                instance_key = f"_selective_{sub_name}_{strategy_name}"
                expanded_params[instance_key] = {"_pre_built_instance": selective_converter}
                converter_names.append(instance_key)
            else:
                # 普通字典格式的 converter 名称
                name = item.get("name", "")
                if name:
                    converter_names.append(name)
        elif isinstance(item, str):
            converter_names.append(item)

    # 检查是否有预构建的实例需要特殊处理
    converters = []
    for name in converter_names:
        params = expanded_params.get(name, {})
        pre_built = params.pop("_pre_built_instance", None)
        if pre_built is not None:
            converters.append(pre_built)
        else:
            instance = create_converter_instance(
                name, converter_target=converter_target, **params
            )
            converters.append(instance)

    # 模态验证
    simple_names = [
        n for n in converter_names
        if not n.startswith("_selective_")
    ]
    if simple_names:
        warnings = validate_converter_chain_modality(simple_names)
        for w in warnings:
            logger.warning(f"预置链 '{chain_name}' 模态验证: {w}")

    chain = ConverterConfiguration(converters=converters)

    if chain_config.get("apply_to_response", False):
        return AttackConverterConfig(
            request_converters=[chain],
            response_converters=[chain],
        )
    return AttackConverterConfig(request_converters=[chain])


def get_preset_converter_chain_names() -> List[str]:
    """
    获取所有预置 Converter 链的名称

    Returns:
        Converter 链名称列表
    """
    config_loader = get_config_loader()
    return list(config_loader.get_converter_chains().keys())


def get_preset_converter_chain_names_for_scenario(
    scenario_name: str,
) -> List[str]:
    """
    获取特定 Scenario 的推荐 Converter 链

    Args:
        scenario_name: Scenario 名称，如 "airt.jailbreak"

    Returns:
        Converter 链名称列表
    """
    config_loader = get_config_loader()
    scenario_config = config_loader.get_scenario_config(scenario_name)

    if scenario_config is None:
        return []

    return scenario_config.get("converter_chains", [])


def get_converters_for_scenario(
    scenario_name: str,
) -> List[str]:
    """
    获取特定 Scenario 的推荐 Converter 名称

    Args:
        scenario_name: Scenario 名称，如 "airt.jailbreak"

    Returns:
        Converter 名称列表
    """
    config_loader = get_config_loader()
    scenario_config = config_loader.get_scenario_config(scenario_name)

    if scenario_config is None:
        return []

    return scenario_config.get("converters", [])


# ============================================================
# 常用 Converter 链（快捷方法）
# ============================================================


def create_stealth_evasion_chain() -> AttackConverterConfig:
    """
    创建隐身规避链（Unicode 混淆 + Base64 + 后缀追加）

    模态: text → text → text → text

    Returns:
        AttackConverterConfig 实例
    """
    return create_attack_converter_config(
        converter_names=[
            "unicode_confusable",
            "base64",
            "suffix_append",
        ],
        converter_params={
            "suffix_append": {"suffix": "!"},
        },
    )


def create_encoding_bypass_chain() -> AttackConverterConfig:
    """
    创建编码绕过链（Base64 + ROT13 + Caesar）

    模态: text → text → text → text

    Returns:
        AttackConverterConfig 实例
    """
    return create_attack_converter_config(
        converter_names=[
            "base64",
            "rot13",
            "caesar",
        ],
        converter_params={
            "caesar": {"caesar_offset": 13},
        },
    )


def create_format_injection_chain() -> AttackConverterConfig:
    """
    创建格式注入链（ASCII 艺术 + QR 码）

    注意: QRCodeConverter 输出 image_path，后续 Converter 必须接受 image_path 输入。
    此链仅包含 text→text 和 text→image_path 两个 Converter，不串联不兼容模态。

    模态: text → text (ascii_art), 独立的 text → image_path (qr_code)

    Returns:
        AttackConverterConfig 实例
    """
    # ascii_art: text → text, qr_code: text → image_path
    # 这两个 Converter 不能串联（模态不兼容），只取 ascii_art
    return create_attack_converter_config(
        converter_names=[
            "ascii_art",
        ],
    )


def create_llm_assisted_chain(
    language: str = "en",
    tone: str = "formal",
    persuasion_technique: str = "logical_appeal",
    converter_target: Any = None,
) -> AttackConverterConfig:
    """
    创建 LLM 辅助链（说服转换 + 语气转换 + 翻译）

    模态: text → text → text → text

    所有 Converter 都需要 converter_target 参数。

    Args:
        language: 翻译目标语言
        tone: 语气（如 upset, sarcastic, indifferent, formal 等）
        persuasion_technique: 说服技术
            有效值: authority_endorsement / evidence_based / expert_endorsement /
            logical_appeal / misrepresentation
        converter_target: LLM 辅助转换用的 PromptTarget

    Returns:
        AttackConverterConfig 实例
    """
    return create_attack_converter_config(
        converter_names=[
            "persuasion",
            "tone",
            "translation",
        ],
        converter_params={
            "translation": {"language": language},
            "tone": {"tone": tone},
            "persuasion": {"persuasion_technique": persuasion_technique},
        },
        converter_target=converter_target,
    )


def create_unicode_attack_chain() -> AttackConverterConfig:
    """
    创建 Unicode 攻击链（Unicode 混淆 + 双向文本 + 零宽字符）

    模态: text → text → text → text

    Returns:
        AttackConverterConfig 实例
    """
    return create_attack_converter_config(
        converter_names=[
            "unicode_confusable",
            "bidi",
            "zero_width",
        ],
    )


def create_multi_encoding_chain() -> AttackConverterConfig:
    """
    创建多层编码链（Base64 + ROT13 + Caesar + Atbash）

    模态: text → text → text → text → text

    Returns:
        AttackConverterConfig 实例
    """
    return create_attack_converter_config(
        converter_names=[
            "base64",
            "rot13",
            "caesar",
            "atbash",
        ],
        converter_params={
            "caesar": {"caesar_offset": 5},
        },
    )


def create_leetspeak_chain(
    repeat_token: str = ".",
    repeat_count: int = 3,
) -> AttackConverterConfig:
    """
    创建 Leetspeak 链（Leetspeak + Flip + RepeatToken）

    模态: text → text → text → text

    Args:
        repeat_token: 要重复的 token
        repeat_count: 重复次数

    Returns:
        AttackConverterConfig 实例
    """
    return create_attack_converter_config(
        converter_names=[
            "leetspeak",
            "flip",
            "repeat_token",
        ],
        converter_params={
            "repeat_token": {
                "token_to_repeat": repeat_token,
                "times_to_repeat": repeat_count,
                "token_insert_mode": "append",
            },
        },
    )


def create_policy_puppetry_chain(
    prompt_template: Any = None,
) -> AttackConverterConfig:
    """
    创建 PolicyPuppetry 链（PyRIT 1.0.0 新增）

    替代已弃用的 RolePlayAttack，通过模拟系统策略格式来绕过安全检查。

    PolicyPuppetryConverter 签名: (*, prompt_template: SeedPrompt | None = None)
    如果不提供 prompt_template，会随机选择 PolicyPuppetryTemplate（DR_HOUSE / MEDICAL_ADVISOR）。

    模态: text → text

    Args:
        prompt_template: 可选的 SeedPrompt 模板。
            如不提供，Converter 会从 PolicyPuppetryTemplate 枚举中随机选择。

    Returns:
        AttackConverterConfig 实例
    """
    params: Dict[str, Any] = {}
    if prompt_template is not None:
        params["prompt_template"] = prompt_template

    return create_attack_converter_config(
        converter_names=["policy_puppetry"],
        converter_params={"policy_puppetry": params} if params else None,
    )


def create_decomposition_chain(
    converter_target: Any = None,
    use_word_game: bool = False,
) -> AttackConverterConfig:
    """
    创建分解+重构链（PyRIT 1.0.0 新增）

    DecompositionConverter 基于 DrAttack 论文，将目标分解为有序的角色标记短语，
    然后重建为 "Question A / Question B" 任务格式。

    DecompositionConverter 签名:
        (*, converter_target, decomposition_prompt=None,
         reconstruction_prompt=None, use_word_game=False, codewords=...)

    模态: text → text

    Args:
        converter_target: 用于分解的 LLM PromptTarget
        use_word_game: 是否启用单词游戏模式（用无害的代号替换有害名词短语）

    Returns:
        AttackConverterConfig 实例
    """
    return create_attack_converter_config(
        converter_names=["decomposition"],
        converter_params={
            "decomposition": {
                "use_word_game": use_word_game,
            },
        },
        converter_target=converter_target,
    )


def create_noise_chain(
    converter_target: Any = None,
    number_errors: int = 5,
    noise: Optional[str] = None,
) -> AttackConverterConfig:
    """
    创建噪声链（PyRIT 1.0.0 新增）

    NoiseConverter 使用 LLM 在文本中注入噪声错误（语法错误、删除随机字母等）。

    NoiseConverter 签名:
        (*, converter_target, noise=None, number_errors=5, prompt_template=None)

    模态: text → text

    Args:
        converter_target: 用于噪声注入的 LLM PromptTarget
        number_errors: 注入的错误数量
        noise: 噪声类型描述（None 使用默认值）

    Returns:
        AttackConverterConfig 实例
    """
    params: Dict[str, Any] = {"number_errors": number_errors}
    if noise is not None:
        params["noise"] = noise

    return create_attack_converter_config(
        converter_names=["noise"],
        converter_params={"noise": params},
        converter_target=converter_target,
    )


def create_noise_case_chain(
    converter_target: Any = None,
    number_errors: int = 5,
    percentage: float = 40.0,
) -> AttackConverterConfig:
    """
    创建噪声+随机大写链（PyRIT 1.0.0 新增）

    在 prompt 中注入随机噪声和大写字符，干扰内容过滤器。

    NoiseConverter 签名: (*, converter_target, noise=None, number_errors=5, prompt_template=None)
    RandomCapitalLettersConverter 签名: (*, percentage: float = 100.0)

    模态: text → text → text → text

    Args:
        converter_target: 用于噪声注入的 LLM PromptTarget
        number_errors: 噪声数量
        percentage: 大写字符百分比（1.0 ~ 100.0）

    Returns:
        AttackConverterConfig 实例
    """
    return create_attack_converter_config(
        converter_names=[
            "noise",
            "random_capital_letters",
            "base64",
        ],
        converter_params={
            "noise": {
                "number_errors": number_errors,
            },
            "random_capital_letters": {
                "percentage": percentage,
            },
        },
        converter_target=converter_target,
    )


def create_task_framing_chain(
    task_template: str = "TASK is '{{ prompt }}'",
    strip_characters: str = "",
    converter_target: Any = None,
) -> AttackConverterConfig:
    """
    创建任务框架链（PyRIT 1.0.0 新增）

    将恶意请求包装为特定任务格式，伪装成正常业务操作。

    TaskFramingConverter 签名:
        (*, task_template: str = "TASK is '{{ prompt }}'", strip_characters: str = "")

    模态: text → text → text

    Args:
        task_template: 任务框架模板，必须包含 {{ prompt }} 占位符
        strip_characters: 从输入中移除的字符
        converter_target: 用于后续 PersuasionConverter 的 LLM PromptTarget

    Returns:
        AttackConverterConfig 实例
    """
    return create_attack_converter_config(
        converter_names=[
            "task_framing",
            "persuasion",
        ],
        converter_params={
            "task_framing": {
                "task_template": task_template,
                "strip_characters": strip_characters,
            },
            "persuasion": {
                "persuasion_technique": "logical_appeal",
            },
        },
        converter_target=converter_target,
    )


def create_selective_encoding_chain(
    sub_converter_name: str = "base64",
    selection_strategy_name: str = "word_proportion",
    proportion: float = 0.3,
    preserve_tokens: bool = True,
) -> AttackConverterConfig:
    """
    创建选择性编码链（PyRIT 1.0.0 Selective Converting）

    使用 SelectiveTextConverter 将编码 Converter 应用到文本的选定部分。
    preserve_tokens=True 时用 ⟪⟫ 标记包裹转换结果，可用于链式选择转换。

    模态: text → text

    Args:
        sub_converter_name: 被包装的 Converter 名称（如 base64 / rot13 / morse 等）
        selection_strategy_name: 选择策略名称
        proportion: 选择比例（用于 word_proportion 策略）
        preserve_tokens: 是否保留 ⟪⟫ 标记

    Returns:
        AttackConverterConfig 实例
    """
    strategy_params: Dict[str, Any] = {}
    if selection_strategy_name == "word_proportion":
        strategy_params["proportion"] = proportion
    elif selection_strategy_name == "proportion":
        strategy_params["proportion"] = proportion

    selective_converter = create_selective_text_converter(
        sub_converter_name=sub_converter_name,
        selection_strategy_name=selection_strategy_name,
        preserve_tokens=preserve_tokens,
        selection_strategy_params=strategy_params,
    )

    chain = ConverterConfiguration(converters=[selective_converter])
    return AttackConverterConfig(request_converters=[chain])


def create_multimodal_text_to_image_chain(
    converter_name: str = "qr_code",
    **kwargs: Any,
) -> AttackConverterConfig:
    """
    创建多模态 text→image 链

    将文本 prompt 转换为图像格式，用于多模态红队测试。

    模态: text → image_path

    Args:
        converter_name: 多模态 Converter 名称
            可用: qr_code / add_image_text / image_prompt_style
        **kwargs: Converter 构造参数

    Returns:
        AttackConverterConfig 实例
    """
    return create_attack_converter_config(
        converter_names=[converter_name],
        converter_params={converter_name: kwargs} if kwargs else None,
    )


# ============================================================
# 注册到 PyRIT ConverterRegistry
# ============================================================


def register_converters_to_pyrit_registry() -> None:
    """
    将所有 Converter 注册到 PyRIT ConverterRegistry

    PyRIT 1.0.0 Registry API：
    - register_class()（注册类而非实例）
    - ConverterRegistry 自动发现 pyrit.converter 包中的所有 Converter 子类
    - 此函数确保自定义 Converter 类也被注册

    使用反射自动检测需要 converter_target 的 Converter 并跳过注册。
    """
    registry = ConverterRegistry.get_registry_singleton()

    registered_count = 0
    skipped_count = 0
    failed_count = 0

    # 使用反射获取所有需要 converter_target 的 Converter（去重）
    requires_target_names = set(get_converters_requiring_target())

    seen_classes = set()
    for name, converter_class in CONVERTER_CLASS_MAP.items():
        # 跳过类名别名（只注册每个类一次）
        if converter_class in seen_classes:
            continue
        seen_classes.add(converter_class)

        # 跳过需要 converter_target 的 Converter（LLM 辅助 Converter）
        if name in requires_target_names:
            skipped_count += 1
            logger.debug(f"跳过 LLM 辅助 Converter: {name}（需要 converter_target 参数）")
            continue

        try:
            registry.register_class(converter_class)
            registered_count += 1
            logger.debug(f"成功注册 Converter: {name} ({converter_class.__name__})")

        except Exception as e:
            error_msg = str(e).lower()
            if "already registered" in error_msg or "duplicate" in error_msg:
                logger.debug(f"Converter 已由 PyRIT 自动发现: {name}")
                registered_count += 1
            else:
                failed_count += 1
                logger.warning(f"注册 Converter 失败: {name} - {e}")

    logger.info(
        f"Converter 注册完成: 成功 {registered_count}, 跳过 {skipped_count}, 失败 {failed_count}"
    )

    # 验证注册状态
    try:
        registered_names = registry.get_class_names()
        unregistered = seen_classes - requires_target_names
        unregistered_names = [
            cls.__name__ for cls in unregistered
            if cls.__name__ not in registered_names
        ]
        if unregistered_names:
            logger.debug(f"未注册的 Converter: {unregistered_names}")
    except Exception as e:
        logger.debug(f"验证注册状态失败: {e}")


def get_converter_from_pyrit_registry(name: str) -> Optional[Any]:
    """
    从 PyRIT ConverterRegistry 获取 Converter 实例

    PyRIT 1.0.0 API：
    - get_instance_by_name() 已移除
    - 改用 create_instance() 通过类名创建实例

    Args:
        name: Converter 名称（类名）

    Returns:
        Converter 实例，如果不存在则返回 None
    """
    registry = ConverterRegistry.get_registry_singleton()

    # 验证类是否已注册
    try:
        registered_names = registry.get_class_names()
        if name not in registered_names:
            logger.warning(f"尝试创建未注册的 Converter: {name}")
            return None
    except Exception as e:
        logger.debug(f"检查注册状态失败: {e}")

    try:
        instance = registry.create_instance(name)
        logger.debug(f"成功创建 Converter 实例: {name}")
        return instance

    except TypeError as e:
        if "converter_target" in str(e):
            logger.warning(
                f"Converter {name} 需要 converter_target 参数，"
                f"请通过 create_converter_instance() 并传入 converter_target"
            )
            return None
        else:
            logger.error(f"创建 Converter 失败: {name} - {e}")
            return None

    except Exception as e:
        logger.error(f"创建 Converter 失败: {name} - {e}")
        return None


def list_registered_converters() -> List[str]:
    """
    列出所有已注册到 PyRIT ConverterRegistry 的 Converter

    Returns:
        Converter 类名列表
    """
    registry = ConverterRegistry.get_registry_singleton()

    try:
        names = registry.get_class_names()
        logger.debug(f"已注册 {len(names)} 个 Converter")
        return sorted(names)

    except Exception as e:
        logger.error(f"获取已注册 Converter 列表失败: {e}")
        return []


# 延迟导入 ConverterRegistry（避免循环导入）
def _ensure_registry_imported():
    """延迟导入 ConverterRegistry，避免模块加载时的循环依赖"""
    from pyrit.registry import ConverterRegistry
    return ConverterRegistry


# 在需要时替换 register/get/list 函数中的 ConverterRegistry 引用
ConverterRegistry = _ensure_registry_imported()
