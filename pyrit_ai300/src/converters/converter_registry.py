"""
Converters Module
=================

本模块负责 Converter 链的配置和注册（遵循开发规则 1.4.1）。

Converter 用于对提示词进行编码、混淆、转换等操作，以绕过 AI 安全检测。

 Converter 链可以组合多个 Converter，形成复杂的转换序列。
"""

from typing import Any, Dict, List, Optional

from pyrit.prompt_converter import (
    # 编码类 Converter
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
    # Unicode 类 Converter
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
    # 语义类 Converter
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
    # 格式类 Converter
    AsciiArtConverter,
    QRCodeConverter,
    PDFConverter,
    WordDocConverter,
    JsonStringConverter,
    TemplateSegmentConverter,
    UrlConverter,
    DenylistConverter,
    SelectiveTextConverter,
    # LLM 辅助类 Converter
    PersuasionConverter,
    LLMGenericTextConverter,
    MaliciousQuestionGeneratorConverter,
    ToxicSentenceGeneratorConverter,
    TextJailbreakConverter,
    AskToDecodeConverter,
    CodeChameleonConverter,
    # 特殊类 Converter
    AnsiAttackConverter,
    FlipConverter,
    RepeatTokenConverter,
    SuffixAppendConverter,
    ZalgoConverter,
    TransparencyAttackConverter,
)

from pyrit.prompt_normalizer.prompt_converter_configuration import (
    PromptConverterConfiguration,
)

from pyrit.executor.attack import AttackConverterConfig

from src.core.config_loader import get_config_loader


# ============================================================
# Converter 类名到 Converter 类的映射
# ============================================================

def _build_converter_map() -> Dict[str, Any]:
    """构建 Converter 映射表，同时支持 snake_case 和类名两种风格"""

    raw = {
        # 编码类
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
        # Unicode 类
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
        # 语义类
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
        # 格式类
        "ascii_art": AsciiArtConverter,
        "qr_code": QRCodeConverter,
        "pdf": PDFConverter,
        "word_doc": WordDocConverter,
        "json_string": JsonStringConverter,
        "template_segment": TemplateSegmentConverter,
        "url": UrlConverter,
        "denylist": DenylistConverter,
        "selective_text": SelectiveTextConverter,
        # LLM 辅助类
        "persuasion": PersuasionConverter,
        "llm_generic_text": LLMGenericTextConverter,
        "malicious_question_generator": MaliciousQuestionGeneratorConverter,
        "toxic_sentence_generator": ToxicSentenceGeneratorConverter,
        "text_jailbreak": TextJailbreakConverter,
        "ask_to_decode": AskToDecodeConverter,
        "code_chameleon": CodeChameleonConverter,
        # 特殊类
        "ansi_attack": AnsiAttackConverter,
        "flip": FlipConverter,
        "repeat_token": RepeatTokenConverter,
        "suffix_append": SuffixAppendConverter,
        "zalgo": ZalgoConverter,
        "transparency_attack": TransparencyAttackConverter,
    }

    # 自动添加类名别名（如 "Base64Converter" → Base64Converter）
    result = dict(raw)
    for cls in raw.values():
        result[cls.__name__] = cls

    return result


CONVERTER_CLASS_MAP: Dict[str, Any] = _build_converter_map()


# ============================================================
# Converter 链构建器
# ============================================================


def create_converter_instance(
    converter_name: str,
    **kwargs: Any,
) -> Any:
    """
    创建 Converter 实例

    Args:
        converter_name: Converter 名称（来自 CONVERTER_CLASS_MAP 的键）
        **kwargs: Converter 构造参数

    Returns:
        Converter 实例

    Raises:
        ValueError: 如果 Converter 名称不存在
    """
    converter_class = CONVERTER_CLASS_MAP.get(converter_name)
    if converter_class is None:
        raise ValueError(f"未知的 Converter 名称: {converter_name}")

    return converter_class(**kwargs)


def create_converter_chain_config(
    converter_names: List[str],
    converter_params: Optional[Dict[str, Dict[str, Any]]] = None,
) -> PromptConverterConfiguration:
    """
    创建 Converter 链配置

    Args:
        converter_names: Converter 名称列表，按执行顺序排列
        converter_params: Converter 参数字典，key 为 Converter 名称，value 为参数字典

    Returns:
        PromptConverterConfiguration 实例

    Raises:
        ValueError: 如果 Converter 名称不存在
    """
    converter_params = converter_params or {}

    converters = []
    for converter_name in converter_names:
        params = converter_params.get(converter_name, {})
        converter_instance = create_converter_instance(converter_name, **params)
        converters.append(converter_instance)

    return PromptConverterConfiguration(converters=converters)


def create_attack_converter_config(
    converter_names: List[str],
    converter_params: Optional[Dict[str, Dict[str, Any]]] = None,
    apply_to_request: bool = True,
    apply_to_response: bool = False,
) -> AttackConverterConfig:
    """
    创建 AttackConverterConfig

    Args:
        converter_names: Converter 名称列表，按执行顺序排列
        converter_params: Converter 参数字典，key 为 Converter 名称，value 为参数字典
        apply_to_request: 是否应用到请求
        apply_to_response: 是否应用到响应

    Returns:
        AttackConverterConfig 实例
    """
    converter_chain = create_converter_chain_config(converter_names, converter_params)

    converters = []
    if apply_to_request:
        converters.append(converter_chain)
    if apply_to_response:
        converters.append(converter_chain)

    if apply_to_request and apply_to_response:
        # 如果都应用，需要创建两个独立的 chain
        converter_chain_req = create_converter_chain_config(converter_names, converter_params)
        converter_chain_resp = create_converter_chain_config(converter_names, converter_params)
        return AttackConverterConfig(
            request_converters=[converter_chain_req],
            response_converters=[converter_chain_resp],
        )
    elif apply_to_request:
        return AttackConverterConfig(request_converters=[converter_chain])
    else:
        return AttackConverterConfig(response_converters=[converter_chain])


# ============================================================
# 预置 Converter 链加载
# ============================================================


def load_preset_converter_chain(chain_name: str) -> Optional[AttackConverterConfig]:
    """
    从配置文件加载预置 Converter 链

    Args:
        chain_name: 链名称，如 "stealth_evasion"

    Returns:
        AttackConverterConfig 实例，如果链不存在则返回 None
    """
    config_loader = get_config_loader()
    chain_config = config_loader.get_converter_chain_config(chain_name)

    if chain_config is None:
        return None

    converter_names = chain_config.get("converters", [])
    converter_params = chain_config.get("params", {})

    return create_attack_converter_config(converter_names, converter_params)


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
    创建格式注入链（ASCII 艺术 + QR 码 + PDF）

    Returns:
        AttackConverterConfig 实例
    """
    return create_attack_converter_config(
        converter_names=[
            "ascii_art",
            "qr_code",
            "pdf",
        ],
    )


def create_llm_assisted_chain(
    language: str = "en",
    tone: str = "formal",
    persuasion_technique: str = "authority",
) -> AttackConverterConfig:
    """
    创建 LLM 辅助链（说服转换 + 语气转换 + 翻译）

    Args:
        language: 翻译目标语言
        tone: 语气
        persuasion_technique: 说服技术

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
    )


def create_unicode_attack_chain() -> AttackConverterConfig:
    """
    创建 Unicode 攻击链（Unicode 混淆 + 双向文本 + 零宽字符）

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


# ============================================================
# 注册到 PyRIT ConverterRegistry
# ============================================================


def register_converters_to_pyrit_registry() -> None:
    """
    将所有 Converter 注册到 PyRIT ConverterRegistry

    注意：这会注册 Converter 实例（而非类），适合运行时使用
    """
    from pyrit.registry import ConverterRegistry

    for name, converter_class in CONVERTER_CLASS_MAP.items():
        try:
            # 尝试创建实例（有些 Converter 需要参数）
            if name in ["translation", "persuasion", "scientific_translation", "random_translation"]:
                # 这些 Converter 需要 converter_target 参数，跳过
                continue
            instance = converter_class()
            ConverterRegistry.register_instance(name, instance)
        except Exception as e:
            # 忽略无法创建实例的 Converter
            pass


def get_converter_from_pyrit_registry(name: str) -> Optional[Any]:
    """
    从 PyRIT ConverterRegistry 获取 Converter 实例

    Args:
        name: Converter 名称

    Returns:
        Converter 实例，如果不存在则返回 None
    """
    from pyrit.registry import ConverterRegistry

    try:
        return ConverterRegistry.get_instance_by_name(name)
    except KeyError:
        return None


def list_registered_converters() -> List[str]:
    """
    列出所有已注册到 PyRIT ConverterRegistry 的 Converter

    Returns:
        Converter 名称列表
    """
    from pyrit.registry import ConverterRegistry

    return ConverterRegistry.get_names()