"""
Converters Module
=================

本模块负责 Converter 链的配置和注册。

PyRIT 1.0.0 对齐（L5 专家级）：
  - 全系列 Text-to-Text / File / Image / Audio / Video Converter
  - Selective Converting 子系统（TextSelectionStrategy 全层级 + WordLevelConverter）
  - @apply_defaults 全局默认值注入对齐
  - 模态感知链路验证
  - PolicyPuppetryTemplate 枚举导出
  - ConverterConfiguration 高级字段支持
"""

from src.converters.converter_registry import (
    # Converter 类映射
    CONVERTER_CLASS_MAP,
    # 模态分类常量
    TEXT_TO_TEXT_CONVERTERS,
    TEXT_TO_FILE_CONVERTERS,
    IMAGE_CONVERTERS,
    AUDIO_CONVERTERS,
    VIDEO_CONVERTERS,
    MULTIMODAL_CONVERTERS,
    # 模态感知工具
    get_all_converter_modalities,
    get_converter_supported_types,
    validate_converter_chain_modality,
    filter_converters_by_input_type,
    # @apply_defaults 对齐
    get_converters_requiring_target,
    # Converter 实例创建
    create_converter_instance,
    create_converter_chain_config,
    create_attack_converter_config,
    # Selective Converting
    SELECTION_STRATEGY_MAP,
    create_selection_strategy,
    create_selective_text_converter,
    # 预置链加载
    load_preset_converter_chain,
    get_preset_converter_chain_names,
    get_preset_converter_chain_names_for_scenario,
    get_converters_for_scenario,
    # 常用 Converter 链（快捷方法）
    create_stealth_evasion_chain,
    create_encoding_bypass_chain,
    create_format_injection_chain,
    create_llm_assisted_chain,
    create_unicode_attack_chain,
    create_multi_encoding_chain,
    create_leetspeak_chain,
    # PyRIT 1.0.0 新增快捷方法
    create_policy_puppetry_chain,
    create_decomposition_chain,
    create_noise_chain,
    create_noise_case_chain,
    create_task_framing_chain,
    create_selective_encoding_chain,
    create_multimodal_text_to_image_chain,
    # PyRIT Registry 集成
    register_converters_to_pyrit_registry,
    get_converter_from_pyrit_registry,
    list_registered_converters,
)

# PyRIT 1.0.0 枚举和基类直接导出
from pyrit.converter import (
    PolicyPuppetryTemplate,
    Converter,
    ConverterResult,
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
)

__all__ = [
    # Converter 类映射
    "CONVERTER_CLASS_MAP",
    # 模态分类常量
    "TEXT_TO_TEXT_CONVERTERS",
    "TEXT_TO_FILE_CONVERTERS",
    "IMAGE_CONVERTERS",
    "AUDIO_CONVERTERS",
    "VIDEO_CONVERTERS",
    "MULTIMODAL_CONVERTERS",
    # 模态感知工具
    "get_all_converter_modalities",
    "get_converter_supported_types",
    "validate_converter_chain_modality",
    "filter_converters_by_input_type",
    # @apply_defaults 对齐
    "get_converters_requiring_target",
    # Converter 实例创建
    "create_converter_instance",
    "create_converter_chain_config",
    "create_attack_converter_config",
    # Selective Converting
    "SELECTION_STRATEGY_MAP",
    "create_selection_strategy",
    "create_selective_text_converter",
    # 预置链加载
    "load_preset_converter_chain",
    "get_preset_converter_chain_names",
    "get_preset_converter_chain_names_for_scenario",
    "get_converters_for_scenario",
    # 常用 Converter 链（快捷方法）
    "create_stealth_evasion_chain",
    "create_encoding_bypass_chain",
    "create_format_injection_chain",
    "create_llm_assisted_chain",
    "create_unicode_attack_chain",
    "create_multi_encoding_chain",
    "create_leetspeak_chain",
    # PyRIT 1.0.0 新增快捷方法
    "create_policy_puppetry_chain",
    "create_decomposition_chain",
    "create_noise_chain",
    "create_noise_case_chain",
    "create_task_framing_chain",
    "create_selective_encoding_chain",
    "create_multimodal_text_to_image_chain",
    # PyRIT Registry 集成
    "register_converters_to_pyrit_registry",
    "get_converter_from_pyrit_registry",
    "list_registered_converters",
    # PyRIT 1.0.0 枚举和基类
    "PolicyPuppetryTemplate",
    "Converter",
    "ConverterResult",
    "SelectiveTextConverter",
    "TextSelectionStrategy",
    "TokenSelectionStrategy",
    "WordSelectionStrategy",
    "AllWordsSelectionStrategy",
    "IndexSelectionStrategy",
    "RegexSelectionStrategy",
    "KeywordSelectionStrategy",
    "PositionSelectionStrategy",
    "ProportionSelectionStrategy",
    "RangeSelectionStrategy",
    "WordIndexSelectionStrategy",
    "WordKeywordSelectionStrategy",
    "WordProportionSelectionStrategy",
    "WordRegexSelectionStrategy",
    "WordPositionSelectionStrategy",
]
