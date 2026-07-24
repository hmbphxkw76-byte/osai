"""
Converters Module
=================

本模块负责 Converter 链的配置和注册。
"""

from src.converters.converter_registry import (
    # Converter 类映射
    CONVERTER_CLASS_MAP,
    # Converter 实例创建
    create_converter_instance,
    create_converter_chain_config,
    create_attack_converter_config,
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
    # PyRIT Registry 集成
    register_converters_to_pyrit_registry,
    get_converter_from_pyrit_registry,
    list_registered_converters,
)

__all__ = [
    "CONVERTER_CLASS_MAP",
    "create_converter_instance",
    "create_converter_chain_config",
    "create_attack_converter_config",
    "load_preset_converter_chain",
    "get_preset_converter_chain_names",
    "get_preset_converter_chain_names_for_scenario",
    "get_converters_for_scenario",
    "create_stealth_evasion_chain",
    "create_encoding_bypass_chain",
    "create_format_injection_chain",
    "create_llm_assisted_chain",
    "create_unicode_attack_chain",
    "create_multi_encoding_chain",
    "create_leetspeak_chain",
    "register_converters_to_pyrit_registry",
    "get_converter_from_pyrit_registry",
    "list_registered_converters",
]