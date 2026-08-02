# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Converter 工厂、链与路由子包。.

包含以下模块:
  - factory: Converter 工厂 (CLI 名称 → PyRIT Converter 实例)
  - chains: Converter 变体链定义 (使用原生 extra_request_converters API)
  - log: Converter 转换日志收集
  - target_aware_router: Target-Aware Converter 路由
  - model_tier_detector: 模型等级自动探测器
  - steganography_converter: LSB 隐写 Converter (多模态注入增强)
  - audio_steganography_converter: WAV LSB 隐写 Converter (音频注入增强)

统一入口:
    from pipeline.converters import (
        build_technique_converter_map,
        build_target_aware_converter_map,
        merge_converter_maps,
        get_chains_for_target_type,
        detect_model_tier_from_registry,
    )
"""

from pipeline.converters.audio_steganography_converter import AudioSteganographyConverter
from pipeline.converters.chains import build_converters_from_chain_names, load_preset_converter_chain
from pipeline.converters.factory import (
    build_target_aware_converter_map,
    build_technique_converter_map,
    create_converters,
    get_available_converter_names,
    merge_converter_maps,
)
from pipeline.converters.model_tier_detector import (
    detect_model_tier_from_registry,
    should_use_llm_converters,
)
from pipeline.converters.steganography_converter import SteganographyConverter
from pipeline.converters.target_aware_router import get_chains_for_target_type, infer_target_type

__all__ = [
    # factory
    "build_target_aware_converter_map",
    "build_technique_converter_map",
    "create_converters",
    "get_available_converter_names",
    "merge_converter_maps",
    # chains
    "build_converters_from_chain_names",
    "load_preset_converter_chain",
    # target_aware_router
    "get_chains_for_target_type",
    "infer_target_type",
    # model_tier_detector
    "detect_model_tier_from_registry",
    "should_use_llm_converters",
    # steganography_converter
    "SteganographyConverter",
    # audio_steganography_converter
    "AudioSteganographyConverter",
]
