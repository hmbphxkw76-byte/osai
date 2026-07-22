# -*- coding: utf-8 -*-
"""
AI-300 Framework - Converter Builder
PyRIT 转换器配置构建模块

职责：
- 根据配置列表构建 PyRIT PromptConverterConfiguration
- 自动注入 converter_target（LLM 后端）给需要的转换器
- 处理特殊 preset 跳过逻辑
- 为必需参数提供默认值（CaesarConverter / TextJailbreakConverter 等）
- SPA 目标过滤 binary_path 转换器（PlaywrightTarget 不支持）

从 AttackOrchestrator 拆分，遵循单一职责原则。

PyRIT 0.14.0 兼容
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from pyrit.prompt_converter import PromptConverter
from pyrit.prompt_normalizer.prompt_converter_configuration import PromptConverterConfiguration
from pyrit.prompt_target import PromptTarget

from .component_registry import (
    CONVERTER_MAP,
    SPECIAL_PRESETS,
    CONVERTERS_NEEDING_TARGET,
    CONVERTER_DEFAULT_PARAMS,
    CONVERTERS_PRODUCING_BINARY_PATH,
    SPA_TARGET_TYPES,
)

logger = logging.getLogger(__name__)


class ConverterBuilder:
    """
    PyRIT 转换器配置构建器

    根据转换器配置列表构建 PromptConverterConfiguration 列表，
    自动处理 converter_target 注入、特殊 preset 跳过、
    必需参数默认值填充、SPA 目标 binary_path 过滤。

    使用方式：
        builder = ConverterBuilder()
        converters = builder.build(converter_configs, converter_target=target)
    """

    def build(
        self,
        converter_configs: List[Dict[str, Any]],
        converter_target: Optional[PromptTarget] = None,
        target_type: str = "",
    ) -> List[PromptConverterConfiguration]:
        """
        根据配置列表构建转换器配置（PyRIT 0.14.0 兼容）

        Args:
            converter_configs: 转换器配置列表，每项为 {"name": str, "params": dict} 或纯字符串
            converter_target: 需要 LLM 后端的转换器目标（自动注入）
            target_type: 目标类型（spa_chat/playwright/ollama/openai 等），
                        用于过滤不兼容的转换器

        Returns:
            List[PromptConverterConfiguration] - AttackConverterConfig 需要的格式
        """
        is_spa = target_type in SPA_TARGET_TYPES
        converters = []
        for config in converter_configs:
            name = config.get("name") if isinstance(config, dict) else config
            params = config.get("params", {}) if isinstance(config, dict) else {}

            if name in SPECIAL_PRESETS:
                logger.debug("Special preset '%s' - skipping converter creation", name)
                continue

            # SPA 目标过滤：跳过产生 binary_path 的转换器
            # PlaywrightTarget 只支持 image_path 和 text，不支持 binary_path
            if is_spa and name in CONVERTERS_PRODUCING_BINARY_PATH:
                logger.info(
                    "Skipping converter '%s' for SPA target (produces binary_path, "
                    "PlaywrightTarget only supports image_path/text)",
                    name,
                )
                continue

            converter_class = CONVERTER_MAP.get(name)
            if converter_class:
                try:
                    if name in CONVERTERS_NEEDING_TARGET and "converter_target" not in params:
                        if converter_target:
                            params["converter_target"] = converter_target
                            logger.debug("Auto-injected converter_target for: %s", name)
                        else:
                            logger.warning(
                                "Converter '%s' requires converter_target (LLM backend), "
                                "but none available. Skipping.",
                                name,
                            )
                            continue

                    # 填充必需参数默认值（用户未提供时）
                    if name in CONVERTER_DEFAULT_PARAMS:
                        for param_name, param_value in CONVERTER_DEFAULT_PARAMS[name].items():
                            if param_name not in params:
                                # param_value 可能是 callable（延迟创建），如 _default_text_jailbreak_template
                                if callable(param_value):
                                    params[param_name] = param_value()
                                else:
                                    params[param_name] = param_value
                                logger.debug("Auto-filled default param for %s: %s", name, param_name)

                    converter_instance = converter_class(**params)
                    converters.append(PromptConverterConfiguration(converters=[converter_instance]))
                    logger.debug("Added converter: %s", name)
                except TypeError as e:
                    logger.warning("Converter %s requires params: %s", name, e)
            else:
                logger.warning("Unknown converter: %s", name)
        return converters
