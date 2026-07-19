# -*- coding: utf-8 -*-
"""
AI-300 Framework - Converter Builder
PyRIT 转换器配置构建模块

职责：
- 根据配置列表构建 PyRIT PromptConverterConfiguration
- 自动注入 converter_target（LLM 后端）给需要的转换器
- 处理特殊 preset 跳过逻辑

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
)

logger = logging.getLogger(__name__)


class ConverterBuilder:
    """
    PyRIT 转换器配置构建器

    根据转换器配置列表构建 PromptConverterConfiguration 列表，
    自动处理 converter_target 注入和特殊 preset 跳过。

    使用方式：
        builder = ConverterBuilder()
        converters = builder.build(converter_configs, converter_target=target)
    """

    def build(
        self,
        converter_configs: List[Dict[str, Any]],
        converter_target: Optional[PromptTarget] = None,
    ) -> List[PromptConverterConfiguration]:
        """
        根据配置列表构建转换器配置（PyRIT 0.14.0 兼容）

        Args:
            converter_configs: 转换器配置列表，每项为 {"name": str, "params": dict} 或纯字符串
            converter_target: 需要 LLM 后端的转换器目标（自动注入）

        Returns:
            List[PromptConverterConfiguration] - AttackConverterConfig 需要的格式
        """
        converters = []
        for config in converter_configs:
            name = config.get("name") if isinstance(config, dict) else config
            params = config.get("params", {}) if isinstance(config, dict) else {}

            if name in SPECIAL_PRESETS:
                logger.debug("Special preset '%s' - skipping converter creation", name)
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

                    converter_instance = converter_class(**params)
                    converters.append(PromptConverterConfiguration(converters=[converter_instance]))
                    logger.debug("Added converter: %s", name)
                except TypeError as e:
                    logger.warning("Converter %s requires params: %s", name, e)
            else:
                logger.warning("Unknown converter: %s", name)
        return converters
