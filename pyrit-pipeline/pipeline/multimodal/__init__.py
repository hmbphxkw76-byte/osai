# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""多模态攻击支持 — 使用 PyRIT 原生 ``ModalityRouter`` + 多模态 Target/Converter。.

PyRIT 原生支持多模态攻击:
  - ``_ModalityFeedbackRouter``: 能力感知的多模态载荷路由
  - ``OpenAIImageTarget``: 图像生成目标
  - ``OpenAIVideoTarget``: 视频生成目标
  - ``OpenAITTSTarget``: 语音合成目标
  - ``OpenAIRealtimeTarget``: 实时音频目标
  - 多模态 Converter: ``AddImageTextConverter``, ``ImageOverlayConverter`` 等

``TargetCapabilities.input_modalities`` 声明目标接受的数据类型，
原生 ``ModalityRouter`` 自动根据能力路由载荷。

学术依据:
  - Shayegani et al. (arXiv:2306.13254) "Jailbreak in Pieces:
    Compositional Adversarial Attacks on Multi-Modal Language Models"
  - PyRIT 官方多模态文档

> **日期**: 2026-8-1
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from pyrit.prompt_target import PromptTarget


# ============================================================
# 多模态攻击配置
# ============================================================

MULTIMODAL_CONVERTER_PRESETS: dict[str, dict[str, Any]] = {
    "image_text_overlay": {
        "description": "在图像上叠加文本指令，绕过文本过滤",
        "converter_class": "AddImageTextConverter",
        "requires_target": True,
        "modality": "image",
    },
    "image_prompt_style": {
        "description": "修改图像提示风格，注入对抗性风格描述",
        "converter_class": "ImagePromptStyleConverter",
        "requires_target": True,
        "modality": "image",
    },
    "image_overlay": {
        "description": "在图像上叠加另一张图像，隐藏攻击指令",
        "converter_class": "ImageOverlayConverter",
        "requires_target": True,
        "modality": "image",
    },
    "image_resizing": {
        "description": "调整图像大小以绕过尺寸检查",
        "converter_class": "ImageResizingConverter",
        "requires_target": False,
        "modality": "image",
    },
    "image_rotation": {
        "description": "旋转图像以绕过 OCR 检测",
        "converter_class": "ImageRotationConverter",
        "requires_target": False,
        "modality": "image",
    },
    "image_compression": {
        "description": "压缩图像以改变像素级特征",
        "converter_class": "ImageCompressionConverter",
        "requires_target": False,
        "modality": "image",
    },
    "image_color_saturation": {
        "description": "调整图像色彩饱和度",
        "converter_class": "ImageColorSaturationConverter",
        "requires_target": False,
        "modality": "image",
    },
}


def get_multimodal_converter(
    preset_name: str,
    *,
    converter_target: PromptTarget | None = None,
) -> Any | None:
    """根据预设名称构建多模态 Converter (原生 API)。.

    Args:
        preset_name: 预设名称 (见 ``MULTIMODAL_CONVERTER_PRESETS``)。
        converter_target: LLM 链所需的 Converter Target (如 OpenAIChatTarget)。

    Returns:
        原生 Converter 实例，或 None (如果构建失败)。
    """
    preset = MULTIMODAL_CONVERTER_PRESETS.get(preset_name)
    if preset is None:
        logger.warning(f"Unknown multimodal converter preset: {preset_name}")
        return None

    if preset["requires_target"] and converter_target is None:
        logger.warning(f"Multimodal converter '{preset_name}' requires converter_target, but none provided. Skipping.")
        return None

    try:
        from pyrit.converter import (
            AddImageTextConverter,
            ImageColorSaturationConverter,
            ImageCompressionConverter,
            ImageOverlayConverter,
            ImagePromptStyleConverter,
            ImageResizingConverter,
            ImageRotationConverter,
        )

        class_map = {
            "AddImageTextConverter": AddImageTextConverter,
            "ImagePromptStyleConverter": ImagePromptStyleConverter,
            "ImageOverlayConverter": ImageOverlayConverter,
            "ImageResizingConverter": ImageResizingConverter,
            "ImageRotationConverter": ImageRotationConverter,
            "ImageCompressionConverter": ImageCompressionConverter,
            "ImageColorSaturationConverter": ImageColorSaturationConverter,
        }

        cls = class_map.get(preset["converter_class"])
        if cls is None:
            logger.warning(f"Converter class not found: {preset['converter_class']}")
            return None

        if preset["requires_target"]:
            return cls(converter_target=converter_target)
        return cls()

    except Exception as e:
        logger.warning(f"Failed to build multimodal converter '{preset_name}': {e}")
        return None


def detect_target_modalities(target: PromptTarget) -> set[str]:
    """检测目标模型支持的输入模态 (原生 API)。.

    v7.0: 优先使用原生 ``target.capabilities.input_modalities`` 静态声明,
    运行时探测由 ``discover_target_modalities_async`` 异步函数实现。

    Args:
        target: PyRIT 目标实例。

    Returns:
        支持的模态集合 (如 {"text"}, {"text", "image"}, {"text", "audio"})。
    """
    try:
        capabilities = target.capabilities
        modalities: set[str] = set()
        for combo in capabilities.input_modalities:
            modalities.update(combo)
        return modalities if modalities else {"text"}
    except Exception as e:
        logger.debug(f"Failed to detect target modalities: {e}")
        return {"text"}


async def discover_target_modalities_async(
    target: PromptTarget,
    *,
    per_probe_timeout_s: float = 30.0,
    apply: bool = True,
) -> set[str]:
    """运行时探测目标模型实际支持的输入模态 (原生 API)。.

    v7.0: 使用原生 ``discover_target_capabilities_async`` 发送最小化探测请求,
    验证目标实际接受哪些模态组合, 而非仅依赖静态声明。

    学术依据:
      - PyRIT 官方 ``discover_target_capabilities`` 文档
      - 运行时探测比静态声明更准确 (过滤误报)

    Args:
        target: PyRIT 目标实例。
        per_probe_timeout_s: 每次探测的超时时间 (秒)。
        apply: 是否将探测结果应用到目标 (更新 capabilities)。

    Returns:
        实际支持的模态集合。
    """
    try:
        from pyrit.prompt_target.common.discover_target_capabilities import (
            discover_target_capabilities_async,
        )

        capabilities = await discover_target_capabilities_async(
            target=target,
            per_probe_timeout_s=per_probe_timeout_s,
            apply=apply,
        )
        modalities: set[str] = set()
        for combo in capabilities.input_modalities:
            modalities.update(combo)
        logger.info(f"Runtime modality discovery: {modalities} (apply={apply})")
        return modalities if modalities else {"text"}
    except ImportError:
        logger.warning("discover_target_capabilities_async not available, falling back to static capabilities")
        return detect_target_modalities(target)
    except Exception as e:
        logger.warning(f"Runtime modality discovery failed: {e}, using static")
        return detect_target_modalities(target)


def is_multimodal_target(target: PromptTarget) -> bool:
    """检测目标是否支持多模态输入。.

    Args:
        target: PyRIT 目标实例。

    Returns:
        True 如果目标支持文本以外的模态 (image/audio/video)。
    """
    modalities = detect_target_modalities(target)
    return len(modalities - {"text"}) > 0


def recommend_multimodal_converters(
    target: PromptTarget,
    *,
    converter_target: PromptTarget | None = None,
) -> list[str]:
    """根据目标模态推荐多模态 Converter 链。.

    Args:
        target: 目标模型。
        converter_target: LLM 链所需的 Converter Target。

    Returns:
        推荐的 Converter 预设名称列表。
    """
    modalities = detect_target_modalities(target)
    recommendations: list[str] = []

    if "image" in modalities:
        recommendations.extend(
            [
                "image_text_overlay",
                "image_prompt_style",
                "image_overlay",
                "image_resizing",
                "image_rotation",
            ]
        )

    if "audio" in modalities:
        logger.info("Audio modality detected, audio converters may be applicable")

    if "video" in modalities:
        logger.info("Video modality detected, video converters may be applicable")

    return recommendations
