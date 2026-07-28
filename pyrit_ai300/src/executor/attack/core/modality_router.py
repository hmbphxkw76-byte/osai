"""
Modality Router — L5 Expert
=============================

模态路由系统 — 对齐 PyRIT 1.0.0 TargetCapabilities

功能：
1. 检查目标能力（多轮/多消息片段/JSON/系统提示/流式音频/图片输入/图片输出）
2. 根据目标能力自动路由攻击（跳过不支持的能力）
3. 多模态种子消息构建（text + image_path 混合）
4. 模态兼容性验证（确保种子消息的数据类型被目标支持）

设计原则：
- 使用原生 TargetCapabilities（frozen BaseModel）
- 不修改目标实例的能力配置
- 提供清晰的降级策略（不支持时跳过或降级）

对齐 PyRIT:
- pyrit.prompt_target.common.target_capabilities.TargetCapabilities
- pyrit.prompt_target.common.target_capabilities.CapabilityName
- pyrit.models.PromptDataType (text/image_path/audio_path/video_path/...)
"""

import logging
from typing import Dict, List

from pyrit.models import Message
from pyrit.prompt_target import PromptTarget
from pyrit.prompt_target.common.target_capabilities import (
    CapabilityName,
    TargetCapabilities,
)

logger = logging.getLogger(__name__)


# ============================================================
# 预设能力配置（常用模型 Profile）
# ============================================================

# 文本-only 目标（如 Ollama, vLLM, 部分 LiteLLM）
TEXT_ONLY_CAPABILITIES = TargetCapabilities()

# GPT-4o / GPT-4o-mini — 支持多模态
GPT4O_CAPABILITIES = TargetCapabilities(
    supports_multi_turn=True,
    supports_multi_message_pieces=True,
    supports_json_output=True,
    supports_system_prompt=True,
    input_modalities=frozenset({
        frozenset({"text"}),
        frozenset({"image_path", "text"}),
    }),
    output_modalities=frozenset({
        frozenset({"text"}),
    }),
)

# DALL-E / GPT-Image — 图片生成目标
IMAGE_GENERATION_CAPABILITIES = TargetCapabilities(
    input_modalities=frozenset({
        frozenset({"text"}),
    }),
    output_modalities=frozenset({
        frozenset({"image_path"}),
    }),
)

# o1 / o3 推理模型 — 不支持 system_prompt，但支持多轮
REASONING_MODEL_CAPABILITIES = TargetCapabilities(
    supports_multi_turn=True,
    supports_system_prompt=False,
)


# ============================================================
# 模态路由器
# ============================================================


class ModalityRouter:
    """
    模态路由器

    根据 TargetCapabilities 自动判断攻击是否需要降级或跳过：
    - 多轮攻击 → 检查 supports_multi_turn
    - 多消息片段 → 检查 supports_multi_message_pieces
    - 图片输入 → 检查 input_modalities 包含 image_path
    - JSON 输出 → 检查 supports_json_output
    - System Prompt → 检查 supports_system_prompt

    用法：
        router = ModalityRouter()
        caps = router.get_capabilities(target)

        if router.supports_modality(caps, "image_path", direction="input"):
            # 发送多模态消息
            ...
        else:
            # 降级到纯文本
            logger.warning("Target doesn't support image input, downgrading to text")
    """

    # 能力名到 CapabilityName 枚举的映射
    _CAPABILITY_MAP: Dict[str, CapabilityName] = {
        "multi_turn": CapabilityName.MULTI_TURN,
        "multi_message_pieces": CapabilityName.MULTI_MESSAGE_PIECES,
        "json_schema": CapabilityName.JSON_SCHEMA,
        "json_output": CapabilityName.JSON_OUTPUT,
        "editable_history": CapabilityName.EDITABLE_HISTORY,
        "system_prompt": CapabilityName.SYSTEM_PROMPT,
        "streaming_audio": CapabilityName.STREAMING_AUDIO,
    }

    @staticmethod
    def get_capabilities(target: PromptTarget) -> TargetCapabilities:
        """
        获取目标的 TargetCapabilities

        优先使用目标实例的 capabilities 属性，
        如果不存在则返回默认（text-only）能力配置。

        Args:
            target: PromptTarget 实例

        Returns:
            TargetCapabilities 实例
        """
        caps = getattr(target, "_capabilities", None)
        if caps is not None:
            return caps

        # 尝试从 _DEFAULT_CONFIGURATION 获取
        default_config = getattr(type(target), "_DEFAULT_CONFIGURATION", None)
        if default_config is not None:
            caps_attr = getattr(default_config, "capabilities", None)
            if caps_attr is not None:
                return caps_attr

        # 回退到 text-only 默认
        return TEXT_ONLY_CAPABILITIES

    @staticmethod
    def supports_modality(
        target: PromptTarget,
        data_type: str,
        direction: str = "input",
    ) -> bool:
        """
        检查目标是否支持指定模态

        Args:
            target: PromptTarget 实例
            data_type: 数据类型（如 "text", "image_path", "audio_path", "video_path"）
            direction: 方向 — "input" 或 "output"

        Returns:
            bool: 是否支持
        """
        caps = ModalityRouter.get_capabilities(target)

        if direction == "input":
            supported = caps.supported_input_modalities
        elif direction == "output":
            supported = caps.supported_output_modalities
        else:
            logger.warning(f"Invalid direction: {direction}")
            return False

        return data_type in supported

    @staticmethod
    def supports_audio_input(target: PromptTarget) -> bool:
        """快捷方法：检查目标是否支持音频输入"""
        return ModalityRouter.supports_modality(target, "audio_path", "input")

    @staticmethod
    def validate_message(
        target: PromptTarget,
        message: Message,
    ) -> List[str]:
        """
        验证消息中的所有 MessagePiece 数据类型是否被目标支持

        Args:
            target: PromptTarget 实例
            message: Message 实例

        Returns:
            不支持的数据类型列表（空列表 = 全部支持）
        """
        caps = ModalityRouter.get_capabilities(target)
        supported_input = set(caps.supported_input_modalities)

        unsupported: List[str] = []
        for piece in message.message_pieces:
            data_type = piece.original_value_data_type
            if data_type not in supported_input:
                unsupported.append(data_type)
                logger.warning(
                    f"Target {type(target).__name__} does not support "
                    f"input modality '{data_type}'"
                )

        return unsupported


