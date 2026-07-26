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
from typing import Any, Dict, List, Optional, Set

from pyrit.models import Message, MessagePiece, PromptDataType
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
    def supports_capability(
        target: PromptTarget,
        capability: str,
    ) -> bool:
        """
        检查目标是否支持指定能力

        Args:
            target: PromptTarget 实例
            capability: 能力名称（如 "multi_turn", "json_output", "system_prompt"）

        Returns:
            bool: 是否支持
        """
        caps = ModalityRouter.get_capabilities(target)
        cap_name = ModalityRouter._CAPABILITY_MAP.get(capability)
        if cap_name is None:
            logger.warning(f"Unknown capability: {capability}")
            return False
        return caps.includes(capability=cap_name)

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
    def supports_image_input(target: PromptTarget) -> bool:
        """快捷方法：检查目标是否支持图片输入"""
        return ModalityRouter.supports_modality(target, "image_path", "input")

    @staticmethod
    def supports_image_output(target: PromptTarget) -> bool:
        """快捷方法：检查目标是否支持图片输出"""
        return ModalityRouter.supports_modality(target, "image_path", "output")

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

    @staticmethod
    def route_attack(
        target: PromptTarget,
        attack_technique: str,
        seed_message: Optional[Message] = None,
    ) -> Dict[str, Any]:
        """
        根据目标能力路由攻击

        检查攻击技术和种子消息是否与目标能力兼容，
        返回路由决策（跳过/降级/正常执行）。

        Args:
            target: PromptTarget 实例
            attack_technique: 攻击技术名称
            seed_message: 种子消息（可选）

        Returns:
            路由决策字典:
            - action: "execute" / "skip" / "downgrade"
            - reason: 决策原因
            - unsupported_modalities: 不支持的模态列表
            - missing_capabilities: 缺失的能力列表
        """
        caps = ModalityRouter.get_capabilities(target)

        missing_caps: List[str] = []
        unsupported_modalities: List[str] = []

        # 检查多轮攻击
        multi_turn_techniques = {
            "red_teaming", "crescendo", "pair", "tap",
            "tree_of_attacks_pruned", "skeleton_key",
        }
        if attack_technique in multi_turn_techniques:
            if not caps.includes(capability=CapabilityName.MULTI_TURN):
                missing_caps.append("multi_turn")

        # 检查种子消息模态
        if seed_message is not None:
            unsupported_modalities = ModalityRouter.validate_message(target, seed_message)

        # 决策
        if missing_caps and unsupported_modalities:
            return {
                "action": "skip",
                "reason": f"Target missing capabilities {missing_caps} "
                          f"and modalities {unsupported_modalities}",
                "unsupported_modalities": unsupported_modalities,
                "missing_capabilities": missing_caps,
            }
        elif unsupported_modalities:
            return {
                "action": "downgrade",
                "reason": f"Target doesn't support modalities {unsupported_modalities}, "
                          f"downgrading to text-only",
                "unsupported_modalities": unsupported_modalities,
                "missing_capabilities": [],
            }
        elif missing_caps:
            return {
                "action": "downgrade",
                "reason": f"Target missing capabilities {missing_caps}, "
                          f"downgrading to single-turn",
                "unsupported_modalities": [],
                "missing_capabilities": missing_caps,
            }
        else:
            return {
                "action": "execute",
                "reason": "All capabilities and modalities supported",
                "unsupported_modalities": [],
                "missing_capabilities": [],
            }

    @staticmethod
    def build_multimodal_message(
        text: str,
        image_path: Optional[str] = None,
        role: str = "user",
    ) -> Message:
        """
        构建多模态消息（文本 + 可选图片）

        使用 MessagePiece 新 API：文本片段和图片片段分别构建。

        Args:
            text: 文本内容
            image_path: 图片文件路径（可选）
            role: 消息角色

        Returns:
            Message 实例（含一个或两个 MessagePiece）
        """
        pieces: List[MessagePiece] = []

        if image_path:
            pieces.append(MessagePiece(
                role=role,
                original_value=image_path,
                original_value_data_type="image_path",
            ))

        pieces.append(MessagePiece(
            role=role,
            original_value=text,
            original_value_data_type="text",
        ))

        return Message(message_pieces=pieces)

    @staticmethod
    def describe_capabilities(target: PromptTarget) -> Dict[str, Any]:
        """
        描述目标的能力配置（用于日志/调试）

        Args:
            target: PromptTarget 实例

        Returns:
            能力描述字典
        """
        caps = ModalityRouter.get_capabilities(target)
        return {
            "target_type": type(target).__name__,
            "supports_multi_turn": caps.supports_multi_turn,
            "supports_multi_message_pieces": caps.supports_multi_message_pieces,
            "supports_json_schema": caps.supports_json_schema,
            "supports_json_output": caps.supports_json_output,
            "supports_editable_history": caps.supports_editable_history,
            "supports_system_prompt": caps.supports_system_prompt,
            "supports_streaming_audio": caps.supports_streaming_audio,
            "supported_input_modalities": caps.supported_input_modalities,
            "supported_output_modalities": caps.supported_output_modalities,
        }
