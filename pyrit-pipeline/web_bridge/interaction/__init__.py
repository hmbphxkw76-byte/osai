# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""目标交互层: 从配置生成 PlaywrightTarget 的 interaction_func。."""

from web_bridge.interaction.generic_chat_interaction import GenericChatInteraction
from web_bridge.interaction.interaction_factory import InteractionFactory

__all__ = [
    "GenericChatInteraction",
    "InteractionFactory",
]
