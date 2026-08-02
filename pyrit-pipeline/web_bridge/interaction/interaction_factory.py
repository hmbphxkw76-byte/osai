# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Interaction Factory: 从配置生成 PlaywrightTarget 的 interaction_func。.

这是 InteractionConfig → InteractionFunc 的桥接层,
将 YAML 配置转化为运行时闭包。
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from web_bridge.interaction.generic_chat_interaction import GenericChatInteraction
from web_bridge.targets.target_profile import InteractionConfig

if TYPE_CHECKING:
    from playwright.async_api import Page
    from pyrit.models import Message

logger = logging.getLogger(__name__)

# Type alias matching PlaywrightTarget.InteractionFunction Protocol
InteractionFunc = Callable[["Page", "Message"], Awaitable[str]]


class InteractionFactory:
    """interaction_func 工厂。.

    从 TargetProfile.interaction 配置生成符合
    PlaywrightTarget.InteractionFunction Protocol 的异步函数。

    用法:
        interaction_func = InteractionFactory.create(profile.interaction)
        target = PlaywrightTarget(interaction_func=interaction_func, page=page)
    """

    @staticmethod
    def create(interaction_config: InteractionConfig) -> InteractionFunc:
        """从配置创建 interaction_func 闭包。.

        Args:
            interaction_config: TargetProfile.interaction 字段。

        Returns:
            符合 InteractionFunction Protocol 的异步函数。
        """
        logger.info(
            f"InteractionFactory: creating interaction_func "
            f"(input={interaction_config.input.type}, "
            f"wait={interaction_config.response.wait_strategy})"
        )
        return GenericChatInteraction.create(interaction_config)
