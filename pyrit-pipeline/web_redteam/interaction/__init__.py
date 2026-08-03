# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""目标交互层: 从配置生成 PlaywrightTarget 的 interaction_func.

G17: InteractionFunc 类型别名统一定义在此处,
generic_chat_interaction.py 和 interaction_factory.py 统一导入。
"""

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from playwright.async_api import Page
    from pyrit.models import Message

# G17: 统一的 InteractionFunc 类型别名
InteractionFunc = Callable[["Page", "Message"], Awaitable[str]]

from web_redteam.interaction.generic_chat_interaction import GenericChatInteraction  # noqa: E402
from web_redteam.interaction.interaction_factory import InteractionFactory  # noqa: E402

__all__ = [
    "GenericChatInteraction",
    "InteractionFactory",
    "InteractionFunc",
]
