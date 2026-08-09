"""自研 Buff 攻击链包 — 覆盖 garak 原生未提供的攻击变换

对齐 L5 专家水平：garak 原生 Buff 仅含 Base64/Lowercase 等编码变换。
L5 红队需完整攻击链：翻译绕过 + 角色扮演越狱 + Prompt 拆分 + 多轮诱导。

设计原则（规则一：garak 原生框架优先）：
    本包提供 Buff 类（继承 garak.buffs.base.Buff）+ 向后兼容的 SPEC 列表。
    通过 register_custom_buffs() 将自定义类注入 garak.buffs.custom 命名空间，
    使 garak 的 run.spec / load_plugin / enumerate_plugins 原生支持。
"""

from __future__ import annotations

import sys
import types
from datetime import datetime, timezone

from garak import _plugins
from garak.buffs.base import Buff

from pipeline.custom_buffs.multi_turn import (
    MULTI_TURN_BUFF_CLASSES,
    MULTI_TURN_BUFFS,
)
from pipeline.custom_buffs.prompt_split import (
    PROMPT_SPLIT_BUFF_CLASSES,
    PROMPT_SPLIT_BUFFS,
)
from pipeline.custom_buffs.roleplay import (
    ROLEPLAY_BUFF_CLASSES,
    ROLEPLAY_BUFFS,
)
from pipeline.custom_buffs.translation import (
    TRANSLATION_BUFF_CLASSES,
    TRANSLATION_BUFFS,
)

__all__ = [
    "ALL_CUSTOM_BUFFS",
    "ALL_CUSTOM_BUFF_CLASSES",
    "MULTI_TURN_BUFFS",
    "MULTI_TURN_BUFF_CLASSES",
    "PROMPT_SPLIT_BUFFS",
    "PROMPT_SPLIT_BUFF_CLASSES",
    "ROLEPLAY_BUFFS",
    "ROLEPLAY_BUFF_CLASSES",
    "TRANSLATION_BUFFS",
    "TRANSLATION_BUFF_CLASSES",
    "get_custom_buff_names",
    "register_custom_buffs",
]


ALL_CUSTOM_BUFF_CLASSES: list[type[Buff]] = (
    TRANSLATION_BUFF_CLASSES
    + ROLEPLAY_BUFF_CLASSES
    + PROMPT_SPLIT_BUFF_CLASSES
    + MULTI_TURN_BUFF_CLASSES
)


ALL_CUSTOM_BUFFS: list[dict] = (
    TRANSLATION_BUFFS + ROLEPLAY_BUFFS
    + PROMPT_SPLIT_BUFFS + MULTI_TURN_BUFFS
)


def get_custom_buff_names() -> list[str]:
    """返回所有自研 Buff 的全名列表"""
    return [b["name"] for b in ALL_CUSTOM_BUFFS]


def register_custom_buffs() -> None:
    """注册自定义 Buff 到 garak 插件系统

    三步命名空间注入：
    1. 创建 fake module `garak.buffs.custom` 并挂到 sys.modules
    2. 每个 Buff 类的 __module__ 改为 "garak.buffs.custom"，并注入 fake module.__dict__
    3. 将自定义 Buff 条目注入 garak._plugins.PluginCache，使 enumerate_plugins 可发现
    """

    custom_mod_name = "garak.buffs.custom"

    if custom_mod_name not in sys.modules:
        custom_mod = types.ModuleType(custom_mod_name)
        custom_mod.__file__ = __file__
        custom_mod.__package__ = "garak.buffs"
        sys.modules[custom_mod_name] = custom_mod
    else:
        custom_mod = sys.modules[custom_mod_name]

    for cls in ALL_CUSTOM_BUFF_CLASSES:
        cls.__module__ = custom_mod_name
        setattr(custom_mod, cls.__name__, cls)
        custom_mod.__dict__[cls.__name__] = cls

    cache = _plugins.PluginCache.instance()
    if "buffs" not in cache:
        cache["buffs"] = {}

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %z")
    for cls in ALL_CUSTOM_BUFF_CLASSES:
        plugin_key = f"buffs.custom.{cls.__name__}"
        desc = cls.__doc__.split("\n")[0] if cls.__doc__ else cls.__name__
        cache["buffs"][plugin_key] = {
            "description": desc,
            "active": getattr(cls, "active", True),
            "doc_uri": getattr(cls, "doc_uri", ""),
            "lang": getattr(cls, "lang", None),
            "mod_time": now_str,
        }

    sorted_keys = sorted(cache["buffs"].keys())
    cache["buffs"] = {k: cache["buffs"][k] for k in sorted_keys}
