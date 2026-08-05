# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""集中式配置加载。

职责:
  - 从 config/settings.py 读取开箱即用的最优默认参数
  - 从 .env 读取必填变量 (TARGET_URL) 和可选凭证 (API_KEY)
  - 其余可选变量 (TARGET_TYPE / AUTH_TYPE / ORG_DOMAINS 等) 未设置时
    自动使用 config/settings.py RuntimeDefaults 中的默认值
  - 提供统一访问入口, 供各阶段/探针引用

不在此处定义任何"应随环境变化"的机密或目标特定值。
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from config.settings import DEFAULT_SETTINGS, PipelineSettings

_DOTENV_PATH = Path(__file__).resolve().parent.parent / ".env"


def _load_dotenv() -> dict[str, str]:
    """极简 .env 解析。"""
    env: dict[str, str] = {}
    if _DOTENV_PATH.exists():
        for line in _DOTENV_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            env[key.strip()] = val.strip().strip('"').strip("'")
    return env


@lru_cache(maxsize=1)
def get_settings() -> PipelineSettings:
    """返回全局配置单例 (已合并 .env 环境变量)。"""
    dotenv = _load_dotenv()
    merged_env = {**dotenv, **os.environ}
    # 当前阶段:.env 仅提供"运行参数", 不动 settings 的冻结默认值。
    # 若未来需要按环境变量覆盖超时等, 在此展开。
    _ = merged_env
    return DEFAULT_SETTINGS


def env(key: str, default: str = "") -> str:
    """读取必须通过 .env 修改的变量。"""
    dotenv = _load_dotenv()
    return os.environ.get(key) or dotenv.get(key) or default


def as_dict() -> dict[str, Any]:
    """返回配置的可序列化字典 (调试用)。"""
    return DEFAULT_SETTINGS.__class__ and _settings_to_dict(DEFAULT_SETTINGS)


def _settings_to_dict(settings: PipelineSettings) -> dict[str, Any]:
    import dataclasses

    def conv(obj: Any) -> Any:
        if dataclasses.is_dataclass(obj):
            return {f.name: conv(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
        if isinstance(obj, tuple):
            return list(obj)
        return obj

    return conv(settings)
