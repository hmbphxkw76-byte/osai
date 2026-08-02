"""环境变量加载 — 统一从项目根 .env 读取默认参数

提供：
  - load_env()   : 在程序入口调用一次，加载 .env（幂等）
  - get_env()    : 带默认值的读取（优先真实环境变量，其次 .env，最后 default）

设计：
  - 不强制依赖 python-dotenv；若未安装则静默跳过（环境变量仍可从 shell 继承）
  - 加载路径：项目根目录的 .env（相对本文件向上两级）
"""

from __future__ import annotations

import os
from pathlib import Path

_LOADED = False
_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def load_env() -> None:
    """加载项目根 .env（幂等，多次调用仅生效一次）"""
    global _LOADED
    if _LOADED:
        return
    try:
        from dotenv import load_dotenv

        env_path = _PROJECT_ROOT / ".env"
        # override=False: 不覆盖已存在的真实环境变量（shell 优先）
        load_dotenv(dotenv_path=env_path, override=False)
    except Exception:
        # python-dotenv 未安装或 .env 不存在：静默跳过
        pass
    _LOADED = True


def get_env(key: str, default: str = "") -> str:
    """读取环境变量，带默认值

    :param key: 变量名
    :param default: 未设置时的默认值
    :returns: 字符串值
    """
    load_env()
    return os.getenv(key, default)
