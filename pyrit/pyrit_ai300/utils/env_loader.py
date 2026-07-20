# -*- coding: utf-8 -*-
"""
AI-300 Framework - Environment Variable Loader
环境变量加载器：从 .env 文件读取敏感配置 + YAML 配置中的 ${VAR} 自动替换

设计原则：
1. 零外部依赖 — 不依赖 python-dotenv，使用内置 os/pathlib/re
2. 加载优先级：系统环境变量 > .env 文件 > YAML 默认值
3. 递归替换 — 支持嵌套 dict/list/str 中的 ${VAR} 模式
4. 安全失败 — 变量未设置时返回空字符串并记录警告，不崩溃

使用方式：
    # 1. 包入口自动加载 .env（在 __init__.py 中调用）
    from pyrit_ai300.utils.env_loader import load_dotenv
    load_dotenv()  # 从项目根目录 .env 文件加载

    # 2. 加载 YAML 配置时自动替换 ${VAR}
    from pyrit_ai300.utils.env_loader import resolve_env_vars
    config = yaml.safe_load(f)
    config = resolve_env_vars(config)  # 递归替换所有 ${VAR}

    # 3. 直接获取环境变量
    from pyrit_ai300.utils.env_loader import get_env
    api_key = get_env("LLM_API_KEY", default="not-needed")
"""

from __future__ import annotations

import logging
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

# ${VAR_NAME} 模式匹配（支持 ${VAR} 和 ${VAR:-default} 两种格式）
_ENV_VAR_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

# 标记是否已加载过 .env 文件
_dotenv_loaded = False


def load_dotenv(env_file: Optional[str] = None) -> bool:
    """
    从 .env 文件加载环境变量到 os.environ

    加载策略：
    1. 如果系统环境变量已设置，不覆盖（系统 > .env）
    2. .env 文件不存在时静默跳过（不影响运行）
    3. 仅在首次调用时加载（幂等）

    Args:
        env_file: .env 文件路径。为 None 时自动查找项目根目录的 .env

    Returns:
        是否成功加载
    """
    global _dotenv_loaded
    if _dotenv_loaded and env_file is None:
        return True

    # 自动查找 .env 文件
    if env_file is None:
        # 搜索策略：依次从 CWD 和 __file__ 路径向上查找
        # 1. 从当前工作目录向上查找（支持从任意目录运行 ai300 命令）
        cwd = Path.cwd()
        for _ in range(5):
            candidate = cwd / ".env"
            if candidate.exists():
                env_file = str(candidate)
                break
            cwd = cwd.parent

        # 2. 从当前文件路径向上查找（支持 site-packages 安装时找到项目根目录）
        if env_file is None:
            current = Path(__file__).resolve().parent
            for _ in range(5):
                candidate = current / ".env"
                if candidate.exists():
                    env_file = str(candidate)
                    break
                current = current.parent

        if env_file is None:
            logger.debug("No .env file found, using system environment variables only")
            # 注意：不设置 _dotenv_loaded=True，允许后续重新查找
            return False

    env_path = Path(env_file)
    if not env_path.exists():
        logger.debug(".env file not found: %s", env_file)
        # 注意：不设置 _dotenv_loaded=True，允许后续重新查找
        return False

    loaded_count = 0
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()
                # 去除引号
                if value and value[0] in ('"', "'") and value[-1] == value[0]:
                    value = value[1:-1]
                # 系统 > .env（不覆盖已有）
                if key and key not in os.environ:
                    os.environ[key] = value
                    loaded_count += 1
    except Exception as e:
        logger.warning("Failed to load .env file %s: %s", env_file, e)
        _dotenv_loaded = True
        return False

    logger.debug("Loaded %d variables from %s", loaded_count, env_file)
    _dotenv_loaded = True
    return True


def get_env(key: str, default: str = "") -> str:
    """
    获取环境变量值（自动加载 .env）

    Args:
        key: 环境变量名
        default: 默认值（变量未设置时返回）

    Returns:
        环境变量值或默认值
    """
    if not _dotenv_loaded:
        load_dotenv()
    return os.environ.get(key, default)


def resolve_env_vars(obj: Any) -> Any:
    """
    递归替换对象中的 ${VAR} 环境变量引用

    支持格式：
        ${VAR}           — 直接引用环境变量
        ${VAR:-default}  — 带默认值的引用（变量未设置时使用 default）

    支持类型：dict / list / str（其他类型原样返回）

    Args:
        obj: 任意 Python 对象（通常从 yaml.safe_load 返回）

    Returns:
        替换后的对象

    示例：
        >>> config = {"api_key": "${LLM_API_KEY}", "nested": {"url": "${BASE_URL}"}}
        >>> resolve_env_vars(config)
        {"api_key": "sk-xxx", "nested": {"url": "https://..."}}
    """
    # 每次都尝试加载 .env（load_dotenv 内部有幂等检查）
    if not _dotenv_loaded:
        load_dotenv()
    # 即使 _dotenv_loaded=True，也确保 env vars 可用
    # （防止首次加载时 .env 尚未创建的情况）

    if isinstance(obj, str):
        return _resolve_string(obj)
    elif isinstance(obj, dict):
        return {k: resolve_env_vars(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [resolve_env_vars(item) for item in obj]
    return obj


def _resolve_string(s: str) -> str:
    """
    替换字符串中的 ${VAR} 和 ${VAR:-default} 模式

    Args:
        s: 原始字符串

    Returns:
        替换后的字符串
    """
    def replacer(match: re.Match) -> str:
        var_name = match.group(1)
        default_val = match.group(2) if match.group(2) is not None else None
        value = os.environ.get(var_name)
        if value is not None:
            return value
        if default_val is not None:
            return default_val
        logger.warning("Environment variable %s not set (in string: %s), using empty string", var_name, s[:80])
        return ""

    return _ENV_VAR_PATTERN.sub(replacer, s)


def resolve_env_in_text(text: str) -> str:
    """
    替换纯文本中的 ${VAR} 环境变量引用（用于 http_request 等多行文本）

    Args:
        text: 原始文本

    Returns:
        替换后的文本
    """
    if not _dotenv_loaded:
        load_dotenv()
    return _resolve_string(text)
