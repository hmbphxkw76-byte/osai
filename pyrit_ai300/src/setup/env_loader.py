"""
Environment Variable Loader — 对齐 PyRIT .env / .env_local 加载
================================================================

PyRIT 1.0.0 Configuration 文档要求：
  - .env 文件提供基础环境变量
  - .env_local 文件覆盖 .env（用于个人覆盖团队共享配置）
  PyRIT 原生 initialize_pyrit_async 自动发现并加载 .env 和 .env_local

本模块提供：
  1. discover_env_files() — 发现项目根目录和 ~/.pyrit/ 下的 .env 文件
  2. load_env_files() — 加载 .env 和 .env_local（后者覆盖前者）
  3. EnvLoader — 封装环境变量加载逻辑

设计原则：
  - .env_local 总是覆盖 .env（与 PyRIT 原生行为一致）
  - 优先级：系统环境变量 > .env_local > .env
  - 向 PyRIT 的 env_files 参数传递发现的文件列表
"""

import os
from pathlib import Path
from typing import Optional, Sequence

from dotenv import load_dotenv

from src.core.config_loader import get_config_loader


# ============================================================
# 环境文件发现
# ============================================================

def discover_env_files(
    project_root: Optional[Path] = None,
    *,
    check_pyrit_dir: bool = True,
) -> list[Path]:
    """
    发现环境变量文件

    查找顺序（与 PyRIT 原生一致）：
      1. <project_root>/.env          — 项目级共享配置
      2. <project_root>/.env_local    — 个人覆盖（覆盖 .env）
      3. ~/.pyrit/.env                — PyRIT 全局配置
      4. ~/.pyrit/.env_local          — PyRIT 全局个人覆盖

    Args:
        project_root: 项目根目录，默认为当前工作区根
        check_pyrit_dir: 是否检查 ~/.pyrit/ 目录

    Returns:
        已存在的环境文件路径列表（按加载顺序排列）
    """
    if project_root is None:
        project_root = Path(get_config_loader().config_dir).parent

    candidates: list[Path] = []

    # 项目级环境文件
    project_env = project_root / ".env"
    project_env_local = project_root / ".env_local"

    if project_env.exists():
        candidates.append(project_env)
    if project_env_local.exists():
        candidates.append(project_env_local)

    # PyRIT 全局环境文件
    if check_pyrit_dir:
        pyrit_dir = Path.home() / ".pyrit"
        pyrit_env = pyrit_dir / ".env"
        pyrit_env_local = pyrit_dir / ".env_local"

        if pyrit_env.exists():
            candidates.append(pyrit_env)
        if pyrit_env_local.exists():
            candidates.append(pyrit_env_local)

    return candidates


def load_env_files(
    env_files: Optional[Sequence[Path | str]] = None,
    *,
    project_root: Optional[Path] = None,
    override: bool = True,
) -> list[Path]:
    """
    加载环境变量文件

    按 .env → .env_local 顺序加载，后加载的覆盖先加载的。
    如果 env_files 为 None，自动发现文件。

    Args:
        env_files: 显式指定的环境文件路径列表
        project_root: 项目根目录（用于自动发现）
        override: 是否覆盖已存在的系统环境变量

    Returns:
        实际加载的文件路径列表
    """
    if env_files is None:
        loaded_files = discover_env_files(project_root)
    else:
        loaded_files = [Path(f) for f in env_files if Path(f).exists()]

    for env_file in loaded_files:
        load_dotenv(env_file, override=override)

    return loaded_files


# ============================================================
# EnvLoader 封装类
# ============================================================

class EnvLoader:
    """
    环境变量加载器

    封装 .env / .env_local 发现和加载逻辑。

    Usage:
        loader = EnvLoader()
        files = loader.load()
        print(f"Loaded {len(files)} env files")

    或传递给 PyRIT 原生 initialize_pyrit_async:
        files = loader.discover()
        await initialize_pyrit_async(
            memory_db_type="InMemory",
            env_files=files,
        )
    """

    def __init__(
        self,
        *,
        project_root: Optional[Path] = None,
        check_pyrit_dir: bool = True,
    ) -> None:
        self._project_root = project_root
        self._check_pyrit_dir = check_pyrit_dir
        self._loaded_files: list[Path] = []

    def discover(self) -> list[Path]:
        """发现环境变量文件"""
        return discover_env_files(
            self._project_root,
            check_pyrit_dir=self._check_pyrit_dir,
        )

    def load(self, *, override: bool = True) -> list[Path]:
        """加载环境变量文件"""
        self._loaded_files = load_env_files(
            project_root=self._project_root,
            override=override,
        )
        return self._loaded_files

    def get_loaded_files(self) -> list[Path]:
        """获取已加载的文件列表"""
        return self._loaded_files

    def get_env(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """获取环境变量"""
        return os.getenv(key, default)

    def require_env(self, key: str) -> str:
        """
        获取必需的环境变量

        Raises:
            ValueError: 环境变量未设置
        """
        value = os.getenv(key)
        if not value:
            raise ValueError(
                f"Required environment variable '{key}' is not set. "
                f"Please set it in .env or .env_local file."
            )
        return value

    def print_loaded_files(self) -> None:
        """打印已加载的环境文件"""
        if not self._loaded_files:
            print("No environment files found. Using system environment variables only.")
        else:
            print(f"Found environment files: {[str(f) for f in self._loaded_files]}")
            for f in self._loaded_files:
                print(f"Loaded environment file: {f}")
