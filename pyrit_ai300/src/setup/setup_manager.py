"""
AI-300 Setup Manager — 对齐 pyrit.setup.initialize_pyrit_async
==============================================================

PyRIT 1.0.0 Setup 文档定义三步初始化流程：
  1. Set up environment variables (recommended) → EnvLoader
  2. Pick a database (required) → memory_db_type
  3. Set initialization scripts and defaults (recommended) → Initializers

本模块封装完整的初始化流程：

  from src.setup import initialize_ai300_async
  await initialize_ai300_async()

等价于 PyRIT 文档的 Quick Start:
  from pyrit.setup import initialize_pyrit_async
  from pyrit.setup.initializers import ScorerInitializer, TargetInitializer
  await initialize_pyrit_async(
      memory_db_type="InMemory",
      initializers=[TargetInitializer(), ScorerInitializer()]
  )

关键设计：
  1. 自动发现并加载 .env / .env_local（对齐 PyRIT 原生行为）
  2. 从 config/defaults/pipeline.yaml 读取重试配置并传播到环境变量
  3. 使用 AI300Initializer 体系（Target/Scorer/Technique/Datasets）
  4. 支持 ~/.pyrit/.pyrit_conf 配置文件
  5. 向下游提供 register-then-retrieve 循环

执行顺序（与 PyRIT 文档完全一致）：
  Environment files → Memory database → Initializers (in order)
"""

import logging
import os
from pathlib import Path
from typing import Any, Optional, Sequence

from pyrit.setup import initialize_pyrit_async
from pyrit.setup.pyrit_initializer import PyRITInitializer

from src.setup.env_loader import EnvLoader, discover_env_files
from src.setup.retry_config import RetryConfig, configure_retry_env_vars
from src.setup.ai300_initializers import get_default_initializers
from src.setup.config_file import load_config_file

logger = logging.getLogger(__name__)


# ============================================================
# AI300SetupManager
# ============================================================

class AI300SetupManager:
    """
    AI-300 Setup 管理器

    封装 PyRIT 1.0.0 三步初始化流程：
      Step 1: 环境变量加载 (.env / .env_local)
      Step 2: 数据库配置
      Step 3: 初始化器执行（DefaultValues → Target → Scorer → Technique → Datasets）

    Usage:
        manager = AI300SetupManager()
        result = await manager.initialize_async()

    或一步到位:
        from src.setup import initialize_ai300_async
        await initialize_ai300_async()
    """

    def __init__(
        self,
        *,
        project_root: Optional[Path] = None,
        memory_db_type: Optional[str] = None,
        initializers: Optional[Sequence[PyRITInitializer]] = None,
        initialization_scripts: Optional[Sequence[str | Path]] = None,
        env_files: Optional[Sequence[Path | str]] = None,
        env_akv_ref: Optional[Sequence[str]] = None,
        load_defaults: bool = True,
        silent: bool = False,
        configure_retry: bool = True,
    ) -> None:
        """
        Args:
            project_root: 项目根目录（用于发现 .env 文件）
            memory_db_type: 数据库类型 ("InMemory" / "SQLite" / "AzureSQL")
            initializers: 初始化器列表；None 时使用默认序列
            initialization_scripts: 外部初始化脚本路径列表
            env_files: 显式环境文件路径；None 时自动发现
            env_akv_ref: Azure Key Vault 密钥 URL 列表（对齐原生）
            load_defaults: 无 initializers 时是否加载原生默认初始化器
            silent: 是否静默模式（不打印日志）
            configure_retry: 是否自动配置重试环境变量
        """
        self._project_root = project_root
        self._memory_db_type = memory_db_type
        self._initializers = initializers
        self._initialization_scripts = initialization_scripts
        self._env_files = env_files
        self._env_akv_ref = env_akv_ref
        self._load_defaults = load_defaults
        self._silent = silent
        self._configure_retry = configure_retry

        self._env_loader = EnvLoader(project_root=project_root)
        self._loaded_env_files: list[Path] = []
        self._retry_config: Optional[RetryConfig] = None
        self._initialized: bool = False

    def _resolve_memory_db_type(self) -> str:
        """解析数据库类型"""
        if self._memory_db_type:
            return self._memory_db_type

        from src.core.config_loader import get_config_loader
        return get_config_loader().get_memory_db_type()

    def _resolve_db_path(self) -> Optional[str]:
        """解析数据库路径"""
        from src.core.config_loader import get_config_loader
        loader = get_config_loader()
        db_path = loader.get_memory_db_path()
        if db_path:
            return str(Path(db_path))
        return None

    def _resolve_initializers(self) -> list[PyRITInitializer]:
        """解析初始化器列表"""
        if self._initializers is not None:
            return list(self._initializers)
        return get_default_initializers()

    def _resolve_env_files(self) -> list[Path]:
        """解析环境文件列表"""
        if self._env_files is not None:
            return [Path(f) for f in self._env_files if Path(f).exists()]
        return discover_env_files(self._project_root)

    async def initialize_async(self) -> dict[str, Any]:
        """
        执行完整的三步初始化流程

        Returns:
            初始化结果摘要字典
        """
        if self._initialized:
            logger.warning("AI300SetupManager: already initialized, skipping")
            return {"status": "already_initialized"}

        # Step 1: 发现环境文件（不预加载，交给原生 initialize_pyrit_async 统一加载）
        self._loaded_env_files = self._resolve_env_files()
        if self._loaded_env_files and not self._silent:
            print(f"Found environment files: {[str(f) for f in self._loaded_env_files]}")
        elif not self._silent:
            print("No default environment files found. Using system environment variables only.")

        # Step 1.5: 重试配置传播（设置 RETRY_* 环境变量）
        if self._configure_retry:
            self._retry_config = configure_retry_env_vars()
            if not self._silent:
                print(f"Retry configured: {self._retry_config}")

        # Step 2: 数据库配置
        memory_db_type = self._resolve_memory_db_type()
        db_path = self._resolve_db_path()

        # 构建 memory_instance_kwargs
        memory_kwargs: dict[str, Any] = {}
        if db_path and memory_db_type in ("SQLite", "sqlite"):
            memory_kwargs["db_path"] = db_path

        # 合并从 initialize_ai300_async 传入的额外 memory_kwargs（如 db_path）
        extra_kwargs = getattr(self, "_extra_memory_kwargs", None)
        if extra_kwargs:
            memory_kwargs.update(extra_kwargs)

        # Step 3: 初始化器执行
        initializers = self._resolve_initializers()

        # 调用 PyRIT 原生 initialize_pyrit_async（统一处理 env 文件加载）
        # 注意：不在本地预加载 env 文件，由原生 _load_environment_files 统一处理
        # 这避免了同一文件被 dotenv.load_dotenv 加载两次的问题
        await initialize_pyrit_async(
            memory_db_type=memory_db_type,
            initializers=initializers if initializers else None,
            initialization_scripts=self._initialization_scripts,
            env_files=self._loaded_env_files if self._loaded_env_files else None,
            env_akv_ref=self._env_akv_ref,
            load_defaults=self._load_defaults,
            silent=self._silent,
            **memory_kwargs,
        )

        self._initialized = True

        # 返回结果摘要
        result = {
            "status": "success",
            "memory_db_type": memory_db_type,
            "db_path": db_path,
            "env_files_loaded": [str(f) for f in self._loaded_env_files],
            "initializers_count": len(initializers),
            "initializers": [type(init).__name__ for init in initializers],
            "retry_config": str(self._retry_config) if self._retry_config else None,
        }

        if not self._silent:
            print(f"  [OK] Memory: {memory_db_type}")
            if db_path:
                print(f"  [OK] Database: {db_path}")
            print(f"  [OK] Initializers: {len(initializers)} ({', '.join(result['initializers'])})")

        return result

    @property
    def is_initialized(self) -> bool:
        """是否已初始化"""
        return self._initialized

    @property
    def retry_config(self) -> Optional[RetryConfig]:
        """重试配置"""
        return self._retry_config

    @property
    def loaded_env_files(self) -> list[Path]:
        """已加载的环境文件"""
        return self._loaded_env_files


# ============================================================
# 便捷函数
# ============================================================

async def initialize_ai300_async(
    *,
    memory_db_type: Optional[str] = None,
    initializers: Optional[Sequence[PyRITInitializer]] = None,
    initialization_scripts: Optional[Sequence[str | Path]] = None,
    project_root: Optional[Path] = None,
    env_files: Optional[Sequence[Path | str]] = None,
    env_akv_ref: Optional[Sequence[str]] = None,
    load_defaults: bool = True,
    silent: bool = False,
    configure_retry: bool = True,
    **memory_kwargs: Any,
) -> AI300SetupManager:
    """
    AI-300 一站式初始化（L5 原生优先）

    对齐 PyRIT 文档的 Quick Start:
      from pyrit.setup import initialize_pyrit_async
      from pyrit.setup.initializers import ScorerInitializer, TargetInitializer
      await initialize_pyrit_async(
          memory_db_type="InMemory",
          initializers=[TargetInitializer(), ScorerInitializer()]
      )

    本函数封装了完整的三步初始化流程：
      1. 自动发现并加载 .env / .env_local（由原生统一加载）
      2. 从配置读取数据库类型和路径
      3. 使用默认 AI-300 初始化器序列（原生优先 + AI-300 扩展）

    Args:
        memory_db_type: 数据库类型 ("InMemory" / "SQLite" / "AzureSQL")
        initializers: 初始化器列表；None 时使用默认序列
        initialization_scripts: 外部初始化脚本路径
        project_root: 项目根目录
        env_files: 显式环境文件路径
        env_akv_ref: Azure Key Vault 密钥 URL 列表
        load_defaults: 无 initializers 时是否加载原生默认初始化器
        silent: 静默模式
        configure_retry: 是否自动配置重试
        **memory_kwargs: 传递给 initialize_pyrit_async 的额外参数（如 db_path）

    Returns:
        AI300SetupManager 实例（可用于查询初始化结果）

    Usage:
        # 最简方式（使用全部默认值）
        from src.setup import initialize_ai300_async
        await initialize_ai300_async()

        # 指定 SQLite + 自定义 db_path
        await initialize_ai300_async(memory_db_type="SQLite", db_path="/tmp/exam.db")

        # 使用自定义初始化器
        from src.setup import AI300TargetInitializer, AI300ScorerInitializer
        await initialize_ai300_async(
            initializers=[AI300TargetInitializer(), AI300ScorerInitializer()]
        )
    """
    manager = AI300SetupManager(
        project_root=project_root,
        memory_db_type=memory_db_type,
        initializers=initializers,
        initialization_scripts=initialization_scripts,
        env_files=env_files,
        env_akv_ref=env_akv_ref,
        load_defaults=load_defaults,
        silent=silent,
        configure_retry=configure_retry,
    )

    # 传递额外的 memory_kwargs（如 db_path）
    if memory_kwargs:
        # 直接注入到 manager 的 initialize_async 中
        # 通过临时属性传递，initialize_async 已支持 **memory_kwargs
        manager._extra_memory_kwargs = memory_kwargs

    await manager.initialize_async()
    return manager


async def initialize_from_config_file_async(
    config_path: Optional[Path | str] = None,
) -> AI300SetupManager:
    """
    从配置文件初始化

    对齐 PyRIT 文档:
      from pyrit.setup.configuration_loader import initialize_from_config_async
      await initialize_from_config_async()

    本函数从 ~/.pyrit/.pyrit_conf 加载配置，然后执行初始化。

    Args:
        config_path: 配置文件路径，默认为 ~/.pyrit/.pyrit_conf

    Returns:
        AI300SetupManager 实例
    """
    config = load_config_file(config_path)

    # 解析初始化器
    initializers: list[PyRITInitializer] = []
    for init_config in config.initializers:
        name = init_config.get("name", "")
        args = init_config.get("args", {})

        init_map = {
            "target": "AI300TargetInitializer",
            "scorer": "AI300ScorerInitializer",
            "technique": "AI300TechniqueInitializerWrapper",
            "load_default_datasets": "AI300LoadDefaultDatasets",
            "default_values": "AI300DefaultValuesInitializer",
        }

        if name in init_map:
            from src.setup import ai300_initializers
            init_class = getattr(ai300_initializers, init_map[name])
            init_instance = init_class()
            if args:
                init_instance.set_params_from_args(args=args)
            initializers.append(init_instance)

    manager = AI300SetupManager(
        memory_db_type=config.memory_db_type,
        initializers=initializers if initializers else None,
        initialization_scripts=config.initialization_scripts if config.initialization_scripts else None,
        env_files=[Path(f) for f in config.env_files] if config.env_files else None,
        env_akv_ref=config.env_akv_ref if config.env_akv_ref else None,
        load_defaults=False,
        silent=config.silent,
        configure_retry=True,
    )

    # 设置 scenario_max_retries 到环境变量
    if config.scenario_max_retries > 0:
        os.environ["SCENARIO_MAX_RETRIES"] = str(config.scenario_max_retries)

    await manager.initialize_async()
    return manager
