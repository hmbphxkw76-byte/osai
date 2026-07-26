"""
AI-300 Setup Module — 对齐 pyrit.setup
======================================

PyRIT 1.0.0 Setup 子系统 — 初始化、配置、弹性重试

本模块封装 PyRIT 原生 setup 体系，为 AI-300 考试场景提供：
  - initialize_pyrit_async 包装器（env 加载 + retry 配置 + initializers）
  - AI300Initializer 体系（Target/Scorer/Technique/Datasets 四大初始化器）
  - 弹性重试配置（三层重试机制环境变量传播）
  - 配置文件支持（~/.pyrit/.pyrit_conf）
  - 默认值体系（set_default_value + @apply_defaults）

对齐 PyRIT 1.0.0 Setup 文档的五大主题：
  1. Setup — initialize_pyrit_async 三步走（env vars → database → initializers）
  2. Configuration — .env / .env_local / ~/.pyrit/.pyrit_conf 三级配置
  3. Resiliency — target-level / json-level / scenario-level 三层重试
  4. Default Values — set_default_value + @apply_defaults 装饰器
  5. PyRIT Initializers — PyRITInitializer 基类 + 四大内置初始化器

模块组成：
  - setup_manager.py     AI300SetupManager 初始化管理器
  - env_loader.py        环境变量加载器（.env + .env_local）
  - retry_config.py      三层重试配置传播器
  - ai300_initializers.py  AI-300 专用 PyRITInitializer 子类
  - config_file.py      ~/.pyrit/.pyrit_conf 配置文件支持
"""

from src.setup.setup_manager import (
    AI300SetupManager,
    initialize_ai300_async,
    initialize_from_config_file_async,
)
from src.setup.env_loader import (
    EnvLoader,
    load_env_files,
    discover_env_files,
)
from src.setup.retry_config import (
    RetryConfig,
    configure_retry_env_vars,
    get_retry_config,
)
from src.setup.ai300_initializers import (
    AI300TargetInitializer,
    AI300ScorerInitializer,
    AI300TechniqueInitializerWrapper,
    AI300LoadDefaultDatasets,
    AI300DefaultValuesInitializer,
)
from src.setup.config_file import (
    AI300ConfigFile,
    load_config_file,
    save_config_file,
)

__all__ = [
    # Setup Manager
    "AI300SetupManager",
    "initialize_ai300_async",
    "initialize_from_config_file_async",
    # Env Loader
    "EnvLoader",
    "load_env_files",
    "discover_env_files",
    # Retry Config
    "RetryConfig",
    "configure_retry_env_vars",
    "get_retry_config",
    # AI-300 Initializers
    "AI300TargetInitializer",
    "AI300ScorerInitializer",
    "AI300TechniqueInitializerWrapper",
    "AI300LoadDefaultDatasets",
    "AI300DefaultValuesInitializer",
    # Config File
    "AI300ConfigFile",
    "load_config_file",
    "save_config_file",
]
