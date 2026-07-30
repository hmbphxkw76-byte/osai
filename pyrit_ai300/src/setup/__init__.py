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

性能优化 (v8.2):
  使用 PEP 562 __getattr__ 实现懒加载。ai300_initializers 模块导入了
  pyrit.prompt_target.OpenAIChatTarget（重模块），懒加载可推迟到实际使用时。
  推荐直接从子模块导入：
    from src.setup.setup_manager import initialize_ai300_async  # ✓ 最快
"""

# 懒加载映射表
_LAZY_IMPORTS = {
    # ── setup_manager ──
    "AI300SetupManager": ("src.setup.setup_manager", "AI300SetupManager"),
    "initialize_ai300_async": ("src.setup.setup_manager", "initialize_ai300_async"),
    "initialize_from_config_file_async": ("src.setup.setup_manager", "initialize_from_config_file_async"),
    # ── env_loader ──
    "EnvLoader": ("src.setup.env_loader", "EnvLoader"),
    "load_env_files": ("src.setup.env_loader", "load_env_files"),
    "discover_env_files": ("src.setup.env_loader", "discover_env_files"),
    # ── retry_config ──
    "RetryConfig": ("src.setup.retry_config", "RetryConfig"),
    "configure_retry_env_vars": ("src.setup.retry_config", "configure_retry_env_vars"),
    "get_retry_config": ("src.setup.retry_config", "get_retry_config"),
    # ── ai300_initializers ──
    "AI300TargetInitializer": ("src.setup.ai300_initializers", "AI300TargetInitializer"),
    "AI300ScorerInitializer": ("src.setup.ai300_initializers", "AI300ScorerInitializer"),
    "AI300TechniqueInitializerWrapper": ("src.setup.ai300_initializers", "AI300TechniqueInitializerWrapper"),
    "AI300LoadDefaultDatasets": ("src.setup.ai300_initializers", "AI300LoadDefaultDatasets"),
    "AI300DefaultValuesInitializer": ("src.setup.ai300_initializers", "AI300DefaultValuesInitializer"),
    "AI300PreloadScenarioMetadata": ("src.setup.ai300_initializers", "AI300PreloadScenarioMetadata"),
    # ── config_file ──
    "AI300ConfigFile": ("src.setup.config_file", "AI300ConfigFile"),
    "load_config_file": ("src.setup.config_file", "load_config_file"),
    "save_config_file": ("src.setup.config_file", "save_config_file"),
}

__all__ = list(_LAZY_IMPORTS.keys())


def __getattr__(name: str):
    """PEP 562 懒加载：首次访问属性时才触发对应模块的导入。"""
    import importlib

    mapping = _LAZY_IMPORTS.get(name)
    if mapping is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    module_path, attr_name = mapping
    module = importlib.import_module(module_path)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value
