"""
Core Module
===========

本模块包含核心数据模型、配置加载器、注册表管理器和日志工具。

PyRIT 1.0.0 原生集成（L5 专家水准）：
- TargetCapabilities: 使用原生 pyrit.models.TargetCapabilities
- ConfigLoader: 集成原生 verify_and_resolve_path / get_non_required_value /
  set_default_value / ConfigurationLoader / CentralMemory
- RegistryManager: 原生 6 大 Registry Facade
- logging_utils: 集成原生 pyrit.common.logger
- Re-export 原生 common 工具函数，使项目代码统一入口

性能优化 (v8.2):
  本模块使用 PEP 562 __getattr__ 实现懒加载。
  import src.core 不会触发任何子模块加载；
  首次访问属性时才按需导入对应模块。
  经测试：eager import 导致 ~1s 启动延迟（registry_manager 导入 6 大 Registry），
  lazy import 降至 ~0ms。

  推荐用法（直接从子模块导入，避免 __getattr__ 开销）：
    from src.core.config_loader import get_config_loader  # ✓ 最快
    from src.core.models import ReconResult               # ✓ 最快
  向后兼容用法（通过 __getattr__ 懒加载）：
    from src.core import get_config_loader                # ✓ 可用但稍慢
    from src.core import verify_and_resolve_path          # ✓ 可用但稍慢
"""

# 懒加载映射表：属性名 → (模块路径, 属性名)
# 首次访问时通过 __getattr__ 触发导入
_LAZY_IMPORTS = {
    # ── src.core.models ──
    "AISystemType": ("src.core.models", "AISystemType"),
    "AuthStatus": ("src.core.models", "AuthStatus"),
    "AuthType": ("src.core.models", "AuthType"),
    "ReconResult": ("src.core.models", "ReconResult"),
    "AuthResult": ("src.core.models", "AuthResult"),
    "StrategySelection": ("src.core.models", "StrategySelection"),
    "OWASPFinding": ("src.core.models", "OWASPFinding"),
    "AttackEvidence": ("src.core.models", "AttackEvidence"),
    "ReportSummary": ("src.core.models", "ReportSummary"),
    "ReportResult": ("src.core.models", "ReportResult"),
    "TargetPriority": ("src.core.models", "TargetPriority"),
    "TimeWarning": ("src.core.models", "TimeWarning"),
    "ExamProgress": ("src.core.models", "ExamProgress"),
    "TargetCapabilities": ("src.core.models", "TargetCapabilities"),
    "create_recon_result": ("src.core.models", "create_recon_result"),
    "create_strategy_selection": ("src.core.models", "create_strategy_selection"),
    # ── src.core.config_loader ──
    "ConfigLoader": ("src.core.config_loader", "ConfigLoader"),
    "get_config_loader": ("src.core.config_loader", "get_config_loader"),
    # ── src.core.registry_manager ──
    "RegistryManager": ("src.core.registry_manager", "RegistryManager"),
    "get_registry_manager": ("src.core.registry_manager", "get_registry_manager"),
    "reset_registry_manager": ("src.core.registry_manager", "reset_registry_manager"),
    # ── src.core.logging_utils ──
    "TeeOutput": ("src.core.logging_utils", "TeeOutput"),
    "configure_pyrit_logger": ("src.core.logging_utils", "configure_pyrit_logger"),
    "get_pyrit_logger": ("src.core.logging_utils", "get_pyrit_logger"),
    "setup_logging": ("src.core.logging_utils", "setup_logging"),
    # ── src.core.pipeline_display ──
    "PipelineDisplay": ("src.core.pipeline_display", "PipelineDisplay"),
    "PyRITNoiseFilter": ("src.core.pipeline_display", "PyRITNoiseFilter"),
    "get_display": ("src.core.pipeline_display", "get_display"),
    "reset_display": ("src.core.pipeline_display", "reset_display"),
    # ── PyRIT 原生 common 工具函数 re-export ──
    "REQUIRED_VALUE": ("pyrit.common.apply_defaults", "REQUIRED_VALUE"),
    "apply_defaults": ("pyrit.common.apply_defaults", "apply_defaults"),
    "set_default_value": ("pyrit.common.apply_defaults", "set_default_value"),
    "reset_default_values": ("pyrit.common.apply_defaults", "reset_default_values"),
    "get_non_required_value": ("pyrit.common.default_values", "get_non_required_value"),
    "get_required_value": ("pyrit.common.default_values", "get_required_value"),
    "Singleton": ("pyrit.common.singleton", "Singleton"),
    "combine_dict": ("pyrit.common.utils", "combine_dict"),
    "combine_list": ("pyrit.common.utils", "combine_list"),
    "verify_and_resolve_path": ("pyrit.common.utils", "verify_and_resolve_path"),
    "YamlLoadable": ("pyrit.common.yaml_loadable", "YamlLoadable"),
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
    globals()[name] = value  # 缓存到 globals，后续访问直接命中
    return value
