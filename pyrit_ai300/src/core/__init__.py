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
"""

from src.core.models import (
    AISystemType,
    AuthStatus,
    AuthType,
    ReconResult,
    AuthResult,
    StrategySelection,
    OWASPFinding,
    AttackEvidence,
    ReportSummary,
    ReportResult,
    TargetPriority,
    TimeWarning,
    ExamProgress,
    TargetCapabilities,
    create_recon_result,
    create_strategy_selection,
)

from src.core.config_loader import (
    ConfigLoader,
    get_config_loader,
)

from src.core.registry_manager import (
    RegistryManager,
    get_registry_manager,
    reset_registry_manager,
)

from src.core.logging_utils import (
    TeeOutput,
    configure_pyrit_logger,
    get_pyrit_logger,
    setup_logging,
)

from src.core.pipeline_display import (
    PipelineDisplay,
    PyRITNoiseFilter,
    get_display,
    reset_display,
)

# PyRIT 原生 common 工具函数 re-export（统一项目入口）
from pyrit.common.apply_defaults import (
    REQUIRED_VALUE,
    apply_defaults,
    set_default_value,
    reset_default_values,
)
from pyrit.common.default_values import (
    get_non_required_value,
    get_required_value,
)
from pyrit.common.singleton import Singleton
from pyrit.common.utils import (
    combine_dict,
    combine_list,
    verify_and_resolve_path,
)
from pyrit.common.yaml_loadable import YamlLoadable

__all__ = [
    # 枚举类型
    "AISystemType",
    "AuthStatus",
    "AuthType",
    # 模型类
    "ReconResult",
    "AuthResult",
    "StrategySelection",
    "OWASPFinding",
    "AttackEvidence",
    "ReportSummary",
    "ReportResult",
    "TargetPriority",
    "TimeWarning",
    "ExamProgress",
    "TargetCapabilities",
    # 工厂函数
    "create_recon_result",
    "create_strategy_selection",
    # 配置加载器
    "ConfigLoader",
    "get_config_loader",
    # 注册表管理器
    "RegistryManager",
    "get_registry_manager",
    "reset_registry_manager",
    # 日志工具
    "TeeOutput",
    "configure_pyrit_logger",
    "get_pyrit_logger",
    "setup_logging",
    # 展示层
    "PipelineDisplay",
    "PyRITNoiseFilter",
    "get_display",
    "reset_display",
    # PyRIT 原生 common 工具函数 re-export
    "REQUIRED_VALUE",
    "apply_defaults",
    "set_default_value",
    "reset_default_values",
    "get_non_required_value",
    "get_required_value",
    "Singleton",
    "combine_dict",
    "combine_list",
    "verify_and_resolve_path",
    "YamlLoadable",
]
