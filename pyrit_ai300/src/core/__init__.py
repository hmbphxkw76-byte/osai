"""
Core Module
===========

本模块包含核心数据模型和配置加载器。
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
]