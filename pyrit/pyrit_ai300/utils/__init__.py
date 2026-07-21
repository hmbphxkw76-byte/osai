"""
AI-300 Framework - Utilities Module
工具函数模块
"""

from .platform import setup_windows_utf8
from .logger import setup_logger
from .async_helper import run_async, run_async_batch, AsyncRunner
from .env_loader import load_dotenv, get_env, resolve_env_vars, resolve_env_in_text
from .exceptions import (
    AI300Error,
    ConfigError,
    ConfigNotFoundError,
    ConfigValidationError,
    EnvVarResolveError,
    ReconError,
    AdapterError,
    AdapterTimeoutError,
    ProfileMergeError,
    AttackError,
    TargetBuildError,
    ConverterBuildError,
    ScorerBuildError,
    AttackExecutionError,
    CredentialError,
    CredentialExpiredError,
    PipelineError,
    PhaseExecutionError,
    safe_execute,
)
from .structured_log import (
    StructuredLogger,
    BoundLogger,
    StructuredLogFormatter,
    TextLogFormatter,
    setup_structured_logging,
)
from .config_validator import (
    ConfigValidator,
    ReconConfigSchema,
    ScorerBackendConfig,
    AttackConfigSchema,
    TargetConfigSchema,
)
from .protocols import (
    ReconEngineProtocol,
    ProfileMergerProtocol,
    BaseAdapterProtocol,
    AttackOrchestratorProtocol,
    SmartMatcherProtocol,
    ConverterBuilderProtocol,
    ScorerBuilderProtocol,
    PipelineOrchestratorProtocol,
    CredentialManagerProtocol,
    RateControllerProtocol,
)

__all__ = [
    "setup_windows_utf8",
    "setup_logger",
    "run_async",
    "run_async_batch",
    "AsyncRunner",
    "load_dotenv",
    "get_env",
    "resolve_env_vars",
    "resolve_env_in_text",
    # L5: 异常分类体系
    "AI300Error",
    "ConfigError",
    "ConfigNotFoundError",
    "ConfigValidationError",
    "EnvVarResolveError",
    "ReconError",
    "AdapterError",
    "AdapterTimeoutError",
    "ProfileMergeError",
    "AttackError",
    "TargetBuildError",
    "ConverterBuildError",
    "ScorerBuildError",
    "AttackExecutionError",
    "CredentialError",
    "CredentialExpiredError",
    "PipelineError",
    "PhaseExecutionError",
    "safe_execute",
    # L5: 结构化日志
    "StructuredLogger",
    "BoundLogger",
    "StructuredLogFormatter",
    "TextLogFormatter",
    "setup_structured_logging",
    # L5: 配置验证
    "ConfigValidator",
    "ReconConfigSchema",
    "ScorerBackendConfig",
    "AttackConfigSchema",
    "TargetConfigSchema",
    # L5: Protocol 接口
    "ReconEngineProtocol",
    "ProfileMergerProtocol",
    "BaseAdapterProtocol",
    "AttackOrchestratorProtocol",
    "SmartMatcherProtocol",
    "ConverterBuilderProtocol",
    "ScorerBuilderProtocol",
    "PipelineOrchestratorProtocol",
    "CredentialManagerProtocol",
    "RateControllerProtocol",
]
