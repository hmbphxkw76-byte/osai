# -*- coding: utf-8 -*-
"""
AI-300 Framework - Custom Exception Hierarchy (L5)
统一异常分类体系：分类清晰、可恢复、可追踪

异常层级：
    AI300Error (base)
    ├── ConfigError          — 配置加载/验证/环境变量
    │   ├── ConfigNotFoundError
    │   ├── ConfigValidationError
    │   └── EnvVarResolveError
    ├── ReconError           — 侦察阶段
    │   ├── AdapterError
    │   ├── AdapterTimeoutError
    │   └── ProfileMergeError
    ├── AttackError          — 攻击阶段
    │   ├── TargetBuildError
    │   ├── ConverterBuildError
    │   ├── ScorerBuildError
    │   └── AttackExecutionError
    ├── CredentialError      — 凭据管理
    │   └── CredentialExpiredError
    └── PipelineError       — 流水线编排
        └── PhaseExecutionError

设计原则（L5 最佳实践）：
1. 每个异常携带 context dict（结构化诊断信息）
2. 可选 recovery_hint 字段（建议恢复策略）
3. 支持 cause 链（__cause__）
4. __str__ 输出可读的诊断摘要
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════
# Base Exception
# ════════════════════════════════════════════════════════════════

class AI300Error(Exception):
    """
    AI-300 Framework 基础异常

    所有框架自定义异常的基类，携带结构化上下文信息。

    Attributes:
        message: 错误描述
        context: 结构化诊断信息（用于 JSON 日志和追踪）
        recovery_hint: 建议的恢复策略
    """

    def __init__(
        self,
        message: str,
        context: Optional[Dict[str, Any]] = None,
        recovery_hint: str = "",
        cause: Optional[Exception] = None,
    ):
        self.message = message
        self.context = context or {}
        self.recovery_hint = recovery_hint
        if cause:
            self.__cause__ = cause
        super().__init__(message)

    def __str__(self) -> str:
        parts = [self.message]
        if self.context:
            ctx_str = ", ".join(f"{k}={v}" for k, v in self.context.items())
            parts.append(f" [{ctx_str}]")
        if self.recovery_hint:
            parts.append(f" (recovery: {self.recovery_hint})")
        return "".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        """转为字典（用于结构化日志）"""
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "context": self.context,
            "recovery_hint": self.recovery_hint,
        }


# ════════════════════════════════════════════════════════════════
# Config Errors
# ════════════════════════════════════════════════════════════════

class ConfigError(AI300Error):
    """配置相关错误"""
    pass


class ConfigNotFoundError(ConfigError):
    """配置文件未找到"""

    def __init__(self, config_path: str, **kwargs: Any):
        super().__init__(
            message=f"Config file not found: {config_path}",
            context={"config_path": config_path, **kwargs.pop("context", {})},
            recovery_hint="Check file path or create the config file",
            **kwargs,
        )


class ConfigValidationError(ConfigError):
    """配置验证失败"""

    def __init__(self, config_path: str, errors: list, **kwargs: Any):
        super().__init__(
            message=f"Config validation failed: {config_path}",
            context={"config_path": config_path, "validation_errors": errors, **kwargs.pop("context", {})},
            recovery_hint="Fix the validation errors and reload",
            **kwargs,
        )


class EnvVarResolveError(ConfigError):
    """环境变量解析失败"""

    def __init__(self, var_name: str, **kwargs: Any):
        super().__init__(
            message=f"Environment variable not resolved: {var_name}",
            context={"var_name": var_name, **kwargs.pop("context", {})},
            recovery_hint=f"Set {var_name} in .env or system environment",
            **kwargs,
        )


# ════════════════════════════════════════════════════════════════
# Recon Errors
# ════════════════════════════════════════════════════════════════

class ReconError(AI300Error):
    """侦察阶段错误"""
    pass


class AdapterError(ReconError):
    """适配器执行错误"""

    def __init__(self, tool: str, message: str, **kwargs: Any):
        super().__init__(
            message=f"Adapter '{tool}' error: {message}",
            context={"tool": tool, **kwargs.pop("context", {})},
            **kwargs,
        )


class AdapterTimeoutError(ReconError):
    """适配器超时"""

    def __init__(self, tool: str, timeout: float, **kwargs: Any):
        super().__init__(
            message=f"Adapter '{tool}' timed out after {timeout}s",
            context={"tool": tool, "timeout": timeout, **kwargs.pop("context", {})},
            recovery_hint="Increase timeout or check target availability",
            **kwargs,
        )


class ProfileMergeError(ReconError):
    """画像合并错误"""

    def __init__(self, message: str, **kwargs: Any):
        super().__init__(message, **kwargs)


# ════════════════════════════════════════════════════════════════
# Attack Errors
# ════════════════════════════════════════════════════════════════

class AttackError(AI300Error):
    """攻击阶段错误"""
    pass


class TargetBuildError(AttackError):
    """目标构建错误"""

    def __init__(self, target_type: str, message: str, **kwargs: Any):
        super().__init__(
            message=f"Target build failed ({target_type}): {message}",
            context={"target_type": target_type, **kwargs.pop("context", {})},
            **kwargs,
        )


class ConverterBuildError(AttackError):
    """转换器构建错误"""

    def __init__(self, converter_name: str, message: str, **kwargs: Any):
        super().__init__(
            message=f"Converter '{converter_name}' build failed: {message}",
            context={"converter_name": converter_name, **kwargs.pop("context", {})},
            recovery_hint="Check converter params or use default params",
            **kwargs,
        )


class ScorerBuildError(AttackError):
    """评分器构建错误"""

    def __init__(self, scorer_type: str, message: str, **kwargs: Any):
        super().__init__(
            message=f"Scorer '{scorer_type}' build failed: {message}",
            context={"scorer_type": scorer_type, **kwargs.pop("context", {})},
            recovery_hint="Check scorer config or use rule-based fallback",
            **kwargs,
        )


class AttackExecutionError(AttackError):
    """攻击执行错误"""

    def __init__(self, attack_class: str, message: str, **kwargs: Any):
        super().__init__(
            message=f"Attack '{attack_class}' execution failed: {message}",
            context={"attack_class": attack_class, **kwargs.pop("context", {})},
            **kwargs,
        )


# ════════════════════════════════════════════════════════════════
# Credential Errors
# ════════════════════════════════════════════════════════════════

class CredentialError(AI300Error):
    """凭据管理错误"""
    pass


class CredentialExpiredError(CredentialError):
    """凭据已过期"""

    def __init__(self, domain: str, **kwargs: Any):
        super().__init__(
            message=f"Credential expired for domain: {domain}",
            context={"domain": domain, **kwargs.pop("context", {})},
            recovery_hint="Re-authenticate to obtain fresh credentials",
            **kwargs,
        )


# ════════════════════════════════════════════════════════════════
# Pipeline Errors
# ════════════════════════════════════════════════════════════════

class PipelineError(AI300Error):
    """流水线编排错误"""
    pass


class PhaseExecutionError(PipelineError):
    """阶段执行错误"""

    def __init__(self, phase: str, message: str, **kwargs: Any):
        super().__init__(
            message=f"Phase '{phase}' execution failed: {message}",
            context={"phase": phase, **kwargs.pop("context", {})},
            **kwargs,
        )


# ════════════════════════════════════════════════════════════════
# Helper: Safe execution decorator
# ════════════════════════════════════════════════════════════════

def safe_execute(
    operation: str,
    error_cls: type = AI300Error,
    recovery_hint: str = "",
    reraise: bool = True,
    default_return: Any = None,
):
    """
    安全执行装饰器：统一异常捕获与转换

    Args:
        operation: 操作描述（用于日志）
        error_cls: 转换为的异常类型
        recovery_hint: 恢复建议
        reraise: 是否重新抛出（False 时返回 default_return）
        default_return: reraise=False 时的默认返回值

    Returns:
        装饰器函数

    Usage:
        @safe_execute("adapter run", AdapterError, reraise=False)
        def run_adapter(target, config):
            ...
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except AI300Error:
                raise
            except Exception as e:
                logger.error("%s failed: %s", operation, e, exc_info=True)
                if reraise:
                    raise error_cls(
                        message=str(e),
                        context={"operation": operation, "function": func.__name__},
                        recovery_hint=recovery_hint,
                        cause=e,
                    ) from e
                logger.warning("%s: using fallback (recovery: %s)", operation, recovery_hint)
                return default_return
        return wrapper
    return decorator
