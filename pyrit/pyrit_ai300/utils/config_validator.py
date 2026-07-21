# -*- coding: utf-8 -*-
"""
AI-300 Framework - Config Validator (L5)
配置验证模块：基于 dataclass 的声明式 schema 验证

特性：
1. 声明式配置 schema（dataclass + 类型注解）
2. 多级验证：类型检查 + 值域约束 + 必填字段
3. 清晰的错误报告（字段路径 + 验证错误列表）
4. 向后兼容：验证失败时返回默认值，不中断运行
5. 支持嵌套配置（dict 中的 dict/list）

设计原则（L5 最佳实践）：
- 配置验证与业务逻辑分离
- 快速失败：配置错误在启动时发现，不延迟到运行时
- 错误信息可操作：指明哪个字段、期望什么、实际什么
- 零外部依赖：不依赖 pydantic，使用标准库 dataclass + typing
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, fields
from typing import Any, Dict, List, Optional, Tuple, Type, get_args, get_origin, get_type_hints

from .exceptions import ConfigValidationError

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════
# 配置 Schema 定义
# ════════════════════════════════════════════════════════════════

@dataclass
class ReconToolConfig:
    """单个侦察工具配置 schema"""
    enabled: bool = True
    timeout: int = 300
    depth: str = "standard"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReconToolConfig":
        """从字典创建，忽略未知字段"""
        valid_keys = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


@dataclass
class ReconConfigSchema:
    """侦察配置 schema（recon.yaml）"""
    cache: Dict[str, Any] = field(default_factory=lambda: {"enabled": True, "ttl_hours": 24})
    tools: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    depth: str = "standard"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReconConfigSchema":
        valid_keys = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


@dataclass
class ScorerBackendConfig:
    """评分器后端配置 schema"""
    provider: str = "ollama"
    base_url: str = "http://localhost:11434/v1"
    api_key: str = ""
    model_name: str = "gpt-4o-mini"
    temperature: float = 0.0
    max_tokens: int = 1024

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScorerBackendConfig":
        valid_keys = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


@dataclass
class AttackConfigSchema:
    """攻击配置 schema（单个 attack 配置）"""
    name: str = ""
    mode: str = "smart_match"
    payloads: List[Any] = field(default_factory=list)
    owasp_id: str = ""
    asi_category: str = ""
    severity: str = "medium"
    target_model: str = ""
    converter_presets: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class TargetConfigSchema:
    """目标配置 schema"""
    url: str = ""
    target_type: str = ""
    api_key: str = ""
    model_name: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TargetConfigSchema":
        valid_keys = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


# ════════════════════════════════════════════════════════════════
# 验证器
# ════════════════════════════════════════════════════════════════

class ConfigValidator:
    """
    配置验证器

    对 YAML 加载后的 dict 进行类型检查和值域约束验证。

    Usage:
        validator = ConfigValidator()
        errors = validator.validate_recon_config(config_dict)
        if errors:
            raise ConfigValidationError("recon.yaml", errors)
    """

    @staticmethod
    def validate_type(value: Any, expected_type: Type, field_name: str) -> List[str]:
        """
        验证值类型

        Returns:
            错误列表（空列表表示通过）
        """
        errors: List[str] = []
        origin = get_origin(expected_type)
        args = get_args(expected_type)

        if origin is None:
            # 简单类型
            if not isinstance(value, expected_type):
                errors.append(
                    f"{field_name}: expected {expected_type.__name__}, got {type(value).__name__}"
                )
        elif origin is list:
            if not isinstance(value, list):
                errors.append(f"{field_name}: expected list, got {type(value).__name__}")
        elif origin is dict:
            if not isinstance(value, dict):
                errors.append(f"{field_name}: expected dict, got {type(value).__name__}")
        elif origin is Optional or (origin is Union and type(None) in args):
            # Optional[X] → 检查非 None 时类型
            non_none_args = [a for a in args if a is not type(None)]
            if value is not None and len(non_none_args) == 1:
                errors.extend(ConfigValidator.validate_type(value, non_none_args[0], field_name))

        return errors

    @staticmethod
    def validate_recon_config(config: Dict[str, Any]) -> List[str]:
        """
        验证侦察配置

        Returns:
            验证错误列表（空列表表示通过）
        """
        errors: List[str] = []

        # 检查 tools 字段
        tools = config.get("tools", {})
        if not isinstance(tools, dict):
            errors.append("tools: expected dict, got " + type(tools).__name__)
        else:
            for tool_name, tool_config in tools.items():
                if not isinstance(tool_config, dict):
                    errors.append(f"tools.{tool_name}: expected dict, got {type(tool_config).__name__}")
                    continue
                # 检查 enabled 字段
                if "enabled" in tool_config and not isinstance(tool_config["enabled"], bool):
                    errors.append(f"tools.{tool_name}.enabled: expected bool")
                # 检查 timeout 字段
                if "timeout" in tool_config:
                    if not isinstance(tool_config["timeout"], (int, float)):
                        errors.append(f"tools.{tool_name}.timeout: expected number")
                    elif tool_config["timeout"] <= 0:
                        errors.append(f"tools.{tool_name}.timeout: must be positive")

        # 检查 cache 字段
        cache = config.get("cache", {})
        if not isinstance(cache, dict):
            errors.append("cache: expected dict, got " + type(cache).__name__)
        else:
            if "enabled" in cache and not isinstance(cache["enabled"], bool):
                errors.append("cache.enabled: expected bool")
            if "ttl_hours" in cache:
                if not isinstance(cache["ttl_hours"], (int, float)) or cache["ttl_hours"] <= 0:
                    errors.append("cache.ttl_hours: expected positive number")

        # 检查 depth 字段
        depth = config.get("depth", "standard")
        if depth not in ("quick", "standard", "deep"):
            errors.append(f"depth: expected quick/standard/deep, got '{depth}'")

        return errors

    @staticmethod
    def validate_scorer_backend(config: Dict[str, Any], backend_name: str = "") -> List[str]:
        """
        验证评分器后端配置

        Returns:
            验证错误列表
        """
        errors: List[str] = []
        prefix = f"backend '{backend_name}'" if backend_name else "backend"

        # provider 必须是字符串
        provider = config.get("provider", "ollama")
        if not isinstance(provider, str):
            errors.append(f"{prefix}.provider: expected str")

        # base_url 必须是字符串且以 http 开头
        base_url = config.get("base_url", "")
        if not isinstance(base_url, str):
            errors.append(f"{prefix}.base_url: expected str")
        elif base_url and not base_url.startswith("http"):
            errors.append(f"{prefix}.base_url: must start with http:// or https://")

        # api_key 必须是字符串
        api_key = config.get("api_key", "")
        if not isinstance(api_key, str):
            errors.append(f"{prefix}.api_key: expected str")

        # model_name 必须是字符串
        model_name = config.get("model_name", "")
        if not isinstance(model_name, str):
            errors.append(f"{prefix}.model_name: expected str")

        # temperature 必须在 0-2 之间
        temperature = config.get("temperature", 0.0)
        if not isinstance(temperature, (int, float)):
            errors.append(f"{prefix}.temperature: expected number")
        elif temperature < 0 or temperature > 2:
            errors.append(f"{prefix}.temperature: must be 0.0-2.0, got {temperature}")

        # max_tokens 必须是正整数
        max_tokens = config.get("max_tokens", 1024)
        if not isinstance(max_tokens, int) or max_tokens <= 0:
            errors.append(f"{prefix}.max_tokens: expected positive int")

        return errors

    @staticmethod
    def validate_attack_config(config: Dict[str, Any]) -> List[str]:
        """
        验证攻击配置

        Returns:
            验证错误列表
        """
        errors: List[str] = []

        # name 必须存在
        if not config.get("name"):
            errors.append("name: required field is empty or missing")

        # mode 必须是有效值
        mode = config.get("mode", "smart_match")
        valid_modes = {"smart_match", "chain", "presets", "single"}
        if mode not in valid_modes:
            errors.append(f"mode: expected one of {valid_modes}, got '{mode}'")

        # payloads 必须是列表
        payloads = config.get("payloads", [])
        if not isinstance(payloads, list):
            errors.append(f"payloads: expected list, got {type(payloads).__name__}")

        # converter_presets 必须是 dict（如果存在）
        presets = config.get("converter_presets", {})
        if not isinstance(presets, dict):
            errors.append(f"converter_presets: expected dict, got {type(presets).__name__}")

        return errors

    @staticmethod
    def validate_target_config(config: Dict[str, Any]) -> List[str]:
        """
        验证目标配置

        Returns:
            验证错误列表
        """
        errors: List[str] = []

        url = config.get("url", "")
        if not url:
            errors.append("url: required field is empty")
        elif not isinstance(url, str):
            errors.append("url: expected str")
        elif not url.startswith("http"):
            errors.append("url: must start with http:// or https://")

        return errors

    @staticmethod
    def validate_or_default(
        config: Dict[str, Any],
        config_type: str,
        config_path: str = "",
    ) -> Dict[str, Any]:
        """
        验证配置，验证失败时记录警告并返回原始配置（不中断）

        Args:
            config: 配置字典
            config_type: 配置类型 ("recon"/"scorer_backend"/"attack"/"target")
            config_path: 配置文件路径（用于错误信息）

        Returns:
            原始配置字典（验证仅产生警告，不修改配置）
        """
        validators = {
            "recon": ConfigValidator.validate_recon_config,
            "scorer_backend": ConfigValidator.validate_scorer_backend,
            "attack": ConfigValidator.validate_attack_config,
            "target": ConfigValidator.validate_target_config,
        }

        validator = validators.get(config_type)
        if not validator:
            logger.warning("Unknown config type for validation: %s", config_type)
            return config

        errors = validator(config)
        if errors:
            for err in errors:
                logger.warning("Config validation [%s]: %s", config_path or config_type, err)
            # 不抛出异常，返回原始配置（向后兼容）
            # 严重错误可通过 raise_on_error 参数控制

        return config

    @staticmethod
    def validate_and_raise(
        config: Dict[str, Any],
        config_type: str,
        config_path: str = "",
    ) -> Dict[str, Any]:
        """
        验证配置，验证失败时抛出 ConfigValidationError

        Usage:
            ConfigValidator.validate_and_raise(config, "recon", "config/recon/recon.yaml")
        """
        validators = {
            "recon": ConfigValidator.validate_recon_config,
            "scorer_backend": ConfigValidator.validate_scorer_backend,
            "attack": ConfigValidator.validate_attack_config,
            "target": ConfigValidator.validate_target_config,
        }

        validator = validators.get(config_type)
        if not validator:
            return config

        errors = validator(config)
        if errors:
            raise ConfigValidationError(
                config_path=config_path or config_type,
                errors=errors,
            )

        return config
