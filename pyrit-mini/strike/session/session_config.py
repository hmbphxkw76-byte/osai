# -*- coding: utf-8 -*-
"""SessionConfig - 会话感知攻击配置模型

支持任意 stateful agent 的会话状态管理配置。
通过 declarative 配置驱动，无需修改代码即可适配不同 API 格式。

配置结构:
    SessionConfig
        ├── extraction_rules: 从响应提取会话状态的规则列表
        ├── injection_rules: 向请求注入会话状态的规则列表
        ├── validation: 会话一致性验证配置
        └── rotation: 会话轮换策略配置

Academic basis:
    - Crothers et al. (arXiv:2306.05685) — Adaptive session management
    - Gao et al. (arXiv:2311.10536) — Structured response parsing taxonomy
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ExtractionMethod(str, Enum):
    """状态提取方法"""
    JSON_PATH = "json_path"
    REGEX = "regex"
    HEADER = "header"
    COOKIE = "cookie"


class InjectionTarget(str, Enum):
    """状态注入目标位置"""
    BODY = "body"
    HEADER = "header"
    QUERY = "query"
    COOKIE = "cookie"


class RotationType(str, Enum):
    """轮换策略类型"""
    STICKY = "sticky"                   # 单 session 粘性
    POOL = "pool"                       # session 池
    FRESH_PER_REQUEST = "fresh_per_request"  # 每次新 session


@dataclass
class ExtractionRule:
    """会话状态提取规则

    定义如何从响应中提取会话状态 token。

    Attributes:
        name: token 名称 (如 "session_id", "csrf_token")
        primary: 主提取方法
        fallbacks: 备用提取方法列表
    """
    name: str
    primary: dict[str, Any]
    fallbacks: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "primary": self.primary,
            "fallbacks": self.fallbacks,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExtractionRule:
        return cls(
            name=data.get("name", ""),
            primary=data.get("primary", {}),
            fallbacks=data.get("fallbacks", []),
        )


@dataclass
class InjectionRule:
    """会话状态注入规则

    定义如何向请求注入会话状态 token。

    Attributes:
        name: 要注入的 token 名称 (对应 extraction_rules 的 name)
        target: 注入目标位置 (body/header/query/cookie)
        field: 目标字段名
        template: 注入模板，{value} 会被替换为实际值
    """
    name: str
    target: InjectionTarget
    field: str
    template: str = "{value}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "target": self.target.value if isinstance(self.target, InjectionTarget) else self.target,
            "field": self.field,
            "template": self.template,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InjectionRule:
        return cls(
            name=data.get("name", ""),
            target=InjectionTarget(data.get("target", "body")),
            field=data.get("field", ""),
            template=data.get("template", "{value}"),
        )


@dataclass
class SessionValidationConfig:
    """会话一致性验证配置

    Attributes:
        enabled: 是否启用验证
        strategy: 验证策略 (track_changes / fixed / custom)
        alert_on_reset: session 重置时告警
        max_age_turns: 最大 session 存活轮数
    """
    enabled: bool = True
    strategy: str = "track_changes"
    alert_on_reset: bool = True
    max_age_turns: int = 100

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "strategy": self.strategy,
            "alert_on_reset": self.alert_on_reset,
            "max_age_turns": self.max_age_turns,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionValidationConfig:
        return cls(
            enabled=data.get("enabled", True),
            strategy=data.get("strategy", "track_changes"),
            alert_on_reset=data.get("alert_on_reset", True),
            max_age_turns=data.get("max_age_turns", 100),
        )


@dataclass
class RotationPolicy:
    """会话轮换策略

    Attributes:
        type: 轮换类型
        max_turns: 单 session 最大使用轮数
        pool_size: 池大小 (仅 pool 模式)
        reuse_threshold_turns: 复用阈值轮数 (仅 pool 模式)
    """
    type: RotationType = RotationType.STICKY
    max_turns: int = 50
    pool_size: int = 3
    reuse_threshold_turns: int = 10

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type.value if isinstance(self.type, RotationType) else self.type,
            "max_turns": self.max_turns,
            "pool_size": self.pool_size,
            "reuse_threshold_turns": self.reuse_threshold_turns,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RotationPolicy:
        return cls(
            type=RotationType(data.get("type", "sticky")),
            max_turns=data.get("max_turns", 50),
            pool_size=data.get("pool_size", 3),
            reuse_threshold_turns=data.get("reuse_threshold_turns", 10),
        )


@dataclass
class SessionConfig:
    """会话感知攻击完整配置

    顶级配置容器，定义完整的会话状态管理策略。

    Attributes:
        extraction_rules: 状态提取规则列表
        injection_rules: 状态注入规则列表
        validation: 一致性验证配置
        rotation: 轮换策略配置
    """
    extraction_rules: list[ExtractionRule] = field(default_factory=list)
    injection_rules: list[InjectionRule] = field(default_factory=list)
    validation: SessionValidationConfig = field(default_factory=SessionValidationConfig)
    rotation: RotationPolicy = field(default_factory=RotationPolicy)

    def to_dict(self) -> dict[str, Any]:
        return {
            "extraction_rules": [r.to_dict() for r in self.extraction_rules],
            "injection_rules": [r.to_dict() for r in self.injection_rules],
            "validation": self.validation.to_dict(),
            "rotation": self.rotation.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionConfig:
        extraction_rules = [
            ExtractionRule.from_dict(r)
            for r in data.get("extraction_rules", [])
        ]
        injection_rules = [
            InjectionRule.from_dict(r)
            for r in data.get("injection_rules", [])
        ]
        validation_data = data.get("validation", {})
        rotation_data = data.get("rotation", {})
        return cls(
            extraction_rules=extraction_rules,
            injection_rules=injection_rules,
            validation=SessionValidationConfig.from_dict(validation_data),
            rotation=RotationPolicy.from_dict(rotation_data),
        )

    @classmethod
    def default_config(cls) -> SessionConfig:
        """创建默认会话配置

        默认配置覆盖最常见的场景:
        - JSON body 中的 session_id / sessionId
        - Header 中的 X-Session-Id
        - 自动注入到 body 和 header
        """
        return cls(
            extraction_rules=[
                ExtractionRule(
                    name="session_id",
                    primary={"method": "json_path", "path": "$.session_id"},
                    fallbacks=[
                        {"method": "regex", "pattern": r'"session_id"\s*:\s*"([^"]+)"'},
                        {"method": "regex", "pattern": r'"sessionId"\s*:\s*"([^"]+)"'},
                        {"method": "header", "name": "X-Session-Id"},
                    ],
                ),
            ],
            injection_rules=[
                InjectionRule(
                    name="session_id",
                    target=InjectionTarget.BODY,
                    field="session_id",
                ),
                InjectionRule(
                    name="session_id",
                    target=InjectionTarget.HEADER,
                    field="X-Session-Id",
                ),
            ],
            validation=SessionValidationConfig(),
            rotation=RotationPolicy(),
        )
