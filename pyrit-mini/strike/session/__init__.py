# -*- coding: utf-8 -*-
"""strike/session - 会话感知攻击框架 (Session-Aware Attack Framework)

为任意 stateful agent 提供通用的会话状态管理能力。
通过配置驱动，支持 JSON/Header/Cookie 等多种会话追踪方式。

架构对齐:
    - PyRIT 原生优先: 利用 HTTPTarget.callback_function 机制
    - 配置驱动: YAML 定义提取/注入规则
    - 通用适配: 不硬编码任何特定 agent 格式

模块清单:
    - session_config.py   : 配置模型 (SessionConfig, ExtractionRule, InjectionRule)
    - session_manager.py  : 会话状态管理器 (SessionStateManager) SSOT
    - extraction.py       : 状态提取器 (SessionExtractor)
    - injection.py        : 状态注入器 (SessionInjector)
    - validation.py       : 会话一致性验证 (SessionValidator)
    - rotation.py         : 轮换策略 (SessionRotationPolicy)

Academic basis:
    - Perez et al. (arXiv:2202.03286) — Session-based attack persistence
    - Russinovich et al. (arXiv:2404.01833) — Crescendo multi-turn state tracking

Constitution compliance:
    - R-SIZE: 每模块 < 300 行
    - R-H3: 单一职责，无双重实现
    - R-SESSION: 会话感知架构完整性
"""

from strike.session.session_config import (
    ExtractionRule,
    InjectionRule,
    RotationPolicy,
    SessionConfig,
    SessionValidationConfig,
)
from strike.session.session_manager import SessionStateManager

__all__ = [
    "SessionConfig",
    "ExtractionRule",
    "InjectionRule",
    "SessionValidationConfig",
    "RotationPolicy",
    "SessionStateManager",
]
