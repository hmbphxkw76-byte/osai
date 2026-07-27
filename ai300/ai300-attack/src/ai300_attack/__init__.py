# -*- coding: utf-8 -*-
"""
ai300-attack
====================

基于 ai300-recon 侦察结果，调用 PyRIT / Garak 执行对话层攻击。

核心模块：
  - loaders: 读取侦察结果
  - adapters: 攻击工具适配器（PyRIT / Garak）
  - strategies: 根据目标特征选择攻击策略
  - reporting: 将攻击结果转换为 UnifiedFinding
"""

from .adapters.base import AttackAdapter, AttackResult, AttackStrategy
from .reporting.attack_report import AttackReport

__all__ = [
    "AttackAdapter",
    "AttackResult",
    "AttackReport",
    "AttackStrategy",
]

__version__ = "0.1.0"
