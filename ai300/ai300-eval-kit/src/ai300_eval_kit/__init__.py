# -*- coding: utf-8 -*-
"""
ai300-eval-kit
==============

基于 ai300-recon 侦察结果，对 LLM 应用执行自动化评估。

核心模块：
  - loaders: 读取侦察结果
  - adapters: 评估工具适配器（Giskard / ART）
  - strategies: 根据目标特征选择评估维度
  - reporting: 将评估结果转换为 UnifiedFinding
"""

from __future__ import annotations

from .adapters.base import EvalAdapter, EvalResult, EvalStrategy
from .reporting.eval_report import EvalReport

__all__ = [
    "EvalAdapter",
    "EvalResult",
    "EvalReport",
    "EvalStrategy",
]

__version__ = "0.1.0"
