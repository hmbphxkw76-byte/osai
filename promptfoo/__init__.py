"""
===============================================================================
Promptfoo 模块 — Layer 5 统一评估判定 + Layer 6 标准化报告生成
===============================================================================
本包提供:
  - PromptfooManager: 提示词管理中心（加载、筛选、导出、评估）
  - EvalEngine: 统一评估引擎（ASR 评分 + OWASP/MITRE 映射）
  - ReportGenerator: OffSec 风格渗透测试报告生成器

架构位置: L5 (统一评估判定) + L6 (标准化报告生成)
依赖方向: → promptfoo/templates (下行), ← pyrit 核心 (被调用)
===============================================================================
"""
from promptfoo.schema import (
    PromptEntry,
    PromptSet,
    PromptfooEvalResult,
)
from promptfoo.manager import PromptfooManager
from promptfoo.eval.engine import EvalEngine
from promptfoo.reporting.generator import ReportGenerator

__all__ = [
    "PromptEntry",
    "PromptSet",
    "PromptfooEvalResult",
    "PromptfooManager",
    "EvalEngine",
    "ReportGenerator",
]
