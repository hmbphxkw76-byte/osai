"""
===============================================================================
向后兼容桥接 — Promptfoo 提示词管理器
===============================================================================
⚠️ 此模块已迁移到 promptfoo/ 独立目录 (Layer 5: 统一评估 + Layer 6: 报告生成)。

原代码位于: pyrit/executor/promptfoo_manager.py
新代码位于: promptfoo/manager.py

本文件保留向后兼容，所有导入重定向到新位置。
===============================================================================
"""
# 向后兼容: 从新位置重新导出
from promptfoo.manager import PromptfooManager
from promptfoo.schema import PromptEntry, PromptSet, PromptfooEvalResult

__all__ = [
    "PromptfooManager",
    "PromptEntry",
    "PromptSet",
    "PromptfooEvalResult",
]
