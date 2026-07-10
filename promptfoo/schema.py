"""
===============================================================================
Promptfoo 数据模型 — 提示词评估 Schema
===============================================================================
定义提示词管理使用的核心数据类。
===============================================================================
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class PromptEntry:
    """单条提示词条目。"""
    id: str
    objective: str
    criterion: str
    content: str
    category: str = ""           # injection / jailbreak / xpia / rag / agent_abuse
    owasp_mapping: str = ""      # e.g. LLM01
    risk_level: str = "medium"   # critical / high / medium / low
    tags: list[str] = field(default_factory=list)
    source: str = "builtin"


@dataclass
class PromptSet:
    """一组提示词（通常对应一个攻击场景）。"""
    name: str
    description: str = ""
    prompts: list[PromptEntry] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class PromptfooEvalResult:
    """Promptfoo 评估结果。"""
    success: bool
    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    asr_score: float = 0.0
    output_path: str = ""
    raw_results: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


__all__ = [
    "PromptEntry",
    "PromptSet",
    "PromptfooEvalResult",
]
