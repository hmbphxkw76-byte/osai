# -*- coding: utf-8 -*-
"""
AI-300 Framework - Component Registry
PyRIT 组件映射表：转换器 + 评分器

集中管理所有 PyRIT 组件的简短名称到实际类的映射。
新增转换器/评分器只需在此文件添加条目，无需修改 AttackOrchestrator。

PyRIT 0.14.0 兼容
"""

import os
import sys
from typing import Dict, Set

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

# PyRIT 转换器导入
from pyrit.prompt_converter import (
    Base64Converter,
    ROT13Converter,
    UnicodeConfusableConverter,
    LeetspeakConverter,
    MaliciousQuestionGeneratorConverter,
    AddTextImageConverter,
    PDFConverter,
    WordDocConverter,
    PersuasionConverter,
    SearchReplaceConverter,
    TextJailbreakConverter,
    AsciiSmugglerConverter,
    ZeroWidthConverter,
    DiacriticConverter,
    TranslationConverter,
    VariationConverter,
)

# PyRIT 评分器导入
from pyrit.score import (
    SelfAskRefusalScorer,
    SelfAskTrueFalseScorer,
    SubStringScorer,
    SelfAskCategoryScorer,
    PromptShieldScorer,
    InsecureCodeScorer,
    ShellCommandOutputScorer,
    SQLInjectionOutputScorer,
    XSSOutputScorer,
    PathTraversalOutputScorer,
    GandalfScorer,
    CredentialLeakScorer,
    AzureContentFilterScorer,
    StaticPromptInjectionScorer,
)

# PyRIT 目标导入


# ──────────────────────────────────────────────────────────────────────────────
# 转换器映射表：配置名称 → 实际类
# ──────────────────────────────────────────────────────────────────────────────

CONVERTER_MAP: Dict[str, type] = {
    # 编码混淆（ASI01 基础编码技术）
    "base64": Base64Converter,
    "rot13": ROT13Converter,
    "unicode_confusable": UnicodeConfusableConverter,
    "leetspeak": LeetspeakConverter,
    # 越狱模板（ASI01/ASI06 高级越狱）
    "persuasion": PersuasionConverter,
    "text_jailbreak": TextJailbreakConverter,
    "malicious_question_generator": MaliciousQuestionGeneratorConverter,
    # Token 走私（ASI01/ASI05 绕过过滤）
    "ascii_smuggler": AsciiSmugglerConverter,
    "zero_width": ZeroWidthConverter,
    "diacritic": DiacriticConverter,
    # 搜索替换（ASI02 工具参数操纵）
    "search_replace": SearchReplaceConverter,
    # 翻译混淆（ASI01/ASI09 多语言绕过）
    "translation": TranslationConverter,
    # 变异生成（通用变异测试）
    "variation": VariationConverter,
    # 多模态注入（ASI02/RAG 文档载荷）
    "add_text_image": AddTextImageConverter,
    "pdf": PDFConverter,
    "word_doc": WordDocConverter,
}

# 特殊 preset 处理（不映射到单一 converter，需要特殊逻辑）
SPECIAL_PRESETS: Set[str] = {"identity", "context_wrap", "chunked_delivery"}

# 需要 converter_target（LLM 后端）的转换器
# 这些转换器构造时要求传入 converter_target: PromptTarget
CONVERTERS_NEEDING_TARGET: Set[str] = {
    "malicious_question_generator",
    "persuasion",
    "translation",
    "variation",
}


# ──────────────────────────────────────────────────────────────────────────────
# 评分器映射表：配置名称 → 实际类
# ──────────────────────────────────────────────────────────────────────────────

SCORER_MAP: Dict[str, type] = {
    # SelfAsk 系列（需要 LLM 后端）
    "refusal": SelfAskRefusalScorer,
    "true_false": SelfAskTrueFalseScorer,
    "category": SelfAskCategoryScorer,
    # 规则匹配系列（无需 LLM）
    "substring": SubStringScorer,
    "prompt_shield": PromptShieldScorer,
    "insecure_code": InsecureCodeScorer,
    "shell_command": ShellCommandOutputScorer,
    "sql_injection": SQLInjectionOutputScorer,
    "xss": XSSOutputScorer,
    "path_traversal": PathTraversalOutputScorer,
    "credential_leak": CredentialLeakScorer,
    "static_prompt_injection": StaticPromptInjectionScorer,
    # Float Scale 系列
    "gandalf": GandalfScorer,
    "azure_content_filter": AzureContentFilterScorer,
}

# 需要 LLM 后端的评分器类型（SelfAsk 系列）
LLM_BACKEND_SCORERS: Set[str] = {"refusal", "true_false", "category"}

# 规则匹配评分器（无需 LLM，纯 regex/关键词）
RULE_BASED_SCORERS: Set[str] = {
    "substring", "prompt_shield", "insecure_code", "shell_command",
    "sql_injection", "xss", "path_traversal", "credential_leak",
    "static_prompt_injection", "gandalf", "azure_content_filter",
}


# ──────────────────────────────────────────────────────────────────────────────
# 名称映射：PyRIT 全限定类名 → 简短名称
# ──────────────────────────────────────────────────────────────────────────────

CONVERTER_NAME_MAP: Dict[str, str] = {
    # 编码混淆
    "Base64Converter": "base64",
    "ROT13Converter": "rot13",
    "UnicodeConfusableConverter": "unicode_confusable",
    "LeetspeakConverter": "leetspeak",
    # 越狱模板
    "PersuasionConverter": "persuasion",
    "TextJailbreakConverter": "text_jailbreak",
    "MaliciousQuestionGeneratorConverter": "malicious_question_generator",
    # Token 走私
    "AsciiSmugglerConverter": "ascii_smuggler",
    "ZeroWidthConverter": "zero_width",
    "DiacriticConverter": "diacritic",
    # 搜索替换
    "SearchReplaceConverter": "search_replace",
    # 翻译混淆
    "TranslationConverter": "translation",
    # 变异生成
    "VariationConverter": "variation",
    # 多模态
    "AddTextImageConverter": "add_text_image",
    "PDFConverter": "pdf",
    "WordDocConverter": "word_doc",
}

SCORER_NAME_MAP: Dict[str, str] = {
    # SelfAsk 系列
    "SelfAskRefusalScorer": "refusal",
    "SelfAskTrueFalseScorer": "true_false",
    "SelfAskCategoryScorer": "category",
    # 规则匹配系列
    "SubStringScorer": "substring",
    "PromptShieldScorer": "prompt_shield",
    "InsecureCodeScorer": "insecure_code",
    "ShellCommandOutputScorer": "shell_command",
    "SQLInjectionOutputScorer": "sql_injection",
    "XSSOutputScorer": "xss",
    "PathTraversalOutputScorer": "path_traversal",
    "CredentialLeakScorer": "credential_leak",
    "StaticPromptInjectionScorer": "static_prompt_injection",
    # Float Scale 系列
    "GandalfScorer": "gandalf",
    "AzureContentFilterScorer": "azure_content_filter",
}
