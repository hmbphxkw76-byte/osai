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
    # 新增：更多编码混淆转换器
    AtbashConverter,
    CaesarConverter,
    BinaryConverter,
    MorseConverter,
    BrailleConverter,
    EcojiConverter,
    Base2048Converter,
    CharSwapConverter,
    RandomCapitalLettersConverter,
    FirstLetterConverter,
    UnicodeSubstitutionConverter,
    UnicodeReplacementConverter,
    AskToDecodeConverter,
    SneakyBitsSmugglerConverter,
    VariationSelectorSmugglerConverter,
    CodeChameleonConverter,
    MathObfuscationConverter,
    DenylistConverter,
    TenseConverter,
    ToneConverter,
    ColloquialWordswapConverter,
    RandomTranslationConverter,
    QRCodeConverter,
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
    # ── 编码混淆（基础编码技术）──
    "base64": Base64Converter,
    "rot13": ROT13Converter,
    "unicode_confusable": UnicodeConfusableConverter,
    "leetspeak": LeetspeakConverter,
    "atbash": AtbashConverter,
    "caesar": CaesarConverter,
    "binary": BinaryConverter,
    "morse": MorseConverter,
    "braille": BrailleConverter,
    "ecoji": EcojiConverter,
    "base2048": Base2048Converter,
    "char_swap": CharSwapConverter,
    "random_capital": RandomCapitalLettersConverter,
    "first_letter": FirstLetterConverter,
    "unicode_substitution": UnicodeSubstitutionConverter,
    "unicode_replacement": UnicodeReplacementConverter,
    "ask_to_decode": AskToDecodeConverter,
    "sneaky_bits": SneakyBitsSmugglerConverter,
    "variation_selector_smuggler": VariationSelectorSmugglerConverter,
    # ── 越狱/说服类 ──
    "persuasion": PersuasionConverter,
    "text_jailbreak": TextJailbreakConverter,
    "malicious_question_generator": MaliciousQuestionGeneratorConverter,
    # ── Token 走私 ──
    "ascii_smuggler": AsciiSmugglerConverter,
    "zero_width": ZeroWidthConverter,
    "diacritic": DiacriticConverter,
    # ── 翻译混淆 ──
    "translation": TranslationConverter,
    "random_translation": RandomTranslationConverter,
    # ── 变异生成 ──
    "variation": VariationConverter,
    # ── 多模态注入 ──
    "add_text_image": AddTextImageConverter,
    "pdf": PDFConverter,
    "word_doc": WordDocConverter,
    "qr_code": QRCodeConverter,
    # ── 代码伪装 ──
    "code_chameleon": CodeChameleonConverter,
    "math_obfuscation": MathObfuscationConverter,
    # ── 搜索替换 ──
    "search_replace": SearchReplaceConverter,
    # ── 否定陷阱 ──
    "denylist": DenylistConverter,
    # ── 风格变异 ──
    "tense": TenseConverter,
    "tone": ToneConverter,
    "colloquial_swap": ColloquialWordswapConverter,
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
    "AtbashConverter": "atbash",
    "CaesarConverter": "caesar",
    "BinaryConverter": "binary",
    "MorseConverter": "morse",
    "BrailleConverter": "braille",
    "EcojiConverter": "ecoji",
    "Base2048Converter": "base2048",
    "CharSwapConverter": "char_swap",
    "RandomCapitalLettersConverter": "random_capital",
    "FirstLetterConverter": "first_letter",
    "UnicodeSubstitutionConverter": "unicode_substitution",
    "UnicodeReplacementConverter": "unicode_replacement",
    "AskToDecodeConverter": "ask_to_decode",
    "SneakyBitsSmugglerConverter": "sneaky_bits",
    "VariationSelectorSmugglerConverter": "variation_selector_smuggler",
    # 越狱/说服
    "PersuasionConverter": "persuasion",
    "TextJailbreakConverter": "text_jailbreak",
    "MaliciousQuestionGeneratorConverter": "malicious_question_generator",
    # Token 走私
    "AsciiSmugglerConverter": "ascii_smuggler",
    "ZeroWidthConverter": "zero_width",
    "DiacriticConverter": "diacritic",
    # 翻译混淆
    "TranslationConverter": "translation",
    "RandomTranslationConverter": "random_translation",
    # 变异生成
    "VariationConverter": "variation",
    # 多模态
    "AddTextImageConverter": "add_text_image",
    "PDFConverter": "pdf",
    "WordDocConverter": "word_doc",
    "QRCodeConverter": "qr_code",
    # 代码伪装
    "CodeChameleonConverter": "code_chameleon",
    "MathObfuscationConverter": "math_obfuscation",
    # 搜索替换
    "SearchReplaceConverter": "search_replace",
    # 否定陷阱
    "DenylistConverter": "denylist",
    # 风格变异
    "TenseConverter": "tense",
    "ToneConverter": "tone",
    "ColloquialWordswapConverter": "colloquial_swap",
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
