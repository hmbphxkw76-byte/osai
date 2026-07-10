"""
===============================================================================
PyRIT Red Team — 转换器模块
===============================================================================
PyRIT 原生类使用:
  ✅ 所有 14 个自定义转换器 → 继承 pyrit.prompt_converter.PromptConverter
  ✅ 40+ 个编码混淆转换器  → PyRIT 原生（Base64/ROT13/Caesar/Zalgo/Binary/...）
  ✅ 转换器实例化统一        → CONVERTER_REGISTRY + resolve_converters()
  ✅ 分类体系               → encoding / obfuscation / jailbreak / injection /
                              bypass / reasoning / meta / llm_based / pyrit_native

───────────────────────────────────────────────────────────────────────────────
扩展模式（渗透场景零改动原则）

  场景 1: 添加新转换器（不改任何现有文件）
  ─────────────────────────────────────────
    from converters import register_converter
    register_converter("MyNovelJailbreak", MyNovelJailbreak, category="jailbreak")

  场景 2: 添加新攻击组合
  ─────────────────────
    from converters import register_combo
    register_combo({"name": "Novel + Base64", "converters": ["MyNovelJailbreak", "Base64Converter"]})

  场景 3: 批量发现（Python package）
  ──────────────────────────────────
    from converters import discover_converters
    discover_converters("plugins")  # 自动扫描并注册所有 PromptConverter 子类

  场景 4: 批量发现（文件系统路径）
  ────────────────────────────────
    from converters import discover_converters_from_path
    discover_converters_from_path("./exam_converters/")  # U 盘/网络路径零配置

  场景 5: 自动同步 PyRIT 原生转换器
  ──────────────────────────────────
    from converters import sync_pyrit_converters
    sync_pyrit_converters()  # PyRIT 版本升级后自动补全新转换器

  ✅ 以上操作均不需要修改 converters/ 目录中任何现有文件
  ✅ 渗透时只需在 main.py 或临时脚本中调用注册函数
───────────────────────────────────────────────────────────────────────────────

统一对外接口:
  - CONVERTER_REGISTRY, CONVERTER_MAP, GLOBAL_ATTACK_COMBINATIONS, resolve_converters
  - register_converter, register_combo, discover_converters, discover_converters_from_path
  - sync_pyrit_converters, get_converters_by_category
  - 14 个自定义转换器类 + 40+ 个 PyRIT 原生转换器

import: from converters import CONVERTER_MAP, resolve_converters, ...
===============================================================================
"""
from converters.registry import (
    CONVERTER_REGISTRY, CONVERTER_MAP,
    GLOBAL_ATTACK_COMBINATIONS,
    resolve_converters,
    register_converter,
    register_combo,
    discover_converters,
    discover_converters_from_path,
    sync_pyrit_converters,
    get_converters_by_category,
)

# ── 转换器类 direct export（方便类型引用，保持向后兼容） ──
from converters.jailbreak import (
    RoleplayJailbreakConverter,
    ContextualPrimingConverter,
    PAIRJailbreakConverter,
    DAN6FullJailbreakConverter,
    AIMJailbreakConverter,
    AcademicResearchConverter,
    DeveloperModeConverter,
)
from converters.injection import SuffixAppendConverter, JSONStructuredOutputHijackConverter
from converters.bypass import TranslationBypassConverter, DeepInceptionConverter, FewShotPrimingConverter
from converters.reasoning import CoTReasoningExtractionConverter, ConstitutionJailbreakConverter

# ── 🆕 P0+P1+P2 新增转换器 ──
from converters.rag_poisoning import RAGPoisoningConverter
from converters.embedding_attack import EmbeddingAdversarialAttack
from converters.jailbreak import ManyShotJailbreakConverter, FlipAttackConverter

# P0: 自适应 + GCG
from converters.adaptive import (
    LLMGuidedJailbreakConverter,
    PayattentionAttackConverter,
    CodeNestingBypassConverter,
    PersonaSplitConverter,
    IndirectPromptInjectionConverter,
    MultiTurnStateManipulationConverter,
    TokenSmugglingConverter,
    PromptCompressionBypassConverter,
    RecursiveSelfImprovementConverter,
)
from converters.gcg_suffix import GCGSuffixAppendConverter, GCGAdaptiveSuffixConverter

# P1: 真实多模态
from converters.multimodal_attack import RealMultimodalConverter

__all__ = [
    # ── 全局注册表（main.py 主要 import） ──
    "CONVERTER_REGISTRY",
    "CONVERTER_MAP",
    "GLOBAL_ATTACK_COMBINATIONS",
    "resolve_converters",
    # ── 动态扩展 API ──
    "register_converter",
    "register_combo",
    "discover_converters",
    "discover_converters_from_path",
    "sync_pyrit_converters",
    # ── 查询 API ──
    "get_converters_by_category",
    # ── 越狱前缀类 ──
    "RoleplayJailbreakConverter",
    "ContextualPrimingConverter",
    "PAIRJailbreakConverter",
    "DAN6FullJailbreakConverter",
    "AIMJailbreakConverter",
    "AcademicResearchConverter",
    "DeveloperModeConverter",
    "ManyShotJailbreakConverter",
    "FlipAttackConverter",
    # ── 注入类 ──
    "SuffixAppendConverter",
    "JSONStructuredOutputHijackConverter",
    # ── 绕过类 ──
    "TranslationBypassConverter",
    "DeepInceptionConverter",
    "FewShotPrimingConverter",
    # ── 推理/宪法类 ──
    "CoTReasoningExtractionConverter",
    "ConstitutionJailbreakConverter",
    # ── 🆕 P0: 自适应 + GCG ──
    "LLMGuidedJailbreakConverter",
    "GCGSuffixAppendConverter",
    "GCGAdaptiveSuffixConverter",
    # ── 🆕 P1: 新绕过器 ──
    "PayattentionAttackConverter",
    "CodeNestingBypassConverter",
    "PersonaSplitConverter",
    "IndirectPromptInjectionConverter",
    "MultiTurnStateManipulationConverter",
    "RealMultimodalConverter",
    # ── 🆕 P2: 高级绕过 ──
    "TokenSmugglingConverter",
    "PromptCompressionBypassConverter",
    "RecursiveSelfImprovementConverter",
    # ── 已有 P0-P2 ──
    "RAGPoisoningConverter",
    "EmbeddingAdversarialAttack",
]
