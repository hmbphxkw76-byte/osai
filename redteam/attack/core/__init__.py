"""攻击核心引擎（AI-300 Ch3-Ch9）。

模块结构（v2.3 Native-First 重构后）：
  核心接口层：
    - runner.py: AttackRunner ABC + 辅助函数 + 再导出
    - native_runner.py: NativeAttackRunner（httpx 直连，默认攻击引擎）
    - multi_turn_runner.py: 多轮攻击执行器（Crescendo + TAP 算法）

  评分器层：
    - scorer.py: RuleBasedScorer + is_likely_refusal + 工厂 + 再导出
    - grayscale_scorer.py: 灰度评分系统（KeywordDensity + RefusalPattern + FastGrayscale
                           + GrayscaleLevel + HybridScoreResult + AttackScorer ABC）
    - hybrid_scorer.py: HybridScorer（多维度加权投票）
    - llm_judge_scorer.py: LLMJudgeScorer（需外部 Judge LLM 端点）

  转换器层：
    - converters.py: ConverterCategory + ConverterRegistry + 工厂 + 再导出
    - encoding_converters.py: 11 种纯 Python 编码转换器（PromptConverter ABC + 编码/混淆类）
    - jailbreak_converters.py: 8 种越狱提示词转换器

  编排层：
    - strategy_router.py: StrategyRouter（攻击策略 → 执行器映射）
    - determinism_router.py: DeterminismAwareRouter（侦察→攻击战术衔接）
    - pipeline_orchestrator.py: PipelineOrchestrator（预固化多阶段攻击流程）
    - payload_loader.py: PayloadLoader（YAML 载荷库加载器）
    - scorer_probe.py: 评分器可用性探测 + NO_JUDGE_LLM 检测 + default_scorers
    - in_memory_memory.py: 纯 Python 内存存储（结果存储/导出）

PyRIT 多轮增强：
  - multi_turn_orchestrator.py（位于 scenario/ 目录）: PyRIT 可选增强
    Crescendo/TAP/PAIR — PyRIT 可用时使用其 adversarial_chat，不可用时原生兜底
"""
from .in_memory_memory import (
    InMemoryMemory,
    ConversationEntry,
    AttackResultEntry,
    setup_memory_with_fallback,
)
from .runner import (
    AttackRunner,
    NativeAttackRunner,
    is_pyrit_available,
    pyrit_version,
    is_no_judge_llm,
    default_scorers,
    probe_scorer_availability,
    ScorerProbeResult,
)
from .multi_turn_runner import (
    MultiTurnAttackRunner,
    CrescendoAttackRunner,
    TAPAttackRunner,
)
from .scorer import (
    AttackScorer,
    RuleBasedScorer,
    HybridScorer,
    FastGrayscaleScorer,
    KeywordDensityScorer,
    RefusalPatternScorer,
    LLMJudgeScorer,
    GrayscaleLevel,
    HybridScoreResult,
    is_likely_refusal,
    build_scorer,
    build_scorers,
)
from .converters import (
    PromptConverter,
    Base64Converter,
    ROT13Converter,
    UnicodeConfusableConverter,
    PAIRJailbreakConverter,
    DAN6Converter,
    AIMConverter,
    AcademicJailbreakConverter,
    ManyShotJailbreakConverter,
    FlipAttackConverter,
    RoleplayJailbreakConverter,
    ConverterCategory,
    ConverterRegistry,
    build_converter,
    build_converters,
    apply_converters,
    get_converter_registry,
)
from .payload_loader import PayloadLoader
from .strategy_router import StrategyRouter, AttackStrategy, STRATEGY_CONVERTER_MAP
from .determinism_router import (
    DeterminismProfile,
    DeterminismAwareRouter,
)
from .pipeline_orchestrator import PipelineOrchestrator

__all__ = [
    # InMemoryMemory
    "InMemoryMemory",
    "ConversationEntry",
    "AttackResultEntry",
    "setup_memory_with_fallback",
    # Runner
    "AttackRunner",
    "NativeAttackRunner",
    "is_pyrit_available",
    "pyrit_version",
    "is_no_judge_llm",
    "default_scorers",
    "probe_scorer_availability",
    "ScorerProbeResult",
    # Multi-turn Runner
    "MultiTurnAttackRunner",
    "CrescendoAttackRunner",
    "TAPAttackRunner",
    # Scorer
    "AttackScorer",
    "RuleBasedScorer",
    "HybridScorer",
    "FastGrayscaleScorer",
    "KeywordDensityScorer",
    "RefusalPatternScorer",
    "LLMJudgeScorer",
    "GrayscaleLevel",
    "HybridScoreResult",
    "is_likely_refusal",
    "build_scorer",
    "build_scorers",
    # Converter
    "PromptConverter",
    "Base64Converter",
    "ROT13Converter",
    "UnicodeConfusableConverter",
    "PAIRJailbreakConverter",
    "DAN6Converter",
    "AIMConverter",
    "AcademicJailbreakConverter",
    "ManyShotJailbreakConverter",
    "FlipAttackConverter",
    "RoleplayJailbreakConverter",
    "ConverterCategory",
    "ConverterRegistry",
    "build_converter",
    "build_converters",
    "apply_converters",
    "get_converter_registry",
    # Payload Loader
    "PayloadLoader",
    # Strategy Router
    "StrategyRouter",
    "AttackStrategy",
    "STRATEGY_CONVERTER_MAP",
    # Determinism Router
    "DeterminismProfile",
    "DeterminismAwareRouter",
    # Pipeline Orchestrator
    "PipelineOrchestrator",
]
