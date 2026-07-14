"""攻击核心引擎（AI-300 Ch3-Ch9）。

模块：
  - runner.py: 执行器抽象层（AttackRunner ABC + PyRIT/Native 实现）
  - multi_turn_runner.py: 多轮攻击执行器（Crescendo + TAP 算法）
  - scorer.py: 评分器接口（LLM-as-Judge + 规则评分 + 灰度评分）
  - converters.py: 编码转换器（Base64/ROT13/Unicode + 越狱转换器）
  - payload_loader.py: YAML 载荷库加载器（OWASP 分类管理）

PyRIT 融合增强：
  - FastGrayscaleScorer: 快速灰度评分器（无 LLM 依赖）
  - KeywordDensityScorer: 关键词密度分析器
  - RefusalPatternScorer: 拒绝模式检测器
  - ConverterRegistry: 转换器注册表（分类体系、动态注册）
  - JailbreakConverters: 越狱提示词转换器（PAIR、DAN6、AIM、Academic、ManyShot、FlipAttack）
"""

from .runner import (
    AttackRunner,
    PyRITAttackRunner,
    NativeAttackRunner,
    is_pyrit_available,
    pyrit_version,
    is_no_judge_llm,
    default_scorers,
    CONVERTER_MAP,
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
    # Runner
    "AttackRunner",
    "PyRITAttackRunner",
    "NativeAttackRunner",
    "is_pyrit_available",
    "pyrit_version",
    "is_no_judge_llm",
    "default_scorers",
    "CONVERTER_MAP",
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