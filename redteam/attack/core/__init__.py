"""攻击核心引擎（AI-300 Ch3-Ch9）。

模块：
  - runner.py: 执行器抽象层（AttackRunner ABC + PyRIT/Native 实现）
  - multi_turn_runner.py: 多轮攻击执行器（Crescendo + TAP 算法）
  - scorer.py: 评分器接口（LLM-as-Judge + 规则评分）
  - converters.py: 编码转换器（Base64/ROT13/Unicode 等）
  - payload_loader.py: YAML 载荷库加载器（OWASP 分类管理）
"""

from .runner import (
    AttackRunner,
    PyRITAttackRunner,
    NativeAttackRunner,
    is_pyrit_available,
    pyrit_version,
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
    build_scorer,
    build_scorers,
)
from .converters import (
    PromptConverter,
    Base64Converter,
    ROT13Converter,
    UnicodeConfusableConverter,
    build_converter,
)
from .payload_loader import PayloadLoader

__all__ = [
    # Runner
    "AttackRunner",
    "PyRITAttackRunner",
    "NativeAttackRunner",
    "is_pyrit_available",
    "pyrit_version",
    "CONVERTER_MAP",
    # Multi-turn Runner
    "MultiTurnAttackRunner",
    "CrescendoAttackRunner",
    "TAPAttackRunner",
    # Scorer
    "AttackScorer",
    "RuleBasedScorer",
    "HybridScorer",
    "build_scorer",
    "build_scorers",
    # Converter
    "PromptConverter",
    "Base64Converter",
    "ROT13Converter",
    "UnicodeConfusableConverter",
    "build_converter",
    # Payload Loader
    "PayloadLoader",
]