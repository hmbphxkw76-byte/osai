# -*- coding: utf-8 -*-
"""检查评分器签名"""
import inspect

from pyrit.score import (
    SelfAskLikertScorer,
    SelfAskScaleScorer,
    MarkdownInjectionScorer,
    FloatScaleThresholdScorer,
    ConversationScorer,
    BatchScorer,
    TrueFalseInverterScorer,
    TrueFalseCompositeScorer,
    SelfAskGeneralFloatScaleScorer,
    SelfAskGeneralTrueFalseScorer,
    SelfAskRefusalScorer,
    SelfAskTrueFalseScorer,
    SubStringScorer,
)

scorers = [
    SelfAskLikertScorer,
    SelfAskScaleScorer,
    MarkdownInjectionScorer,
    FloatScaleThresholdScorer,
    ConversationScorer,
    BatchScorer,
    TrueFalseInverterScorer,
    TrueFalseCompositeScorer,
    SelfAskGeneralFloatScaleScorer,
    SelfAskGeneralTrueFalseScorer,
    SelfAskRefusalScorer,
    SelfAskTrueFalseScorer,
    SubStringScorer,
]

for cls in scorers:
    print(f"\n=== {cls.__name__}.__init__ ===")
    try:
        sig = inspect.signature(cls.__init__)
        print(f"  {sig}")
    except Exception as e:
        print(f"  Error: {e}")

# Also check how attacks are executed
from pyrit.executor.attack import AttackExecutor
print("\n=== AttackExecutor methods ===")
for name in dir(AttackExecutor):
    if not name.startswith("_"):
        print(f"  {name}")

# Check the execute method signature
print("\n=== AttackExecutor.execute_attack ===")
try:
    sig = inspect.signature(AttackExecutor.execute_attack)
    print(f"  {sig}")
except Exception as e:
    print(f"  Error: {e}")
