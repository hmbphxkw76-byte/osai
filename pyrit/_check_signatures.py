# -*- coding: utf-8 -*-
"""检查 PyRIT 关键攻击类和评分器签名"""
import inspect

from pyrit.executor.attack import (
    ManyShotJailbreakAttack,
    SkeletonKeyAttack,
    RolePlayAttack,
    FlipAttack,
    ContextComplianceAttack,
    ChunkedRequestAttack,
    CrescendoAttack,
    TreeOfAttacksWithPruningAttack,
    SequentialAttack,
    PromptSendingAttack,
    AttackExecutor,
    AttackParameters,
    AttackContext,
    AttackConverterConfig,
    AttackScoringConfig,
    AttackAdversarialConfig,
    SingleTurnAttackContext,
    SingleTurnAttackStrategy,
    MultiTurnAttackStrategy,
    MultiTurnAttackContext,
    SequentialChildAttack,
)

# Check attack strategy enum
print("=== SingleTurnAttackStrategy ===")
try:
    for s in SingleTurnAttackStrategy:
        print(f"  {s.name} = {s.value}")
except Exception as e:
    print(f"  Error: {e}")

print("\n=== MultiTurnAttackStrategy ===")
try:
    for s in MultiTurnAttackStrategy:
        print(f"  {s.name} = {s.value}")
except Exception as e:
    print(f"  Error: {e}")

# Check attack class init signatures
attacks = [
    PromptSendingAttack,
    ManyShotJailbreakAttack,
    SkeletonKeyAttack,
    RolePlayAttack,
    FlipAttack,
    ContextComplianceAttack,
    ChunkedRequestAttack,
    CrescendoAttack,
    TreeOfAttacksWithPruningAttack,
    SequentialAttack,
    AttackExecutor,
    SequentialChildAttack,
]
for cls in attacks:
    print(f"\n=== {cls.__name__}.__init__ ===")
    try:
        sig = inspect.signature(cls.__init__)
        print(f"  {sig}")
    except Exception as e:
        print(f"  Error: {e}")

# Check AttackParameters and context classes
contexts = [
    AttackParameters,
    AttackContext,
    SingleTurnAttackContext,
    MultiTurnAttackContext,
    AttackConverterConfig,
    AttackScoringConfig,
    AttackAdversarialConfig,
]
for cls in contexts:
    print(f"\n=== {cls.__name__} fields ===")
    try:
        if hasattr(cls, '__dataclass_fields__'):
            for fname, finfo in cls.__dataclass_fields__.items():
                print(f"  {fname}: {finfo.type}")
        else:
            sig = inspect.signature(cls.__init__)
            print(f"  {sig}")
    except Exception as e:
        print(f"  Error: {e}")
