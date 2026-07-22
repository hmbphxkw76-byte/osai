# -*- coding: utf-8 -*-
"""检查 PyRIT 攻击类的模块路径"""
from pyrit.executor.attack import (
    ManyShotJailbreakAttack,
    SkeletonKeyAttack,
    RolePlayAttack,
    FlipAttack,
    ContextComplianceAttack,
    ChunkedRequestAttack,
    PAIRAttack,
    RedTeamingAttack,
)

attacks = [
    ManyShotJailbreakAttack,
    SkeletonKeyAttack,
    RolePlayAttack,
    FlipAttack,
    ContextComplianceAttack,
    ChunkedRequestAttack,
    PAIRAttack,
    RedTeamingAttack,
]

for cls in attacks:
    print(f"{cls.__name__}: {cls.__module__}")

# Check LikertScalePaths enum
from pyrit.score import SelfAskLikertScorer
try:
    print(f"\nLikertScalePaths: {SelfAskLikertScorer.__init__.__annotations__}")
    # Try to get the enum
    from pyrit.score.float_scale.self_ask_likert_scorer import LikertScalePaths
    for p in LikertScalePaths:
        print(f"  {p.name} = {p.value}")
except Exception as e:
    print(f"Error: {e}")

# Check conversation scorer
from pyrit.score import ConversationScorer
import inspect
print(f"\nConversationScorer.__init__: {inspect.signature(ConversationScorer.__init__)}")

# Check BatchScorer
from pyrit.score import BatchScorer
print(f"BatchScorer.__init__: {inspect.signature(BatchScorer.__init__)}")

# Check BatchScorer methods
for name in dir(BatchScorer):
    if not name.startswith("_"):
        print(f"  BatchScorer.{name}")
