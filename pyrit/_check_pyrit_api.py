# -*- coding: utf-8 -*-
"""临时脚本：检查 PyRIT API 可用性"""
import sys

import pyrit.prompt_normalizer
import pyrit.score
import pyrit.prompt_converter
import pyrit.executor.attack

print("=== Attack classes ===")
for name in dir(pyrit.executor.attack):
    obj = getattr(pyrit.executor.attack, name)
    if isinstance(obj, type) and "Attack" in name:
        print(f"  {name}")

print("\n=== Scorer classes ===")
for name in dir(pyrit.score):
    obj = getattr(pyrit.score, name)
    if isinstance(obj, type) and "Scorer" in name:
        print(f"  {name}")

print("\n=== Converter/Generator/Fuzzer classes ===")
for name in dir(pyrit.prompt_converter):
    obj = getattr(pyrit.prompt_converter, name)
    if isinstance(obj, type) and ("Generator" in name or "Fuzzer" in name):
        print(f"  {name}")

# Check for specific attack subclasses
print("\n=== Checking specific attack imports ===")
attacks_to_check = [
    "ManyShotJailbreakAttack",
    "SkeletonKeyAttack",
    "RolePlayAttack",
    "FlipAttack",
    "ContextComplianceAttack",
    "ChunkedRequestAttack",
    "ViolentDurianAttack",
    "CrescendoAttack",
    "TreeOfAttacksWithPruningAttack",
    "SequentialAttack",
    "MultiTurnAttack",
]
for atk in attacks_to_check:
    try:
        obj = getattr(pyrit.executor.attack, atk)
        print(f"  {atk}: AVAILABLE ({type(obj)})")
    except AttributeError:
        print(f"  {atk}: NOT FOUND")

# Check scorers
print("\n=== Checking specific scorer imports ===")
scorers_to_check = [
    "SelfAskLikertScorer",
    "SelfAskScaleScorer",
    "MarkdownInjectionScorer",
    "FloatScaleThresholdScorer",
    "ConversationScorer",
    "BatchScorer",
    "CompositeScorer",
    "TrueFalseInverterScorer",
    "HumanInTheLoopScorer",
]
for s in scorers_to_check:
    try:
        obj = getattr(pyrit.score, s)
        print(f"  {s}: AVAILABLE ({type(obj)})")
    except AttributeError:
        print(f"  {s}: NOT FOUND")

# Check converters/generators
print("\n=== Checking specific converter imports ===")
converters_to_check = [
    "FuzzerConverter",
    "FuzzerGenerator",
    "MCTSConverter",
    "MultiSlugConverter",
]
for c in converters_to_check:
    try:
        obj = getattr(pyrit.prompt_converter, c)
        print(f"  {c}: AVAILABLE ({type(obj)})")
    except AttributeError:
        print(f"  {c}: NOT FOUND")

# Check PyRIT version
try:
    import pyrit
    print(f"\nPyRIT version: {getattr(pyrit, '__version__', 'unknown')}")
except Exception:
    pass

# Check memory labels
print("\n=== Memory / CentralMemory ===")
try:
    from pyrit.memory import CentralMemory
    print(f"  CentralMemory: {CentralMemory}")
    cm_methods = [m for m in dir(CentralMemory) if not m.startswith("_")]
    print(f"  Methods: {cm_methods}")
except Exception as e:
    print(f"  CentralMemory import error: {e}")

# Check orchestrator attack classes (PyRIT < 0.13 style)
print("\n=== Checking orchestrator module ===")
try:
    import pyrit.orchestrator
    orcs = [name for name in dir(pyrit.orchestrator) if "Attack" in name or "Orchestrator" in name]
    print(f"  Found: {orcs}")
except Exception as e:
    print(f"  orchestrator module error: {e}")
