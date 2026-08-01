"""Deep investigation of Scenario.run_async internal execution flow."""

import inspect

# 1. Check Scenario.run_async full source
from pyrit.scenario.core.scenario import Scenario

print("=== Scenario.run_async full source ===")
src = inspect.getsource(Scenario.run_async)
print(src[:4000])

# 2. Check for _execute_single_attack or similar methods
print("\n=== Scenario methods ===")
methods = [m for m in dir(Scenario) if not m.startswith("__") and callable(getattr(Scenario, m, None))]
print(f"  All methods: {methods}")

# 3. Check _get_remaining_atomic_attacks_async
if hasattr(Scenario, "_get_remaining_atomic_attacks_async"):
    sig = inspect.signature(Scenario._get_remaining_atomic_attacks_async)
    print(f"\n  _get_remaining_atomic_attacks_async: {sig}")

# 4. Check _run_single_atomic_attack_async
for name in [
    "_run_single_atomic_attack_async",
    "_execute_atomic_attack_async",
    "_run_atomic_attack_async",
    "_execute_attack_async",
    "_process_atomic_attack_async",
    "_run_attack_async",
]:
    if hasattr(Scenario, name):
        sig = inspect.signature(getattr(Scenario, name))
        print(f"\n  {name}: {sig}")
        src_method = inspect.getsource(getattr(Scenario, name))
        print(src_method[:1500])

# 5. Check AdaptiveScenario for additional methods
print("\n=== AdaptiveScenario methods ===")
from pyrit.scenario.scenarios.adaptive import AdaptiveScenario

adaptive_methods = [m for m in dir(AdaptiveScenario) if not m.startswith("__") and m not in methods]
print(f"  Additional methods: {adaptive_methods}")

# 6. Check _build_atomic_attacks_async
if hasattr(AdaptiveScenario, "_build_atomic_attacks_async"):
    sig = inspect.signature(AdaptiveScenario._build_atomic_attacks_async)
    print(f"\n  _build_atomic_attacks_async: {sig}")
    src_baa = inspect.getsource(AdaptiveScenario._build_atomic_attacks_async)
    print(src_baa[:3000])

# 7. Check AdaptiveTechniqueDispatcher
print("\n=== AdaptiveTechniqueDispatcher ===")
try:
    from pyrit.scenario.scenarios.adaptive.adaptive_technique_dispatcher import AdaptiveTechniqueDispatcher

    print(f"  found: {AdaptiveTechniqueDispatcher}")
    disp_methods = [m for m in dir(AdaptiveTechniqueDispatcher) if not m.startswith("__")]
    print(f"  methods: {disp_methods}")
    if hasattr(AdaptiveTechniqueDispatcher, "run_async"):
        sig_disp = inspect.signature(AdaptiveTechniqueDispatcher.run_async)
        print(f"  run_async: {sig_disp}")
        src_disp = inspect.getsource(AdaptiveTechniqueDispatcher.run_async)
        print(src_disp[:2000])
except ImportError as e:
    print(f"  ImportError: {e}")

# 8. Check if Scenario has _atomic_attacks attribute
print("\n=== Scenario attributes ===")
# Look at __init__ or __slots__
if hasattr(Scenario, "__init__"):
    src_init = inspect.getsource(Scenario.__init__)
    print("  __init__ source (first 1500 chars):")
    print(src_init[:1500])
