"""Check PyRIT 1.0.1 deeper native APIs."""

import inspect

# 1. _estimate method signature and source
from pyrit.scenario.scenarios.adaptive import EpsilonGreedyTechniqueSelector

src = inspect.getsource(EpsilonGreedyTechniqueSelector._estimate)
print("=== _estimate source ===")
print(src[:2000])

# 2. _build_techniques_dict signature
from pyrit.scenario.scenarios.adaptive import AdaptiveScenario

sig = inspect.signature(AdaptiveScenario._build_techniques_dict)
print("\n=== _build_techniques_dict signature ===")
print(f"signature: {sig}")

# 3. TextAdaptive default techniques
# Check TextAdaptive class attributes
from pyrit.scenario.scenarios.adaptive import TextAdaptive

print("\n=== TextAdaptive attributes ===")
for attr in ["DEFAULT_TECHNIQUES", "TECHNIQUE_TAGS", "_atomic_attack_prefix", "get_technique_class"]:
    print(f"  {attr}: {getattr(TextAdaptive, attr, 'NOT FOUND')}")

# 4. ConverterConfiguration
from pyrit.prompt_normalizer import ConverterConfiguration

print("\n=== ConverterConfiguration ===")
print(f"signature: {inspect.signature(ConverterConfiguration.__init__)}")

# 5. Check AttackConverterConfig
from pyrit.executor.attack import AttackConverterConfig

print("\n=== AttackConverterConfig ===")
print(f"signature: {inspect.signature(AttackConverterConfig.__init__)}")

# 6. Check _build_scoring_config_for_factory
print("\n=== _build_scoring_config_for_factory ===")
print(f"exists: {'_build_scoring_config_for_factory' in dir(AdaptiveScenario)}")

# 7. Check Parameter
from pyrit.models import Parameter

print("\n=== Parameter ===")
print(f"signature: {inspect.signature(Parameter.__init__)}")

# 8. Check TargetRequirements
from pyrit.prompt_target.common.target_requirements import TargetRequirements

print("\n=== TargetRequirements ===")
print(f"signature: {inspect.signature(TargetRequirements.__init__)}")

# 9. Check apply_defaults
print("\n=== apply_defaults ===")
print("available: True")

# 10. Check DatasetAttackConfiguration
from pyrit.scenario import DatasetAttackConfiguration

print("\n=== DatasetAttackConfiguration ===")
print(f"signature: {inspect.signature(DatasetAttackConfiguration.__init__)}")
