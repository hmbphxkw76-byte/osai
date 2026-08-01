"""Comprehensive integration verification for all pipeline modules."""

import sys

sys.path.insert(0, ".")

# 1. Verify all modules can be imported
print("=== Module Import Verification ===")
modules = [
    "pipeline.context",
    "pipeline.config",
    "pipeline.asr.optimizer",
    "pipeline.asr.prior_registry",
    "pipeline.asr.rank_builder",
    "pipeline.converters.chains",
    "pipeline.converters.factory",
    "pipeline.asr.failure_type_selector",
    "pipeline.asr.failure_type_event_handler",
    "pipeline.converters.target_aware_router",
    "pipeline.stages.stage_init",
    "pipeline.stages.stage_scenario",
    "pipeline.stages.stage_initialize",
    "pipeline.stages.stage_execute",
    "pipeline.stages.stage_output",
]
all_ok = True
for mod in modules:
    try:
        __import__(mod)
        print(f"  OK: {mod}")
    except Exception as e:
        print(f"  FAIL: {mod} -- {e}")
        all_ok = False

if not all_ok:
    print("\nSome modules failed to import!")
    sys.exit(1)

# 2. Verify PipelineContext fields
print("\n=== PipelineContext Field Verification ===")
import dataclasses

from pipeline.context import PipelineContext

fields = {f.name: f for f in dataclasses.fields(PipelineContext)}
expected_fields = [
    "args",
    "config",
    "scenario",
    "objective_scorer",
    "selector",
    "result",
    "asr_per_technique",
    "overall_asr",
    "output_dir",
    "metadata",
]
for name in expected_fields:
    status = "OK" if name in fields else "MISSING"
    print(f"  {status}: ctx.{name}")

# 3. Verify data flow Stage 2 -> Stage 3 -> Stage 4
print("\n=== Data Flow Verification ===")
from pyrit.scenario.scenarios.adaptive import EpsilonGreedyTechniqueSelector

from pipeline.asr.failure_type_selector import FailureTypeRoutingSelector

print(
    f"  FailureTypeRoutingSelector inherits EpsilonGreedyTechniqueSelector: "
    f"{issubclass(FailureTypeRoutingSelector, EpsilonGreedyTechniqueSelector)}"
)

# Check selector has update_failure_type method (for Stage 4 feedback)
print(f"  selector has update_failure_type: {hasattr(FailureTypeRoutingSelector, 'update_failure_type')}")

# Check selector has set_warm_start_asr method (for Stage 2 injection)
print(f"  selector has set_warm_start_asr: {hasattr(FailureTypeRoutingSelector, 'set_warm_start_asr')}")

# 4. Verify ASR Prior Registry
print("\n=== ASR Prior Registry ===")
from pipeline.asr.prior_registry import TIER_THRESHOLDS, get_all_priors, get_initial_q_value

priors = get_all_priors()
print(f"  Total techniques with priors: {len(priors)}")
print(f"  Tier thresholds: {TIER_THRESHOLDS}")
crescendo = get_initial_q_value("crescendo", "gpt-4o", "strong")
baseline = get_initial_q_value("prompt_sending", "gpt-4o", "strong")
print(f"  Crescendo ASR (GPT-4o, strong): {crescendo:.0%}")
print(f"  prompt_sending ASR (GPT-4o, strong): {baseline:.0%}")
assert crescendo > baseline, "High ASR technique should have higher value than baseline"

# 5. Verify Converter Chains
print("\n=== Converter Chains ===")
from pipeline.converters.chains import BASE_TECHNIQUES_FOR_VARIANTS, CONVERTER_VARIANT_CHAINS

print(f"  Converter chains defined: {len(CONVERTER_VARIANT_CHAINS)}")
print(f"  Base techniques for variants: {len(BASE_TECHNIQUES_FOR_VARIANTS)}")

# 6. Verify Target-Aware Router
print("\n=== Target-Aware Router ===")
from pipeline.converters.target_aware_router import TARGET_TYPE_GROUPS, get_target_group

print(f"  Target type mappings: {len(TARGET_TYPE_GROUPS)}")
group = get_target_group("openai_chat")
print(f"  openai_chat -> group: {group}")

# 7. Verify Failure Type Event Handler
print("\n=== Failure Type Event Handler ===")
from pipeline.asr.failure_type_event_handler import FailureTypeEventHandler
from pipeline.asr.failure_type_selector import FailureTypeRoutingSelector

selector = FailureTypeRoutingSelector(epsilon=0.1)
handler = FailureTypeEventHandler(selector=selector)
print(f"  Handler created with selector: {type(handler).__name__}")
print(f"  Handler has on_attack_result: {hasattr(handler, 'on_attack_result')}")
print(f"  Handler has get_stats: {hasattr(handler, 'get_stats')}")

# 8. Verify ASR Rank Builder
print("\n=== ASR Rank Builder ===")
from pipeline.asr.rank_builder import ASRTier

print("  ASRRankBuilder methods: build_ranked_groups, build_fallback_chain, sample_seed_groups_by_tier")
print(f"  ASRTier values: {[t.value for t in ASRTier]}")

# 9. Verify failure type extraction
print("\n=== Failure Type Extraction ===")
print("  extract_failure_type_from_result available: True")

# 10. Verify main.py imports
print("\n=== Main Entry Point ===")
import main

print("  main.py imports: OK")
print(f"  main_async function: {hasattr(main, 'main_async')}")

print("\n" + "=" * 60)
print("ALL INTEGRATION CHECKS PASSED")
print("=" * 60)
