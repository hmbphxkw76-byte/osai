"""PipelineContext — converter(s)

all Phase converter(s) PipelineContext 
"""

from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    import argparse

    from pyrit.models import AttackSeedGroup, ScenarioResult

    from recon.burp_parser import ParsedBurpRequest


@dataclass
class PipelineContext:
    """

    :
        args: CLI 
        output_dir: Output directory
        model_name:  ()
        parsed_request:  Burp 
        objective_target:  (PyRIT PromptTarget )
        adversarial_target:  ()
        converter_target: Converter  LLM  ()
        scoring_target:  LLM 
        seeds: Load
        techniques: 
        converter_map:  → Converter 
        attack_results: 
        asr_per_technique:  ASR
        overall_asr:  ASR
        scenario_result_id:  ID ()
    """

    args: "argparse.Namespace"
    output_dir: Path = Path("outputs")
    model_name: str = ""

    # L5 v54+: Adaptive Probe Context (6-Strategy Integration)
    # Data flow: create_target → _init_adaptive_probe → ctx.adaptive_probe_ctx
    #            → arm phase (seed_preferences, stealth_policy, probe_budget)
    #            → strike phase (drift_monitor, guardrail_report)
    adaptive_probe_ctx: dict[str, Any] = field(default_factory=dict)
    seed_preferences: dict[str, Any] = field(default_factory=dict)
    guardrail_report: dict[str, Any] = field(default_factory=dict)
    stealth_policy: dict[str, Any] = field(default_factory=dict)
    drift_monitor: Any = None  # CapabilityDriftMonitor 

    # Recon phase
    parsed_request: "ParsedBurpRequest | None" = None
    #  endpoint :  endpoint 
    # Academic basis: Greshake et al. (arXiv:2302.12173) — 
    #   Chao et al. (arXiv:2310.08419) —  ASR = 1 - ∏(1 - ASRᵢ)
    multi_endpoint_results: list[dict[str, Any]] = field(default_factory=list)
    #  endpoint  ( endpoint )
    _current_endpoint_idx: int = 0

    # Targets
    objective_target: Any = None
    multi_turn_target: Any = None  #  ( supports_multi_turn )
    adversarial_target: Any = None
    # L5 v10:  adversarial targets ()
    extra_adversarial_targets: list[Any] = field(default_factory=list)
    converter_target: Any = None
    scoring_target: Any = None
    # L5 v48:  target (port_expander)
    #  MCP/A2A/Agent 
    extra_objective_targets: dict[int, Any] = field(default_factory=dict)

    # Arm phase
    seeds: list["AttackSeedGroup"] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    converter_map: dict[str, list[Any]] = field(default_factory=dict)

    # Strike phase
    attack_results: dict[str, list[Any]] = field(default_factory=dict)

    # Assess phase
    asr_per_technique: dict[str, float] = field(default_factory=dict)
    overall_asr: float = 0.0
    wilson_ci: tuple[float, float] = (0.0, 0.0)
    dual_judge_stats: dict[str, Any] = field(default_factory=dict)
    # L5 v9:  scorer , 
    scorer: Any = None

    # Scenario
    scenario_result_id: str | None = None
    scenario_result: "ScenarioResult | None" = None

    # P2-MCP: MCP  ( mcp_rag_attack.py )
    #  target_router MCP  (mcp_tools/mcp_resources) ,
    #  _execute_specialized_seeds  mcp_attack 
    _mcp_dynamic_seeds: list[dict[str, Any]] = field(default_factory=list)

    # Production-grade: Playwright  ()
    _playwright_instance: Any = None
    _browser: Any = None
    _browser_context: Any = None

    #  #6 :  — →→
    #  "Orchestration Decision Log" , 
    orchestration_log: list[dict[str, Any]] = field(default_factory=list)

    # P3-Synergy: → (v60 )
    # v60 Data flow: burp_profile → synergy_orchestrator → ctx.synergy_config
    #            (attack_surface + technique_tags + confidence)
    #            → adaptive_executor (TextAdaptive technique filter)
    #  SynergyConfig ,  /  / 
    synergy_config: Any = None

    # == :  (pyrit_scan --memory-labels) ==
    #  CentralMemory, 
    # Data flow: config.py (parse_args) → ctx.memory_labels → main.py (CentralMemory.set_labels)
    # : {"run_id": "r001", "target": "deepseek", "environment": "production"}
    memory_labels: dict[str, str] = field(default_factory=dict)

    # == Scenario  (v60: →) ==
    # v60 Data flow: synergy_orchestrator → scenario_router → ctx.scenario_config
    #            ( technique_tags,  seeds/converters/scorer)
    #            → adaptive_executor (TextAdaptive technique filter)
    # Scenario : technique_tags ()
    scenario_config: dict[str, Any] = field(default_factory=dict)
    scenario_name: str = ""

    # == P3 : Circuit Breaker  ( strike/escalation.py ) ==
    #  —  endpoint  target  circuit breaker 
    # Data flow: escalation → ctx._circuit_breaker_states → circuit breaker 
    # Academic basis: Michael Nygard, "Release It!" 2nd Ed. (2018) — Circuit Breaker 
    _circuit_breaker_states: dict[str, dict[str, Any]] = field(default_factory=dict)
    _whitebox_confirmed: bool = False


def get_effective_concurrency(
    ctx: PipelineContext,
    *,
    default: int = 3,
    min_val: int = 1,
    max_val: int = 3,
) -> int:
    """imports ctx.args.max_concurrency ,  SSOT.

    L5 v45:  max_concurrency=2 
    config/defaults.yaml  max_concurrency=3,  ctx.args
     2, 

    PyRIT SQLite WAL  max_concurrency=3  (busy_timeout=5000ms)
     IntegrityError,  RateLimitedTarget Retry

    Args:
        ctx:  ( ctx.args.max_concurrency)
        default: ctx.args  fallback (imports config/defaults.yaml  3)
        min_val:  ( = 1)
        max_val:  (SQLite WAL  = 3)

    Returns:
        , clamp  [min_val, max_val]
    """
    raw = getattr(getattr(ctx, "args", None), "max_concurrency", None)
    if raw is None or not isinstance(raw, int):
        return default
    return max(min_val, min(max_val, raw))


def _get_config_int(ctx: PipelineContext, key: str, default: int) -> int:
    """imports ctx.args  config/defaults.yaml  int  (SSOT).

    L5 v45:  TAP/PAIR tree_width/tree_depth 
    parse_args  _apply_defaults  defaults.yaml all key  args,
     ctx.args.tap_tree_width 

    Args:
        ctx: 
        key: defaults.yaml  key ( "tap_tree_width", "pair_tree_depth")
        default:  fallback

    Returns:
        int 
    """
    raw = getattr(getattr(ctx, "args", None), key, None)
    if raw is None or not isinstance(raw, int):
        return default
    return raw


# == L5 v13: Relaxed Adversarial Schema monkey-patch ==
# Academic basis: Zheng et al. (arXiv:2306.05685) — LLM-as-a-Judge 
#  API (DeepSeek-V3, LongCat)  JSON ,
#  rationale / last_response_summary  InvalidJsonException
# → Retry → 
#  monkey-patch , "Layer",
#  PyRIT , 

_relaxed_schema_applied = False


def apply_relaxed_adversarial_schema() -> None:
    """Monkey-patch PyRIT  adversarial_chat JSON schema,  rationale  last_response_summary 

    Academic basis: Zheng et al. (arXiv:2306.05685) — LLM /
     JSON  JSON schema, 
    InvalidJsonException Retry

    :
        1. converter(s) "adversarial_chat_relaxed" schema,  required: ["next_message"]
        2. Monkey-patch get_common_json_schema,  "adversarial_chat"  relaxed 
        3.  PyRIT ,  (Layer)
    """
    global _relaxed_schema_applied
    if _relaxed_schema_applied:
        return

    try:
        import pyrit.models.target.json_schema_definition as schema_mod

        # Ensure schema  YAML 
        schema_mod._ensure_discovered()

        #  schema
        original = schema_mod.get_common_json_schema("adversarial_chat")

        #  relaxed :  next_message 
        relaxed = copy.deepcopy(original)
        relaxed["required"] = ["next_message"]

        #  relaxed schema (overwrite=True )
        schema_mod.register_common_json_schema(
            name="adversarial_chat", schema=relaxed, overwrite=True
        )

        #  true_false_with_rationale  relaxed 
        tf_original = schema_mod.get_common_json_schema("true_false_with_rationale")
        tf_relaxed = copy.deepcopy(tf_original)
        #  required  additionalProperties
        tf_relaxed["additionalProperties"] = True
        schema_mod.register_common_json_schema(
            name="true_false_with_rationale", schema=tf_relaxed, overwrite=True
        )

        # scale_with_rationale relaxed 
        scale_original = schema_mod.get_common_json_schema("scale_with_rationale")
        scale_relaxed = copy.deepcopy(scale_original)
        scale_relaxed["additionalProperties"] = True
        schema_mod.register_common_json_schema(
            name="scale_with_rationale", schema=scale_relaxed, overwrite=True
        )

        _relaxed_schema_applied = True
        logger.debug(
            "Relaxed adversarial schema applied: "
            "adversarial_chat (required=['next_message']), "
            "true_false_with_rationale (additionalProperties=True), "
            "scale_with_rationale (additionalProperties=True)"
        )

    except Exception as e:
        logger.debug("Relaxed adversarial schema skipped: %s", e)

