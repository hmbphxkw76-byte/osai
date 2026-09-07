"""recon — Burp 

 1 : imports Burp  HTTP ,
 HTTPTarget, 

Core modules:
    - burp_parser:  Burp HTTP ,  URL/Headers/Body,  {PROMPT}
    - target_router:  HTTPTarget + RateLimitedTarget,  adversarial/scoring target
    - capability_detector:  (agent/mcp/rag/embedding)
    - confidence_scorer:  (SSOT)
    - mcp_enumerator: MCP 
    - system_prompt_extractor: 
    - endpoint_sorter:  endpoint 
    - adaptive_probe_config:  ()
    - behavioral_verifier: Layer ( vs )
    - capability_monitor:  ()
    - guardrail_detector:  ()
    - model_seed_mapper:  ( → )
    - stealth_config: Stealth Level  ()
"""

from recon.adaptive_probe_config import compute_probe_budget, should_run_probe
from recon.behavioral_verifier import BehavioralVerifyReport, behavioral_verify
from recon.burp_parser import ParsedBurpRequest, build_http_target, parse_burp_request
from recon.capability_monitor import CapabilityDriftMonitor, CapabilitySnapshot, get_drift_monitor
from recon.confidence_scorer import (
    CapabilityResult,
    ConvergenceResult,
    aggregate_capabilities,
    merge_verification_into_capabilities,
    score_capability,
    score_capability_with_convergence,
)
from recon.endpoint_sorter import sort_burp_list_by_priority, sort_endpoints_by_priority
from recon.guardrail_detector import GuardrailReport, detect_guardrail
from recon.model_seed_mapper import (
    ModelSeedMapper,
    detect_model_family,
    get_mapper,
    get_seeds_for_model,
)
from recon.stealth_config import StealthLevelManager, StealthPolicy, get_stealth_manager
from recon.target_router import create_target

__all__ = [
    # Core (existing)
    "ParsedBurpRequest",
    "parse_burp_request",
    "build_http_target",
    "create_target",
    "sort_burp_list_by_priority",
    "sort_endpoints_by_priority",
    # Adaptive probing (NEW - Strategy 3)
    "compute_probe_budget",
    "should_run_probe",
    # Behavioral verification (NEW - Strategy 2)
    "BehavioralVerifyReport",
    "behavioral_verify",
    # Confidence scoring with convergence (NEW - Strategy 1)
    "CapabilityResult",
    "ConvergenceResult",
    "aggregate_capabilities",
    "score_capability",
    "score_capability_with_convergence",
    "merge_verification_into_capabilities",
    # Capability drift monitor (NEW - Strategy 4)
    "CapabilityDriftMonitor",
    "CapabilitySnapshot",
    "get_drift_monitor",
    # Guardrail detection (NEW)
    "GuardrailReport",
    "detect_guardrail",
    # Model seed mapping (NEW - Strategy 6)
    "ModelSeedMapper",
    "detect_model_family",
    "get_mapper",
    "get_seeds_for_model",
    # Stealth config (NEW - Strategy 5)
    "StealthLevelManager",
    "StealthPolicy",
    "get_stealth_manager",
]
