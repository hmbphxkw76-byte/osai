"""recon — Burp

 1 : imports Burp  HTTP , HTTPTarget,

Core modules:
    - burp_parser:  Burp HTTP ,  URL/Headers/Body,  {PROMPT}
    - target_router:  HTTPTarget + RateLimitedTarget,  adversarial/scoring target
    - capability_detector:  (agent/mcp/rag/embedding)
    - confidence_scorer:  (SSOT)
    - mcpsec_bridge: MCP (MCPSec v2.7.2 bridge)
    - system_prompt_extractor:
    - endpoint_sorter:  endpoint + attack surface classification
    - adaptive_probe_config:  ()
    - auth_detector:  ( detection only, no execution)
    - guardrail_detector:  ()
    - model_seed_mapper:  ( → )
    - stealth_config: Stealth Level  ()
    - health_probe:  (4-layer active reconnaissance)
    - rag_pipeline_probe: P1 RAG (KB structure + citations + chunking)

Removed modules (v1.5 Red Team Alignment):
    - health_probe: KEPT (active black-box reconnaissance - directly feeds attack)
    - port_expander: →  (60+ ports, DEPRECATED)
    - behavioral_verifier: →  (no ASR contribution)
    - capability_monitor: → core/runtime/capability_drift.py (runtime monitoring)
    - attack_surface_classifier: → recon/endpoint_sorter.py (merged)
    - auth_state_manager.py → recon/auth_detector.py (removed execution logic)

Constitution compliance:
    - R-RECON-1: Every remaining module has explicit ASR contribution path
"""

from recon.adaptive_probe_config import compute_probe_budget
from recon.auth_detector import AuthDetector, AuthState, decode_jwt_payload
from recon.burp_parser import ParsedBurpRequest, build_http_target, parse_burp_request
from recon.confidence_scorer import (
    CapabilityResult,
    aggregate_capabilities,
    score_capability,
)
from recon.endpoint_sorter import (
    ClassificationResult,
    classify_http_content,
    sort_burp_list_by_priority,
    sort_endpoints_by_priority,
)
from recon.guardrail_detector import GuardrailReport, detect_guardrail
from recon.model_seed_mapper import (
    ModelSeedMapper,
    detect_model_family,
    get_mapper,
    get_seeds_for_model,
)
from recon.rag_pipeline_probe import RAGPipelineProfile, run_rag_pipeline_probe
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
    # Adaptive probing (v1.5: simplified)
    "compute_probe_budget",
    # Confidence scoring (v1.5: simplified, removed convergence model)
    "CapabilityResult",
    "aggregate_capabilities",
    "score_capability",
    # Guardrail detection (NEW)
    "GuardrailReport",
    "detect_guardrail",
    # Model seed mapping (v1.5: simplified)
    "ModelSeedMapper",
    "detect_model_family",
    "get_mapper",
    "get_seeds_for_model",
    # Stealth config (NEW - Strategy 5)
    "StealthLevelManager",
    "StealthPolicy",
    "get_stealth_manager",
    # Auth detection (v1.5 refactor: detection only)
    "AuthDetector",
    "AuthState",
    "decode_jwt_payload",
    # Attack surface classification (merged from attack_surface_classifier)
    "ClassificationResult",
    "classify_http_content",
    # RAG pipeline probe (P1 enhancement 2026-09-08, attacker-slimmed)
    "RAGPipelineProfile",
    "run_rag_pipeline_probe",
]
