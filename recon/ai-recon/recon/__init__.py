"""
AI Reconnaissance Engine (AI 侦测引擎)
=======================================
Phase 1 standalone reconnaissance — browser-based SPA rendering,
auth flow automation, API endpoint discovery, and target profiling.

Output: target_profile.json → consumed by PyRIT Phase 2.
"""

__version__ = "2.0.0"
__all__ = [
    "ReconEngine",
    "TargetProfile",
    "validate_profile",
    "ModelProbeResult",
    "probe_model_info",
    "probe_to_summary",
    "JsSdkScanner",
    "CredentialScanner",
    "WafDetector",
    "RagProber",
    "PromptExtractor",
    "BehaviorMapper",
    "ModuleRegistry",
    "ProbeModule",
]

from recon.schema import TargetProfile, validate_profile
from recon.engine import ReconEngine
from recon.probes.model_probe import ModelProbeResult, probe_model_info, probe_to_summary
from recon.scanners.js_sdk_scanner import JsSdkScanner
from recon.scanners.credential_scanner import CredentialScanner
from recon.scanners.waf_detector import WafDetector
from recon.probes.rag_probe import RagProber
from recon.probes.prompt_extractor import PromptExtractor
from recon.analysis.behavior_mapper import BehaviorMapper
from recon.module_registry import ModuleRegistry, ProbeModule
