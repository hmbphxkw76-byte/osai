# arXiv:2402.12109 — Russinovich et al., Crescendo
# arXiv:2407.01232 — PyRIT, framework foundation
# arXiv:2302.12173 — Greshake et al., PromptSendingAttack
# MCPSec Bridge - mcpsec v2.7.2 (manthanganghasadiya/mcpsec)
# Stealth Exec - SIEM evasion timing (arXiv:2306.05685 / arXiv:2204.01326)
# Output Filter Bypass - arXiv:2402.05124 (Many-Shot Jailbreaking)
# Multimodal Injection - arXiv:2403.07860 (FigStep) / arXiv:2306.13213 (Visual Adv)
# Backdoor Attack - arXiv:2301.11916 (Sleeper Agents) / arXiv:2004.06660 (TrojLLM)
# PAIR/TAP - arXiv:2310.08419 (PAIR) / arXiv:2405.17350 (TAP)
# ASR Trend Tracker - arXiv:2403.04132 (Statistical Significance)
# Decision Safety - arXiv:2407.01232 (Auth Framework) / NIST AI RMF 600-1
"""strike - Attack execution module.

6-phase attack pipeline with PyRIT native AttackExecutor:

Core modules:
    - executor: PromptSendingAttack execution (FIRST_SUCCESS)
    - arm/converter_selector: Converter selection + OWASP mapping (arm/)
    - escalation_runtime: Multi-turn escalation (Crescendo/TAP/SkeletonKey, arXiv:2402.14266)
    - adaptive_executor: Best-of-N retry logic
    - web_orchestrator: Web security attacks orchestrator

Web Security Attacks:
    - auth_attacks: Authentication attacks (JWT/OAuth/Session)
    - web_attacks: Web application attacks (smuggling/cache poisoning/etc.)
    - audit_evasion: Audit evasion attacks (log injection)
    - http_attack_engine: Unified HTTP attack engine

MCPSec + PyRIT Integration (v2.7.2):
    - mcpsec_bridge: Bridge MCPSec CLI to pyrit-mini attack pipeline
    - malicious_mcp_server: Rogue MCP server for client-side testing
    - mcpsec_orchestrator: Full MCPSec + PyRIT attack pipeline orchestrator
    - dynamic_mcp_seeds: Runtime attack seed generation via MCPSec

Output Filter Bypass (arXiv:2402.05124):
    - output_filter_bypass: ManyShotJailbreakAttack + ChunkedRequestAttack + XPIAAttack

Multimodal Injection (arXiv:2403.07860):
    - multimodal_injection: Image/Audio/File carrier channels for VLM attacks

Backdoor Attack (arXiv:2301.11916):
    - backdoor_attack: Trigger word activation + context-conditional behavior

Decision System (v2.0):
    - decision_safety: R-DECIDE-1 safety boundary protection
    - asr_trend_tracker: ASR trend analysis for adaptive decisions
    - pair_tap_strategies: PAIR/TAP as independent strategy options
    - attack_knowledge_base: Historical attack knowledge for cross-target transfer
"""

from typing import Any

from strike.executor import execute_attacks
from strike.stealth_exec import StealthConfig, StealthExecutor, _pareto_delay

__all__ = [
    "execute_attacks",
    # Stealth Executor (SIEM evasion)
    "StealthConfig",
    "StealthExecutor",
    "_pareto_delay",
    # Web Security Attacks
    "AuthAttacks",
    "WebAttacks",
    "AuditEvasionAttacks",
    "HTTPAttackEngine",
    "WebAttackOrchestrator",
    # MCPSec Integration
    "MCPSecBridge",
    "MCPSecScanResult",
    "create_mcpsec_bridge",
    "MaliciousMCPServer",
    "MaliciousMCPConfig",
    "create_and_start_rogue_server",
    "MCPOrchestrator",
    "MCPOrchestratorConfig",
    "MCPAttackReport",
    "run_mcpsec_pyrit_attack",
    "generate_dynamic_seeds",
    "load_mcp_seeds_for_target",
    # Output Filter Bypass (arXiv:2402.05124)
    "run_output_filter_bypass",
    "OutputFilterBypassContext",
    # Multimodal Injection (arXiv:2403.07860)
    "run_multimodal_injection",
    "MultimodalInjectionContext",
    # Backdoor Attack (arXiv:2301.11916)
    "run_backdoor_attack",
    "BackdoorAttackContext",
    # Document Poisoning (arXiv:2302.12173)
    "create_poisoned_document",
    "generate_pdf_with_payload",
    "generate_docx_with_payload",
    "generate_markdown_with_watermark",
]

# Lazy imports for Web security modules
def __getattr__(name: str) -> Any:
    """Lazy import for Web security and MCPSec integration modules."""
    # Web Security Attacks
    if name == "AuthAttacks":
        from strike.auth_attacks import AuthAttacks
        return AuthAttacks
    if name == "WebAttacks":
        from strike.web_attacks import WebAttacks
        return WebAttacks
    if name == "AuditEvasionAttacks":
        from strike.audit_evasion import AuditEvasionAttacks
        return AuditEvasionAttacks
    if name == "HTTPAttackEngine":
        from strike.http_attack_engine import HTTPAttackEngine
        return HTTPAttackEngine
    if name == "WebAttackOrchestrator":
        from strike.web_orchestrator import WebAttackOrchestrator
        return WebAttackOrchestrator

    # MCPSec modules
    if name in (
        "MCPSecBridge",
        "MCPSecScanResult",
        "create_mcpsec_bridge",
    ):
        from strike import mcpsec_bridge
        return getattr(mcpsec_bridge, name)
    if name in (
        "MaliciousMCPServer",
        "MaliciousMCPConfig",
        "create_and_start_rogue_server",
    ):
        from strike import malicious_mcp_server
        return getattr(malicious_mcp_server, name)
    if name in (
        "MCPOrchestrator",
        "MCPOrchestratorConfig",
        "MCPAttackReport",
        "run_mcpsec_pyrit_attack",
    ):
        from strike import mcpsec_orchestrator
        return getattr(mcpsec_orchestrator, name)
    if name in ("generate_dynamic_seeds", "load_mcp_seeds_for_target"):
        from strike import dynamic_mcp_seeds
        return getattr(dynamic_mcp_seeds, name)

    # Output Filter Bypass modules
    if name in ("run_output_filter_bypass", "OutputFilterBypassContext"):
        from strike import output_filter_bypass
        return getattr(output_filter_bypass, name)

    # Multimodal Injection modules
    if name in ("run_multimodal_injection", "MultimodalInjectionContext"):
        from strike import multimodal_injection
        return getattr(multimodal_injection, name)

    # Backdoor Attack modules
    if name in ("run_backdoor_attack", "BackdoorAttackContext"):
        from strike import backdoor_attack
        return getattr(backdoor_attack, name)

    # Document Poisoning modules
    if name in ("create_poisoned_document", "generate_pdf_with_payload",
                "generate_docx_with_payload", "generate_markdown_with_watermark"):
        from strike import document_poisoner
        return getattr(document_poisoner, name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
