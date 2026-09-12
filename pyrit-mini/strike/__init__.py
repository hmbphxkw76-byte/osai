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
# SQL Injection Evasion - arXiv:2403.15514 (SQL obfuscation) / arXiv:2306.05685 (Adaptive evasion)
"""strike - Attack execution module.

6-phase attack pipeline with PyRIT native AttackExecutor:

Component-based architecture (aligned with recon/ and data/seeds/):
    - a2a/          A2A / Multi-Agent attacks
    - mcp/          MCP protocol attacks
    - rag/          RAG poisoning attacks
    - model/        Direct LLM model attacks
    - web/          Web application attacks
    - memory/       Agent memory attacks
    - session/      Session / Auth attacks
    - evasion/      Evasion techniques (SQL, audit, etc.)
    - injection/    Injection attacks (auth, doc, file, PI, stealth)
    - common/       Shared infrastructure (dispatcher, executor, etc.)

Usage:
    # Import from subdirectories (recommended):
    from strike.a2a import A2AWorkflowAttacker
    from strike.mcp import MCPOrchestrator
    from strike.rag import VectorDBPoisoner
    from strike.model import BackdoorAttack
    from strike.web import WebAttackOrchestrator
    from strike.memory import MemoryInjector
    from strike.session import SessionManager
    from strike.evasion import SQLInjectionEvasion
    from strike.injection import IndirectPIAttackGenerator
    from strike.common import execute_attacks

    # Or use lazy imports from strike package:
    import strike
    attacker = strike.A2AWorkflowAttacker()
"""

from typing import Any

from strike.common.executor import execute_attacks
from strike.injection.stealth_exec import StealthConfig, StealthExecutor, _pareto_delay

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
    # Indirect Prompt Injection (arXiv:2302.12173)
    "IndirectPIAttackGenerator",
    "AttackPayload",
    "EvasionLevel",
    # Link Evasion (arXiv:2407.16924)
    "LinkEvasionResult",
    "generate_link_evasion_payloads",
    "generate_display_url_mismatch",
    "generate_legitimate_framing",
    "generate_gradual_injection_chain",
    "generate_shortened_url_payload",
    "generate_homograph_link_payload",
    "generate_homograph_domain",
    "get_available_techniques",
    # SQL Injection Evasion (arXiv:2403.15514 / arXiv:2306.05685)
    "SQLInjectionEvasion",
    "create_sql_injection_evasion",
    "EvasionPayload",
    "generate_hex_encoded_xp_cmdshell",
    "generate_gradual_escalation_chain",
    "generate_lolbin_evasion",
    "encode_hex",
    "generate_char_concatenation",
    "generate_timing_jitter_evasion",
    "generate_multi_step_fragmentation",
]


# Lazy imports for all submodules
def __getattr__(name: str) -> Any:
    """Lazy import for all strike submodules."""
    # Web Security Attacks
    if name == "AuthAttacks":
        from strike.injection.auth_attacks import AuthAttacks

        return AuthAttacks
    if name == "WebAttacks":
        from strike.web.attacks import WebAttacks

        return WebAttacks
    if name == "AuditEvasionAttacks":
        from strike.evasion.audit import AuditEvasionAttacks

        return AuditEvasionAttacks
    if name == "HTTPAttackEngine":
        from strike.web.http_engine import HTTPAttackEngine

        return HTTPAttackEngine
    if name == "WebAttackOrchestrator":
        from strike.web.orchestrator import WebAttackOrchestrator

        return WebAttackOrchestrator

    # MCPSec modules (now in strike/mcp/)
    if name in (
        "MCPSecBridge",
        "MCPSecScanResult",
        "create_mcpsec_bridge",
    ):
        # Legacy compatibility: mcpsec_bridge functions are now in mcp/orchestrator
        raise AttributeError(
            f"module {__name__!r} has no attribute {name!r}. Use 'from strike.mcp.orchestrator import ...' instead"
        )
    if name in (
        "MaliciousMCPServer",
        "MaliciousMCPConfig",
        "create_and_start_rogue_server",
    ):
        from strike.mcp import malicious_server

        return getattr(malicious_server, name)
    if name in (
        "MCPOrchestrator",
        "MCPOrchestratorConfig",
        "MCPAttackReport",
        "run_mcpsec_pyrit_attack",
    ):
        from strike.mcp import orchestrator

        return getattr(orchestrator, name)
    if name in ("generate_dynamic_seeds", "load_mcp_seeds_for_target"):
        from strike.mcp import dynamic_seeds

        return getattr(dynamic_seeds, name)

    # Output Filter Bypass modules (now in strike/model/)
    if name in ("run_output_filter_bypass", "OutputFilterBypassContext"):
        from strike.model import filter_bypass

        return getattr(filter_bypass, name)

    # Multimodal Injection modules (now in strike/model/)
    if name in ("run_multimodal_injection", "MultimodalInjectionContext"):
        from strike.model import multimodal

        return getattr(multimodal, name)

    # Backdoor Attack modules (now in strike/model/)
    if name in ("run_backdoor_attack", "BackdoorAttackContext"):
        from strike.model import backdoor

        return getattr(backdoor, name)

    # Document Poisoning modules
    if name in (
        "create_poisoned_document",
        "generate_pdf_with_payload",
        "generate_docx_with_payload",
        "generate_markdown_with_watermark",
    ):
        from strike.injection import doc_poisoner

        return getattr(doc_poisoner, name)

    # Indirect PI Generator module (arXiv:2302.12173)
    if name in ("IndirectPIAttackGenerator", "AttackPayload", "EvasionLevel"):
        from strike.injection import indirect_pi

        return getattr(indirect_pi, name)

    # Link Evasion module (arXiv:2407.16924)
    if name in (
        "LinkEvasionResult",
        "generate_link_evasion_payloads",
        "generate_display_url_mismatch",
        "generate_legitimate_framing",
        "generate_gradual_injection_chain",
        "generate_shortened_url_payload",
        "generate_homograph_link_payload",
        "generate_homograph_domain",
        "get_available_techniques",
    ):
        from strike.web import link_evasion

        return getattr(link_evasion, name)

    # SQL Injection Evasion module (arXiv:2403.15514 / arXiv:2306.05685)
    if name in (
        "SQLInjectionEvasion",
        "create_sql_injection_evasion",
        "EvasionPayload",
        "generate_hex_encoded_xp_cmdshell",
        "generate_gradual_escalation_chain",
        "generate_lolbin_evasion",
        "encode_hex",
        "generate_char_concatenation",
        "generate_timing_jitter_evasion",
        "generate_multi_step_fragmentation",
    ):
        from strike.evasion import sql

        return getattr(sql, name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
