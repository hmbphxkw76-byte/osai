# arXiv:2402.12109 — Russinovich et al., Crescendo
# arXiv:2407.01232 — PyRIT, framework foundation
# arXiv:2302.12173 — Greshake et al., PromptSendingAttack
# MCPSec Bridge - mcpsec v2.7.2 (manthanganghasadiya/mcpsec)
"""strike - Attack execution module.

6-phase attack pipeline with PyRIT native AttackExecutor:

Core modules:
    - executor: PromptSendingAttack execution (FIRST_SUCCESS)
    - arm/converter_selector: Converter selection + OWASP mapping (arm/)
    - escalation_runtime: Multi-turn escalation (Crescendo/TAP/SkeletonKey)
    - adaptive_executor: Best-of-N retry logic
    - web_orchestrator: Web security attacks orchestrator

Web Security Attacks:
    - auth_attacks: Authentication attacks (JWT/OAuth/Session)
    - web_attacks: Web application attacks (smuggling/cache poisoning/etc.)
    - audit_evasion: Audit evasion attacks (log injection)
    - http_attack_engine: Unified HTTP attack engine

MCPSec + PyRIT Integration (v2.7.2):
    - mcpsec_bridge: Bridge MCPSec CLI to pyrit-mini attack pipeline
    - mcp_agent_target: PyRIT PromptChatTarget for MCP-enabled LLM agents
    - malicious_mcp_server: Rogue MCP server for client-side testing
    - mcpsec_orchestrator: Full MCPSec + PyRIT attack pipeline orchestrator
    - dynamic_mcp_seeds: Runtime attack seed generation via MCPSec
"""

from typing import Any

from strike.executor import execute_attacks

__all__ = [
    "execute_attacks",
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
    "MCPAgentTarget",
    "MCPAgentTargetConfig",
    "MCPSideEffect",
    "create_mcp_agent_target",
    "MaliciousMCPServer",
    "MaliciousMCPConfig",
    "create_and_start_rogue_server",
    "MCPOrchestrator",
    "MCPOrchestratorConfig",
    "MCPAttackReport",
    "run_mcpsec_pyrit_attack",
    "generate_dynamic_seeds",
    "load_mcp_seeds_for_target",
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
        "MCPAgentTarget",
        "MCPAgentTargetConfig",
        "MCPSideEffect",
        "create_mcp_agent_target",
    ):
        from strike import mcp_agent_target
        return getattr(mcp_agent_target, name)
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
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
