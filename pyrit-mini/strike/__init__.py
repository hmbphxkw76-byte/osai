# arXiv:2402.12109 — Russinovich et al., Crescendo
# arXiv:2407.01232 — PyRIT, framework foundation
# arXiv:2302.12173 — Greshake et al., PromptSendingAttack
# MCPSec Bridge - mcpsec v2.7.2 (manthanghasadiya/mcpsec)
"""strike - Attack execution module.

6-phase attack pipeline with PyRIT native AttackExecutor:

Core modules:
    - executor: PromptSendingAttack execution (FIRST_SUCCESS)
    - arm/converter_selector: Converter selection + OWASP mapping (arm/)
    - escalation: Multi-level escalation (Crescendo/TAP/PAIR/GCG)
    - adaptive_executor: PyRIT TextAdaptive + Best-of-N

MCPSec + PyRIT Integration (v2.7.2):
    - mcpsec_bridge: Bridge MCPSec CLI to pyrit-mini attack pipeline
    - mcp_agent_target: PyRIT PromptChatTarget for MCP-enabled LLM agents
    - malicious_mcp_server: Rogue MCP server for client-side testing
    - mcpsec_orchestrator: Full MCPSec + PyRIT attack pipeline orchestrator
    - dynamic_mcp_seeds: Runtime attack seed generation via MCPSec
"""

from typing import Any

from strike.escalation import check_and_escalate
from strike.executor import execute_attacks

__all__ = [
    "execute_attacks",
    "check_and_escalate",
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

# Lazy imports for MCPSec modules (imported on demand to avoid hard dependency)
def __getattr__(name: str) -> Any:
    """Lazy import for MCPSec integration modules."""
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
