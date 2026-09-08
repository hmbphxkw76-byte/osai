# MCPSec Bridge - mcpsec v2.7.2 (manthanghasadiya/mcpsec)
# arXiv:2302.12173 - Greshake et al., Indirect prompt injection
# arXiv:2402.14266 - SKELETONKEY, SkeletonKey
# arXiv:2404.01833 - Russinovich et al., Crescendo
# arXiv:2310.08419 - Chao et al., PAIR
"""mcpsec_orchestrator - MCPSec + PyRIT Combined Attack Orchestrator.

Unified attack pipeline combining MCPSec reconnaissance with PyRIT attack execution:
    1. RECON: MCPSec enumerate + fuzz → discover attack surface
    2. SEED:   Dynamic seed generation from scan results
    3. ATTACK: PyRIT PromptSendingAttack / SkeletonKeyAttack / Crescendo
    4. VERIFY: Side-effect validation against MaliciousMCP server
    5. REPORT: Combined MCPSec + PyRIT findings

Architecture:
    MCPSec Orchestrator
        ├── Phase 1: Enumerate (mcpsec info / tools)
        ├── Phase 2: Scan     (mcpsec scan → vulnerabilities)
        ├── Phase 3: Fuzz     (mcpsec fuzz → dynamic seeds)
        ├── Phase 4: Attack   (PyRIT → PromptSending/Crescendo/TAP)
        ├── Phase 5: Verify   (Side-effect analysis → ground truth)
        └── Phase 6: Report   (Combined findings + ASR)

Academic basis:
    - MCPSec (manthanghasadiya/mcpsec v2.7.2) - MCP security scanning
    - PyRIT (arXiv:2407.01232) - Red teaming framework
    - Greshake et al. (arXiv:2302.12173) - MCP indirect injection
    - Zhan et al. (arXiv:2307.00929) - Agent tool injection
    - Russinovich et al. (arXiv:2404.01833) - Crescendo multi-turn

Design principles:
    1. MCPSec for reconnaissance, PyRIT for execution
    2. Dynamic seed generation replaces static files
    3. Side-effect verification as ground truth
    4. Compatible with existing PipelineContext
    5. Async throughout for concurrency
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class MCPAttackReport:
    """Combined MCPSec + PyRIT attack report.

    Attributes:
        target_url: Target MCP server URL
        phase_results: Results from each pipeline phase
        vulnerabilities: MCPSec-detected vulnerabilities
        attack_results: PyRIT attack execution results
        side_effects: Observed side-effects (ground truth)
        asr_final: Final attack success rate
        seed_count: Number of seeds generated/executed
        scan_coverage: MCPSec scanner coverage
        recommendations: Remediation recommendations
    """
    target_url: str = ""
    phase_results: dict[str, Any] = field(default_factory=dict)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    attack_results: dict[str, list] = field(default_factory=dict)
    side_effects: list[dict[str, Any]] = field(default_factory=list)
    asr_final: float = 0.0
    seed_count: int = 0
    scan_coverage: dict[str, int] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)


@dataclass
class MCPOrchestratorConfig:
    """Configuration for MCP attack orchestrator.

    Attributes:
        target_url: Target MCP server endpoint
        transport: MCP transport (http/stdio)
        stdio_command: Command for stdio transport
        auth_header: Optional auth header
        use_mcpsec_scan: Enable MCPSec scanning
        use_mcpsec_fuzz: Enable MCPSec fuzzing
        use_pyrit_attack: Enable PyRIT attack execution
        use_side_effect_verify: Enable side-effect verification
        fuzz_intensity: MCPSec fuzz intensity
        max_seeds: Maximum attack seeds
        attack_timeout: Timeout per attack
        scanners: Custom scanner list
    """
    target_url: str = ""
    transport: str = "http"
    stdio_command: Optional[str] = None
    auth_header: Optional[str] = None
    use_mcpsec_scan: bool = True
    use_mcpsec_fuzz: bool = True
    use_pyrit_attack: bool = True
    use_side_effect_verify: bool = True
    fuzz_intensity: str = "high"
    max_seeds: int = 50
    attack_timeout: float = 600.0
    scanners: Optional[list[str]] = None


class MCPOrchestrator:
    """Orchestrates MCPSec + PyRIT combined attack pipeline.

    Combines MCPSec's reconnaissance capabilities with PyRIT's attack execution:
    - MCPSec provides: enumeration, scanning, fuzzing, seed generation
    - PyRIT provides: attack execution (PromptSending, Crescendo, TAP, etc.)
    - Combined: end-to-end MCP red team pipeline

    Attributes:
        config: Orchestrator configuration
        mcpsec_bridge: MCPSecBridge instance
        malicious_server: Optional MaliciousMCP instance
        report: Attack report accumulator
    """

    def __init__(
        self,
        config: MCPOrchestratorConfig,
        bridge: Optional[Any] = None,
    ) -> None:
        """Initialize MCPOrchestrator.

        Args:
            config: Orchestrator configuration
            bridge: Optional pre-configured MCPSecBridge
        """
        self._config = config
        self._bridge = bridge
        self._malicious_server: Optional[Any] = None
        self._report = MCPAttackReport(target_url=config.target_url)

    @property
    def report(self) -> MCPAttackReport:
        """Current attack report."""
        return self._report

    @property
    def bridge(self) -> Any:
        """MCPSecBridge instance (lazy-initialized)."""
        if self._bridge is None:
            from strike.mcpsec_bridge import create_mcpsec_bridge

            self._bridge = create_mcpsec_bridge()
        return self._bridge

    async def run_full_pipeline(self) -> MCPAttackReport:
        """Execute the complete MCP attack pipeline.

        Phases:
            1. Enumerate attack surface
            2. Scan for vulnerabilities
            3. Fuzz and generate seeds
            4. Execute PyRIT attacks
            5. Verify side-effects
            6. Generate report

        Returns:
            Complete attack report
        """
        logger.info("MCPOrchestrator: starting full pipeline for %s", self._config.target_url)
        asyncio.get_event_loop().time() if hasattr(asyncio, "get_event_loop") else 0

        try:
            # Phase 1: Enumerate
            await self._phase_enumerate()

            # Phase 2: Scan
            if self._config.use_mcpsec_scan:
                await self._phase_scan()

            # Phase 3: Generate seeds
            if self._config.use_mcpsec_fuzz:
                await self._phase_generate_seeds()

            # Phase 4: Execute attacks
            if self._config.use_pyrit_attack:
                await self._phase_attack()

            # Phase 5: Verify side-effects
            if self._config.use_side_effect_verify:
                await self._phase_verify()

        except Exception as e:
            logger.error("MCPOrchestrator: pipeline error: %s", e)
            self._report.phase_results["error"] = str(e)

        # Phase 6: Finalize report
        await self._phase_generate_report()

        elapsed = 0
        logger.info(
            "MCPOrchestrator: pipeline complete in %.1fs, ASR=%.1f%%",
            elapsed,
            self._report.asr_final,
        )
        return self._report

    async def _phase_enumerate(self) -> None:
        """Phase 1: Enumerate MCP attack surface."""
        logger.info("MCPOrchestrator: Phase 1 - Enumerate attack surface")

        if not self.bridge.is_available:
            self._report.phase_results["enumerate"] = {
                "status": "skipped",
                "reason": "mcpsec not available",
            }
            return

        try:
            info = await self.bridge.enumerate_surface(
                self._config.target_url,
                transport=self._config.transport,
                stdio_command=self._config.stdio_command,
                auth_header=self._config.auth_header,
            )

            self._report.phase_results["enumerate"] = {
                "status": "complete",
                "tools_count": len(info.get("tools", [])),
                "resources_count": len(info.get("resources", [])),
                "prompts_count": len(info.get("prompts", [])),
                "server_info": info.get("server_info"),
                "raw": info,
            }

            logger.info(
                "MCPOrchestrator: found %d tools, %d resources",
                info.get("tools_count", 0),
                info.get("resources_count", 0),
            )
        except Exception as e:
            logger.warning("MCPOrchestrator: enumerate phase failed: %s", e)
            self._report.phase_results["enumerate"] = {
                "status": "failed",
                "error": str(e),
            }

    async def _phase_scan(self) -> None:
        """Phase 2: Scan for vulnerabilities."""
        logger.info("MCPOrchestrator: Phase 2 - Vulnerability scanning")

        if not self.bridge.is_available:
            self._report.phase_results["scan"] = {
                "status": "skipped",
                "reason": "mcpsec not available",
            }
            return

        try:
            scan_results = await self.bridge.scan_target(
                self._config.target_url,
                scanners=self._config.scanners,
                auth_header=self._config.auth_header,
                transport=self._config.transport,
                stdio_command=self._config.stdio_command,
            )

            # Categorize findings
            critical = [r for r in scan_results if r.severity == "critical"]
            high = [r for r in scan_results if r.severity == "high"]
            medium = [r for r in scan_results if r.severity == "medium"]
            low = [r for r in scan_results if r.severity in ("low", "info")]

            self._report.phase_results["scan"] = {
                "status": "complete",
                "total_findings": len(scan_results),
                "critical": len(critical),
                "high": len(high),
                "medium": len(medium),
                "low": len(low),
                "findings": [
                    {
                        "scanner": r.scanner,
                        "vulnerability": r.vulnerability,
                        "severity": r.severity,
                        "tool": r.tool_name,
                        "evidence": r.evidence[:200],
                    }
                    for r in scan_results
                ],
            }

            self._report.vulnerabilities = self._report.phase_results["scan"]["findings"]
            self._report.scan_coverage = {
                "total": len(scan_results),
                "by_scanner": {},
            }
            for r in scan_results:
                scanner = r.scanner  # FIX: MCPSecScanResult.scorer is .scanner
                self._report.scan_coverage["by_scanner"][scanner] = (
                    self._report.scan_coverage["by_scanner"].get(scanner, 0) + 1
                )

            logger.info(
                "MCPOrchestrator: scan found %d vulnerabilities (C:%d H:%d M:%d L:%d)",
                len(scan_results),
                len(critical),
                len(high),
                len(medium),
                len(low),
            )
        except Exception as e:
            logger.warning("MCPOrchestrator: scan phase failed: %s", e)
            self._report.phase_results["scan"] = {
                "status": "failed",
                "error": str(e),
            }

    async def _phase_generate_seeds(self) -> None:
        """Phase 3: Generate attack seeds from fuzzing."""
        logger.info("MCPOrchestrator: Phase 3 - Dynamic seed generation")

        if not self.bridge.is_available:
            self._report.phase_results["seeds"] = {
                "status": "skipped",
                "reason": "mcpsec not available",
            }
            return

        try:
            from strike.dynamic_mcp_seeds import generate_dynamic_seeds

            # Get tool list from enumeration
            enum_data = self._report.phase_results.get("enumerate", {})
            raw_info = enum_data.get("raw", {})
            tools = raw_info.get("tools", [])

            dataset = await generate_dynamic_seeds(
                self._config.target_url,
                self.bridge,
                max_seeds=self._config.max_seeds,
                tools=tools,
            )

            self._report.phase_results["seeds"] = {
                "status": "complete",
                "count": len(dataset.prompts),
                "source": "mcpsec_fuzz_dynamic",
            }
            self._report.seed_count = len(dataset.prompts)

            logger.info(
                "MCPOrchestrator: generated %d attack seeds",
                len(dataset.prompts),
            )
        except Exception as e:
            logger.warning("MCPOrchestrator: seed generation failed: %s", e)
            self._report.phase_results["seeds"] = {
                "status": "failed",
                "error": str(e),
            }

    async def _phase_attack(self) -> None:
        """Phase 4: Execute PyRIT attacks (placeholder - requires live target)."""
        logger.info("MCPOrchestrator: Phase 4 - Execute PyRIT attacks")

        seeds_count = self._report.seed_count
        if seeds_count == 0:
            logger.info("MCPOrchestrator: no seeds available, skipping attack phase")
            self._report.phase_results["attack"] = {
                "status": "skipped",
                "reason": "no seeds available",
            }
            return

        # Note: Actual attack execution requires a live PyRIT target connected
        # to the MCP-enabled agent. This is a placeholder for future implementation.
        self._report.phase_results["attack"] = {
            "status": "placeholder",
            "reason": "requires live PyRIT target",
            "seeds_available": seeds_count,
        }

    async def _phase_verify(self) -> None:
        """Phase 5: Verify attacks through side-effect analysis."""
        logger.info("MCPOrchestrator: Phase 5 - Side-effect verification")

        side_effects: list[dict[str, Any]] = []

        # Collect from MaliciousMCP server if running
        if self._malicious_server and self._malicious_server.is_running:
            report = self._malicious_server.generate_attack_report()
            side_effects = report.get("ground_truth", [])

        # Collect from PyRIT attack results
        for technique, results in self._report.attack_results.items():
            for result in results:
                # Extract side-effect indicators from responses
                if hasattr(result, "metadata"):
                    meta = result.metadata or {}
                    if meta.get("side_effect"):
                        side_effects.append(meta["side_effect"])

        self._report.side_effects = side_effects
        self._report.phase_results["verify"] = {
            "status": "complete",
            "side_effects_count": len(side_effects),
            "ground_truth_available": self._malicious_server is not None,
        }

        logger.info(
            "MCPOrchestrator: verified %d side-effects",
            len(side_effects),
        )

    async def _phase_generate_report(self) -> None:
        """Phase 6: Generate final attack report."""
        logger.info("MCPOrchestrator: Phase 6 - Generate report")

        # Calculate final ASR
        total_attacks = sum(
            len(v) for v in self._report.attack_results.values()
        )
        successful = sum(
            1
            for results in self._report.attack_results.values()
            for r in results
            if _is_attack_success(r)
        )

        # Side-effect based success count
        side_effect_success = len(self._report.side_effects)

        if total_attacks > 0:
            self._report.asr_final = max(
                successful / total_attacks * 100,
                side_effect_success / max(total_attacks, 1) * 100,
            )

        # Generate recommendations from vulnerabilities
        self._report.recommendations = _generate_recommendations(
            self._report.vulnerabilities
        )

        self._report.phase_results["report"] = {
            "status": "complete",
            "asr": self._report.asr_final,
            "total_attacks": total_attacks,
            "side_effects": side_effect_success,
            "recommendations": len(self._report.recommendations),
        }

    async def deploy_rogue_server(
        self,
        port: int = 9999,
    ) -> Any:
        """Deploy malicious MCP server for client-side testing."""
        from strike.malicious_mcp_server import MaliciousMCPConfig, MaliciousMCPServer

        config = MaliciousMCPConfig(
            port=port,
            auto_start=True,
        )
        self._malicious_server = MaliciousMCPServer(config)
        await self._malicious_server.start()
        return self._malicious_server

    async def stop_rogue_server(self) -> None:
        """Stop the malicious MCP server."""
        if self._malicious_server:
            await self._malicious_server.stop()
            self._malicious_server = None


def _is_attack_success(result: Any) -> bool:
    """Check if an attack result indicates success."""
    if hasattr(result, "outcome"):
        from pyrit.models import AttackOutcome
        return result.outcome == AttackOutcome.SUCCESS
    if hasattr(result, "metadata"):
        meta = result.metadata or {}
        return meta.get("success", False) or meta.get("side_effect", False)
    return False


def _generate_recommendations(
    vulnerabilities: list[dict[str, Any]],
) -> list[str]:
    """Generate remediation recommendations from vulnerabilities."""
    recommendations: list[str] = []

    # Group by category
    categories = {v.get("category", "unknown") for v in vulnerabilities}

    if "prompt_injection" in categories:
        recommendations.append(
            "Sanitize all MCP tool descriptions to remove potential prompt injection payloads"
        )
    if "command_injection" in categories:
        recommendations.append(
            "Implement strict input validation on MCP tools that execute system commands"
        )
    if "path_traversal" in categories:
        recommendations.append(
            "Validate and sanitize file paths in MCP tools to prevent directory traversal"
        )
    if "ssrf" in categories:
        recommendations.append(
            "Implement URL allowlisting for MCP tools that make HTTP requests"
        )
    if "credential_harvesting" in categories:
        recommendations.append(
            "Remove sensitive data patterns from MCP tool responses"
        )
    if "tool_poisoning" in categories:
        recommendations.append(
            "Implement tool description integrity verification (signed descriptions)"
        )

    if not recommendations:
        recommendations.append(
            "No critical vulnerabilities detected. Continue monitoring MCP attack surface."
        )

    return recommendations


async def run_mcpsec_pyrit_attack(
    target_url: str,
    *,
    transport: str = "http",
    auth_header: Optional[str] = None,
    max_seeds: int = 50,
    deploy_rogue: bool = False,
) -> MCPAttackReport:
    """Convenience function: Run full MCPSec + PyRIT attack pipeline.

    Args:
        target_url: Target MCP server endpoint
        transport: Transport protocol
        auth_header: Optional auth header
        max_seeds: Maximum attack seeds
        deploy_rogue: Whether to deploy rogue server

    Returns:
        Complete attack report
    """
    config = MCPOrchestratorConfig(
        target_url=target_url,
        transport=transport,
        auth_header=auth_header,
        max_seeds=max_seeds,
    )

    orchestrator = MCPOrchestrator(config)

    if deploy_rogue:
        await orchestrator.deploy_rogue_server()

    report = await orchestrator.run_full_pipeline()

    if deploy_rogue:
        await orchestrator.stop_rogue_server()

    return report
