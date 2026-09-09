""" RECON  +  + .

Academic basis:
    - Greshake et al. (arXiv:2302.12173) - converter(s)
    - PyRIT (arXiv:2407.01232) - Target HTTP
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)


def _derive_stealth_mode(ctx: Any) -> bool:
    """Derive stealth_mode boolean from ctx.stealth_policy.

    Extracts stealth configuration from the pipeline context and returns
    a boolean indicating whether stealth timing should be enabled.

    Logic:
        - ctx.stealth_policy["name"] == "paranoid" -> True (aggressive stealth)
        - ctx.stealth_policy["name"] == "balanced" -> True (default stealth)
        - ctx.stealth_policy["name"] == "aggressive" -> False (OFF for speed)
        - Missing/invalid policy -> True (safe default)

    Args:
        ctx: PipelineContext with stealth_policy field

    Returns:
        True if stealth mode should be enabled, False otherwise
    """
    policy = getattr(ctx, "stealth_policy", None)
    if not isinstance(policy, dict):
        return True  # Safe default

    policy_name = policy.get("name", "balanced")

    # Disable stealth only for "aggressive" policy (speed prioritized)
    if policy_name == "aggressive":
        return False

    # paranoid and balanced both use stealth timing
    return True

async def _run_recon_phase(
        ctx: "PipelineContext", output_dir: Path) -> None:
    """(1) Recon : HTTP & """
    from utils.display import print_phase, print_recon_card, print_status

    print_phase(
        "RECON", " HTTP  & ...")
    from recon.target_router import create_target

    try:
        await create_target(ctx)
    except ConnectionError as e:
        logger.error(": %s", e)
        from utils.display import print_error
        print_error(f": {e}\nRetry")
        raise
    except Exception as e:
        logger.error(": %s", e)
        from utils.display import print_error
        print_error(f": {e}")
        raise

    #
    _is_recon_only = getattr(
        ctx.args, "stage", None) == "recon"
    if ctx.parsed_request and not _is_recon_only:
        print_recon_card(ctx)

        # :
        from core.phases._helpers import _record_recon_orchestration
        _record_recon_orchestration(ctx)

        # RAG Pipeline Probe (P1 enhancement): KB structure + citations + chunking
        if getattr(ctx.args, "rag_probe", True) and ctx.parsed_request:
            try:
                from recon.rag_pipeline_probe import run_rag_pipeline_probe
                stealth_mode = _derive_stealth_mode(ctx)
                rag_profile = await run_rag_pipeline_probe(
                    ctx.parsed_request,
                    stealth_mode=stealth_mode,
                )
                if rag_profile.has_rag:
                    ctx.service_profile["rag_pipeline"] = rag_profile.to_dict()
                    logger.info(
                        "[Recon] RAG detected: namespaces=%d, collections=%d, citations=%d",
                        len(rag_profile.kb_namespaces),
                        len(rag_profile.kb_collections),
                        len(rag_profile.citation_markers),
                    )
            except Exception as e:
                logger.debug("[Recon] RAG probe skipped: %s", e)

            # RAG Metadata Auto-Parser: format-agnostic structured field extraction
            # Runs only when RAG pipeline probe confirms RAG presence
            if rag_profile.has_rag and getattr(ctx.args, "rag_metadata", True):
                try:
                    from recon.rag_metadata_parser import run_rag_metadata_collection
                    num_queries = getattr(ctx.args, "rag_metadata_queries", 15)
                    kb_map = await run_rag_metadata_collection(
                        ctx.parsed_request,
                        num_queries=num_queries,
                        max_concurrency=2,
                        stealth_mode=stealth_mode,
                    )
                    if kb_map.document_count > 0:
                        ctx.service_profile["rag_kb_map"] = kb_map.to_dict()
                        logger.info(
                            "[Recon] RAG KB mapped: documents=%d, formula=%s, chunk_size=%s",
                            kb_map.document_count,
                            kb_map.inferred_retrieval_formula,
                            kb_map.inferred_chunk_size,
                        )
                except Exception as e:
                    logger.debug("[Recon] RAG metadata collection skipped: %s", e)

            # RAG Typo Fuzzer: query rewriting / fuzzy matching detection
            if rag_profile.has_rag and getattr(ctx.args, "rag_typo_fuzz", True):
                try:
                    from recon.rag_typo_fuzzer import run_typo_fuzzing
                    typo_report = await run_typo_fuzzing(
                        ctx.parsed_request,
                        max_concurrency=2,
                        variants_per_query=3,
                        stealth_mode=stealth_mode,
                    )
                    if typo_report.has_rag:
                        ctx.service_profile["rag_typo_fuzz"] = typo_report.to_dict()
                        logger.info(
                            "[Recon] Typo fuzz: tests=%d, rewriting=%s, bm25_poisoning=%s, failure_rate=%.2f",
                            typo_report.total_tests,
                            typo_report.query_rewriting_detected,
                            typo_report.vulnerable_to_bm25_poisoning,
                            typo_report.failure_rate,
                        )
                except Exception as e:
                    logger.debug("[Recon] RAG typo fuzzing skipped: %s", e)

        # MCPSec v2.7.2: MCP Security Scanning (replaces self-developed mcp_enumerator)
        # Architecture alignment: MCPSecBridge.enumerate_surface() -> ctx.mcpsec_surface
        #                         MCPSecBridge.scan_target() -> ctx.mcpsec_scan_results
        target_url = getattr(ctx.args, "target_url", None) if hasattr(ctx, "args") else None
        if target_url:
            await _run_mcpsec_reconnaissance(ctx, target_url)

        # A2A v3.0: Multi-Agent Reconnaissance (multi-port scanning + topology)
        # OffSec-style: Scan common agent ports -> AgentCard -> Topology -> Defense -> Plan
        # Architecture: scan_agent_cards_by_ports -> ctx.a2a_inventory
        #              analyze_topology -> ctx.a2a_topology
        #              detect_defenses -> ctx.a2a_defense_profile
        #              generate_attack_plan -> ctx.a2a_attack_plan
        a2a_target = getattr(ctx.args, "a2a_target", None) if hasattr(ctx, "args") else None
        if a2a_target:
            await _run_a2a_multi_agent_recon(ctx, a2a_target)

        # --stage recon (minimal output, red team focus)
        if _is_recon_only:
            if ctx.parsed_request:
                # Save fingerprint JSON if output_dir provided
                if output_dir:
                    import json
                    fp = ctx.parsed_request.target_fingerprint
                    fp_path = output_dir / "recon_fingerprint.json"
                    fp_path.write_text(
                        json.dumps(fp, indent=2, ensure_ascii=False),
                        encoding="utf-8",
                    )
                print_status("RECON", "DONE", "", ok=True)

    # === 数据流完整性快照: post_recon ===
    try:
        from tools.data_flow_hooks import snapshot_hook
        snapshot_hook(ctx, "post_recon")
    except Exception as e:
        logger.debug("[Recon] Data flow snapshot skipped: %s", e)

async def _run_a2a_multi_agent_recon(
        ctx: "PipelineContext", target_ip: str) -> None:
    """Execute A2A multi-agent reconnaissance with full analysis pipeline.

    Architecture alignment:
        Phase 1: scan_agent_cards_by_ports -> ctx.a2a_inventory
        Phase 2: analyze_topology -> ctx.a2a_topology
        Phase 3: detect_defenses -> ctx.a2a_defense_profile
        Phase 4: generate_attack_plan -> ctx.a2a_attack_plan

    Data contract:
        ctx.a2a_inventory = {
            "target_ip": str, "scanned_ports": [...],
            "agent_count": int, "agents": [...],
            "all_skills": [...], "all_tags": [...]
        }
        ctx.a2a_topology = {
            "pattern": str, "agent_count": int,
            "has_defense": bool, "has_orchestrator": bool,
            "control_agent": str, "data_agents": [...], ...
        }
    """
    from utils.display import print_status

    # Skip in dry-run mode
    dry_run = getattr(ctx.args, "dry_run", False)
    if dry_run:
        logger.info("[A2A] Dry run - skipping multi-agent reconnaissance")
        return

    try:
        # Phase 1: Multi-port Agent Card scanning
        from recon.a2a_discoverer import scan_agent_cards_by_ports
        stealth_mode = _derive_stealth_mode(ctx)

        ports = getattr(ctx.args, "a2a_ports", None)
        timeout = getattr(ctx.args, "a2a_timeout", 10.0)

        inventory = await scan_agent_cards_by_ports(
            target_ip,
            ports=ports,
            timeout=timeout,
            stealth_delay=stealth_mode,
        )
        ctx.a2a_inventory = inventory.to_dict()

        if inventory.agent_count == 0:
            print_status("A2A", "No agents detected", "", ok=True)
            logger.info("[A2A] No agents detected on %s", target_ip)
            return

        print_status(
            "A2A",
            f"{inventory.agent_count} agent(s) on {target_ip}",
            f"ports={inventory.reachable_count}",
            ok=True,
        )

        # Phase 2: Topology analysis
        from recon.multi_agent_topology import analyze_topology
        topology = analyze_topology(inventory)
        ctx.a2a_topology = topology.to_dict()

        logger.info(
            "[A2A] Topology: pattern=%s, agents=%d, defense=%s, orchestrator=%s",
            topology.pattern.value,
            topology.agent_count,
            topology.has_defense,
            topology.has_orchestrator,
        )

        # Phase 3: Defense awareness
        from recon.a2a_defense_awareness import detect_defenses
        defense = detect_defenses(topology)
        ctx.a2a_defense_profile = defense.to_dict()

        if defense.requires_evasion:
            logger.info(
                "[A2A] Defense detected: score=%.2f, link_scan=%s, malware=%s",
                defense.defense_score,
                defense.has_link_scanning,
                defense.has_malware_detection,
            )

        # Phase 4: Attack plan generation
        from recon.a2a_attack_planner import generate_attack_plan
        plan = generate_attack_plan(topology, defense)
        ctx.a2a_attack_plan = plan.to_dict()

        logger.info(
            "[A2A] Attack plan: %d steps, primary=%s, risk=%s",
            plan.step_count,
            plan.primary_target,
            plan.risk_level,
        )

        # Orchestration log
        if hasattr(ctx, "orchestration_log"):
            ctx.orchestration_log.append({
                "phase": "recon",
                "decision": "a2a_multi_agent_recon",
                "input": {"target_ip": target_ip, "ports_scanned": len(inventory.scanned_ports)},
                "output": {
                    "agents_found": inventory.agent_count,
                    "pattern": topology.pattern.value,
                    "attack_steps": plan.step_count,
                    "primary_target": plan.primary_target,
                    "risk_level": plan.risk_level,
                },
                "reasoning": (
                    f"A2A multi-agent recon on {target_ip}: "
                    f"{inventory.agent_count} agents, {topology.pattern.value} pattern, "
                    f"plan={plan.step_count} steps targeting {plan.primary_target}"
                ),
            })

    except Exception as e:
        logger.warning("[A2A] Multi-agent reconnaissance failed: %s", e)
        # Non-fatal: continue with reduced capabilities


async def _run_mcpsec_reconnaissance(
        ctx: "PipelineContext", target_url: str) -> None:
    """Execute MCPSec reconnaissance phase with production-grade observability.

    Architecture alignment:
        - enumerate_surface() -> ctx.mcpsec_surface (tools, resources, prompts)
        - scan_target() -> ctx.mcpsec_scan_results (vulnerabilities)

    Data contract:
        ctx.mcpsec_surface = {
            "tools": [{"name", "description", "inputSchema"}],
            "resources": [{"uri", "name", "description"}],
            "prompts": [{"name", "description"}]
        }
        ctx.mcpsec_scan_results = {
            "vulnerabilities": [{"severity", "scanner", "description", "target"}]
        }
    """
    import time

    from tools.mcpsec_factory import get_shared_bridge

    bridge = get_shared_bridge()
    if not bridge or not bridge.is_available:
        logger.info("[Recon] MCPSec not installed reconnaissance skipped")
        return

    mcpsec_start = time.monotonic()
    enum_result: dict[str, Any] = {}
    scan_result: dict[str, Any] = {"vulnerabilities": []}

    try:
        # Phase 1: Enumerate attack surface
        try:
            mcp_info = await bridge.enumerate_surface(target_url)
            # Architecture compliance: ensure dict format for ctx.mcpsec_surface
            if isinstance(mcp_info, dict):
                enum_result = mcp_info
            else:
                # Convert from object format to dict (defensive)
                enum_result = {
                    "tools": getattr(mcp_info, "tools", []),
                    "resources": getattr(mcp_info, "resources", []),
                    "prompts": getattr(mcp_info, "prompts", []),
                    "raw": str(mcp_info),
                }
            ctx.mcpsec_surface = enum_result
            ctx.mcpsec_version = bridge.version or "unknown"

            logger.info(
                "[Recon] MCPSec enumerate complete: %d tools, %d resources, %d prompts",
                len(enum_result.get("tools", [])),
                len(enum_result.get("resources", [])),
                len(enum_result.get("prompts", [])),
            )
        except Exception as e:
            logger.warning("[Recon] MCPSec enumerate failed: %s", e)

        # Phase 2: Vulnerability scan
        try:
            raw_scan_results = await bridge.scan_target(target_url)
            # Architecture compliance: normalize to dict format
            vulns = []
            for r in raw_scan_results:
                vulns.append({
                    "scanner": r.scanner,
                    "vulnerability": r.vulnerability,
                    "severity": r.severity,
                    "description": r.evidence,
                    "target": r.tool_name,
                    "payload": r.payload,
                })
            scan_result["vulnerabilities"] = vulns
            ctx.mcpsec_scan_results = scan_result

            logger.info(
                "[Recon] MCPSec scan complete: %d vulnerabilities (C:%d H:%d M:%d L:%d)",
                len(vulns),
                sum(1 for v in vulns if v["severity"] == "critical"),
                sum(1 for v in vulns if v["severity"] == "high"),
                sum(1 for v in vulns if v["severity"] == "medium"),
                sum(1 for v in vulns if v["severity"] in ("low", "info")),
            )
        except Exception as e:
            logger.debug("[Recon] MCPSec scan non-fatal: %s", e)

    finally:
        # Production observability: orchestration_log audit trail
        elapsed = time.monotonic() - mcpsec_start
        if hasattr(ctx, "orchestration_log"):
            ctx.orchestration_log.append({
                "phase": "recon",
                "decision": "mcpsec_reconnaissance",
                "input": {"target_url": target_url, "mcpsec_version": ctx.mcpsec_version},
                "output": {
                    "tools_found": len(enum_result.get("tools", [])),
                    "vulnerabilities_found": len(scan_result.get("vulnerabilities", [])),
                    "elapsed_seconds": round(elapsed, 2),
                },
                "reasoning": f"MCPSec v{ctx.mcpsec_version} reconnaissance completed",
            })




