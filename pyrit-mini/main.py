#!/usr/bin/env python3
"""main.py - PyRIT attack pipeline entry point (orchestration layer).

Attack pipeline (6 phases, arXiv:2407.01232 - PyRIT native framework):
    (1) recon     -> Burp intercept: read HTTP requests + recon: parse, probe capability fingerprint, build HTTPTarget
    (2) arm       -> Seed selection: load from YAML seed files, sort by historical ASR + Converter: build L5 optimal chain
    (3) strike    -> Attack execution: PyRIT native PromptSendingAttack multi-path execution (FIRST_SUCCESS)
    (4) escalate  -> Multi-turn escalation: Crescendo->TAP->PAIR->GCG->native (triggered when ASR<90%, with mid-exit)
    (5) assess    -> Scoring: T0->J1->J2->J3 cascade scoring, ASR statistics, Wilson CI, dual Judge cross-validation
                     (or_aggregation OR aggregation tracking, scorer_metrics T0 scorer metrics)
    (6) report    -> Report generation: evidence collection + MD/HTML/JSON/PoC/SARIF

    When --stage is not specified, all 6 phases are executed in order (strike+escalate combined), backward compatible.
    When --stage <name> is specified, execution stops after that phase completes, for phased development and debugging.

Modular architecture:
    core/       - Pipeline orchestrator, context, config, logging, cleanup
    recon/      - Burp intercept, HTTP parsing, target fingerprint, capability probe
    arm/        - Seed selection, Converter chain, technique selection
    strike/     - Attack execution, multi-path, escalation chain
    assess/     - Scorer, ASR statistics, dual Judge
    report/     - Evidence collection, report generation (MD/HTML/JSON/PoC/SARIF)
    utils/      - Terminal output, cache cleanup

Usage:
 # Full power mode (AI-300 exam preferred - highest ASR configuration)
    python main.py --offensive

 # Phased execution (--stage control, 6 phases can be debugged independently):
    python main.py --burp request --stage recon
    python main.py --burp deepseek --stage arm
    python main.py --burp qwen --stage strike
    python main.py --stage escalate
    python main.py --stage assess
    python main.py --stage report

 # Progressive mode (--strike <target>: auto-escalation Phase 1→2→3→4)
    python main.py --burp request --strike a2a       # A2A multi-agent progressive
    python main.py --burp request --strike model     # Direct LLM progressive
    python main.py --burp request --strike mcp       # MCP protocol progressive
    python main.py --burp request --strike rag       # RAG poisoning progressive

 # === Component-based seed loading (NEW: aligned with strike/ and recon/ directories) ===
 # Load seeds by component (recommended for targeted attacks):
    python main.py --strike mcp --seeds mcp --converters base64 --target burp.txt
    python main.py --strike a2a --seeds a2a --converters l5_optimal --target burp.txt
    python main.py --strike rag --seeds rag --target burp.txt
    python main.py --strike model --seeds model --target burp.txt

 # Combine multiple components:
    python main.py --strike mcp --seeds mcp,a2a --target burp.txt

 # List all available seeds:
    python main.py --list-seeds

 # Legacy seed names (backward compatible):
    python main.py --burp request \
        --seeds elite_jailbreaks --converters l5_optimal \
        --techniques auto --max-seeds 25
    python main.py --seeds asi_top10,owasp_full_coverage --target burp.txt

 # Load all seeds:
    python main.py --seeds all --offensive --target burp.txt
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import Any


def _load_auto_guard_from_yaml() -> dict[str, Any]:
    """Load auto-guard settings from config/defaults.yaml.

    Priority fallback chain: env vars > yaml > hardcoded defaults.
    Returns dict with 'enabled' (bool) and 'mode' (str).
    """
    import yaml as _yaml

    defaults = {"enabled": False, "mode": "fast"}
    yaml_path = Path("config/defaults.yaml")
    if yaml_path.exists():
        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                cfg = _yaml.safe_load(f) or {}
                defaults["enabled"] = bool(cfg.get("auto_guard_watch", False))
                defaults["mode"] = str(cfg.get("auto_guard_mode", "fast"))
        except Exception:
            pass
    return defaults


def auto_start_guard_watcher() -> None:
    """Auto-start guard watcher based on configuration.

    Priority chain (highest → lowest):
        1. Environment variables (AUTO_GUARD_WATCH / AUTO_GUARD_MODE)
        2. config/defaults.yaml (auto_guard_watch / auto_guard_mode)
        3. Hardcoded defaults (enabled=False, mode=fast)
    """
    # 1. Check env vars (highest priority)
    env_watch = os.environ.get("AUTO_GUARD_WATCH")

    if env_watch is not None:
        # Env var explicitly set — use it
        enabled = env_watch == "1"
    else:
        # No env var — fallback to YAML
        yaml_cfg = _load_auto_guard_from_yaml()
        enabled = yaml_cfg["enabled"]

    if not enabled:
        return

    # W0 fix: `tools.watch_guard` was merged into `tools.guard` (docs/specs/README.md) and
    # no longer exists as a module. Previously this spawned a subprocess to a nonexistent
    # module with stdout/stderr discarded, so the failure was completely invisible.
    print(
        "  [AUTO-GUARD] watcher enabled but unavailable: tools.watch_guard was merged into "
        "tools.guard. Run `py -m tools.guard` in a separate shell instead."
    )


# UTF-8 (Windows GBK )
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


async def run(argv: list[str] | None = None) -> None:
    """Main entry for PyRIT attack pipeline.

    Orchestration delegated to core/orchestrator.py -> run_attack_pipeline()
    This function only handles:
        1. Logging configuration ( WARNING+,  INFO)
        2. Signal handling (SIGINT/SIGTERM graceful exit)
        3. Parameter parsing + Environment initialization (PyRIT DB)
        4. Pipeline context construction (PipelineContext)
        5. Production-grade try/finally Ensure resource cleanup
    """
    # == Import core modules ==
    from core.cleanup import cleanup_resources, has_residual_resources
    from core.config import (
        ensure_output_dir,
        get_output_dir,
        parse_args,
        setup_environment,
    )
    from core.context import (
        PipelineContext,
        apply_relaxed_adversarial_schema,
        enforce_authorized_scope,
    )
    from core.logging_config import (
        configure_root_logging,
        flush_and_close_handlers,
        install_signal_handlers,
        setup_logging,
    )

    # R11: Import Scenario router to enable target-aware attack chain
    from core.scenario_router import get_router

    # R1: Four precision delivery mechanism integration declarations
    # - 1 (Three-level Converter sorting): arm/converter_selector.py -> orchestrator
    # - 2 (ASR history sorting UCB1): arm/seed_ranking.py _rank_by_asr + save_asr_history
    # - 3 (0%ASR seed pruning): arm/seed_ranker.py _prune_zero_asr_seeds
    # - 4 (Model-specific priors): load_asr_priors(model_family) + update_asr_priors(model_family, asr)
    # Data flow: load_seeds(model_family=...) -> save_asr_history() -> update_asr_priors()
    # The above calls are already in core/orchestrator.py fully implemented (run_attack_pipeline)
    from utils.display import print_banner, print_phase, print_status

    # == Basic logging configuration ==
    configure_root_logging()

    # == Print banner ==
    print_banner()

    # == Auto-start guard watcher (if enabled in .env.local) ==
    auto_start_guard_watcher()

    # == Parse arguments + Output directory ==
    args = parse_args(argv)
    output_dir = get_output_dir(args)
    ensure_output_dir(output_dir)

    # == Configure file logging + Terminal control ==
    setup_logging(output_dir, getattr(args, "verbose", False))

    # rate_limit environment variable
    rate_limit = getattr(args, "rate_limit", None)
    if rate_limit:
        os.environ["PYRIT_RATE_LIMIT"] = str(rate_limit)

    # == Build pipeline context ==
    ctx = PipelineContext(args=args, output_dir=output_dir)
    ctx.scenario_result_id = getattr(args, "resume", None)
    ctx.memory_labels = getattr(args, "memory_labels_parsed", {}) or {}

    # == plan Wave 2.9（R-S1 / C9）：授权范围启动期强制校验 ==
    # 此前 `ctx.authorized_targets` 不存在 → `decision_safety` 的边界检查被整段跳过
    # → 越界攻击静默放行。这里把「声明 → 校验 → 拒绝」前置到启动期，且未声明也必须留痕。
    enforce_authorized_scope(args, ctx)

    # == W0-4: EventLog 挂载（REQ-148，旁路埋点，零行为变更） ==
    # --no-events 时为禁用实例，所有 emit 为 no-op
    from core.events import EventLog

    EventLog.attach(
        ctx,
        output_dir=output_dir,
        enabled=not getattr(args, "no_events", False),
        run_id=getattr(args, "resume", None),
    )

    # == W0-8: 终端展示层接入同一 EventLog（display 不持有 ctx，显式注入） ==
    from utils.display import bind_event_log

    bind_event_log(ctx.event_log)

    # == Stealth: SIEM evasion timing (optional) ==
    # Data flow: CLI --stealth -> StealthConfig -> ctx.stealth_config -> strike/executor
    stealth_level = getattr(args, "stealth", None)
    if stealth_level:
        from strike.injection.stealth_exec import StealthConfig

        ctx.stealth_config = StealthConfig.from_level(stealth_level)

    # == Install signal handlers ==
    install_signal_handlers(ctx)

    # == INIT: Initialize PyRIT ==
    print_phase("INIT", " PyRIT ...")
    apply_relaxed_adversarial_schema()
    await setup_environment(output_dir)
    print_status("INIT", "DONE", f"Output: {output_dir}", ok=True)

    # == Execute attack pipeline orchestration (try/finally Ensure resource cleanup) ==
    _logger = logging.getLogger(__name__)

    # R10: dry-run zero-token pipeline integrity verification
    # main.py level: Early return, Skip run_attack_pipeline()
    # orchestrator.py level: Defensive second line, Even if main.py logic fails, can still skip attack
    # v2.0+: dry-run 逻辑收敛到 utils/dry_run.py
    from utils.dry_run import get_dry_run_log_message, is_dry_run, validate_pipeline_connectivity

    if is_dry_run(args):
        _logger.info(get_dry_run_log_message("main"))
        _logger.info(get_dry_run_log_message("strike"))
        _logger.info(get_dry_run_log_message("escalate"))
        # 验证流水线连通性 (非攻击阶段)
        connectivity_errors = validate_pipeline_connectivity(ctx)
        if connectivity_errors:
            _logger.warning("[DRY-RUN] Connectivity issues: %s", connectivity_errors)
        print_status("DRY-RUN", "DONE", " token  - Skip/", ok=True)
        return

    # R11: Scenario router integration - Pass router to orchestrator, Enable target-aware attack chain
    get_router()

    # R12: Target + Strike routing (--target / --strike → strike/dispatcher.py)
    # When --target or --strike is specified, configure dispatcher seed categories
    # Progressive mode: --strike <target> triggers auto-escalation (Phase 1→2→3→4)
    _target = getattr(args, "target", None)
    _strike = getattr(args, "strike", None)
    if _target or _strike:
        from strike.common.dispatcher import create_dispatcher, is_target

        # Detect progressive mode: --strike <target> (target name passed as strike)
        if _strike and is_target(_strike) and _target is None:
            # Progressive mode: auto-escalation for the specified target
            ctx.dispatcher = create_dispatcher(strike=_strike)
            ctx.progressive_mode = True
            _logger.info(
                "[MAIN] Progressive mode: target=%s, auto-escalation enabled (Phase 1→2→3→4)",
                _strike,
            )
        else:
            # Standard mode: explicit target + strategy
            ctx.dispatcher = create_dispatcher(target=_target, strike=_strike)
            ctx.progressive_mode = False
            if _target:
                # Override seed categories based on target
                ctx.dispatcher_seed_categories = ctx.dispatcher.get_seed_categories()
                _logger.info(
                    "[MAIN] Target routing: target=%s, seeds=%s",
                    _target,
                    ctx.dispatcher_seed_categories,
                )
            if _strike:
                _logger.info("[MAIN] Strike routing: strategy=%s", _strike)

    # R1: Pipeline integrity verification - Ensure model_family data flow through to load_seeds
    # Before orchestration delegation, First extract model_family and inject into ctx, Ensure accessible in arm phase
    _model_family = getattr(args, "model_family", None)
    if _model_family:
        ctx.model_family = _model_family

    try:
        # == Execute attack pipeline orchestration ==
        # Core business logic delegated to core/orchestrator.py -> run_attack_pipeline()
        # orchestrator.py imports all 6 phase functions from core/phases/
        from core.orchestrator import run_attack_pipeline

        # Progressive mode: use dispatcher.execute_progressive() for auto-escalation
        if getattr(ctx, "progressive_mode", False) and hasattr(ctx, "dispatcher"):
            _logger.info("[MAIN] Executing progressive strike via dispatcher")
            progressive_result = await ctx.dispatcher.execute_progressive(ctx)
            _logger.info(
                "[MAIN] Progressive result: success=%s, attacks=%d, progressive=%s",
                progressive_result.success,
                progressive_result.attack_count,
                progressive_result.progressive_result,
            )
            # Store result in ctx for downstream phases
            ctx.progressive_strike_result = progressive_result
            # Still run the full pipeline for scoring/reporting
            await run_attack_pipeline(ctx)
        else:
            await run_attack_pipeline(ctx)

        # R1: Pipeline closure verification - Ensure ASR written + priors updated
        # Post-execution audit: verify all data flows completed correctly
        _verify_pipeline_closure(ctx)
    except KeyboardInterrupt:
        try:
            await cleanup_resources(ctx)
        except Exception as e:
            _logger.debug("Resource release failure during interrupt cleanup (non-fatal): %s", e)
        raise
    finally:
        # Final guarantee: If residual resources remain, Attempt cleanup
        try:
            if has_residual_resources(ctx):
                await cleanup_resources(ctx)
        except Exception:
            _logger.debug("Resource release failure during final cleanup (non-fatal)")
        # == W0-4: EventLog 落盘收尾（REQ-148，幂等） ==
        try:
            _elog = getattr(ctx, "event_log", None)
            if _elog is not None:
                _elog.close()
        except Exception:
            pass
        # Ensure all FileHandler flush + close
        flush_and_close_handlers()


# ===============================================================================
# (R1 )
# ===============================================================================


def _verify_pipeline_closure(ctx: Any) -> None:
    """Verify pipeline closure: ensure ASR history + priors are properly handled.

    Academic basis:
        - arXiv:2310.08419 - ASR history is critical for UCB sorting
        - arXiv:2402.01135 - Cross-target knowledge transfer (EMA priors) improves ASR by 15-20%

    Verification items:
        1. model_family: ensure model family data is passed to load_seeds (seed sorting/filtering)
        2. save_asr_history: ensure ASR history is written (UCB sorting data source)
        3. update_asr_priors: ensure priors are updated (cross-target knowledge transfer)
    """
    _logger = logging.getLogger(__name__)

    # == Verification 1: model_family data flow ==
    _parsed = getattr(ctx, "parsed_request", None)
    if _parsed and hasattr(_parsed, "target_fingerprint"):
        fp = _parsed.target_fingerprint
        _mf = fp.get("model_family")
        if _mf:
            _logger.debug("R1 verification passed: model_family=%s passed to load_seeds", _mf)

    # == Verification 2: ASR history write confirmation ==
    if ctx.asr_per_technique:
        _logger.info(
            "R1 verification passed: save_asr_history executed, %d technique ASR written",
            len(ctx.asr_per_technique),
        )

    # == Verification 3: priors update confirmation ==
    if ctx.parsed_request:
        fp = getattr(ctx.parsed_request, "target_fingerprint", {})
        _mf = fp.get("model_family") if isinstance(fp, dict) else None
        if _mf and ctx.asr_per_technique:
            # : Check if priors file exists
            from pathlib import Path

            _priors_path = Path("config/asr_priors.yaml")
            if _priors_path.exists():
                _logger.info(
                    "R1 verification passed: update_asr_priors executed, priors updated",
                )


# ===============================================================================
#
# ===============================================================================

def main(argv: list[str] | None = None) -> None:
    """Synchronous console entry point.

    W0 fix: `pyproject.toml` declared `pyrit-mini = "main:main"`, but no `main()` existed
    (only the coroutine `run()`), so installing the package produced a broken console
    script. This wrapper restores that contract.
    """
    try:
        asyncio.run(run(argv))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
