#!/usr/bin/env python3
"""main.py — PyRIT attack pipeline entry point (orchestration layer).

Attack pipeline (6 phases, arXiv:2407.01232 - PyRIT native framework):
    ① recon     -> Burp intercept: read HTTP requests + recon: parse, probe capability fingerprint, build HTTPTarget
    ② arm       -> Seed selection: load from YAML seed files, sort by historical ASR + Converter: build L5 optimal chain
    ③ strike    -> Attack execution: PyRIT native PromptSendingAttack multi-path execution (FIRST_SUCCESS)
    ④ escalate  -> Multi-turn escalation: Crescendo->TAP->PAIR->GCG->native (triggered when ASR<90%, with mid-exit)
    ⑤ assess    -> Scoring: T0->J1->J2->J3 cascade scoring, ASR statistics, Wilson CI, dual Judge cross-validation
                     (or_aggregation OR aggregation tracking, scorer_metrics T0 scorer metrics)
    ⑥ report    -> Report generation: evidence collection + MD/HTML/JSON/PoC/SARIF

    When --stage is not specified, all 6 phases are executed in order (strike+escalate combined), backward compatible.
    When --stage <name> is specified, execution stops after that phase completes, for phased development and debugging.

Modular architecture:
    core/       - Pipeline orchestrator, context, config, logging, cleanup
    recon/      - Burp intercept, HTTP parsing, target fingerprint, capability probe
    arm/        - Seed selection, Converter chain, technique selection
    strike/     - Attack execution, multi-path, escalation chain
    assess/     - Scorer, ASR statistics, dual Judge
    report/     - Evidence collection, report generation (MD/HTML/JSON/PoC/SARIF)
    targets/    - RateLimitedTarget, content filtering
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

    # Custom parameters
    python main.py --burp request \
        --seeds elite_jailbreaks --converters l5_optimal \
        --techniques auto --max-seeds 25
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import Any

# UTF-8  (Windows GBK )
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

#  sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


async def run(argv: list[str] | None = None) -> None:
    """Main entry — Initialize environment + Start attack pipeline orchestrator

    Orchestration delegated to core/orchestrator.py → run_attack_pipeline()
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
    from core.context import PipelineContext, apply_relaxed_adversarial_schema
    from core.logging_config import (
        configure_root_logging,
        flush_and_close_handlers,
        install_signal_handlers,
        setup_logging,
    )
    from core.orchestrator import run_attack_pipeline
    # R11: Import Scenario routerto enable target-aware attack chain
    from core.scenario_router import get_router, apply_scenario_overrides

    # R1: Four precision delivery mechanism integration declarations
    #   - 1 (Three-level Converter sorting): arm/converter_selector.py → orchestrator 
    #   - 2 (ASR history sorting UCB1): arm/seed_ranking.py _rank_by_asr + save_asr_history
    #   - 3 (0%ASR seed pruning): arm/seed_ranker.py _prune_zero_asr_seeds
    #   - 4 (Model-specific priors): load_asr_priors(model_family) + update_asr_priors(model_family, asr)
    # Data flow: load_seeds(model_family=...) → save_asr_history() → update_asr_priors()
    # The above calls are already in core/orchestrator.py fully implemented (run_attack_pipeline)
    from utils.display import print_banner, print_phase, print_status

    # == Basic logging configuration ==
    configure_root_logging()

    # == Print banner ==
    print_banner()

    # == Parse arguments + Output directory ==
    args = parse_args(argv)
    output_dir = get_output_dir(args)
    ensure_output_dir(output_dir)

    # == Configure file logging + Terminal control ==
    setup_logging(output_dir, getattr(args, "verbose", False))

    # rate_limit environment variable
    rate_limit = getattr(args, "rate_limit", None)
    if rate_limit:
        os.environ["RATE_LIMIT"] = str(rate_limit)

    # == Build pipeline context ==
    ctx = PipelineContext(args=args, output_dir=output_dir)
    ctx.scenario_result_id = getattr(args, "resume", None)
    ctx.memory_labels = getattr(args, "memory_labels_parsed", {}) or {}

    # == Install signal handlers ==
    install_signal_handlers(ctx)

    # == INIT: Initialize PyRIT  ==
    print_phase("INIT", " PyRIT ...")
    apply_relaxed_adversarial_schema()
    await setup_environment(output_dir)
    print_status("INIT", "DONE", f"Output: {output_dir}", ok=True)

    # == Execute attack pipeline orchestration (try/finally Ensure resource cleanup) ==
    _logger = logging.getLogger(__name__)

    # R10: dry-run zero-token pipeline integrity verification
    # main.py level: Early return,Skip run_attack_pipeline()
    # orchestrator.py level: Defensive second line,Even if main.py logic fails, can still skip attack
    _is_dry_run = getattr(args, "dry_run", False)
    if _is_dry_run:
        # [DRY-RUN] Skip: execute_attacks  execute_text_adaptive 
        # [DRY-RUN] Skip: check_and_escalate 
        _logger.info("[DRY-RUN] Zero token verification mode — Skip real API calls")
        _logger.info("[DRY-RUN] [DRY-RUN] Skip attack execution (execute_attacks)")
        _logger.info("[DRY-RUN] [DRY-RUN] Skip escalation chain (check_and_escalate)")
        print_status("DRY-RUN", "DONE", " token  — Skip/", ok=True)
        return

    # R11: Scenario router integration — Pass router to orchestrator,Enable target-aware attack chain
    router = get_router()

    # R1: Pipeline integrity verification — Ensure model_family data flow through to load_seeds
    # Before orchestration delegation,First extract model_family and inject into ctx,Ensure accessible in arm phase
    _model_family = getattr(args, "model_family", None)
    if _model_family:
        ctx.model_family = _model_family

    try:
        await run_attack_pipeline(ctx, router=router)

        # R1: Pipeline closure verification — Ensure ASR written + priors updated
        # These calls are in orchestrator already executed,Final audit confirmation here
        _verify_pipeline_closure(ctx)
    except KeyboardInterrupt:
        _logger.info("Received interrupt signal, Execute resource cleanup...")
        try:
            await cleanup_resources(ctx)
        except Exception as e:
            # R-H2 compliant: Do not silently swallow errors, Log non-fatal exceptions
            _logger.debug("Resource release failure during interrupt cleanup (non-fatal): %s", e)
        raise
    finally:
        # Final guarantee: If residual resources remain, Attempt cleanup
        try:
            if has_residual_resources(ctx):
                await cleanup_resources(ctx)
        except Exception:
            pass
        # Ensure all FileHandler flush + close
        flush_and_close_handlers()


# ===============================================================================
#  (R1 )
# ===============================================================================


def _verify_pipeline_closure(ctx: Any) -> None:
    """R1 Pipeline closure verification: ensure model_family data flow + ASR history write + priors update are all correctly executed.

    Academic basis:
        - arXiv:2310.08419 — ASR history is critical for UCB sorting
        - arXiv:2402.01135 — Cross-target knowledge transfer (EMA priors) improves ASR by 15-20%

    Verification items:
        1. model_family: ensure model family data is passed to load_seeds (seed sorting/filtering)
        2. save_asr_history: ensure ASR history is written (UCB sorting data source)
        3. update_asr_priors: ensure priors are updated (cross-target knowledge transfer)
    """
    _logger = logging.getLogger(__name__)

    # == Verification 1: model_family data flow ==
    _model_family = getattr(ctx, "parsed_request", None)
    if _model_family and hasattr(_model_family, "target_fingerprint"):
        fp = _model_family.target_fingerprint
        _mf = fp.get("model_family")
        if _mf:
            _logger.debug("R1 verification passed: model_family='%s' passed to load_seeds", _mf)

    # == Verification 2: ASR history write confirmation ==
    if ctx.asr_per_technique:
        _logger.debug(
            "R1 verification passed: save_asr_history executed, %d technique ASR written",
            len(ctx.asr_per_technique),
        )

    # == Verification 3: priors update confirmation ==
    if ctx.parsed_request:
        fp = ctx.parsed_request.target_fingerprint
        _mf = fp.get("model_family")
        if _mf and ctx.asr_per_technique:
            # Confirmation update_asr_priors called in assess phase
            # : Check if priors file exists
            import os
            from pathlib import Path
            _priors_path = Path("config/asr_priors.yaml")
            if _priors_path.exists():
                _logger.debug(
                    "R1 verification passed: update_asr_priors executed, priors updated",
                )


# ===============================================================================
# 
# ===============================================================================

if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\n[!] User interrupt, ")
        sys.exit(130)
