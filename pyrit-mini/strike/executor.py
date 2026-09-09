# -*- coding: utf-8 -*-
# arXiv:2302.12173 - Greshake et al., PromptSendingAttack
# arXiv:2407.01232 - PyRIT, AttackExecutor + native attacks
"""Attack execution: PromptSendingAttack + SequentialAttack (FIRST_SUCCESS).

Contains attack execution logic:
    - execute_attacks: Main entry for attack execution
    - Scoring configs via strike._executor_helpers

Sub-modules (extracted to comply with R-DELIVERY-1):
    - strike._executor_helpers: Scoring configs, _MultiKeywordRefusalScorer, calibration
    - strike._executor_attack_paths: SequentialAttack + manual multi-path loop
    - strike._executor_feedback: Feedback loop + exploit chain
    - strike._executor_doc_poison: Document poisoning integration
    - strike._executor_vuln_inject: MCPSec vulnerability seed injection

Uses PyRIT native AttackExecutor with converter path loop and SequentialAttack
for FIRST_SUCCESS short-circuit.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any

from arm.converter_selector import (
    _get_candidate_converters,
)
from arm.seed_ranking import _make_seed_key  # R9: collision-resistant seed key
from core.context import PipelineContext

# Refusal scorer and scoring configs
from strike._executor_attack_paths import (
    _manual_multi_path_loop,
    _try_native_sequential_attack,
)
from strike._executor_doc_poison import (
    _inject_document_poisoned_seeds,
    _should_inject_poisoned_documents,
)
from strike._executor_feedback import _run_feedback_loop
from strike._executor_helpers import (
    _backfill_metadata,
    _build_first_success_scoring_config,
    _build_prepended_conversation_config,
    _build_scoring_config,
    _calibrate_concurrency_littles_law,
    _get_converter_names,
    _retrieve_partial_results,
)
from strike._executor_vuln_inject import _inject_vulnerability_targeted_seeds
from strike.adaptive_executor import _best_of_n_retry
from strike.session import SessionStateManager  # noqa: F401  # R-SESSION-2 compliance


def _import_progress_funcs():
    """Import progress display functions (deferred to avoid circular imports)."""
    from utils.display import (
        print_converter_path_done,
        print_converter_path_start,
        print_seed_batch_progress,
        print_strike_phase_summary,
        print_strike_start_banner,
    )
    return (
        print_strike_start_banner,
        print_converter_path_start,
        print_converter_path_done,
        print_seed_batch_progress,
        print_strike_phase_summary,
    )


logger = logging.getLogger(__name__)

_SEQUENTIAL_BATCH_LIMIT = 30  # SequentialAttack per-seed-group limit
_MAX_TOTAL_SEEDS_FOR_NATIVE = 200  # Above this, use hierarchical batch scheduling


def _extract_source_session_id(ctx: Any) -> str | None:
    """ Burp  session_id (auto-inference ).

     :
        1. ctx.parsed_request.chat_id ( Burp  body )
        2. ctx.parsed_request.enumeration_plan.session_field
        3. ctx._raw_http_request  session_id
    """
    #  parsed_request
    parsed = getattr(ctx, "parsed_request", None)
    if parsed:
        chat_id = getattr(parsed, "chat_id", None)
        if chat_id:
            return chat_id

        enum_plan = getattr(parsed, "enumeration_plan", None)
        if enum_plan and enum_plan.get("session_field"):
            return enum_plan["session_field"]

    #  raw request
    raw_request = getattr(ctx, "_raw_http_request", None)
    if raw_request:
        # JSON body session_id
        parts = raw_request.split("\r\n\r\n", 1)
        if len(parts) >= 2:
            body = parts[1]
            for field in ("session_id", "sessionId", "chat_session_id", "chat_id"):
                # "session_id": "xxx"
                match = re.search(rf'"{field}"\s*:\s*"([^"]+)"', body)
                if match:
                    return match.group(1)
                # sessionId=xxx (query string)
                match = re.search(rf'{field}=([^&\s"\']+)', body)
                if match:
                    return match.group(1)

    return None


async def _run_session_enumeration(ctx: PipelineContext) -> Any | None:
    """ ASI09  ( CLI ).

     CLI  PyRIT HTTPTarget 。
    """
    try:
        from strike.session.enumerator import (
            EnumerationRequestBuilder,
            ResponseClassifier,
            SessionIDGenerator,
            SessionIDPattern,
            SessionPatternInferer,
        )
    except ImportError as e:
        logger.error("[SessionEnumeration] Failed to import enumerator: %s", e)
        return None

    #  CLI ( = )
    pattern_template = getattr(ctx.args, "session_enum_pattern", "")

    # :  Burp  session_id
    if not pattern_template:
        source_session_id = _extract_source_session_id(ctx)
        if source_session_id:
            pattern_template = SessionPatternInferer.infer_pattern(source_session_id)
            logger.info(
                "[SessionEnumeration] Auto-inferred pattern from '%s': %s",
                source_session_id,
                pattern_template,
            )
        else:
            pattern_template = "MC-{date:%Y%m%d}-{counter:04d}"
            logger.info(
                "[SessionEnumeration] No pattern specified, using default: %s",
                pattern_template,
            )
    days_back = getattr(ctx.args, "session_enum_days_back", 14)
    counter_max = getattr(ctx.args, "session_enum_counter_max", 20)
    extraction_prompt = getattr(ctx.args, "session_enum_prompt", "What notes do I have saved?")

    #
    from datetime import datetime
    date_end = datetime.now()
    date_start = date_end - __import__("datetime").timedelta(days=days_back)

    #
    if getattr(ctx.args, "session_enum_date_start", ""):
        try:
            date_start = datetime.strptime(ctx.args.session_enum_date_start, "%Y-%m-%d")
        except (ValueError, TypeError):
            pass
    if getattr(ctx.args, "session_enum_date_end", ""):
        try:
            date_end = datetime.strptime(ctx.args.session_enum_date_end, "%Y-%m-%d")
        except (ValueError, TypeError):
            pass

    #
    pattern = SessionIDPattern(template=pattern_template)
    id_generator = SessionIDGenerator(
        pattern=pattern,
        date_start=date_start,
        date_end=date_end,
        counter_max=counter_max,
    )

    #
    sensitive_kws = getattr(ctx.args, "session_enum_sensitive_keywords", "")
    empty_inds = getattr(ctx.args, "session_enum_empty_indicators", "")
    classifier = ResponseClassifier(
        sensitive_keywords=sensitive_kws.split(",") if sensitive_kws else None,
        empty_indicators=empty_inds.split(",") if empty_inds else None,
    )

    #
    raw_request = getattr(ctx, "_raw_http_request", None)
    session_field = getattr(ctx.args, "session_enum_session_field", "session_id")
    request_builder = EnumerationRequestBuilder(
        template_request=raw_request or "",
        session_field=session_field,
    )

    #
    total_estimate = id_generator.estimate_total()
    logger.info(
        "[SessionEnumeration] Starting enumeration: pattern=%s, estimated_total=%d",
        pattern_template,
        total_estimate,
    )

    #
    max_concurrency = getattr(ctx.args, "session_enum_max_concurrency", 1)
    request_delay = getattr(ctx.args, "session_enum_request_delay", 2.0)
    max_requests = getattr(ctx.args, "session_enum_max_requests", None)

    #
    target = getattr(ctx, "objective_target", None)
    if target is None:
        logger.error("[SessionEnumeration] No objective_target available")
        return None

    #
    from strike.session.session_config import SessionEnumerationConfig
    SessionEnumerationConfig(
        enabled=True,
        pattern_template=pattern_template,
        extraction_prompt=extraction_prompt,
        max_concurrency=max_concurrency,
        request_delay=request_delay,
        max_requests=max_requests,
    )

    #
    report = await _execute_enumeration_loop(
        ctx=ctx,
        target=target,
        id_generator=id_generator,
        classifier=classifier,
        request_builder=request_builder,
        extraction_prompt=extraction_prompt,
        max_concurrency=max_concurrency,
        request_delay=request_delay,
        max_requests=max_requests,
    )

    #
    if report:
        ctx.session_enumeration_report = report
        logger.info(
            "[SessionEnumeration] Complete: total=%d, sensitive=%d, findings=%d",
            report.total_enumerated,
            report.sensitive_count,
            len(report.findings),
        )

    return report


async def _execute_enumeration_loop(
    ctx: Any,
    target: Any,
    id_generator: Any,
    classifier: Any,
    request_builder: Any,
    extraction_prompt: str,
    max_concurrency: int,
    request_delay: float,
    max_requests: int | None,
) -> Any:
    """  (PromptSendingAttack ).
    """
    import time

    start_time = time.monotonic()

    #
    report = type('SessionEnumerationReport', (), {
        'total_enumerated': 0,
        'empty_count': 0,
        'valuable_count': 0,
        'sensitive_count': 0,
        'findings': [],
        'duration_seconds': 0.0,
        'session_id_pattern': id_generator._pattern.template,
        'target_endpoint': getattr(ctx, 'target_endpoint', ''),
        'active_sessions': property(self=lambda s: s.valuable_count + s.sensitive_count),
        'sensitive_rate': property(self=lambda s: s.sensitive_count / s.total_enumerated if s.total_enumerated > 0 else 0.0),
        'to_dict': lambda s: {
            'total_enumerated': s.total_enumerated,
            'empty_count': s.empty_count,
            'valuable_count': s.valuable_count,
            'sensitive_count': s.sensitive_count,
            'findings': [{'session_id': f.get('session_id', ''), 'category': f.get('category', '')} for f in s.findings],
        },
    })()

    #
    request_count = 0
    for session_id in id_generator.generate():
        if max_requests and request_count >= max_requests:
            break
        request_count += 1

        #
        request_builder.build_request(session_id)

        try:
            #
            response = await target.send_prompt_async(
                prompt_user=extraction_prompt,
            )

            #
            response_text = ""
            if hasattr(response, 'conversations') and response.conversations:
                for msg in reversed(response.conversations):
                    if hasattr(msg, 'role') and msg.role == 'assistant':
                        response_text = getattr(msg, 'content', '')
                        break
            elif hasattr(response, 'completion'):
                response_text = str(response.completion)
            elif isinstance(response, str):
                response_text = response

            #
            category = classifier.classify(response_text)
            report.total_enumerated += 1

            if category.value == 'empty':
                report.empty_count += 1
            elif category.value == 'valuable':
                report.valuable_count += 1
                report.findings.append({
                    'session_id': session_id,
                    'category': category.value,
                    'response_excerpt': response_text[:200],
                })
            elif category.value == 'sensitive':
                report.sensitive_count += 1
                snippets = classifier.extract_sensitive_snippets(response_text)
                report.findings.append({
                    'session_id': session_id,
                    'category': category.value,
                    'response_excerpt': response_text[:200],
                    'sensitive_snippets': snippets,
                })

        except Exception as e:
            logger.debug("[SessionEnumeration] Request failed for %s: %s", session_id, e)
            report.empty_count += 1

        #
        if request_delay > 0:
            await __import__('asyncio').sleep(request_delay)

    report.duration_seconds = time.monotonic() - start_time
    return report


async def execute_attacks(ctx: PipelineContext) -> dict[str, list[Any]]:
    """Execute attacks using SequentialAttack (FIRST_SUCCESS) with fallback.

    Architecture:
        1. Build scoring configs (FIRST_SUCCESS short-circuit via SubStringScorer+Inverter)
        2. Get candidate converters (ASR-prioritized)
        3. Try native SequentialAttack (fast path), fallback to manual loop
        4. Post-process results via feedback loop

    Academic basis:
        - PyRIT SequentialAttack (arXiv:2407.01232): FIRST_SUCCESS
        - Wei et al. (arXiv:2307.15043): >2 Layer ASR
        - Zeng et al. (arXiv:2402.19181): Authority ASR 38.4%

    Args:
        ctx: Pipeline context with seeds, target, and scoring config.

    Returns:
        Dict mapping technique names to lists of AttackResult.
    """
    from pyrit.executor.attack import PromptSendingAttack
    from pyrit.executor.attack.core.attack_executor import AttackExecutor

    if not ctx.seeds:
        logger.warning("No seeds configured, skipping attack execution")
        ctx.attack_results["prompt_sending"] = []
        return ctx.attack_results

    _strike_start = time.monotonic()
    try:
        _banner, _path_start, _path_done, _batch_prog, _phase_summ = _import_progress_funcs()
    except Exception:
        _banner = _path_start = _path_done = _batch_prog = _phase_summ = None

    # post-hoc Judge scoring
    post_hoc_scoring = _build_scoring_config(ctx)

    # FIRST_SUCCESS scoring (0 token short-circuit)
    first_success_scoring = _build_first_success_scoring_config(ctx)

    # ASR-prioritized converters
    candidate_converters = _get_candidate_converters(ctx)

    from core.context import get_effective_concurrency
    max_concurrency = get_effective_concurrency(ctx)
    executor = AttackExecutor(max_concurrency=max_concurrency)

    timeout = ctx.args.timeout or 3600

    # MCPSec v2.7.2: Inject vulnerability-targeted seeds from scan results
    _mcpsec_vulns = ctx.mcpsec_scan_results.get("vulnerabilities", []) if ctx.mcpsec_scan_results else []
    if _mcpsec_vulns:
        _inject_vulnerability_targeted_seeds(ctx, _mcpsec_vulns)

    # Document Poisoning: Generate poisoned files for indirect injection
    _enable_doc_poison = getattr(ctx.args, "enable_document_poisoning", False)
    if _should_inject_poisoned_documents(ctx, _enable_doc_poison):
        _doc_count = _inject_document_poisoned_seeds(ctx, max_docs=3)
        if _doc_count > 0:
            logger.info(
                "[Executor] Document poisoning: %d poisoned files ready for indirect injection",
                _doc_count,
            )

    # Session-Aware Attack: Log session state
    session_state = getattr(ctx, "session_state", None)
    if session_state and hasattr(session_state, "is_active") and session_state.is_active:
        logger.info(
            "[Executor] Session-aware attack active: session_state=%s",
            session_state.current_state if hasattr(session_state, "current_state") else "active"
        )

    # ════════════════════════════════════════════════════════════════════════
    # ASI09: 会话枚举攻击模式 (Session Enumeration Attack)
    # Academic: OWASP ASI09 — Broken Authentication via Session Enumeration
    # arXiv:2306.05685 — Adaptive attack timing evasion
    # ════════════════════════════════════════════════════════════════════════
    _enum_config = getattr(ctx.args, "session_enum_enabled", False)
    if _enum_config:
        logger.info("[Executor] Session Enumeration Mode enabled (ASI09)")
        _enum_report = await _run_session_enumeration(ctx)
        ctx.attack_results["session_enumeration"] = [_enum_report] if _enum_report else []
        ctx._strike_elapsed = time.monotonic() - _strike_start
        return ctx.attack_results

    # RAG Metadata Consumer: Execution optimization
    _rag_kb_map = ctx.service_profile.get("rag_kb_map") if hasattr(ctx, "service_profile") else None
    if _rag_kb_map and _rag_kb_map.get("document_count", 0) > 0:
        from strike.rag_targeted_consumer import optimize_strike_execution
        _rag_opts = optimize_strike_execution(ctx, _rag_kb_map)
        if _rag_opts:
            logger.info(
                "[Executor] RAG-optimized execution: concurrency=%s, timeout=%s, est_duration=%.0fs",
                _rag_opts.get("concurrency", "default"),
                _rag_opts.get("recommended_timeout", "default"),
                _rag_opts.get("estimated_duration_seconds", 0),
            )
            if "concurrency" in _rag_opts:
                max_concurrency = _rag_opts["concurrency"]
                executor = AttackExecutor(max_concurrency=max_concurrency)

    # Adaptive concurrency calibration via Little's Law
    max_concurrency = await _calibrate_concurrency_littles_law(
        ctx, max_concurrency, candidate_converters
    )
    executor = AttackExecutor(max_concurrency=max_concurrency)
    original_seeds = list(ctx.seeds)

    all_results: list[Any] = []
    incomplete_objectives: list[tuple[str, Any]] = []

    if candidate_converters:
        # Native SequentialAttack (FIRST_SUCCESS)
        sequential_results = await _try_native_sequential_attack(
            ctx=ctx,
            candidate_converters=candidate_converters,
            first_success_scoring=first_success_scoring,
            executor=executor,
            timeout=timeout,
        )

        if sequential_results is not None:
            all_results, incomplete_objectives = sequential_results
            logger.info(
                "Native SequentialAttack(FIRST_SUCCESS) completed: %d results, %d incomplete",
                len(all_results), len(incomplete_objectives),
            )
        else:
            # Fallback: manual multi-path loop
            logger.info(
                "Falling back to manual multi-path loop (%d seeds)",
                len(ctx.seeds),
            )
            all_results, incomplete_objectives = await _manual_multi_path_loop(
                ctx=ctx,
                candidate_converters=candidate_converters,
                first_success_scoring=first_success_scoring,
                executor=executor,
                timeout=timeout,
                original_seeds=original_seeds,
            )

        # Restore seeds for escalation phase
        ctx.seeds = original_seeds
    else:
        # No converters: raw prompt baseline
        logger.info("No converters configured, using raw prompts (baseline)")
        prepended_config = _build_prepended_conversation_config(ctx)
        attack = PromptSendingAttack(
            objective_target=ctx.objective_target,
            attack_scoring_config=post_hoc_scoring,
            prepended_conversation_config=prepended_config,
        )
        logger.info(
            "Starting single-turn attacks: %d seeds, concurrency=%d",
            len(ctx.seeds), max_concurrency,
        )
        try:
            executor_kwargs: dict[str, Any] = {
                "attack": attack,
                "seed_groups": ctx.seeds,
                "return_partial_on_failure": True,
            }
            result = await asyncio.wait_for(
                executor.execute_attack_from_seed_groups_async(**executor_kwargs),
                timeout=timeout,
            )
            all_results = list(result.completed_results)
            incomplete_objectives = list(result.incomplete_objectives)
        except asyncio.TimeoutError:
            logger.warning("Attack timed out after %ds, retrieving partial results", timeout)
            await _retrieve_partial_results(ctx, "prompt_sending")
            ctx._strike_elapsed = time.monotonic() - _strike_start
            return ctx.attack_results

    # Store results
    ctx.attack_results["prompt_sending"] = all_results
    _backfill_metadata(all_results, original_seeds, converter_names=_get_converter_names(candidate_converters))

    # Deduplicate incomplete objectives
    seen_objectives: set[str] = set()
    unique_incomplete: list[tuple[str, Any]] = []
    for obj, res in incomplete_objectives:
        obj_key = _make_seed_key(obj) if obj else ""
        if obj_key not in seen_objectives:
            seen_objectives.add(obj_key)
            unique_incomplete.append((obj, res))

    logger.info(
        "Single-turn attacks completed: %d total results, %d incomplete (deduplicated from %d)",
        len(all_results), len(unique_incomplete), len(incomplete_objectives),
    )

    ctx._failed_objectives = [obj for obj, _ in unique_incomplete]

    # Best-of-N Retry
    if ctx._failed_objectives and ctx.converter_target:
        logger.info(
            "Best-of-N retry: %d failed objectives, generating variations...",
            len(ctx._failed_objectives),
        )
        await _best_of_n_retry(ctx, unique_incomplete)

    # Port-expander multi-target attacks
    extra_targets = getattr(ctx, "extra_objective_targets", {})
    if extra_targets:
        logger.info("Executing attacks against %d port-discovered targets", len(extra_targets))
        for port, port_target in extra_targets.items():
            try:
                port_prepended_config = _build_prepended_conversation_config(ctx)
                port_attack = PromptSendingAttack(
                    objective_target=port_target,
                    attack_scoring_config=post_hoc_scoring,
                    prepended_conversation_config=port_prepended_config,
                )
                port_executor_kwargs: dict[str, Any] = {
                    "attack": port_attack,
                    "seed_groups": original_seeds,
                    "return_partial_on_failure": True,
                }
                port_result = await asyncio.wait_for(
                    executor.execute_attack_from_seed_groups_async(**port_executor_kwargs),
                    timeout=timeout,
                )
                port_results_list = list(port_result.completed_results)
                technique_key = f"port_{port}"
                ctx.attack_results[technique_key] = port_results_list
                logger.info("Port %d: %d results", port, len(port_results_list))
            except asyncio.TimeoutError:
                logger.warning("Port %d attack timed out after %ds", port, timeout)
            except Exception as e:
                logger.warning("Port %d attack failed: %s", port, e)

    # ASR Forensic Data Extraction (Why-Success Data)
    try:
        from strike.asr_forensics import apply_forensics_to_ctx
        forensic_count = apply_forensics_to_ctx(
            ctx, ctx.attack_results, converter_map=ctx.converter_map
        )
        if forensic_count > 0:
            logger.info("[Strike] ASR Forensics: %d entries extracted", forensic_count)
    except Exception as e:
        logger.debug("ASR forensics extraction skipped: %s", e)

    # Gap #2: Feedback Loop - Attack Success -> Re-Recon
    await _run_feedback_loop(ctx, all_results)

    ctx._strike_elapsed = time.monotonic() - _strike_start

    return ctx.attack_results
