""" - priority_scheduler adaptive_executor .

L-03: 
    converter(s)LoadError handling.

:
    1. SSOT config loading (ctx.args > config/defaults.yaml > module defaults)
    2. Semaphore-guarded parallel asyncio.gather
    3. Unified error handling pattern (TimeoutError, IntegrityError, generic)
    4. Progress display integration
    5. Orchestration log recording

Academic basis:
    - Lattner et al. (arXiv:2406.12609) - 
    - Auer et al. (arXiv:cs/0207052) - UCB1 
    - PyRIT TextAdaptive (arXiv:2407.01232) - 
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any, Callable, Coroutine, TypeVar

from core.context import PipelineContext, get_effective_concurrency

logger = logging.getLogger(__name__)

# (strike/ )
_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# 
T = TypeVar("T")


def load_ssot_config(
    key: str,
    default: Any,
    ctx: Any | None = None,
    *,
    validator: Callable[[Any], bool] | None = None,
    transformer: Callable[[Any], T] | None = None,
) -> T:
 """SSOT Load - imports config/defaults.yaml ctx.args .

    : ctx.args > config/defaults.yaml > 

    Args:
        key: .
        default: .
        ctx: PipelineContext (, ).
        validator: ,  default.
        transformer:  ( float(), int()).

    Returns:
         ().
 """
    value = default

 # 1: ctx.args 
    if ctx is not None:
        args = getattr(ctx, "args", None)
        if args is not None:
            arg_val = getattr(args, key, None)
            if arg_val is not None:
                if validator is None or validator(arg_val):
                    return transformer(arg_val) if transformer else arg_val
                logger.warning(
                    "load_ssot_config: %s=%s fails validation, trying config file",
                    key, arg_val,
                )

 # 2: config/defaults.yaml
    try:
        import yaml
        config_path = _PROJECT_ROOT / "config" / "defaults.yaml"
        if config_path.exists():
            with open(config_path, encoding="utf-8") as f:
                config = yaml.safe_load(f)
            if isinstance(config, dict):
                file_val = config.get(key, value)
                if validator is None or validator(file_val):
                    return transformer(file_val) if transformer else file_val
    except Exception as e:
        logger.warning("load_ssot_config: failed to load %s: %s", key, e)

    return default


def load_ssot_config_float(
    key: str,
    default: float,
    ctx: Any | None = None,
    *,
    min_val: float | None = None,
    max_val: float | None = None,
) -> float:
 """SSOT Load (float , )."""
    def _validator(v: Any) -> bool:
        if not isinstance(v, (int, float)):
            return False
        v = float(v)
        if min_val is not None and v < min_val:
            return False
        if max_val is not None and v > max_val:
            return False
        return True

    return load_ssot_config(
        key, default, ctx,
        validator=_validator,
        transformer=float,
    )


def load_ssot_config_int(
    key: str,
    default: int,
    ctx: Any | None = None,
    *,
    min_val: int | None = None,
) -> int:
 """SSOT Load (int , )."""
    def _validator(v: Any) -> bool:
        if not isinstance(v, (int, float)):
            return False
        v = int(v)
        if min_val is not None and v < min_val:
            return False
        return True

    return load_ssot_config(
        key, default, ctx,
        validator=_validator,
        transformer=lambda x: int(x),
    )


async def safe_async_execute(
    coro: Coroutine[Any, Any, T],
    context: str,
    *,
    timeout: float | None = None,
    on_timeout: Callable[[], Coroutine[Any, Any, T]] | None = None,
    on_integrity_error: Callable[[], T] | None = None,
) -> T | None:
 """ - Error handling.

    :
        1. asyncio.TimeoutError ->  on_timeout 
        2. IntegrityError / Unique Constraint ->  on_integrity_error 
        3.  Exception ->  warning  None

    Args:
        coro: .
        context:  ().
        timeout:  ().
        on_timeout: .
        on_integrity_error: .

    Returns:
        ,  None ().
 """
    try:
        if timeout is not None:
            return await asyncio.wait_for(coro, timeout=timeout)
        return await coro
    except asyncio.TimeoutError:
        logger.warning("safe_async_execute: %s timed out after %ss", context, timeout)
        if on_timeout is not None:
            try:
                return await on_timeout()
            except Exception as e:
                logger.warning("safe_async_execute: %s on_timeout failed: %s", context, e)
        return None
    except Exception as e:
        exc_str = str(e).lower()
        if "integrityerror" in exc_str or "unique constraint" in exc_str:
            logger.warning(
                "safe_async_execute: %s IntegrityError (parallel write conflict): %s",
                context, e,
            )
            if on_integrity_error is not None:
                try:
                    return on_integrity_error()
                except Exception as cb_e:
                    logger.warning(
                        "safe_async_execute: %s on_integrity_error failed: %s",
                        context, cb_e,
                    )
            return None
        logger.warning("safe_async_execute: %s failed: %s", context, e)
        return None


class ParallelGatherHelper:
 """ Gather - semaphore asyncio.gather.

    :
        async with ParallelGatherHelper(ctx, max_concurrency=5) as helper:
            results = await helper.gather(runner1(...), runner2(...))

    :
        - imports ctx  max_concurrency
        - 
        -  (return_exceptions=True,  None)
        - 

    : ,  PyRIT AttackExecutor.
    Rule R2 :  execute_attack_from_seed_groups_async.
 """

    def __init__(
        self,
        ctx: PipelineContext,
        max_concurrency: int | None = None,
        *,
        semaphore: asyncio.Semaphore | None = None,
    ):
 """ gather .

        Args:
            ctx: .
            max_concurrency:  (imports ctx ).
            semaphore:  ().
 """
        self.ctx = ctx
        self.semaphore = semaphore or asyncio.Semaphore(
            max_concurrency or get_effective_concurrency(ctx),
        )
        self._start_time: float | None = None

    async def __aenter__(self) -> ParallelGatherHelper:
        self._start_time = time.monotonic()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._start_time is not None:
            elapsed = time.monotonic() - self._start_time
            logger.debug("ParallelGatherHelper: completed in %.2fs", elapsed)
        return None

    async def gather(
        self,
        *coros: Coroutine[Any, Any, T],
        context: str = "parallel_attack",
    ) -> list[T]:
 """all, .

        Args:
            *coros: .
            context:  ().

        Returns:
             None .
 """
        if not coros:
            return []

        async def _semaphore_gather() -> list[T | BaseException | None]:
            async def _wrap(coro: Coroutine[Any, Any, T]) -> T | BaseException | None:
                async with self.semaphore:
                    try:
                        return await coro
                    except Exception as e:
                        logger.warning("%s: sub-task failed: %s", context, e)
                        return e

            return await asyncio.gather(
                *[_wrap(c) for c in coros],
                return_exceptions=True,
            )

        raw_results = await _semaphore_gather()

 # None 
        results: list[T] = []
        for r in raw_results:
            if r is None or isinstance(r, BaseException):
                continue
            results.append(r)

        logger.info(
            "%s: %d/%d sub-tasks succeeded",
            context, len(results), len(coros),
        )
        return results


def compute_asr_from_results(attack_results: dict[str, Any]) -> float:
 """ ASR - .

    Args:
        attack_results: {technique_name: [AttackResult, ...]}  {technique_name: ASR%}.

    Returns:
        ASR  (0-100).
 """
    if not attack_results:
        return 0.0

    values = list(attack_results.values())

 # float : {technique: ASR%}
    if all(isinstance(v, (int, float)) for v in values):
        return sum(values) / len(values)

 # AttackResult 
    total = sum(len(v) for v in values)
    if total == 0:
        return 0.0

    success = 0
    for results in values:
        for r in results:
            outcome = getattr(r, "outcome", None)
            if outcome:
                outcome_str = str(outcome).lower()
                if "success" in outcome_str:
                    success += 1
                    continue
            score_val = getattr(r, "score_value", None)
            if score_val:
                if isinstance(score_val, str) and score_val.lower() in ("true", "1", "success"):
                    success += 1
                elif isinstance(score_val, (int, float)) and score_val > 0:
                    success += 1

    return (success / total) * 100.0


def format_elapsed(seconds: float) -> str:
 """."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = seconds % 60
    return f"{minutes}m{secs:.0f}s"
