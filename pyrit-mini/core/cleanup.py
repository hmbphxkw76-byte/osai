""" - imports main.py Target 

Production-grade - Ensure all Target 
 httpx.AsyncClient DB 
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)


async def cleanup_resources(
    ctx: "PipelineContext",
    *,
    exclude_shared: bool = False,
) -> None:
 """Production-grade - Ensure all Target 

    :  main.py  () 
     RateLimitedTarget.cleanup()  Playwright ,
     httpx.AsyncClient DB 

     (LIFO - ):
        1. extra_objective_targets (port_expander )
        2. multi_turn_target (,  objective_target )
        3. objective_target (, RateLimitedTarget.cleanup)
        4. Playwright  (_browser, _playwright_instance)
        5. adversarial_target / scoring_target (, )

     endpoint  (exclude_shared=True):
         objective  targets (1-4 + Playwright),
        Skip adversarial/scoring/converter (5),  LLM,
         endpoint  endpoint , 
         objective  None, Ensureconverter(s) endpoint  target

    Academic basis:
        - Heroux et al. (arXiv:2403.04206) Sec3.2 - 
        - PyRIT (arXiv:2407.01232) - dispose_db_engine() 
        - Greshake et al. (arXiv:2302.12173) - converter(s)
 """
    cleaned: set[int] = set()  # (objective_target == multi_turn_target)

    async def _cleanup_target(target: Any, label: str) -> None:
 """converter(s) Target (, )"""
        if target is None:
            return
        target_id = id(target)
        if target_id in cleaned:
            return
        cleaned.add(target_id)
        try:
            if hasattr(target, "cleanup") and callable(target.cleanup):
                result = target.cleanup()
                if asyncio.iscoroutine(result):
                    await result
                logger.debug("Cleaned up %s: %s", label, type(target).__name__)
        except Exception as e:
            logger.debug("Cleanup %s failed (non-fatal): %s", label, e)

 # 1. extra_objective_targets (port_expander )
    for port, extra_target in getattr(ctx, "extra_objective_targets", {}).items():
        await _cleanup_target(extra_target, f"extra_objective_target[port={port}]")
    ctx.extra_objective_targets = {}  # 

 # 2. multi_turn_target ( objective_target , cleaned )
    await _cleanup_target(getattr(ctx, "multi_turn_target", None), "multi_turn_target")
    ctx.multi_turn_target = None  # 

 # 3. objective_target ()
    await _cleanup_target(getattr(ctx, "objective_target", None), "objective_target")
    ctx.objective_target = None  # 

 # 4. Playwright (browser )
 # Data flow: target_router._create_playwright_target -> ctx._browser_context/_browser/_playwright_instance
 # -> cleanup_resources -> browser.close() + playwright.stop()
 # : , finally 
    _browser_context = getattr(ctx, "_browser_context", None)
    _browser = getattr(ctx, "_browser", None)
    _playwright_instance = getattr(ctx, "_playwright_instance", None)
    try:
        if _browser_context is not None:
            await _browser_context.close()
            ctx._browser_context = None  # : 
            logger.debug("Closed Playwright browser context")
    except Exception as e:
        logger.debug("Playwright browser context close failed (non-fatal): %s", e)
    try:
        if _browser is not None:
            await _browser.close()
            ctx._browser = None  # : 
            logger.debug("Closed Playwright browser")
    except Exception as e:
        logger.debug("Playwright browser close failed (non-fatal): %s", e)
    try:
        if _playwright_instance is not None:
            await _playwright_instance.stop()
            ctx._playwright_instance = None  # : 
            logger.debug("Stopped Playwright instance")
    except Exception as e:
        logger.debug("Playwright instance stop failed (non-fatal): %s", e)

 # 5. adversarial_target / scoring_target OpenAIChatTarget ( httpx client )
 # RateLimitedTarget , cleanup 
 # Target ( _create_adversarial_target )
 # endpoint (exclude_shared=True): Skip targets, 
    if not exclude_shared:
 # 5a. extra_adversarial_targets ( LLM)
        for i, extra_adv in enumerate(getattr(ctx, "extra_adversarial_targets", [])):
            await _cleanup_target(extra_adv, f"extra_adversarial_target[{i}]")
        ctx.extra_adversarial_targets = []  # 
        await _cleanup_target(getattr(ctx, "adversarial_target", None), "adversarial_target")
        ctx.adversarial_target = None  # 
        await _cleanup_target(getattr(ctx, "scoring_target", None), "scoring_target")
        ctx.scoring_target = None  # 
        await _cleanup_target(getattr(ctx, "converter_target", None), "converter_target")
        ctx.converter_target = None  # 

    logger.info(
        "Resource cleanup complete (cleaned %d targets, shared_excluded=%s)",
        len(cleaned),
        exclude_shared,
    )


def has_residual_resources(ctx: "PipelineContext") -> bool:
 """ ctx Target """
    return (
        getattr(ctx, "objective_target", None) is not None
        or getattr(ctx, "adversarial_target", None) is not None
        or getattr(ctx, "scoring_target", None) is not None
        or getattr(ctx, "converter_target", None) is not None
        or getattr(ctx, "_browser", None) is not None
        or getattr(ctx, "_playwright_instance", None) is not None
    )
