# arXiv:2402.01135 - Chao et al., Best-of-N (ASR 1.8x improvement)
# arXiv:2407.01232 - PyRIT, SequentialAttack FIRST_SUCCESS
"""
adaptive_executor - Adaptive attack execution with retry logic.

Implements Best-of-N retry and adaptive outcome detection.
"""

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Project root for config loading
_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _adaptive_outcome_success(result: Any) -> bool:
    """Check if attack result indicates success.

    Checks multiple outcome fields:
    - result.outcome (string like "success"/"failure")
    - result.score_value (boolean or numeric)
    - result.scores (dict of scorer -> score)
    """
    outcome = getattr(result, "outcome", None)
    if outcome:
        outcome_str = str(outcome).lower()
        if "success" in outcome_str:
            return True
        if "failure" in outcome_str or "fail" in outcome_str:
            return False

    score_val = getattr(result, "score_value", None)
    if score_val:
        if isinstance(score_val, str):
            return score_val.lower() in ("true", "1", "success")
        if isinstance(score_val, (int, float)):
            return bool(score_val)

    scores = getattr(result, "scores", None)
    if scores:
        try:
            for scorer_name, score in scores.items():
                sv = getattr(score, "score_value", score) if hasattr(score, "score_value") else score
                if str(sv).lower() in ("true", "1", "success"):
                    return True
        except Exception:
            pass

    return False


def _get_best_of_n_retries(ctx: Any | None = None) -> int:
    """Get Best-of-N retry count from context or config.

    Reads from ctx.args or falls back to config/defaults.yaml.

    Academic basis: Chao et al. (arXiv:2402.01135) - N=5 ASR 1.8x, token cost N=10 increases 50%
    R10 override: N>=5

    Returns:
        Number of retry attempts (default 1)
    """
    # Try ctx.args first
    if ctx is not None:
        args = getattr(ctx, "args", None)
        if args is not None:
            val = getattr(args, "best_of_n_retries", None)
            if val is not None:
                return max(1, min(int(val), 10))

    # Fallback to config
    try:
        import yaml
        config_path = _PROJECT_ROOT / "config" / "defaults.yaml"
        if config_path.exists():
            with open(config_path, encoding='utf-8') as f:
                config = yaml.safe_load(f)
            val = config.get("scoring", {}).get("best_of_n_retries", 1)
            return max(1, min(int(val), 10))
    except Exception as e:
        logger.debug("Failed to load best_of_n_retries from config: %s", e)

    return 1


async def _best_of_n_retry(
    ctx: Any,
    attack_fn: callable,
    *,
    n: int | None = None,
) -> list[Any]:
    """Execute attack with Best-of-N retry strategy.

    Retries attack up to n times and returns all results.

    Args:
        ctx: Pipeline context
        attack_fn: Async attack function to execute
        n: Number of retries (defaults to _get_best_of_n_retries)

    Returns:
        List of attack results
    """
    if n is None:
        n = _get_best_of_n_retries(ctx)

    results = []
    for attempt in range(n):
        try:
            result = await attack_fn(ctx)
            if isinstance(result, list):
                results.extend(result)
            else:
                results.append(result)
        except Exception as e:
            logger.warning("Best-of-N attempt %d failed: %s", attempt + 1, e)

    return results
