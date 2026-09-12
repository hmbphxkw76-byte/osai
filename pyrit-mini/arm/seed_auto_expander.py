"""seed_auto_expander - Auto-generate seed variants using VariationConverter.

L5 v27: +3x seed expansion, EUR UCB-C selection.
"""

import asyncio
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

from pyrit.models import AttackSeedGroup

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _load_defaults() -> dict[str, Any]:
    """读取 `config/defaults.yaml`（进程内缓存一次）。"""
    path = Path(__file__).resolve().parents[1] / "config" / "defaults.yaml"
    if not path.exists():
        logger.warning("defaults.yaml 缺失：%s（回退内置常量）", path)
        return {}
    try:
        import yaml

        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        logger.warning("defaults.yaml 读取失败：%s（回退内置常量）", e)
        return {}


def _resolve_expansion_factor(explicit: int | None = None) -> int:
    """种子自动扩充倍数（C7 SSOT：`config/defaults.yaml:auto_seed_expansion_factor`）。

    BL-038 接真（CP-003）：该键此前零消费者，扩充倍数恒为形参默认值 3。
    现由 SSOT 提供；形参显式传入时优先（CLI/调用方覆盖，NFR-10 人类控制权）。

    Args:
        explicit: 调用方显式指定的倍数；None 表示走配置。

    Returns:
        扩充倍数，clamp 到 [1, 10]（防配置误填导致种子爆炸）。
    """
    if isinstance(explicit, int) and not isinstance(explicit, bool) and explicit >= 1:
        return min(10, explicit)
    raw = _load_defaults().get("auto_seed_expansion_factor")
    try:
        value = int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        logger.warning("auto_seed_expansion_factor 取值非法 %r，回退 3", raw)
        return 3
    return max(1, min(10, value))


async def auto_generate_seeds_async(
    base_seeds: list[AttackSeedGroup],
    converter_target: Any | None = None,
    *,
    expansion_factor: int | None = None,
) -> list[AttackSeedGroup]:
    """L5 v27: Auto-generate seed variants using VariationConverter.

    L5 v10 auto_generate_seeds - await convert_async coroutine,
    LLM generates variations of the original seed prompt.

    References:
        - AutoDAN (arXiv:2310.04451) - Liu et al. automated prompt generation
        - Best-of-N (arXiv:2402.01135) - 3x seed expansion yields ASR 1.5-2x

    PyRIT Integration: VariationConverter (from pyrit.executor.converter)
    generates semantically equivalent but syntactically diverse prompts.
    + expands seed pool + increases attack surface coverage.

    Args:
        base_seeds: Original seed groups to expand
        converter_target: LLM target (passed to VariationConverter)
        expansion_factor: Target expansion multiplier (default 3x)

    Returns:
        Expanded seed list (base + generated variants)
    """
    if converter_target is None:
        return base_seeds

    if not base_seeds:
        return base_seeds

    try:
        from pyrit.executor.converter import VariationConverter
    except ImportError:
        logger.warning("VariationConverter not available, returning base seeds")
        return base_seeds

    expanded_seeds: list[AttackSeedGroup] = list(base_seeds)
    generated_count = 0

    # L5 v27: Generate variants for each base seed
    async def _generate_variant(
        original_value: str,
        original_metadata: dict,
        variant_idx: int,
    ) -> AttackSeedGroup | None:
        """Generate single variant using VariationConverter."""
        try:
            variation_converter = VariationConverter(
                converter_target=converter_target,
            )

            # L5 v27: await convert_async
            # L5 v32: PyRIT 1.0.1 API change: prompt= -> prompt_request=
            new_value = None
            if hasattr(variation_converter, "convert_async"):
                result = await variation_converter.convert_async(
                    prompt=original_value,
                )
                if result and hasattr(result, "output_text"):
                    new_value = result.output_text
                elif result and isinstance(result, str):
                    new_value = result
            elif hasattr(variation_converter, "convert"):
                result = variation_converter.convert(prompt=original_value)
                if result and hasattr(result, "output_text"):
                    new_value = result.output_text

            if new_value and new_value != original_value:
                return AttackSeedGroup(
                    value=new_value,
                    objectives=original_metadata.get("objectives", []),
                )
        except Exception as e:
            logger.debug("Variant generation failed for idx %d: %s", variant_idx, e)
        return None

    # Generate variants for each seed（倍数走 C7 SSOT，见 `_resolve_expansion_factor`）
    _factor = _resolve_expansion_factor(expansion_factor)
    tasks = []
    for seed in base_seeds:
        for idx in range(_factor - 1):
            tasks.append(_generate_variant(seed.value, {}, idx))

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, AttackSeedGroup):
                expanded_seeds.append(result)
                generated_count += 1

    logger.info(
        "auto_generate_seeds: expanded %d -> %d seeds (+%d variants)",
        len(base_seeds),
        len(expanded_seeds),
        generated_count,
    )
    return expanded_seeds


def _compute_adaptive_ucb_c(
    mean_reward: float,
    pull_count: int,
    total_pulls: int,
    exploration_factor: float = 1.414,
) -> float:
    """Compute UCB (Upper Confidence Bound) value with adaptive exploration.

    Uses the UCB1 formula: mean_reward + exploration_factor * sqrt(ln(total_pulls) / pull_count)
    The exploration factor adapts based on sample size.

    Args:
        mean_reward: Average reward observed so far
        pull_count: Number of times this arm has been pulled
        total_pulls: Total number of pulls across all arms
        exploration_factor: Exploration constant (default sqrt(2) ≈ 1.414)

    Returns:
        UCB value for this arm
    """
    import math

    if pull_count == 0:
        return float("inf")  # Encourage exploration of unpulled arms
    exploitation = mean_reward
    exploration = exploration_factor * math.sqrt(math.log(total_pulls) / pull_count)
    return exploitation + exploration


def auto_generate_seeds(
    base_seeds: list[AttackSeedGroup],
    converter_target: Any | None = None,
    *,
    expansion_factor: int | None = None,
) -> list[AttackSeedGroup]:
    """Synchronous auto_generate_seeds wrapper."""
    return _auto_generate_seeds_sync(base_seeds, converter_target, expansion_factor=expansion_factor)


def _auto_generate_seeds_sync(
    base_seeds: list[AttackSeedGroup],
    converter_target: Any | None = None,
    *,
    expansion_factor: int | None = None,
) -> list[AttackSeedGroup]:
    """Synchronous wrapper for auto_generate_seeds_async."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If already in an async context, return base seeds
            logger.warning("Cannot run sync seed expansion in async context")
            return base_seeds
        return loop.run_until_complete(
            auto_generate_seeds_async(base_seeds, converter_target, expansion_factor=expansion_factor)
        )
    except RuntimeError:
        # No event loop, create a new one
        return asyncio.run(auto_generate_seeds_async(base_seeds, converter_target, expansion_factor=expansion_factor))
