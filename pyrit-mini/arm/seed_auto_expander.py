"""seed_auto_expander ??seed_ranker.py .

╁, € UCB-C.
"""

import asyncio
import logging
from typing import Any

from pyrit.models import AttackSeedGroup, SeedObjective

logger = logging.getLogger(__name__)

async def auto_generate_seeds_async(
    base_seeds: list[AttackSeedGroup],
    converter_target: Any | None = None,
    *,
    expansion_factor: int = 3,
) -> list[AttackSeedGroup]:
    """L5 v27: ╁ ?‘ await VariationConverter.convert_async?

    L5 v10  auto_generate_seeds ?await convert_async ?coroutine,
     LLM €ら€?

    ︽:
        - AutoDAN (arXiv:2310.04451) ?Liu et al. ?prompt 
        - Best-of-N (arXiv:2402.01135) ?3x ╁ ASR 1.5-2x

    PyRIT : VariationConverter ( converter)
    ? ╁ + ?

    Args:
        base_seeds: ㄣ€?
        converter_target: LLM  (ㄤ VariationConverter)?
        expansion_factor: € ( 3x)?

    Returns:
        ╁?( + )?
    """
    if converter_target is None:
        logger.info("Auto-generate seeds skipped: no converter_target available")
        return base_seeds

    if not base_seeds:
        return base_seeds

    try:
        from pyrit.converter import VariationConverter
    except ImportError:
        logger.warning("VariationConverter not available, skipping seed auto-generation")
        return base_seeds

    expanded_seeds: list[AttackSeedGroup] = list(base_seeds)  # 
    generated_count = 0

    # L5 v27: €?
    async def _generate_variant(
        original_value: str,
        original_metadata: dict,
        variant_idx: int,
    ) -> AttackSeedGroup | None:
        """?"""
        try:
            variation_converter = VariationConverter(
                converter_target=converter_target,
            )

            # L5 v27: ‘ await  convert_async
            # L5 v32: PyRIT 1.0.1 API  ? prompt=  prompt_request=
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
                #  fallback
                result = variation_converter.convert(prompt=original_value)
                if result and hasattr(result, "output_text"):
                    new_value = result.output_text
                elif result and isinstance(result, str):
                    new_value = result

            if not new_value or new_value == original_value:
                return None

            # ф metadata  auto-generated
            new_metadata = dict(original_metadata)
            new_metadata["source"] = "auto_generated"
            new_metadata["parent_seed"] = original_value[:60]
            new_metadata["variant_idx"] = str(variant_idx)

            new_objective = SeedObjective(
                value=new_value,
                harm_categories=original_metadata.get("category", "general")
                if isinstance(original_metadata.get("category"), list)
                else [original_metadata.get("category", "general")],
                metadata=new_metadata,
            )
            return AttackSeedGroup(seeds=[new_objective])
        except Exception as e:
            logger.debug("Seed variation %d failed: %s", variant_idx, e)
            return None

    # €?
    tasks: list[Any] = []
    for group in base_seeds[:10]:  # € 10 ?
        if not group.seeds:
            continue
        original_seed = group.seeds[0]
        original_value = getattr(original_seed, "value", "")
        original_metadata = getattr(original_seed, "metadata", {}) or {}
        if not original_value:
            continue
        for i in range(expansion_factor):
            tasks.append(_generate_variant(original_value, original_metadata, i))

    # L5 v27: ц€?
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, AttackSeedGroup):
            expanded_seeds.append(result)
            generated_count += 1
        elif isinstance(result, Exception):
            logger.debug("Seed generation task failed: %s", result)

    logger.info(
        "L5 v27: Auto-generated %d seed variants from %d base seeds "
        "(expansion_factor=%d, parallel=asyncio.gather)",
        generated_count,
        min(len(base_seeds), 10),
        expansion_factor,
    )

    return expanded_seeds

def auto_generate_seeds(
    base_seeds: list[AttackSeedGroup],
    converter_target: Any | None = None,
    *,
    expansion_factor: int = 3,
) -> list[AttackSeedGroup]:
    """L5 v10: ╁ (ュ)?

    L5 v27:  auto_generate_seeds_async?
    ?event loop ? fallback ラ€ (?await convert_async)?

    Args:
        base_seeds: ㄣ€?
        converter_target: LLM ?
        expansion_factor: ╁?

    Returns:
        ╁ㄣ€?
    """
    import asyncio as _asyncio

    # €ユ﹀ event loop ?
    try:
        _asyncio.get_running_loop()
        # ?event loop ? ?asyncio.run,  fallback
        logger.info("L5 v27: auto_generate_seeds called within event loop, using sync fallback")
        return _auto_generate_seeds_sync(base_seeds, converter_target, expansion_factor=expansion_factor)
    except RuntimeError:
        #  event loop ?  asyncio.run
        return _asyncio.run(
            auto_generate_seeds_async(base_seeds, converter_target, expansion_factor=expansion_factor)
        )

def _auto_generate_seeds_sync(
    base_seeds: list[AttackSeedGroup],
    converter_target: Any | None = None,
    *,
    expansion_factor: int = 3,
) -> list[AttackSeedGroup]:
    """╁ fallback (?await convert_async)?"""
    if converter_target is None or not base_seeds:
        return base_seeds

    try:
        from pyrit.converter import VariationConverter
    except ImportError:
        return base_seeds

    expanded_seeds: list[AttackSeedGroup] = list(base_seeds)
    generated_count = 0

    for group in base_seeds[:10]:
        if not group.seeds:
            continue
        original_seed = group.seeds[0]
        original_value = getattr(original_seed, "value", "")
        original_metadata = getattr(original_seed, "metadata", {}) or {}
        if not original_value:
            continue

        for i in range(expansion_factor):
            try:
                variation_converter = VariationConverter(
                    converter_target=converter_target,
                )
                new_value = None
                if hasattr(variation_converter, "convert"):
                    result = variation_converter.convert(prompt=original_value)
                    if result and hasattr(result, "output_text"):
                        new_value = result.output_text
                    elif result and isinstance(result, str):
                        new_value = result

                if new_value and new_value != original_value:
                    new_metadata = dict(original_metadata)
                    new_metadata["source"] = "auto_generated"
                    new_metadata["parent_seed"] = original_value[:60]
                    new_objective = SeedObjective(
                        value=new_value,
                        harm_categories=original_metadata.get("category", "general")
                        if isinstance(original_metadata.get("category"), list)
                        else [original_metadata.get("category", "general")],
                        metadata=new_metadata,
                    )
                    expanded_seeds.append(AttackSeedGroup(seeds=[new_objective]))
                    generated_count += 1
            except Exception as e:
                logger.debug("Seed variation %d failed (sync): %s", i + 1, e)

    logger.info(
        "L5 v27: Auto-generated %d seed variants (sync fallback, expansion_factor=%d)",
        generated_count,
        expansion_factor,
    )
    return expanded_seeds

def _compute_adaptive_ucb_c(
    seed_attempts: dict[str, int],
    asr_history: dict[str, float],
) -> float:
    """L5 v11: € UCB  C?

    ︽: Auer et al. (arXiv:cs/0207052) ?UCB1 ?C 
    у-╃ (exploration-exploitation) :
        - C ?? (? ?
        - C ??╃ (?ASR , ?

    € ():
        1. ?(N < 10): C=0.8 (?
           : , €?
        2. ?(10 ?N < 50): C=0.5 ()
           : €, -╃
        3. ?(N ?50): C=0.3 (?
           : , ㄥラ ASR 

    ュ?
        -  ASR ?( ASR ?: C +0.1 (?
          : ? €?
        -  ASR ?(ㄧ): C -0.1 (?
          : ㄧ, ╃

    Args:
        seed_attempts: ℃?
        asr_history:  ASR ?

    Returns:
        € C ?[0.1, 1.0]?
    """
    N = sum(seed_attempts.values()) if seed_attempts else 0

    #  C ? ?
    if N < 10:
        C = 0.8
    elif N < 50:
        C = 0.5
    else:
        C = 0.3

    # : ?ASR , 
    if asr_history and len(asr_history) >= 2:
        values = list(asr_history.values())
        avg = sum(values) / len(values)
        variance = sum((v - avg) ** 2 for v in values) / len(values)
        std_dev = variance ** 0.5

        # ???(+0.1); ???(-0.1)
        if std_dev > 30.0:  # ASR ?> 30%
            C += 0.1
            logger.debug(
                "UCB C adjusted +0.1 (high variance std=%.1f): C=%.2f",
                std_dev, C,
            )
        elif std_dev < 10.0:  # ASR ?< 10%
            C -= 0.1
            logger.debug(
                "UCB C adjusted -0.1 (low variance std=%.1f): C=%.2f",
                std_dev, C,
            )

    # ?[0.1, 1.0]
    C = max(0.1, min(1.0, C))

    logger.info(
        "Adaptive UCB C=%.2f (N=%d, seeds=%d)",
        C, N, len(asr_history),
    )
    return C

