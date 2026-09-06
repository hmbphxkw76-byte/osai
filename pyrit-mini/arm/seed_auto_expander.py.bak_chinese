"""seed_auto_expander 鈥?浠?seed_ranker.py 鎷嗗垎鑰屾潵.

鍖呭惈寮傛绉嶅瓙鎵╁厖, 鑷€傚簲 UCB-C.
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
    """L5 v27: 寮傛绉嶅瓙鑷姩鎵╁厖 鈥?姝ｇ‘ await VariationConverter.convert_async銆?

    L5 v10 鍘熺増 auto_generate_seeds 鏈?await convert_async 杩斿洖鐨?coroutine,
    瀵艰嚧 LLM 鍙樺紓绉嶅瓙瀹為檯鏈墽琛屻€傛湰寮傛鐗堟湰淇姝ら棶棰樸€?

    瀛︽湳渚濇嵁:
        - AutoDAN (arXiv:2310.04451) 鈥?Liu et al. 鑷姩鍖栬秺鐙?prompt 鐢熸垚
        - Best-of-N (arXiv:2402.01135) 鈥?3x 鎵╁厖 ASR 1.5-2x

    PyRIT 鍘熺敓寮曟搸: VariationConverter (鍘熺敓 converter)
    澧炲己灞? 寮傛骞惰鎵╁厖 + 鍏冩暟鎹户鎵?

    Args:
        base_seeds: 鍩虹绉嶅瓙缁勫垪琛ㄣ€?
        converter_target: LLM 鐩爣瀹炰緥 (鐢ㄤ簬 VariationConverter)銆?
        expansion_factor: 姣忎釜绉嶅瓙鐨勬墿鍏呭€嶆暟 (榛樿 3x)銆?

    Returns:
        鎵╁厖鍚庣殑绉嶅瓙缁勫垪琛?(鍘熷 + 鐢熸垚鍙樹綋)銆?
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

    expanded_seeds: list[AttackSeedGroup] = list(base_seeds)  # 淇濈暀鍘熷绉嶅瓙
    generated_count = 0

    # L5 v27: 骞惰鐢熸垚鎵€鏈夌瀛愬彉浣?
    async def _generate_variant(
        original_value: str,
        original_metadata: dict,
        variant_idx: int,
    ) -> AttackSeedGroup | None:
        """鐢熸垚鍗曚釜绉嶅瓙鍙樹綋銆?"""
        try:
            variation_converter = VariationConverter(
                converter_target=converter_target,
            )

            # L5 v27: 姝ｇ‘ await 寮傛 convert_async
            # L5 v32: PyRIT 1.0.1 API 淇 鈥?鍙傛暟鍚嶆槸 prompt= 鑰岄潪 prompt_request=
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
                # 鍚屾 fallback
                result = variation_converter.convert(prompt=original_value)
                if result and hasattr(result, "output_text"):
                    new_value = result.output_text
                elif result and isinstance(result, str):
                    new_value = result

            if not new_value or new_value == original_value:
                return None

            # 缁ф壙鍘熷 metadata 浣嗘爣璁颁负 auto-generated
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

    # 鏀堕泦鎵€鏈夊彉浣撶敓鎴愪换鍔?
    tasks: list[Any] = []
    for group in base_seeds[:10]:  # 鏈€澶氭墿鍏呭墠 10 涓瀛?
        if not group.seeds:
            continue
        original_seed = group.seeds[0]
        original_value = getattr(original_seed, "value", "")
        original_metadata = getattr(original_seed, "metadata", {}) or {}
        if not original_value:
            continue
        for i in range(expansion_factor):
            tasks.append(_generate_variant(original_value, original_metadata, i))

    # L5 v27: 骞惰鎵ц鎵€鏈夊彉浣撶敓鎴?
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
    """L5 v10: 鍚屾绉嶅瓙鑷姩鎵╁厖 (鍏煎鎺ュ彛)銆?

    L5 v27: 鍐呴儴璋冪敤 auto_generate_seeds_async銆?
    濡傛灉鍦?event loop 鍐? fallback 鍒板悓姝ラ€昏緫 (涓?await convert_async)銆?

    Args:
        base_seeds: 鍩虹绉嶅瓙缁勫垪琛ㄣ€?
        converter_target: LLM 鐩爣瀹炰緥銆?
        expansion_factor: 鎵╁厖鍊嶆暟銆?

    Returns:
        鎵╁厖鍚庣殑绉嶅瓙缁勫垪琛ㄣ€?
    """
    import asyncio as _asyncio

    # 妫€鏌ユ槸鍚﹀湪 event loop 涓?
    try:
        _asyncio.get_running_loop()
        # 鍦?event loop 涓? 涓嶈兘鐢?asyncio.run, 浣跨敤鍚屾 fallback
        logger.info("L5 v27: auto_generate_seeds called within event loop, using sync fallback")
        return _auto_generate_seeds_sync(base_seeds, converter_target, expansion_factor=expansion_factor)
    except RuntimeError:
        # 涓嶅湪 event loop 涓? 鍙互瀹夊叏浣跨敤 asyncio.run
        return _asyncio.run(
            auto_generate_seeds_async(base_seeds, converter_target, expansion_factor=expansion_factor)
        )

def _auto_generate_seeds_sync(
    base_seeds: list[AttackSeedGroup],
    converter_target: Any | None = None,
    *,
    expansion_factor: int = 3,
) -> list[AttackSeedGroup]:
    """鍚屾绉嶅瓙鎵╁厖 fallback (涓?await convert_async)銆?"""
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
    """L5 v11: 鑷€傚簲璁＄畻 UCB 鎺㈢储鍙傛暟 C銆?

    瀛︽湳渚濇嵁: Auer et al. (arXiv:cs/0207052) 鈥?UCB1 绠楁硶涓?C 鍙傛暟
    鎺у埗鎺㈢储-鍒╃敤 (exploration-exploitation) 骞宠　:
        - C 澶?鈫?鏇村鎺㈢储 (灏濊瘯鏂扮瀛? 閫傜敤浜庢暟鎹笉瓒抽樁娈?
        - C 灏?鈫?鏇村鍒╃敤 (閲嶇敤楂?ASR 绉嶅瓙, 閫傜敤浜庢暟鎹厖瓒抽樁娈?

    鑷€傚簲绛栫暐 (鍒嗗眰):
        1. 绉嶅瓙鎬绘暟灏?(N < 10): C=0.8 (寮烘帰绱?
           鐞嗙敱: 鏍锋湰涓嶈冻, 闇€瑕佹洿澶氭帰绱互鍙戠幇楂樻綔鍔涚瀛?
        2. 绉嶅瓙鎬绘暟涓?(10 鈮?N < 50): C=0.5 (鏍囧噯骞宠　)
           鐞嗙敱: 鏈変竴瀹氭暟鎹熀纭€, 缁存寔鎺㈢储-鍒╃敤骞宠
        3. 绉嶅瓙鎬绘暟澶?(N 鈮?50): C=0.3 (寮辨帰绱?
           鐞嗙敱: 宸叉湁瓒冲鏁版嵁, 搴旀洿澶氬埄鐢ㄥ凡鐭ラ珮 ASR 绉嶅瓙

    杩涗竴姝ュ井璋?
        - 濡傛灉 ASR 鏂瑰樊澶?(涓嶅悓绉嶅瓙 ASR 宸紓澶?: C +0.1 (澶氭帰绱?
          鐞嗙敱: 楂樻柟宸剰鍛崇潃鏈変簺绉嶅瓙鍙兘琚綆浼? 闇€瑕佹帰绱?
        - 濡傛灉 ASR 鏂瑰樊灏?(绉嶅瓙琛ㄧ幇鐩歌繎): C -0.1 (灏戞帰绱?
          鐞嗙敱: 浣庢柟宸剰鍛崇潃绉嶅瓙琛ㄧ幇鐩镐技, 鍒╃敤鍗冲彲

    Args:
        seed_attempts: 绉嶅瓙灏濊瘯娆℃暟鍘嗗彶銆?
        asr_history: 绉嶅瓙 ASR 鍘嗗彶銆?

    Returns:
        鑷€傚簲 C 鍙傛暟鍊?[0.1, 1.0]銆?
    """
    N = sum(seed_attempts.values()) if seed_attempts else 0

    # 鍩虹嚎 C 鍊? 鏍规嵁鎬诲皾璇曟鏁板垎灞?
    if N < 10:
        C = 0.8
    elif N < 50:
        C = 0.5
    else:
        C = 0.3

    # 鏂瑰樊寰皟: 濡傛灉鏈?ASR 鍘嗗彶, 鏍规嵁鏂瑰樊璋冩暣
    if asr_history and len(asr_history) >= 2:
        values = list(asr_history.values())
        avg = sum(values) / len(values)
        variance = sum((v - avg) ** 2 for v in values) / len(values)
        std_dev = variance ** 0.5

        # 楂樻柟宸?鈫?澶氭帰绱?(+0.1); 浣庢柟宸?鈫?灏戞帰绱?(-0.1)
        if std_dev > 30.0:  # ASR 鏍囧噯宸?> 30%
            C += 0.1
            logger.debug(
                "UCB C adjusted +0.1 (high variance std=%.1f): C=%.2f",
                std_dev, C,
            )
        elif std_dev < 10.0:  # ASR 鏍囧噯宸?< 10%
            C -= 0.1
            logger.debug(
                "UCB C adjusted -0.1 (low variance std=%.1f): C=%.2f",
                std_dev, C,
            )

    # 鎴柇鍒?[0.1, 1.0]
    C = max(0.1, min(1.0, C))

    logger.info(
        "Adaptive UCB C=%.2f (N=%d, seeds=%d)",
        C, N, len(asr_history),
    )
    return C

