"""seed_auto_expander — 从 seed_ranker.py 拆分而来.

包含异步种子扩充, 自适应 UCB-C.
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
    """L5 v27: 异步种子自动扩充 — 正确 await VariationConverter.convert_async。

    L5 v10 原版 auto_generate_seeds 未 await convert_async 返回的 coroutine,
    导致 LLM 变异种子实际未执行。本异步版本修复此问题。

    学术依据:
        - AutoDAN (arXiv:2310.04451) — Liu et al. 自动化越狱 prompt 生成
        - Best-of-N (arXiv:2402.01135) — 3x 扩充 ASR 1.5-2x

    PyRIT 原生引擎: VariationConverter (原生 converter)
    增强层: 异步并行扩充 + 元数据继承

    Args:
        base_seeds: 基础种子组列表。
        converter_target: LLM 目标实例 (用于 VariationConverter)。
        expansion_factor: 每个种子的扩充倍数 (默认 3x)。

    Returns:
        扩充后的种子组列表 (原始 + 生成变体)。
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

    expanded_seeds: list[AttackSeedGroup] = list(base_seeds)  # 保留原始种子
    generated_count = 0

    # L5 v27: 并行生成所有种子变体
    async def _generate_variant(
        original_value: str,
        original_metadata: dict,
        variant_idx: int,
    ) -> AttackSeedGroup | None:
        """生成单个种子变体。"""
        try:
            variation_converter = VariationConverter(
                converter_target=converter_target,
            )

            # L5 v27: 正确 await 异步 convert_async
            # L5 v32: PyRIT 1.0.1 API 修正 — 参数名是 prompt= 而非 prompt_request=
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
                # 同步 fallback
                result = variation_converter.convert(prompt=original_value)
                if result and hasattr(result, "output_text"):
                    new_value = result.output_text
                elif result and isinstance(result, str):
                    new_value = result

            if not new_value or new_value == original_value:
                return None

            # 继承原始 metadata 但标记为 auto-generated
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

    # 收集所有变体生成任务
    tasks: list[Any] = []
    for group in base_seeds[:10]:  # 最多扩充前 10 个种子
        if not group.seeds:
            continue
        original_seed = group.seeds[0]
        original_value = getattr(original_seed, "value", "")
        original_metadata = getattr(original_seed, "metadata", {}) or {}
        if not original_value:
            continue
        for i in range(expansion_factor):
            tasks.append(_generate_variant(original_value, original_metadata, i))

    # L5 v27: 并行执行所有变体生成
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
    """L5 v10: 同步种子自动扩充 (兼容接口)。

    L5 v27: 内部调用 auto_generate_seeds_async。
    如果在 event loop 内, fallback 到同步逻辑 (不 await convert_async)。

    Args:
        base_seeds: 基础种子组列表。
        converter_target: LLM 目标实例。
        expansion_factor: 扩充倍数。

    Returns:
        扩充后的种子组列表。
    """
    import asyncio as _asyncio

    # 检查是否在 event loop 中
    try:
        _asyncio.get_running_loop()
        # 在 event loop 中, 不能用 asyncio.run, 使用同步 fallback
        logger.info("L5 v27: auto_generate_seeds called within event loop, using sync fallback")
        return _auto_generate_seeds_sync(base_seeds, converter_target, expansion_factor=expansion_factor)
    except RuntimeError:
        # 不在 event loop 中, 可以安全使用 asyncio.run
        return _asyncio.run(
            auto_generate_seeds_async(base_seeds, converter_target, expansion_factor=expansion_factor)
        )

def _auto_generate_seeds_sync(
    base_seeds: list[AttackSeedGroup],
    converter_target: Any | None = None,
    *,
    expansion_factor: int = 3,
) -> list[AttackSeedGroup]:
    """同步种子扩充 fallback (不 await convert_async)。"""
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
    """L5 v11: 自适应计算 UCB 探索参数 C。

    学术依据: Auer et al. (arXiv:cs/0207052) — UCB1 算法中 C 参数
    控制探索-利用 (exploration-exploitation) 平衡:
        - C 大 → 更多探索 (尝试新种子, 适用于数据不足阶段)
        - C 小 → 更多利用 (重用高 ASR 种子, 适用于数据充足阶段)

    自适应策略 (分层):
        1. 种子总数少 (N < 10): C=0.8 (强探索)
           理由: 样本不足, 需要更多探索以发现高潜力种子
        2. 种子总数中 (10 ≤ N < 50): C=0.5 (标准平衡)
           理由: 有一定数据基础, 维持探索-利用平衡
        3. 种子总数多 (N ≥ 50): C=0.3 (弱探索)
           理由: 已有足够数据, 应更多利用已知高 ASR 种子

    进一步微调:
        - 如果 ASR 方差大 (不同种子 ASR 差异大): C +0.1 (多探索)
          理由: 高方差意味着有些种子可能被低估, 需要探索
        - 如果 ASR 方差小 (种子表现相近): C -0.1 (少探索)
          理由: 低方差意味着种子表现相似, 利用即可

    Args:
        seed_attempts: 种子尝试次数历史。
        asr_history: 种子 ASR 历史。

    Returns:
        自适应 C 参数值 [0.1, 1.0]。
    """
    N = sum(seed_attempts.values()) if seed_attempts else 0

    # 基线 C 值: 根据总尝试次数分层
    if N < 10:
        C = 0.8
    elif N < 50:
        C = 0.5
    else:
        C = 0.3

    # 方差微调: 如果有 ASR 历史, 根据方差调整
    if asr_history and len(asr_history) >= 2:
        values = list(asr_history.values())
        avg = sum(values) / len(values)
        variance = sum((v - avg) ** 2 for v in values) / len(values)
        std_dev = variance ** 0.5

        # 高方差 → 多探索 (+0.1); 低方差 → 少探索 (-0.1)
        if std_dev > 30.0:  # ASR 标准差 > 30%
            C += 0.1
            logger.debug(
                "UCB C adjusted +0.1 (high variance std=%.1f): C=%.2f",
                std_dev, C,
            )
        elif std_dev < 10.0:  # ASR 标准差 < 10%
            C -= 0.1
            logger.debug(
                "UCB C adjusted -0.1 (low variance std=%.1f): C=%.2f",
                std_dev, C,
            )

    # 截断到 [0.1, 1.0]
    C = max(0.1, min(1.0, C))

    logger.info(
        "Adaptive UCB C=%.2f (N=%d, seeds=%d)",
        C, N, len(asr_history),
    )
    return C
