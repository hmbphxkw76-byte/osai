"""PyRIT 原生 CompoundDatasetAttackConfiguration — 多数据集复合攻击编排。
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SEEDS_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "seeds"

def build_compound_dataset_config(
    seed_names: str,
    max_seeds: int = 25,
) -> Any | None:
    """构建 PyRIT 原生 CompoundDatasetAttackConfiguration。
    """
    try:
        from pyrit.scenario import (
            CompoundDatasetAttackConfiguration,
            DatasetAttackConfiguration,
        )
    except ImportError as e:
        logger.warning("PyRIT scenario dataset modules not available: %s", e)
        return None

    names = [s.strip() for s in seed_names.split(",") if s.strip()]
    if not names:
        logger.warning("No seed names provided for compound dataset config")
        return None

    # 每个子数据集独立预算: 均分 max_seeds
    per_dataset_size = max(1, max_seeds // len(names))

    # 构建子配置列表 — 使用 inline seeds (不依赖 Memory 注册)
    child_configs: list[DatasetAttackConfiguration] = []
    for name in names:
        seed_path = _SEEDS_DIR / f"{name}.prompt"
        if not seed_path.exists():
            logger.warning("Seed file not found: %s, skipping", seed_path)
            continue

        try:
            from pyrit.models import SeedPrompt

            seed_prompt = SeedPrompt.from_yaml_file(seed_path)
            seeds = seed_prompt.values if hasattr(seed_prompt, "values") else [seed_prompt]

            if not seeds:
                logger.warning("No seeds loaded from %s, skipping", seed_path)
                continue

            child_config = DatasetAttackConfiguration(
                seeds=seeds,
                max_dataset_size=per_dataset_size,
            )
            child_configs.append(child_config)
            logger.info(
                "CompoundDataset child: %s (%d seeds, budget=%d)",
                name, len(seeds), per_dataset_size,
            )
        except Exception as e:
            logger.warning("Failed to load seed file %s: %s", seed_path, e)
            continue

    if not child_configs:
        logger.warning("No valid child configs built for compound dataset")
        return None

    compound = CompoundDatasetAttackConfiguration(
        configurations=child_configs,
        max_dataset_size=max_seeds,
    )
    logger.info(
        "CompoundDatasetAttackConfiguration built: %d child datasets, "
        "per_dataset=%d, global_cap=%d",
        len(child_configs), per_dataset_size, max_seeds,
    )
    return compound

def build_text_adaptive_dataset_config(
    seed_names: str,
    max_seeds: int = 25,
) -> Any | None:
    """构建 TextAdaptive 场景专用数据集配置。
    """
    names = [s.strip() for s in seed_names.split(",") if s.strip()]

    if len(names) <= 1:
        # 单种子文件: 使用简单 DatasetAttackConfiguration
        name = names[0] if names else "elite_jailbreaks"
        seed_path = _SEEDS_DIR / f"{name}.prompt"
        if not seed_path.exists():
            logger.warning("Seed file not found: %s", seed_path)
            return None

        try:
            from pyrit.models import SeedPrompt
            from pyrit.scenario import DatasetAttackConfiguration

            seed_prompt = SeedPrompt.from_yaml_file(seed_path)
            seeds = seed_prompt.values if hasattr(seed_prompt, "values") else [seed_prompt]
            return DatasetAttackConfiguration(
                seeds=seeds,
                max_dataset_size=max_seeds,
            )
        except Exception as e:
            logger.warning("Failed to build simple dataset config: %s", e)
            return None

    # 多种子文件: 使用 CompoundDatasetAttackConfiguration
    return build_compound_dataset_config(seed_names, max_seeds)
