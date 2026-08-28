"""PyRIT 原生 CompoundDatasetAttackConfiguration — 多数据集复合攻击编排。

学术依据:
    - PyRIT (arXiv:2407.01232) — Microsoft, 原生 Scenario + Dataset 系统
    - CompoundDatasetAttackConfiguration: 每个子配置独立解析、采样、验证,
      合并后可运行额外验证器, 支持每类别独立预算

PyRIT 原生优势 (Rule 2: 原生优先):
    - 独立预算: 每个 OWASP 类别有独立 max_dataset_size, 精确控制每个类别攻击数量
    - 独立过滤: 每个子配置可携带不同 filters (如 {"harm_categories": ["cyber"]})
    - 合并验证: 合并后运行额外验证器, 确保数据集组合满足约束
    - 自动采样: 无需手动种子排序/截断, PyRIT 原生采样无替换

    当前项目的 seed_ranker.py (ASR 排序) 是增强层,
    本模块作为 PyRIT 原生数据集编排的胶水层, 不替换 seed_ranker,
    而是在 TextAdaptive 场景中使用原生编排。
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

    将项目种子文件 (data/seeds/*.prompt) 注册为 PyRIT Memory 中的命名数据集,
    然后使用 CompoundDatasetAttackConfiguration 编排多个数据集的复合攻击。

    每个子配置独立采样, 确保每个种子文件的种子数量均衡覆盖。

    Args:
        seed_names: 逗号分隔的种子文件名 (如 "elite_jailbreaks,asi_top10")。
        max_seeds: 全局种子上限。

    Returns:
        CompoundDatasetAttackConfiguration 实例, 或 None (构建失败时)。
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

    TextAdaptive 场景需要 DatasetAttackConfiguration 作为输入,
    本函数返回 CompoundDatasetAttackConfiguration 或简单
    DatasetAttackConfiguration (单种子文件时)。

    Args:
        seed_names: 逗号分隔的种子文件名。
        max_seeds: 全局种子上限。

    Returns:
        DatasetAttackConfiguration 实例, 或 None (构建失败时)。
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
