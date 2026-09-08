"""PyRIT CompoundDatasetAttackConfiguration ?X?

[:
    - PyRIT (arXiv:2407.01232) ?Microsoft,  Scenario + Dataset
    - CompoundDatasetAttackConfiguration: XBEUREUR?
      XX? XXX?

PyRIT  (Rule 2: ):
    - X:  OWASP ?max_dataset_size, 'u
    - X: X filters (?{"harm_categories": ["cyber"]})
    - : X, X?
    - X: /X, PyRIT ?

    ?seed_ranker.py (ASR ) XX,
    Xa?PyRIT ? ?seed_ranker,
    ?TextAdaptive XengEUR?
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SEEDS_DIR = Path(__file__).resolve().parent.parent / "data" / "seeds"

def build_compound_dataset_config(
    seed_names: str,
    max_seeds: int = 25,
) -> Any | None:
    """ PyRIT CompoundDatasetAttackConfiguration?

    XX?(data/seeds/*.prompt) eng?PyRIT Memory X?
     CompoundDatasetAttackConfiguration ?

    X? XXXXEUR?

    Args:
        seed_names: X (?"elite_jailbreaks,asi_top10")?
        max_seeds: eng?

    Returns:
        CompoundDatasetAttackConfiguration , ?None (??
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

 # XX: max_seeds
    per_dataset_size = max(1, max_seeds // len(names))

 # X?? inline seeds (?Memory eng)
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
    """ TextAdaptive XEUR?

    TextAdaptive EUR?DatasetAttackConfiguration ,
    X?CompoundDatasetAttackConfiguration ?
    DatasetAttackConfiguration (X)?

    Args:
        seed_names: X?
        max_seeds: eng?

    Returns:
        DatasetAttackConfiguration , ?None (??
    """
    names = [s.strip() for s in seed_names.split(",") if s.strip()]

    if len(names) <= 1:
     # X? EUR?DatasetAttackConfiguration
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

 # X? CompoundDatasetAttackConfiguration
    return build_compound_dataset_config(seed_names, max_seeds)
