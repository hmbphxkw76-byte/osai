"""PyRIT 鍘熺敓 CompoundDatasetAttackConfiguration 鈥?澶氭暟鎹泦澶嶅悎鏀诲嚮缂栨帓銆?

瀛︽湳渚濇嵁:
    - PyRIT (arXiv:2407.01232) 鈥?Microsoft, 鍘熺敓 Scenario + Dataset 绯荤粺
    - CompoundDatasetAttackConfiguration: 姣忎釜瀛愰厤缃嫭绔嬭В鏋愩€侀噰鏍枫€侀獙璇?
      鍚堝苟鍚庡彲杩愯棰濆楠岃瘉鍣? 鏀寔姣忕被鍒嫭绔嬮绠?

PyRIT 鍘熺敓浼樺娍 (Rule 2: 鍘熺敓浼樺厛):
    - 鐙珛棰勭畻: 姣忎釜 OWASP 绫诲埆鏈夌嫭绔?max_dataset_size, 绮剧‘鎺у埗姣忎釜绫诲埆鏀诲嚮鏁伴噺
    - 鐙珛杩囨护: 姣忎釜瀛愰厤缃彲鎼哄甫涓嶅悓 filters (濡?{"harm_categories": ["cyber"]})
    - 鍚堝苟楠岃瘉: 鍚堝苟鍚庤繍琛岄澶栭獙璇佸櫒, 纭繚鏁版嵁闆嗙粍鍚堟弧瓒崇害鏉?
    - 鑷姩閲囨牱: 鏃犻渶鎵嬪姩绉嶅瓙鎺掑簭/鎴柇, PyRIT 鍘熺敓閲囨牱鏃犳浛鎹?

    褰撳墠椤圭洰鐨?seed_ranker.py (ASR 鎺掑簭) 鏄寮哄眰,
    鏈ā鍧椾綔涓?PyRIT 鍘熺敓鏁版嵁闆嗙紪鎺掔殑鑳舵按灞? 涓嶆浛鎹?seed_ranker,
    鑰屾槸鍦?TextAdaptive 鍦烘櫙涓娇鐢ㄥ師鐢熺紪鎺掋€?
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
    """鏋勫缓 PyRIT 鍘熺敓 CompoundDatasetAttackConfiguration銆?

    灏嗛」鐩瀛愭枃浠?(data/seeds/*.prompt) 娉ㄥ唽涓?PyRIT Memory 涓殑鍛藉悕鏁版嵁闆?
    鐒跺悗浣跨敤 CompoundDatasetAttackConfiguration 缂栨帓澶氫釜鏁版嵁闆嗙殑澶嶅悎鏀诲嚮銆?

    姣忎釜瀛愰厤缃嫭绔嬮噰鏍? 纭繚姣忎釜绉嶅瓙鏂囦欢鐨勭瀛愭暟閲忓潎琛¤鐩栥€?

    Args:
        seed_names: 閫楀彿鍒嗛殧鐨勭瀛愭枃浠跺悕 (濡?"elite_jailbreaks,asi_top10")銆?
        max_seeds: 鍏ㄥ眬绉嶅瓙涓婇檺銆?

    Returns:
        CompoundDatasetAttackConfiguration 瀹炰緥, 鎴?None (鏋勫缓澶辫触鏃?銆?
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

    # 姣忎釜瀛愭暟鎹泦鐙珛棰勭畻: 鍧囧垎 max_seeds
    per_dataset_size = max(1, max_seeds // len(names))

    # 鏋勫缓瀛愰厤缃垪琛?鈥?浣跨敤 inline seeds (涓嶄緷璧?Memory 娉ㄥ唽)
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
    """鏋勫缓 TextAdaptive 鍦烘櫙涓撶敤鏁版嵁闆嗛厤缃€?

    TextAdaptive 鍦烘櫙闇€瑕?DatasetAttackConfiguration 浣滀负杈撳叆,
    鏈嚱鏁拌繑鍥?CompoundDatasetAttackConfiguration 鎴栫畝鍗?
    DatasetAttackConfiguration (鍗曠瀛愭枃浠舵椂)銆?

    Args:
        seed_names: 閫楀彿鍒嗛殧鐨勭瀛愭枃浠跺悕銆?
        max_seeds: 鍏ㄥ眬绉嶅瓙涓婇檺銆?

    Returns:
        DatasetAttackConfiguration 瀹炰緥, 鎴?None (鏋勫缓澶辫触鏃?銆?
    """
    names = [s.strip() for s in seed_names.split(",") if s.strip()]

    if len(names) <= 1:
        # 鍗曠瀛愭枃浠? 浣跨敤绠€鍗?DatasetAttackConfiguration
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

    # 澶氱瀛愭枃浠? 浣跨敤 CompoundDatasetAttackConfiguration
    return build_compound_dataset_config(seed_names, max_seeds)

