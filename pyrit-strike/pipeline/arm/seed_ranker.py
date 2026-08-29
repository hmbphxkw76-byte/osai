"""种子加载 + ASR 排序。
"""

from __future__ import annotations

import json
import logging
from typing import Any

from pyrit.models import AttackSeedGroup, SeedObjective

from pipeline.arm.seed_auto_expander import (  # noqa: F401 — re-exports for main.py
    _auto_generate_seeds_sync,
    _compute_adaptive_ucb_c,
    auto_generate_seeds,
    auto_generate_seeds_async,
)
from pipeline.arm.seed_ranking import (  # noqa: F401 — re-exports for main.py
    _ASR_HISTORY_PATH,
    _ASR_PRIORS_PATH,
    _SEEDS_DIR,
    _apply_category_diversity,
    _rank_by_asr,
    get_technique_asr_prior,
    load_asr_priors,
    rank_seeds_for_multi_turn,
    update_asr_history,
    update_asr_priors,
)

logger = logging.getLogger(__name__)

# 能力→种子文件映射
# 当深度探测检测到特定能力时, 自动追加定向种子文件
CAPABILITY_SEED_MAP: dict[str, list[str]] = {
    "mcp": ["mcp_attack"],
    "rag": ["rag_attack"],
    "function_calling": ["function_call_exploit"],
    "tool_hijack": ["tool_hijack"],
    "multi_agent": ["multi_agent_attack"],
    "workflow": ["workflow_chain_attack"],
    "session_auth": ["session_auth_attack"],
    "memory": ["token_smuggling"],
    "a2a": ["multi_agent_attack", "tool_hijack"],
}

def load_seeds(
    seed_file: str,
    max_seeds: int = 10,
    target_language: str | None = None,
    enable_dos: bool = False,
    capabilities: str | None = None,
    model_family: str | None = None,
) -> list[AttackSeedGroup]:
    """加载精选种子文件。
    """
    # L5 v8: 支持逗号分隔的多种子文件
    seed_files = [s.strip() for s in seed_file.split(",") if s.strip()]
    if not seed_files:
        seed_files = [seed_file]

    # 断点 #1 修复: 基于能力指纹自动追加定向种子文件
    added_by_capability: list[str] = []
    if capabilities:
        cap_list = [c.strip().lower() for c in capabilities.split(",") if c.strip()]
        for cap in cap_list:
            mapped_seeds = CAPABILITY_SEED_MAP.get(cap, [])
            for ms in mapped_seeds:
                if ms not in seed_files:
                    seed_files.append(ms)
                    added_by_capability.append(ms)
        if added_by_capability:
            logger.info(
                "Capability-adaptive seed augmentation: %s (from capabilities=%s)",
                added_by_capability,
                cap_list,
            )

    all_raw_seeds: list[dict[str, Any]] = []
    loaded_files: list[str] = []

    for sf in seed_files:
        file_path = _SEEDS_DIR / f"{sf}.prompt"
        if not file_path.exists():
            file_path = _SEEDS_DIR / f"{sf}.yaml"
            if not file_path.exists():
                logger.warning("Seed file not found: %s, skipping", sf)
                continue

        import yaml

        data = yaml.safe_load(file_path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            logger.warning("Invalid seed file format for %s: expected list, skipping", sf)
            continue

        all_raw_seeds.extend(data)
        loaded_files.append(sf)
        logger.info("Loaded %d seeds from %s", len(data), sf)

    if not all_raw_seeds:
        raise FileNotFoundError(f"No seed files found from: {seed_file}")

    logger.info("Total seeds loaded from %d files: %d", len(loaded_files), len(all_raw_seeds))

    # DoS 攻击过滤: 默认禁用 LLM10 种子 (消耗大量 token)
    if not enable_dos:
        before_count = len(all_raw_seeds)
        all_raw_seeds = _filter_dos_seeds(all_raw_seeds)
        filtered_count = before_count - len(all_raw_seeds)
        if filtered_count > 0:
            logger.info(
                "DoS attack disabled: filtered %d LLM10 seeds (use --enable-dos to include)",
                filtered_count,
            )

    # 语言自适应筛选
    if target_language:
        all_raw_seeds = _filter_by_language(all_raw_seeds, target_language)
        logger.info("Language-adaptive filtering: target=%s, %d seeds after filter", target_language, len(all_raw_seeds))

    # 构建 AttackSeedGroup
    seed_groups = _build_seed_groups(all_raw_seeds)

    # 按 ASR 排序
    asr_history = _load_asr_history()
    seed_groups = _rank_by_asr(seed_groups, asr_history)

    # 种子动态裁剪 — 自动剔除 0% ASR 种子 (效率优化)
    #   - Auer et al. (arXiv:cs/0207052) UCB1 — 已知 0% ASR 种子应降低优先级
    #   - Chao et al. (arXiv:2402.01135) — 种子质量直接影响 ASR, 低效种子浪费 token
    #   - Liu et al. (arXiv:2310.04451) AutoDAN — 裁剪低效种子提升整体 ASR
    # 策略:
    #   1. 读取 asr_history.json 中的 seed_asr
    #   2. 有 3+ 次尝试且 ASR=0% 的种子自动剔除
    #   3. 保留新种子 (无历史记录) 以探索潜在有效种子
    #   4. 每个 OWASP 类别至少保留 1 个种子 (类别覆盖保障)
    #   5. 裁剪比例不超过 50% (避免过度裁剪)
    seed_groups = _prune_zero_asr_seeds(seed_groups, max_seeds)

    # L5 v32: 类别多样性保障 (Category Diversity Guarantee)
    #   Kulesza & Taskar (arXiv:1207.6083) — 确保选中的种子覆盖不同 OWASP 类别
    # 策略: 每个 owasp_id 至少 1 个种子入选, 剩余名额按 UCB 排序填充
    seed_groups = _apply_category_diversity(seed_groups, max_seeds)

    logger.info("Loaded %d seeds from %s (max=%d, files=%d)", len(seed_groups), seed_file, max_seeds, len(loaded_files))
    return seed_groups

def _filter_dos_seeds(seeds: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """过滤 LLM10 (DoS / Unbounded Consumption) 种子。
    """
    return [
        seed for seed in seeds
        if str(seed.get("metadata", {}).get("owasp_id", "")).upper() != "LLM10"
    ]

def _prune_zero_asr_seeds(
    seed_groups: list[AttackSeedGroup],
    max_seeds: int,
) -> list[AttackSeedGroup]:
    """自动剔除 0% ASR 种子 (效率优化).
    """
    import json

    # 加载种子级 ASR 历史
    seed_asr: dict[str, float] = {}
    seed_attempts: dict[str, int] = {}
    if _ASR_HISTORY_PATH.exists():
        try:
            data = json.loads(_ASR_HISTORY_PATH.read_text(encoding="utf-8"))
            seed_asr = data.get("seed_asr", {})
            seed_attempts = data.get("seed_attempts", {})
        except (json.JSONDecodeError, KeyError):
            pass

    if not seed_asr:
        logger.debug("L5 v40: No seed ASR history, skipping zero-ASR pruning")
        return seed_groups

    # 最小裁剪阈值: 3 次尝试以上才裁剪 (统计显著性)
    _MIN_ATTEMPTS_FOR_PRUNE = 3
    # 最大裁剪比例: 50% (避免过度裁剪)
    _MAX_PRUNE_RATIO = 0.5

    # 标记每个种子是否应被裁剪
    prune_indices: set[int] = set()
    for i, group in enumerate(seed_groups):
        objective_text = ""
        if group.seeds:
            obj = next((s for s in group.seeds if hasattr(s, "value")), None)
            if obj:
                objective_text = obj.value[:100]

        asr = seed_asr.get(objective_text, -1.0)  # -1 = 无历史 (新种子)
        attempts = seed_attempts.get(objective_text, 0)

        # 有 3+ 次尝试且 ASR=0% → 标记裁剪
        if asr == 0.0 and attempts >= _MIN_ATTEMPTS_FOR_PRUNE:
            prune_indices.add(i)
            logger.debug(
                "L5 v40: Pruning zero-ASR seed '%s...' (attempts=%d, ASR=0%%)",
                objective_text[:40], attempts,
            )

    if not prune_indices:
        logger.debug("L5 v40: No zero-ASR seeds to prune")
        return seed_groups

    # 限制裁剪比例不超过 50%
    max_prune = int(len(seed_groups) * _MAX_PRUNE_RATIO)
    if len(prune_indices) > max_prune:
        # 按 attempts 降序保留前 max_prune 个 (尝试次数多的先裁剪)
        prune_candidates: list[tuple[int, int]] = []  # (index, attempts)
        for i in prune_indices:
            obj_text = ""
            if seed_groups[i].seeds:
                obj = next((s for s in seed_groups[i].seeds if hasattr(s, "value")), None)
                if obj:
                    obj_text = obj.value[:100]
            att = seed_attempts.get(obj_text, 0)
            prune_candidates.append((i, att))
        prune_candidates.sort(key=lambda x: -x[1])  # attempts 降序
        prune_indices = {c[0] for c in prune_candidates[:max_prune]}

    # 保留每个 OWASP 类别至少 1 个种子
    # 即使 ASR=0% 的种子, 如果是该类别唯一种子, 仍保留
    category_counts: dict[str, int] = {}
    for group in seed_groups:
        owasp_id = "UNCATEGORIZED"
        if group.seeds:
            obj = next((s for s in group.seeds if hasattr(s, "value")), None)
            if obj:
                meta = getattr(obj, "metadata", {}) or {}
                owasp_id = str(meta.get("owasp_id", "UNCATEGORIZED")).upper()
        category_counts[owasp_id] = category_counts.get(owasp_id, 0) + 1

    # 从裁剪列表中移除“类别唯一种子”
    to_remove_from_prune: set[int] = set()
    for i in prune_indices:
        owasp_id = "UNCATEGORIZED"
        if seed_groups[i].seeds:
            obj = next((s for s in seed_groups[i].seeds if hasattr(s, "value")), None)
            if obj:
                meta = getattr(obj, "metadata", {}) or {}
                owasp_id = str(meta.get("owasp_id", "UNCATEGORIZED")).upper()
        # 如果该类别只剩 1 个种子 (就是当前这个), 保留
        if category_counts.get(owasp_id, 0) <= 1:
            to_remove_from_prune.add(i)
    prune_indices -= to_remove_from_prune

    # 执行裁剪
    pruned = [g for i, g in enumerate(seed_groups) if i not in prune_indices]
    logger.info(
        "L5 v40: Pruned %d zero-ASR seeds (attempts>=%d, ASR=0%%), %d remaining "
        "(%d categories preserved)",
        len(prune_indices), _MIN_ATTEMPTS_FOR_PRUNE, len(pruned),
        len(category_counts),
    )
    return pruned

def _filter_by_language(
    seeds: list[dict[str, Any]],
    target_language: str,
) -> list[dict[str, Any]]:
    """按目标语言筛选种子 (70% 目标语言 + 30% 其他语言)。
    """
    target_lang_code = target_language.lower()[:2]  # "zh" or "en"

    target_seeds: list[dict[str, Any]] = []
    other_seeds: list[dict[str, Any]] = []

    for seed in seeds:
        metadata = seed.get("metadata", {})
        seed_lang = metadata.get("language", "en")  # 默认英文

        if seed_lang.lower().startswith(target_lang_code):
            target_seeds.append(seed)
        else:
            other_seeds.append(seed)

    if not target_seeds:
        # 没有目标语言种子, 使用全部
        logger.warning("No seeds found for language=%s, using all seeds", target_language)
        return seeds

    # 70% 目标语言 + 30% 其他语言
    target_count = int(len(target_seeds) * 0.7) + 1
    other_count = int(len(other_seeds) * 0.3) + 1 if other_seeds else 0

    result = target_seeds[:target_count] + other_seeds[:other_count]
    return result

def _build_seed_groups(raw_seeds: list[dict[str, Any]]) -> list[AttackSeedGroup]:
    """从 YAML 数据构建 AttackSeedGroup 列表。
    """
    groups: list[AttackSeedGroup] = []
    for item in raw_seeds:
        value = item.get("value", "")
        metadata = item.get("metadata", {})

        # 将 metadata 注入 SeedObjective (用于后续传递到 AttackResult)
        objective = SeedObjective(
            value=value,
            harm_categories=[metadata.get("category", "general")],
            metadata=metadata,
        )
        group = AttackSeedGroup(seeds=[objective])
        groups.append(group)

    return groups

def _load_asr_history() -> dict[str, float]:
    """加载 ASR 历史文件。"""
    if not _ASR_HISTORY_PATH.exists():
        return {}
    try:
        data = json.loads(_ASR_HISTORY_PATH.read_text(encoding="utf-8"))
        return data.get("asr", {})
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning("Failed to load ASR history: %s", e)
        return {}
