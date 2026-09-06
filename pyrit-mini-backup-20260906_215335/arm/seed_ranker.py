"""Seed loading + ASR ranking.

Load PyRIT native SeedPrompt YAML format seed files, rank by historical ASR.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from pyrit.models import AttackSeedGroup, SeedObjective

from arm.seed_auto_expander import (  # noqa: F401 — re-exports for main.py
    _auto_generate_seeds_sync,
    _compute_adaptive_ucb_c,
    auto_generate_seeds,
    auto_generate_seeds_async,
)
from arm.seed_ranking import (  # noqa: F401 — re-exports for main.py
    _ASR_HISTORY_PATH,
    _ASR_PRIORS_PATH,
    _SEEDS_DIR,
    _apply_category_diversity,
    _make_seed_key,
    _rank_by_asr,
    get_technique_asr_prior,
    load_asr_priors,
    rank_seeds_for_multi_turn,
    update_asr_history,
    update_asr_priors,
)

logger = logging.getLogger(__name__)


# Capability → seed file mapping
# When deep probing detects specific capabilities, auto-augment targeted seed files
# v2 (2026-09-01): Adapted for directory restructuring, supports subdirectory recursive loading
CAPABILITY_SEED_MAP: dict[str, list[str]] = {
    # MCP attacks — full surface coverage in subdirectory
    "mcp": [
        "_attack_surface/T1_ASI02_mcp_full_surface/mcp_tool_enum",
        "_attack_surface/T1_ASI02_mcp_full_surface/mcp_server_injection",
        "_attack_surface/T1_ASI02_mcp_full_surface/mcp_tool_hijack",
    ],
    "mcp_protocol": [
        "_attack_surface/T1_ASI02_mcp_full_surface/mcp_tool_enum",
        "_attack_surface/T1_ASI02_mcp_full_surface/mcp_server_injection",
    ],
    # RAG attacks
    "rag": ["_attack_surface/T1_LLM08_rag_full_surface/rag_full_attack_surface"],
    # Function calling
    "function_calling": ["_core/T1_ASI02_function_call_exploit"],
    # Tool hijack
    "tool_hijack": ["_core/T1_ASI02_tool_hijack"],
    # Multi-agent attacks — full surface coverage
    "multi_agent": [
        "_attack_surface/T1_ASI06-09_multi_agent/ma_cross_agent_injection",
        "_attack_surface/T1_ASI06-09_multi_agent/ma_identity_spoofing",
    ],
    # Workflow
    "workflow": ["_core/T1_ASI03_workflow_escalation"],
    # Session auth
    "session_auth": ["_core/T1_ASI09_session_auth_bypass"],
    # Token smuggling / memory
    "memory": ["_encoding_evasion/T1_LLM01_token_smuggling_evasion"],
    # Multi-tenant — tenant privilege escalation
    "multi_tenant": ["_core/T1_ASI09_session_auth_bypass"],
    # A2A protocol
    "a2a_protocol": [
        "_attack_surface/T1_ASI06-09_multi_agent/ma_cross_agent_injection",
        "_core/T1_ASI02_tool_hijack",
    ],
    "a2a": [
        "_attack_surface/T1_ASI06-09_multi_agent/ma_cross_agent_injection",
        "_core/T1_ASI02_tool_hijack",
    ],
    # Embedding RAG
    "embedding_rag": ["_attack_surface/T1_LLM08_rag_full_surface/rag_full_attack_surface"],
}


def load_seeds(
    seed_file: str,
    max_seeds: int = 10,
    target_language: str | None = None,
    enable_dos: bool = False,
    capabilities: str | None = None,
    model_family: str | None = None,
    seed_filters: dict[str, str] | None = None,
    model_priors: dict[str, Any] | None = None,
) -> list[AttackSeedGroup]:
    """Load selected seed files.

    Seed file format: PyRIT native SeedPrompt YAML (.prompt)
    Each seed contains:
        - value: attack prompt text
        - metadata: {owasp_id, difficulty, severity, category, language}

    L5 v8: Supports comma-separated seed file loading.
    Example: "elite_jailbreaks,asi_top10,zh_curated" merges 3 files.

    Loaded seeds are ranked by historical ASR:
        1. Read data/seeds/asr_history.json
        2. Seeds with historical ASR ranked by ASR descending
        3. Seeds without historical ASR maintain original order
        4. Truncate to max_seeds

    Language adaptation:
        - If target_language="zh", prioritize Chinese seeds (language: zh)
        - If target_language="en" or None, prioritize English seeds
        - Mixed mode: 70% target language + 30% other languages (ensure coverage)

    DoS attack filtering:
        - enable_dos=False (default): filter seeds with owasp_id=LLM10
        - enable_dos=True: keep LLM10 seeds
        - Rationale: LLM10 (Model DoS / Unbounded Consumption) attacks
          generate extremely large responses, consuming significant tokens;
          disabled by default to control costs.

    Capability adaptation (fixed #1):
        - When capabilities is non-empty, auto-augment targeted seed files
          per CAPABILITY_SEED_MAP (e.g., if MCP detected → augment mcp_attack)
        - Augmented seed files are deduplicated (no duplicate loading).

    Args:
        seed_file: Seed file name(s) (without extension, auto-adds .prompt).
                   Supports comma-separated list.
        max_seeds: Maximum number of seeds.
        target_language: Target language ("zh" or "en", None=auto).
        enable_dos: Whether to keep LLM10 DoS attack seeds
                    (default False, disabled).
        capabilities: Target capability tags (comma-separated,
                      e.g., "mcp,rag,function_calling").
        model_family: Target model family (e.g., "gpt-4", "claude-3",
                      reserved parameter for future extension).

    Returns:
        list[AttackSeedGroup]: Ranked list of attack seed groups.
    """
    # L5 v8: Comma-separated seed files
    seed_files = [s.strip() for s in seed_file.split(",") if s.strip()]
    if not seed_files:
        seed_files = [seed_file]

    # Fixed #1: Auto-augment targeted seed files based on capability tags
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
        # v3: Support directory scanning (e.g., "_core/" scans entire directory)
        # Detect directory by trailing slash or by path existence
        sf_clean = sf.rstrip("/\\")
        sf_dir = _SEEDS_DIR / sf_clean
        if sf_dir.is_dir():
            # Scan directory for .prompt and .yaml files recursively
            dir_files = sorted(sf_dir.rglob("*.prompt")) + sorted(sf_dir.rglob("*.yaml"))
            if not dir_files:
                logger.warning("No seed files found in directory: %s, skipping", sf)
                continue
            logger.info("Directory scan: %s → %d seed files found", sf, len(dir_files))
            for dir_file in dir_files:
                import yaml
                data = yaml.safe_load(dir_file.read_text(encoding="utf-8"))
                if not isinstance(data, list):
                    logger.warning("Invalid seed file format for %s: expected list, skipping", dir_file.name)
                    continue
                all_raw_seeds.extend(data)
                loaded_files.append(str(dir_file.relative_to(_SEEDS_DIR)))
            continue

        # v2: Support subdirectory paths (e.g., "_core/T1_LLM01_elite_jailbreaks")
        # Check if path already has extension before adding .prompt
        if sf.endswith(".prompt") or sf.endswith(".yaml"):
            file_path = _SEEDS_DIR / sf
        else:
            file_path = _SEEDS_DIR / f"{sf}.prompt"
        if not file_path.exists():
            file_path = _SEEDS_DIR / f"{sf}.yaml"
            if not file_path.exists():
                # Try as direct path (backward compatibility)
                alt_path = Path(sf)
                if alt_path.exists():
                    file_path = alt_path
                else:
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

    # DoS attack filtering: Disable LLM10 seeds by default (high token consumption)
    if not enable_dos:
        before_count = len(all_raw_seeds)
        all_raw_seeds = _filter_dos_seeds(all_raw_seeds)
        filtered_count = before_count - len(all_raw_seeds)
        if filtered_count > 0:
            logger.info(
                "DoS attack disabled: filtered %d LLM10 seeds (use --enable-dos to include)",
                filtered_count,
            )

    # Language-adaptive filtering
    if target_language:
        all_raw_seeds = _filter_by_language(all_raw_seeds, target_language)
        logger.info("Language-adaptive filtering: target=%s, %d seeds after filter", target_language, len(all_raw_seeds))

    # Incremental: Seed metadata filtering (--seed-filters KEY=VALUE)
    # Borrowed from pyrit_scan's --seed-filters: Precise seed filtering by metadata KEY=VALUE
    # Example: {"owasp_id": "LLM01", "difficulty": "high"} → retain only matching seeds
    # Multiple KEYs are AND relationship (must match all keys)
    # Supports metadata values as lists (e.g., category: ["attack", "jailbreak"])
    if seed_filters:
        all_raw_seeds = _filter_by_metadata(all_raw_seeds, seed_filters)
        logger.info(
            "Seed metadata filtering: filters=%s, %d seeds after filter",
            seed_filters,
            len(all_raw_seeds),
        )

    # Build AttackSeedGroup
    seed_groups = _build_seed_groups(all_raw_seeds)

    # Rank by ASR
    asr_history = _load_asr_history()

    # Fix: Use model_family to load ASR priors and merge into asr_history
    # Academic basis: Chao et al. (arXiv:2402.01135) — Cross-model ASR transfer
    #   Different model families have different safety strategies;
    #   model-specific ASR priors can improve seed ranking accuracy
    # Data flow: recon (model_identity probe) → target_fingerprint["model_family"]
    #           → load_seeds (model_family) → load_asr_priors → asr_history merge
    if model_family:
        priors = load_asr_priors(model_family)
        if priors:
            # Merge technique_seed_asr model-specific ASR into asr_history
            # If asr_history has no historical record for a seed,
            # use prior ASR as initial value
            _model_lower = model_family.lower()
            _tech_seed_asr = priors.get("technique_seed_asr", {})
            for tech_name, owasp_asr in _tech_seed_asr.items():
                if isinstance(owasp_asr, dict):
                    for owasp_id, asr_val in owasp_asr.items():
                        if owasp_id == "default":
                            continue
                        if owasp_id.lower() in _model_lower or _model_lower in owasp_id.lower():
                            # Found model-specific ASR prior
                            _seed_key = f"{tech_name}:{owasp_id}"
                            if _seed_key not in asr_history:
                                asr_history[_seed_key] = float(asr_val)
            logger.info(
                "Model-specific ASR priors loaded for model_family=%s "
                "(asr_history entries: %d)",
                model_family,
                len(asr_history),
            )

    seed_groups = _rank_by_asr(seed_groups, asr_history)

    # Seed dynamic pruning: Auto-prune 0% ASR seeds (efficiency optimization)
    # Academic basis:
    #   - Auer et al. (arXiv:cs/0207052) UCB1 — Known 0% ASR seeds should be deprioritized
    #   - Chao et al. (arXiv:2402.01135) — Seed quality directly affects ASR,
    #     low-efficiency seeds waste tokens
    #   - Liu et al. (arXiv:2310.04451) AutoDAN — Pruning low-efficiency seeds improves overall ASR
    # Strategy:
    #   1. Read seed_asr in asr_history.json
    #   2. Auto-prune seeds with 3+ attempts AND ASR=0%
    #   3. Retain new seeds (no historical record) as exploratory effective seeds
    #   4. Each OWASP category retains at least 1 seed (category coverage guarantee)
    #   5. Pruning ratio does not exceed 50% (avoid over-pruning)
    seed_groups = _prune_zero_asr_seeds(seed_groups, max_seeds)

    # L5 v32: Category Diversity Guarantee
    # Academic basis: Determinantal Point Processes (DPP) for diverse subset selection
    #   Kulesza & Taskar (arXiv:1207.6083) — Ensures selected seeds cover different OWASP categories
    # Strategy: Each owasp_id gets at least 1 seed in selection,
    #           remaining slots filled by UCB ranking
    seed_groups = _apply_category_diversity(seed_groups, max_seeds)

    logger.info("Loaded %d seeds from %s (max=%d, files=%d)", len(seed_groups), seed_file, max_seeds, len(loaded_files))
    return seed_groups


def _filter_dos_seeds(seeds: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter LLM10 (DoS / Unbounded Consumption) seeds.

    LLM10 attacks (Model DoS / Unbounded Consumption) force target to generate
    extremely large responses (e.g., "generate 100 stories of 5000 characters"),
    consuming significant tokens.
    Disabled by default to control API costs;
    users can explicitly enable via --enable-dos.

    Identification condition: metadata.owasp_id == "LLM10" (case-insensitive)

    Args:
        seeds: Original seed list.

    Returns:
        Filtered seed list (without LLM10 seeds).
    """
    return [
        seed for seed in seeds
        if str(seed.get("metadata", {}).get("owasp_id", "")).upper() != "LLM10"
    ]


def _prune_zero_asr_seeds(
    seed_groups: list[AttackSeedGroup],
    max_seeds: int,
) -> list[AttackSeedGroup]:
    """Auto-prune 0% ASR seeds (efficiency optimization).

    Academic basis:
        - Auer et al. (arXiv:cs/0207052) UCB1 — Known 0% ASR seeds should be deprioritized
        - Chao et al. (arXiv:2402.01135) — Seed quality directly affects ASR
        - Liu et al. (arXiv:2310.04451) AutoDAN — Pruning low-efficiency seeds improves overall ASR

    Strategy:
        1. Read seed_asr and seed_attempts in asr_history.json
        2. Auto-prune seeds with 3+ attempts AND ASR=0%
        3. Retain new seeds (no historical record) as exploratory effective seeds
        4. Each OWASP category retains at least 1 seed (category coverage guarantee)
        5. Pruning ratio does not exceed 50% (avoid over-pruning)

    Args:
        seed_groups: Ranked seed group list.
        max_seeds: Maximum number of seeds.

    Returns:
        Pruned seed group list.
    """
    import json

    # Load seed-level ASR history
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

    # Minimum attempt threshold: 3+ attempts before pruning (statistically significant)
    _MIN_ATTEMPTS_FOR_PRUNE = 3
    # Maximum prune ratio: 50% (avoid over-pruning)
    _MAX_PRUNE_RATIO = 0.5

    # Mark each seed for pruning eligibility
    prune_indices: set[int] = set()
    for i, group in enumerate(seed_groups):
        objective_text = ""
        if group.seeds:
            obj = next((s for s in group.seeds if hasattr(s, "value")), None)
            if obj:
                objective_text = _make_seed_key(obj.value)

        asr = seed_asr.get(objective_text, -1.0)  # -1 = no history (new seed)
        attempts = seed_attempts.get(objective_text, 0)

        # 3+ attempts AND ASR=0% → Mark for pruning
        if asr == 0.0 and attempts >= _MIN_ATTEMPTS_FOR_PRUNE:
            prune_indices.add(i)
            logger.debug(
                "L5 v40: Pruning zero-ASR seed '%s...' (attempts=%d, ASR=0%%)",
                objective_text[:40], attempts,
            )

    if not prune_indices:
        logger.debug("L5 v40: No zero-ASR seeds to prune")
        return seed_groups

    # Limit pruning ratio to no more than 50%
    max_prune = int(len(seed_groups) * _MAX_PRUNE_RATIO)
    if len(prune_indices) > max_prune:
        # Preserve top max_prune by attempts descending (prune high-attempt seeds first)
        prune_candidates: list[tuple[int, int]] = []  # (index, attempts)
        for i in prune_indices:
            obj_text = ""
            if seed_groups[i].seeds:
                obj = next((s for s in seed_groups[i].seeds if hasattr(s, "value")), None)
                if obj:
                    obj_text = _make_seed_key(obj.value)
            att = seed_attempts.get(obj_text, 0)
            prune_candidates.append((i, att))
        prune_candidates.sort(key=lambda x: -x[1])  # attempts descending
        prune_indices = {c[0] for c in prune_candidates[:max_prune]}

    # Preserve at least 1 seed per OWASP category
    # Even ASR=0%, if it's the only seed in its category, retain it
    category_counts: dict[str, int] = {}
    for group in seed_groups:
        owasp_id = "UNCATEGORIZED"
        if group.seeds:
            obj = next((s for s in group.seeds if hasattr(s, "value")), None)
            if obj:
                meta = getattr(obj, "metadata", {}) or {}
                owasp_id = str(meta.get("owasp_id", "UNCATEGORIZED")).upper()
        category_counts[owasp_id] = category_counts.get(owasp_id, 0) + 1

    # Remove "category-only seed" from prune list
    to_remove_from_prune: set[int] = set()
    for i in prune_indices:
        owasp_id = "UNCATEGORIZED"
        if seed_groups[i].seeds:
            obj = next((s for s in seed_groups[i].seeds if hasattr(s, "value")), None)
            if obj:
                meta = getattr(obj, "metadata", {}) or {}
                owasp_id = str(meta.get("owasp_id", "UNCATEGORIZED")).upper()
        # If this category has only 1 seed (this one), retain
        if category_counts.get(owasp_id, 0) <= 1:
            to_remove_from_prune.add(i)
    prune_indices -= to_remove_from_prune

    # Execute pruning
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
    """Filter seeds by target language (70% target + 30% other).

    Args:
        seeds: Original seed list.
        target_language: Target language ("zh" or "en").

    Returns:
        Filtered seed list.
    """
    target_lang_code = target_language.lower()[:2]  # "zh" or "en"

    target_seeds: list[dict[str, Any]] = []
    other_seeds: list[dict[str, Any]] = []

    for seed in seeds:
        metadata = seed.get("metadata", {})
        seed_lang = metadata.get("language", "en")  # Default English

        if seed_lang.lower().startswith(target_lang_code):
            target_seeds.append(seed)
        else:
            other_seeds.append(seed)

    if not target_seeds:
        # No target language seeds, use all
        logger.warning("No seeds found for language=%s, using all seeds", target_language)
        return seeds

    # 70% target language + 30% other languages
    target_count = int(len(target_seeds) * 0.7) + 1
    other_count = int(len(other_seeds) * 0.3) + 1 if other_seeds else 0

    result = target_seeds[:target_count] + other_seeds[:other_count]
    return result


def _filter_by_metadata(
    seeds: list[dict[str, Any]],
    filters: dict[str, str],
) -> list[dict[str, Any]]:
    """Precise seed filtering by metadata KEY=VALUE.

    Incremental borrow from pyrit_scan's --seed-filters CLI pattern.

    Filtering logic:
        - Multiple KEYs are AND relationship (must match all keys)
        - Value matching is case-insensitive substring match
          (e.g., "LLM01" matches "LLM01: Injection")
        - Supports metadata values as lists (e.g., category: ["attack", "jailbreak"])
          Any matching element in list counts as match

    Args:
        seeds: Original seed list.
        filters: {KEY: VALUE} filter conditions.

    Returns:
        Filtered seed list.
    """
    if not filters:
        return seeds

    filtered: list[dict[str, Any]] = []
    for seed in seeds:
        metadata = seed.get("metadata", {})
        if not isinstance(metadata, dict):
            continue

        match_all = True
        for filter_key, filter_val in filters.items():
            seed_val = metadata.get(filter_key)
            if seed_val is None:
                match_all = False
                break

            # List value: Any element match
            if isinstance(seed_val, list):
                found = any(
                    filter_val.lower() in str(v).lower()
                    for v in seed_val
                )
                if not found:
                    match_all = False
                    break
            else:
                # Scalar value: Case-insensitive substring matching
                if filter_val.lower() not in str(seed_val).lower():
                    match_all = False
                    break

        if match_all:
            filtered.append(seed)

    # If filtered result is empty, return original list (avoid no-attack)
    if not filtered:
        logger.warning(
            "Seed metadata filter %s matched 0 seeds, returning all %d seeds",
            filters,
            len(seeds),
        )
        return seeds

    return filtered


def _build_seed_groups(raw_seeds: list[dict[str, Any]]) -> list[AttackSeedGroup]:
    """Build AttackSeedGroup list from YAML data.

    Inject seed metadata (owasp_id, severity, category etc.) into
    SeedObjective's metadata field, allowing subsequent AttackExecutor
    to pass it to AttackResult.metadata.

    Note: AttackSeedGroup.seeds can only contain SeedObjective,
    not SeedPrompt (SeedPrompt would be treated as pre-attack seed by PyRIT, causing duplication).
    """
    groups: list[AttackSeedGroup] = []
    for item in raw_seeds:
        value = item.get("value", "")
        metadata = item.get("metadata", {})

        # Inject metadata into SeedObjective (for subsequent passing to AttackResult)
        objective = SeedObjective(
            value=value,
            harm_categories=[metadata.get("category", "general")],
            metadata=metadata,
        )
        group = AttackSeedGroup(seeds=[objective])
        groups.append(group)

    return groups


def _load_asr_history() -> dict[str, float]:
    """Load ASR history file."""
    if not _ASR_HISTORY_PATH.exists():
        return {}
    try:
        data = json.loads(_ASR_HISTORY_PATH.read_text(encoding="utf-8"))
        return data.get("asr", {})
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning("Failed to load ASR history: %s", e)
        return {}


# ── L5 v13: ASR priors + MTOS selection — kept in seed_ranking.py — ──
