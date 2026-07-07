"""
===============================================================================
OffSec AI-300 — 后续攻击推荐引擎
===============================================================================
纯逻辑层：分析攻击结果 → 返回结构化推荐数据。
终端渲染和 Markdown 渲染各自消费同一份数据，消除 DRY。
===============================================================================
"""
from reporting.data import (
    CASE_CATEGORY, CRESCENDO_CATEGORY,
    get_case_category, get_crescendo_category,
    PROBE_FOLLOWUP_MAP,
)


def build_followup_suggestions(results: list) -> dict | None:
    """基于攻击结果生成后续攻击推荐（纯数据，不含渲染逻辑）。

    Args:
        results: 攻击结果列表（每条含 case_id / status / combo_name / mode）

    Returns:
        结构化推荐 dict，供终端和 Markdown 渲染器消费；无可用推荐时返回 None。

        返回结构:
        {
            "probe_followups": [
                {
                    "probe_id": "PROBE_01_...",
                    "combos": ["Roleplay_Jailbreak", ...],
                    "title": "...",
                    "breakthrough": "...",
                    "single": [(描述, case_ids_comma_sep), ...],
                    "probe": [...],
                    "crescendo": [...],
                }, ...
            ],
            "single_diffusions": [
                {"combo": "...", "entries": [{"category": "...", "other_ids": [...]}]}, ...
            ],
            "cresc_diffusions": [
                {"combo": "...", "entries": [{"category": "...", "other_ids": [...]}]}, ...
            ],
            "merged_single_ids": ["case_1", "case_2", ...],
            "merged_crescendo_ids": ["case_3", ...],
        }
    """
    successes = [r for r in results if r.get("status") == "SUCCESS"]
    if not successes:
        return None

    # ── 分类提取 ──
    probe_s = [r for r in successes if r.get("case_id", "").upper().startswith("PROBE_")]
    single_s = [r for r in successes if not r.get("case_id", "").upper().startswith("PROBE_")
                and r.get("mode") != "crescendo"]
    crescendo_s = [r for r in successes if r.get("mode") == "crescendo"]

    # ── PROBE 漏洞分组 ──
    probe_vulns: dict[str, list[str]] = {}
    for r in probe_s:
        if r["case_id"] in PROBE_FOLLOWUP_MAP:
            probe_vulns.setdefault(r["case_id"], []).append(r["combo_name"])

    # ── 单轮分组: (combo, category) → set(case_ids) ──
    single_groups: dict[tuple[str, str], set[str]] = {}
    for r in single_s:
        ci = get_case_category(r["case_id"])
        if ci:
            single_groups.setdefault((r["combo_name"], ci[0]), set()).add(r["case_id"])

    # ── 多轮分组 ──
    cresc_groups: dict[tuple[str, str], set[str]] = {}
    for r in crescendo_s:
        ci = get_crescendo_category(r["case_id"])
        if ci:
            cresc_groups.setdefault((r["combo_name"], ci[0]), set()).add(r["case_id"])

    if not probe_vulns and not single_groups and not cresc_groups:
        return None

    # ═══ PART 1: PROBE 预定义映射 ═══
    probe_followups = []
    for probe_id, combos in probe_vulns.items():
        mapping = PROBE_FOLLOWUP_MAP[probe_id]
        probe_followups.append({
            "probe_id": probe_id,
            "combos": combos,
            "title": mapping["title"],
            "breakthrough": mapping["breakthrough"],
            "single": mapping.get("single", []),
            "probe": mapping.get("probe", []),
            "crescendo": mapping.get("crescendo", []),
        })

    # ═══ PART 2: 单轮突破 — 按手法×领域扩散 ═══
    single_diffusions = []
    by_combo_s: dict[str, list[tuple[str, set[str]]]] = {}
    for (combo, cat), case_set in single_groups.items():
        by_combo_s.setdefault(combo, []).append((cat, case_set))
    for combo, cat_entries in sorted(by_combo_s.items()):
        entries = []
        for cat_name, case_set in cat_entries:
            other_ids = [cid for cid in CASE_CATEGORY.get(cat_name, []) if cid not in case_set]
            if other_ids:
                entries.append({"category": cat_name, "other_ids": other_ids})
        if entries:
            single_diffusions.append({"combo": combo, "entries": entries})

    # ═══ PART 3: 多轮突破 — 按手法×领域扩散 ═══
    cresc_diffusions = []
    by_combo_c: dict[str, list[tuple[str, set[str]]]] = {}
    for (combo, cat), case_set in cresc_groups.items():
        by_combo_c.setdefault(combo, []).append((cat, case_set))
    for combo, cat_entries in sorted(by_combo_c.items()):
        entries = []
        for cat_name, case_set in cat_entries:
            other_ids = [cid for cid in CRESCENDO_CATEGORY.get(cat_name, []) if cid not in case_set]
            if other_ids:
                entries.append({"category": cat_name, "other_ids": other_ids})
        if entries:
            cresc_diffusions.append({"combo": combo, "entries": entries})

    # ═══ 最快聚合路径 ═══
    probe_single_ids: list[str] = []
    probe_cresc_ids: list[str] = []
    for pid in probe_vulns:
        m = PROBE_FOLLOWUP_MAP.get(pid, {})
        for _, cids in m.get("single", []):
            probe_single_ids.extend(cids.split(","))
        for _, cids in m.get("crescendo", []):
            probe_cresc_ids.extend(cids.split(","))

    single_diff_ids = []
    for (_, cat), case_set in single_groups.items():
        single_diff_ids.extend(cid for cid in CASE_CATEGORY.get(cat, []) if cid not in case_set)
    cresc_diff_ids = []
    for (_, cat), case_set in cresc_groups.items():
        cresc_diff_ids.extend(cid for cid in CRESCENDO_CATEGORY.get(cat, []) if cid not in case_set)

    merged_single = list(dict.fromkeys(probe_single_ids + single_diff_ids))
    merged_cresc = list(dict.fromkeys(probe_cresc_ids + cresc_diff_ids))

    return {
        "probe_followups": probe_followups,
        "single_diffusions": single_diffusions,
        "cresc_diffusions": cresc_diffusions,
        "merged_single_ids": merged_single,
        "merged_crescendo_ids": merged_cresc,
    }
