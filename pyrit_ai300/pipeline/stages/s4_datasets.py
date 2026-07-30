"""
Stage 4/7: Datasets 数据载荷端
=============================

加载 + 预筛选 + 选择 + 准备。
整合 DatasetManager → CentralMemory → TieredSelection → AttackPreparator。

显示架构 (v8.0 优化 — 载荷驱动 + 高 ASR 导向):
  ① 数据加载与预筛选           — 合并旧 4a+4b，加载统计 + 筛选结果
  ② ★ 载荷选择矩阵 ★          — 按技术分组卡片，高 ASR 优先，载荷×计划映射
  ③ ★ 传递到执行层 ★          — 最终结果摘要（决定后续攻击成功率）

设计原则:
  - 以数据载荷为驱动：以选中的种子组为展示核心单元
  - 高 ASR 导向：每个载荷卡片标注 ASR + Tier，按 ASR 降序排列
  - 参照 executor 卡片风格：┏━ 粗线框 + ◆ 技术头 + ┌─ 子区域 + ①②③ 编号
  - 传递结果突出展示：最终输出决定后续攻击成功率
"""

from pathlib import Path
from typing import Any

from pipeline.context import PipelineContext
from pipeline.display import info_box, stage_header
from src.payloads import (
    DatasetManager, SeedGroupSelector, AttackPreparator,
    SeedPromptAdapter, plan_attacks,
    TargetType, TieredSelectionWizard, SelectionPreset, FallbackStrategy,
)

# ── 统一卡片宽度（双线框，与 executor 一致） ──
_W = 68

_CIRCLED = "①②③④⑤⑥⑦⑧⑨⑩"

_TIER_LABELS = {"S": "极高", "A": "高", "B": "中", "C": "低", "D": "极低"}

_TIER_DESCRIPTIONS = {
    "S": "多轮迭代攻击 (极高)",
    "A": "树搜索/迭代/模拟对话 (高)",
    "B": "说服/角色扮演/包装 (中)",
    "C": "编码变换/基线 (低, 兜底)",
    "D": "极低 (兜底尝试 — ASR 非零即值得尝试)",
}

_MODE_CN = {
    "multi_turn": "多轮迭代",
    "single_turn": "单轮直发",
    "sequential": "顺序组合",
    "converter_enhanced": "Converter增强",
}


# ============================================================
# 辅助函数（与 executor 风格统一）
# ============================================================


def _trunc(text: str, limit: int = 60) -> str:
    """截断文本，添加省略号"""
    text = text.replace("\n", " ").strip()
    return text[:limit - 3] + "..." if len(text) > limit else text


def _cjk_width(s: str) -> int:
    """近似计算字符串显示宽度（CJK 字符算 2 列）"""
    return sum(2 if ord(c) > 0x7F else 1 for c in s)


def _pad_right(s: str, width: int) -> str:
    """将字符串填充到指定显示宽度"""
    w = _cjk_width(s)
    return s + " " * max(0, width - w)


def _get_tech_asr(
    tech: str,
    model_name: str,
    warm_start: dict[str, float] | None = None,
) -> tuple[float, str]:
    """获取技术的 ASR 和 Tier (warm_start 优先, 回退学术先验)"""
    try:
        from src.payloads.technique_name_mapper import (
            get_normalized_asr,
            normalize_technique_name,
        )
        from src.payloads.asr_prior_registry import tier_from_asr

        normalized = normalize_technique_name(tech)
        if warm_start and normalized in warm_start:
            asr = warm_start[normalized]
        else:
            asr = get_normalized_asr(tech, model_name)
        tier = tier_from_asr(asr)
        return asr, tier
    except Exception:
        return 0.0, "D"


def _format_tech_display(tech: str, normalized: str) -> str:
    """格式化技术名显示（原始名 → 标准化名 + PascalCase）"""
    try:
        from src.reporting.converter_log import format_technique_display
        if tech != normalized:
            return f"{tech} → {format_technique_display(normalized)}"
        return format_technique_display(tech)
    except Exception:
        return tech


# ============================================================
# 技术分组构建
# ============================================================


def _build_tech_groups(ctx: PipelineContext) -> list[dict[str, Any]]:
    """
    从选中种子组构建技术分组（按 technique_group 聚合）。

    匹配种子组 → prompt_batches → attack_plans 的映射链:
      planning_groups[i] → prompt_batches[i] → attack_plans[offset:offset+n]

    Returns:
        按 ASR 降序排序的技术分组列表
    """
    from src.payloads.technique_name_mapper import normalize_technique_name

    model_name = ctx.strategy_info.get("model_name", ctx.target_model)
    warm_start = ctx.warm_start_asr or None

    # 1. 按 technique_group 聚合种子组
    tech_map: dict[str, dict[str, Any]] = {}
    for g_idx, sg in enumerate(ctx.planning_groups):
        seeds = getattr(sg, "seeds", [])
        first_seed = seeds[0] if seeds else None
        meta = getattr(first_seed, "metadata", {}) or {} if first_seed else {}
        tech = meta.get("technique_group", meta.get("technique", "unknown"))

        if tech not in tech_map:
            normalized = (
                normalize_technique_name(tech)
                if tech != "unknown"
                else tech
            )
            asr, tier = _get_tech_asr(tech, model_name, warm_start)

            tech_map[tech] = {
                "technique_group": tech,
                "normalized": normalized,
                "display": _format_tech_display(tech, normalized),
                "asr": asr,
                "tier": tier,
                "owasp_ids": set(),
                "modes": set(),
                "seeds": [],
                "plans": [],
                "group_indices": [],
            }

        # 收集信息
        owasp_id = meta.get("owasp_id", "")
        if owasp_id:
            tech_map[tech]["owasp_ids"].add(owasp_id)

        tech_map[tech]["group_indices"].append(g_idx)

        # 收集种子摘要
        for seed in seeds:
            s_meta = getattr(seed, "metadata", {}) or {}
            s_oid = s_meta.get("owasp_id", owasp_id)
            s_sev = s_meta.get("severity", "")
            s_val = getattr(seed, "value", "") or getattr(seed, "prompt", "")
            s_mode = s_meta.get("attack_mode", "")
            tech_map[tech]["seeds"].append({
                "owasp_id": s_oid,
                "severity": s_sev,
                "value": s_val,
                "mode": s_mode,
            })
            if s_oid:
                tech_map[tech]["owasp_ids"].add(s_oid)
            if s_mode:
                tech_map[tech]["modes"].add(s_mode)

    # 2. 构建种子组 → 攻击计划映射 (通过 prompt_batches)
    plan_offset = 0
    for g_idx, batch in enumerate(ctx.prompt_batches):
        n_prompts = len(batch.prompts)
        plans_for_batch = ctx.attack_plans[plan_offset:plan_offset + n_prompts]
        plan_offset += n_prompts

        # 找到对应的技术分组
        if g_idx < len(ctx.planning_groups):
            sg = ctx.planning_groups[g_idx]
            seeds = getattr(sg, "seeds", [])
            first_seed = seeds[0] if seeds else None
            meta = (
                getattr(first_seed, "metadata", {}) or {}
                if first_seed else {}
            )
            tech = meta.get(
                "technique_group", meta.get("technique", "unknown")
            )

            if tech in tech_map:
                tech_map[tech]["plans"].extend(plans_for_batch)
                for p in plans_for_batch:
                    pi = getattr(p, "prompt_item", None)
                    if pi:
                        am = getattr(pi, "attack_mode", None)
                        if am:
                            mode_str = (
                                am.value
                                if hasattr(am, "value")
                                else str(am)
                            )
                            tech_map[tech]["modes"].add(mode_str)

    # 3. 按 ASR 降序排序
    result = list(tech_map.values())
    result.sort(key=lambda x: -x["asr"])
    return result


# ============================================================
# ① 数据加载与预筛选
# ============================================================


def _display_data_loading(ctx: PipelineContext) -> None:
    """① 数据加载与预筛选 (合并旧 4a + 4b)"""
    lines = [
        f"加载: {ctx.total_seeds} seeds, {ctx.total_groups} seed groups",
        f"      OWASP: {len(ctx.owasp_counts)} 分类 | "
        f"技术: {len(ctx.technique_counts)} 种 | "
        f"高ASR: {ctx.asr_high_count} seed",
    ]

    # 学术/远程载荷
    dm_academic_cfg = ctx.config_loader.get_dataset_manager_academic_config()
    if dm_academic_cfg.get("enabled", False):
        lines.append("      学术载荷: data/academic/ (本地缓存)")

    dm_remote_cfg = ctx.config_loader.get_dataset_manager_remote_config()
    if dm_remote_cfg.get("enabled", False):
        remote_names = dm_remote_cfg.get("datasets", [])
        lines.append(
            f"      远程数据集: "
            f"{', '.join(remote_names) if remote_names else '全部已注册'}"
        )

    # 预筛选
    if ctx.target_group:
        lines.append("")
        lines.append(f"预筛选: target_group={ctx.target_group}")
        # OWASP 分布横排
        owasp_parts = [
            f"{oid}: {cnt}"
            for oid, cnt in sorted(ctx.owasp_counts.items())
        ]
        lines.append(f"  {'  '.join(owasp_parts)}")

        # Burp HTTP 模板
        _burp_dir = Path(__file__).parent.parent.parent / "data" / "burp"
        _burp_files = (
            list(_burp_dir.glob("*.txt")) if _burp_dir.exists() else []
        )
        if _burp_files and (
            "http" in ctx.target_type or "burp" in ctx.target_type
        ):
            lines.append(
                f"  Burp HTTP 模板: {len(_burp_files)} 个 (data/burp/)"
            )

    info_box("数据加载与预筛选", lines)


# ============================================================
# ② 载荷选择矩阵 — 高 ASR 优先
# ============================================================


def _display_payload_matrix(
    ctx: PipelineContext,
    tech_groups: list[dict[str, Any]],
) -> None:
    """② 载荷选择矩阵 — 按技术分组卡片，高 ASR 优先"""

    # Banner
    print()
    print("  ╔" + "═" * _W + "╗")
    print()
    print("       ★  载荷选择矩阵 — 高 ASR 优先  ★")
    print()
    _asr_label = "经验融合 ASR" if ctx.warm_start_asr else "学术 ASR"
    print(f"    按 {_asr_label} 降序展示选中种子组 · 高成功率技术优先执行")
    print()
    print("  ╚" + "═" * _W + "╝")

    if not tech_groups:
        print("  [!] 无技术分组数据")
        return

    # 全局概览
    total_seeds = sum(len(tg["seeds"]) for tg in tech_groups)
    total_plans = sum(len(tg["plans"]) for tg in tech_groups)

    print()
    print(f"  ┌─ 全局概览 {'─' * max(1, _W - 22)}┐")
    print("  │")
    for i, tg in enumerate(tech_groups):
        tech_pad = _pad_right(tg["technique_group"][:20], 20)
        n_seeds = len(tg["seeds"])
        n_plans = len(tg["plans"])
        print(
            f"  │  技术 {i + 1}: {tech_pad}  "
            f"ASR {tg['asr']:>4.0%}  {n_seeds} 载荷 → {n_plans} 计划"
        )
    print(f"  │  {'─' * max(1, _W - 6)}")
    print(f"  │  合计: {total_seeds} 种子载荷 → {total_plans} 攻击计划")
    print(f"  └{'─' * _W}┘")

    # 全局 P 编号映射 (P1, P2, ... 贯穿全阶段)
    plan_to_pid: dict[int, str] = {}
    for g_idx, p in enumerate(ctx.attack_plans):
        pid = f"P{g_idx + 1}"
        plan_to_pid[id(p)] = pid
    # P0-A: 存入 ctx 供 Stage 5/6 使用
    ctx.plan_pid_map = plan_to_pid

    # 每个技术卡片
    for tg in tech_groups:
        display = tg["display"]
        asr = tg["asr"]
        tier = tg["tier"]
        owasp_ids = sorted(tg["owasp_ids"]) if tg["owasp_ids"] else []
        owasp_str = ", ".join(owasp_ids) if owasp_ids else "N/A"
        modes = sorted(tg["modes"]) if tg["modes"] else []
        mode_cn = (
            " / ".join(_MODE_CN.get(m, m) for m in modes)
            if modes else "未知"
        )

        seeds = tg["seeds"]
        plans = tg["plans"]

        # ── 卡片头 ──
        print()
        print("  ┏" + "━" * _W)
        print(f"  ┃  ◆ {display}")
        print(
            f"  ┃    ASR: {asr:.0%} (Tier {tier} "
            f"{_TIER_LABELS.get(tier, '')})  |  OWASP: {owasp_str}  "
            f"|  模式: {mode_cn}"
        )
        print(f"  ┃    {_TIER_DESCRIPTIONS.get(tier, '')}")
        print("  ┃")

        # ── 种子载荷 ──
        n_seeds = len(seeds)
        seed_hdr = f"种子载荷 ({n_seeds})"
        seed_dashes = max(1, _W - 6 - _cjk_width(seed_hdr) - 2)
        print(f"  ┃    ┌─ {seed_hdr} {'─' * seed_dashes}┐")

        max_show = 4
        for idx, seed in enumerate(seeds[:max_show]):
            marker = (
                _CIRCLED[idx] if idx < len(_CIRCLED) else f"{idx + 1}."
            )
            sev = seed["severity"]
            sev_str = f" [{sev}]" if sev else ""
            val = _trunc(seed["value"], 50)
            oid = seed["owasp_id"]
            oid_str = (
                f" [{oid}]" if oid and oid not in owasp_str else ""
            )
            print(f"  ┃    │ {marker}{sev_str}{oid_str} \"{val}\"")

        if len(seeds) > max_show:
            print(f"  ┃    │ ... ({len(seeds) - max_show} more)")

        print(f"  ┃    └{'─' * max(0, _W - 3)}┘")

        # ── 攻击计划映射 ──
        if plans:
            print("  ┃")
            plan_hdr = f"攻击计划映射 ({len(plans)})"
            plan_dashes = max(1, _W - 6 - _cjk_width(plan_hdr) - 2)
            print(f"  ┃    ┌─ {plan_hdr} {'─' * plan_dashes}┐")

            for idx, plan in enumerate(plans[:max_show]):
                pid = plan_to_pid.get(id(plan), f"P{idx + 1}")
                p_tech = getattr(plan, "attack_technique", "")
                p_oid = getattr(plan, "owasp_id", "") or "N/A"
                pi = getattr(plan, "prompt_item", None)

                # 模式
                am = getattr(pi, "attack_mode", None) if pi else None
                mode_str = (
                    am.value
                    if am and hasattr(am, "value")
                    else (str(am) if am else "unknown")
                )
                mode_cn_plan = _MODE_CN.get(mode_str, mode_str)

                # 多轮步骤
                plan_turns = getattr(plan, "max_turns", 1)
                mode_detail = mode_cn_plan
                if plan_turns > 1 and mode_str == "multi_turn":
                    mode_detail = f"{mode_cn_plan} ({plan_turns} 轮)"

                print(
                    f"  ┃    │ {pid} [{p_oid}] {p_tech} ({mode_detail})"
                )

                # 多轮步骤详情
                if pi and mode_str == "multi_turn":
                    steps = getattr(pi, "multi_turn_steps", None)
                    if steps:
                        for t_idx, step in enumerate(steps[:2]):
                            print(
                                f"  ┃    │   Turn {t_idx + 1}: "
                                f"\"{_trunc(step, 45)}\""
                            )
                        remaining = len(steps) - 2
                        if remaining > 0:
                            print(
                                f"  ┃    │   ... ({remaining} more turns)"
                            )

                # 顺序步骤
                if pi and mode_str == "sequential":
                    steps = getattr(pi, "sequential_steps", None)
                    if steps:
                        for s_idx, step in enumerate(steps[:2]):
                            conv = (
                                f" + {step.converter_chain}"
                                if step.converter_chain
                                else ""
                            )
                            print(
                                f"  ┃    │   Step {s_idx + 1}: "
                                f"{step.attack_technique}{conv}"
                            )
                        remaining = len(steps) - 2
                        if remaining > 0:
                            print(
                                f"  ┃    │   ... ({remaining} more steps)"
                            )

            if len(plans) > max_show:
                print(f"  ┃    │ ... ({len(plans) - max_show} more)")

            print(f"  ┃    └{'─' * max(0, _W - 3)}┘")

        print("  ┗" + "━" * _W)


# ============================================================
# ③ 传递到执行层 — ★ 突出展示 ★
# ============================================================


def _display_handoff(
    ctx: PipelineContext,
    tech_groups: list[dict[str, Any]],
) -> None:
    """③ 传递到执行层 — 最终结果摘要（★ 突出展示 ★）

    最终输出决定后续攻击成功率，因此重点展示:
      - 攻击计划列表 (P1-Pn) — 带来源技术和 ASR 标注
      - 技术提取 → 变体池
      - target_group → Converter 链
      - 策略 + 降级链
      - 模型 + 选择信息
    """

    model_name = ctx.strategy_info.get("model_name", ctx.target_model)
    strategy_mode = ctx.strategy_info.get("strategy_mode", "academic")
    model_tier = ctx.strategy_info.get("model_tier", "unknown")

    # 反向映射: plan → technique_group + ASR
    plan_to_tech: dict[int, str] = {}
    plan_to_asr: dict[int, float] = {}
    for tg in tech_groups:
        for p in tg["plans"]:
            plan_to_tech[id(p)] = tg["technique_group"]
            plan_to_asr[id(p)] = tg["asr"]

    # Banner — 突出显示
    print()
    print("  ╔" + "═" * _W + "╗")
    print()
    print("       ★  传递到执行层 — 决定后续攻击成功率  ★")
    print()
    print("  ╚" + "═" * _W + "╝")

    # 攻击计划列表（最终输出）
    print()
    n_plans = len(ctx.attack_plans)
    handoff_hdr = f"攻击计划 (最终输出: {n_plans} 个)"
    handoff_dashes = max(1, _W - 2 - _cjk_width(handoff_hdr) - 2)
    print(f"  ┌─ {handoff_hdr} {'─' * handoff_dashes}┐")

    for i, plan in enumerate(ctx.attack_plans):
        pid = f"P{i + 1}"
        p_tech = getattr(plan, "attack_technique", "")
        p_oid = getattr(plan, "owasp_id", "") or "N/A"
        pi = getattr(plan, "prompt_item", None)

        # 模式
        am = getattr(pi, "attack_mode", None) if pi else None
        mode_str = (
            am.value
            if am and hasattr(am, "value")
            else (str(am) if am else "unknown")
        )
        mode_cn = _MODE_CN.get(mode_str, mode_str)

        # 来源技术 + ASR
        src_tech = plan_to_tech.get(id(plan), "")
        src_asr = plan_to_asr.get(id(plan), 0.0)
        src_str = ""
        if src_tech and src_tech != p_tech:
            src_str = f"  ← {src_tech} (ASR {src_asr:.0%})"
        elif src_tech:
            src_str = f"  (ASR {src_asr:.0%})"

        print(f"  │ {pid} [{p_oid}] {p_tech} ({mode_cn}){src_str}")

    print("  │")

    # 技术提取
    _seen_tech: set[str] = set()
    for plan in ctx.attack_plans:
        _tech = getattr(plan, "attack_technique", "")
        if _tech:
            _seen_tech.add(_tech)

    _n_multi = ctx.multi_turn_count
    _n_single = len(ctx.attack_groups) - _n_multi

    print(
        f"  │ → {len(_seen_tech)} 种技术提取用于变体池生成  "
        f"({_n_multi} 多轮 / {_n_single} 单轮)"
    )
    print(f"  │ → 提示词: {ctx.total_prompts} 个 | "
          f"OWASP: {len(ctx.owasp_counts)} 分类")
    print(
        f"  │ → target_group: {ctx.target_group} → Converter 链选择"
    )

    # P2: 技术池演化映射 — Stage 2 → Stage 4 → Stage 5 可追溯
    _stage2_techs = set(
        getattr(ctx.strategy_selection, "attack_techniques", []) or []
    )
    _stage4_techs = {tg["technique_group"] for tg in tech_groups}
    _stage5_techs = _seen_tech

    if _stage2_techs or _stage4_techs:
        print("  │")
        print("  │ → 技术池演化 (Stage 2 → 4 → 5):")
        print(
            f"  │   Stage 2 策略选择: {len(_stage2_techs)} 种"
        )
        _matched = _stage2_techs & _stage4_techs
        _unmatched = _stage2_techs - _stage4_techs
        _extra = _stage4_techs - _stage2_techs
        if _matched:
            _matched_str = ", ".join(sorted(_matched)[:5])
            if len(_matched) > 5:
                _matched_str += f" ... (+{len(_matched) - 5})"
            print(f"  │   Stage 4 载荷匹配: {len(_matched)} 种 ✓ ({_matched_str})")
        if _unmatched:
            _unmatched_str = ", ".join(sorted(_unmatched)[:5])
            if len(_unmatched) > 5:
                _unmatched_str += f" ... (+{len(_unmatched) - 5})"
            print(
                f"  │   Stage 4 无载荷:  {len(_unmatched)} 种 ✗ "
                f"({_unmatched_str}) ← 无种子数据"
            )
        if _extra:
            _extra_str = ", ".join(sorted(_extra)[:5])
            if len(_extra) > 5:
                _extra_str += f" ... (+{len(_extra) - 5})"
            print(
                f"  │   Stage 4 额外:    {len(_extra)} 种 "
                f"(载荷自带, 不在策略池: {_extra_str})"
            )
        print(
            f"  │   Stage 5 执行:    {len(_stage5_techs)} 种 "
            f"(从 {len(ctx.attack_plans)} 个计划提取)"
        )

    # P4: 种子组→计划过滤统计
    _n_seed_groups = len(ctx.planning_groups)
    _n_attack_groups = len(ctx.attack_groups)
    _n_plans = len(ctx.attack_plans)
    _empty_groups = 0
    for sg in ctx.planning_groups:
        _seeds = getattr(sg, "seeds", [])
        if not _seeds:
            _empty_groups += 1
    if _empty_groups > 0 or _n_seed_groups != _n_attack_groups:
        print("  │")
        print("  │ → 种子组→计划映射:")
        print(
            f"  │   种子组: {_n_seed_groups} → 攻击组: {_n_attack_groups} "
            f"→ 计划: {_n_plans}"
        )
        if _empty_groups > 0:
            print(
                f"  │   ⚠ {_empty_groups} 个种子组无种子 "
                f"(空组, 0 计划)"
            )

    # 策略信息
    print(f"  │ → 策略: {strategy_mode}", end="")
    if strategy_mode == "academic":
        print(" (Tier S → A → B → C → D 顺序尝试)")
        print(
            "  │   高 ASR 技术优先, Tier D 兜底 "
            "— ASR 非零即值得尝试"
        )
        print(
            "  │   首次运行使用学术先验 Q 值, 后续 memory 学习优化"
        )
    elif strategy_mode == "exam":
        print(" (单轮 → 编码 → 多轮, 按执行速度排序)")
    else:
        print(" (各 Tier 交替尝试)")

    # 降级链
    if (
        ctx.fallback_strategy
        and ctx.fallback_strategy != FallbackStrategy.PARALLEL
        and ctx.fallback_chain
    ):
        tier_summary = []
        for tier_groups in ctx.fallback_chain:
            if not tier_groups:
                continue
            tier_val = (
                tier_groups[0].tier.value
                if hasattr(tier_groups[0].tier, "value")
                else str(tier_groups[0].tier)
            )
            tier_summary.append(f"{tier_val}={len(tier_groups)}组")
        if tier_summary:
            print(
                f"  │ → 降级链: {' → '.join(tier_summary)} "
                f"({ctx.fallback_strategy.display_name})"
            )

    # 模型 + 选择信息
    print(f"  │ → 模型: {model_name} ({model_tier})")

    if ctx.selection_mode_info:
        _tiered_cfg = ctx.config_loader.get_tiered_selection_config()
        _top_n = _tiered_cfg.get("top_n", 3)
        print(
            f"  │ → 选择: {ctx.selection_mode_info} → "
            f"{len(ctx.selected_groups)}/{len(ctx.all_seed_groups)} 个种子组 "
            f"(top-{_top_n})"
        )

    print(f"  └{'─' * _W}┘")

    # P3-B: 降级链与执行策略桥接说明
    if (
        ctx.fallback_strategy
        and ctx.fallback_strategy != FallbackStrategy.PARALLEL
        and ctx.fallback_chain
    ):
        print("  │")
        print("  │ → 降级链 ↔ Stage 5 执行策略桥接:")
        print("  │   降级链 (Tier S→A→B→C→D) 控制技术尝试顺序")
        print("  │   Stage 5 失败路由 (model_refusal→升级/timeout→降级)")
        print("  │   两者协同: 降级链定初始顺序, 失败路由动态调整")

    # P2-A: 阶段间衔接行
    from pipeline.display import handoff_line
    _n_plans_h = len(ctx.attack_plans)
    _n_tech_h = len(_seen_tech)
    _n_owasp_h = len(ctx.owasp_counts)
    handoff_line(4, 5, f"{_n_plans_h} 个攻击计划 | {_n_tech_h} 种技术 | {_n_owasp_h} OWASP 分类")


# ============================================================
# 主流程
# ============================================================


async def run(ctx: PipelineContext) -> bool:
    """执行数据载荷阶段。返回 False 表示无数据，应终止。"""
    stage_header(4, "Datasets 数据载荷端", "加载 + 预筛选 + 选择 + 准备")

    # ── 数据加载 (纯逻辑) ──
    dm_owasp_cfg = ctx.config_loader.get_dataset_manager_owasp_config()
    dm_custom_cfg = ctx.config_loader.get_dataset_manager_custom_config()
    dm_academic_cfg = ctx.config_loader.get_dataset_manager_academic_config()
    dm_remote_cfg = ctx.config_loader.get_dataset_manager_remote_config()

    ctx.config_owasp_ids = (
        ctx.owasp_ids if ctx.owasp_ids
        else dm_owasp_cfg.get("owasp_ids", [])
    )
    exclude_ids = dm_owasp_cfg.get("exclude_ids", [])
    include_custom = dm_custom_cfg.get("enabled", True)
    include_academic = dm_academic_cfg.get("enabled", False)
    include_remote = dm_remote_cfg.get("enabled", False)
    remote_dataset_names = dm_remote_cfg.get("datasets", [])

    ctx.manager = DatasetManager()
    await ctx.manager.load_datasets(
        owasp=True,
        owasp_frameworks=dm_owasp_cfg.get("frameworks", ["llm", "agentic"]),
        owasp_ids=ctx.config_owasp_ids or None,
        exclude_ids=exclude_ids or None,
        custom=include_custom,
        academic=include_academic,
        remote=include_remote,
        remote_dataset_names=remote_dataset_names if include_remote else None,
    )

    ctx.total_seeds = len(ctx.manager.get_seeds())
    ctx.total_groups = len(ctx.manager.get_seed_groups())

    # 数据多样性统计
    from src.payloads.technique_name_mapper import (
        TIER_A_THRESHOLD as _HIGH_ASR,
    )
    for _s in ctx.manager.get_seeds():
        _meta = getattr(_s, "metadata", {}) or {}
        _oid = _meta.get("owasp_id", "unknown")
        ctx.owasp_counts[_oid] = ctx.owasp_counts.get(_oid, 0) + 1
        _tg = _meta.get("technique_group", _meta.get("technique", "unknown"))
        ctx.technique_counts[_tg] = ctx.technique_counts.get(_tg, 0) + 1
        _asr = _meta.get("asr_baseline", {})
        if _asr:
            _numeric = [
                v for v in _asr.values() if isinstance(v, (int, float))
            ]
            if _numeric and max(_numeric) >= _HIGH_ASR:
                ctx.asr_high_count += 1

    # ── ① 数据加载与预筛选 ──
    _display_data_loading(ctx)

    if ctx.total_groups == 0:
        print("  [!] 未加载到任何种子数据，跳过攻击")
        return False

    # ── 种子组选择 (纯逻辑) ──
    ctx.all_seed_groups = ctx.manager.get_seed_groups()
    await _select_groups(ctx)
    if not ctx.selected_groups:
        print("  [!] 未选择任何种子组，跳过攻击")
        return False

    # ── 攻击准备 (纯逻辑) ──
    ctx.attack_groups = await AttackPreparator.prepare_batch(
        ctx.planning_groups
    )
    ctx.multi_turn_count = sum(
        1 for ag in ctx.attack_groups if AttackPreparator.is_multi_turn(ag)
    )

    ctx.prompt_batches = SeedPromptAdapter.seed_groups_to_batches(
        ctx.planning_groups
    )
    ctx.total_prompts = sum(len(b.prompts) for b in ctx.prompt_batches)
    ctx.attack_plans = plan_attacks(
        ctx.prompt_batches, ctx.strategy_selection
    )

    # ── ② 载荷选择矩阵 ──
    tech_groups = _build_tech_groups(ctx)
    _display_payload_matrix(ctx, tech_groups)

    # ── ③ 传递到执行层 (★ 突出展示 ★) ──
    _display_handoff(ctx, tech_groups)

    return True


async def _select_groups(ctx: PipelineContext) -> None:
    """种子组选择 — 纯逻辑，不输出展示"""
    tiered_cfg = ctx.config_loader.get_tiered_selection_config()
    tiered_enabled = tiered_cfg.get("enabled", True)
    interactive_cfg = ctx.config_loader.get_interactive_selection_config()
    interactive_enabled = ctx.config_loader.get_interactive_selection_enabled()

    if not tiered_enabled:
        # 旧版 SeedGroupSelector 路径
        ctx.selection_mode_info = "旧版 SeedGroupSelector (向后兼容)"
        ctx.fallback_strategy = FallbackStrategy.PARALLEL
        ctx.fallback_chain = []
        selector = SeedGroupSelector(
            enabled=interactive_enabled,
            auto_select_if_single=interactive_cfg.get("auto_select_if_single", True),
            page_size=interactive_cfg.get("page_size", 20),
        )
        catalog = selector.build_catalog(ctx.all_seed_groups)
        preset_owasp = ctx.owasp_ids if ctx.owasp_ids else None
        ctx.selected_groups = await selector.prompt_user(
            catalog, preset_owasp=preset_owasp, preset_modes=None,
        )
        ctx.planning_groups = ctx.selected_groups
        return

    # 三层渐进式选择路径
    preset_target = tiered_cfg.get("target_type")

    # 优先级：config target_type > recon target_type 推断 > 交互模式
    _inference_info = ""
    if not preset_target and ctx.target_type:
        from src.payloads.target_profile_router import TargetProfileRouter
        _inferred = TargetProfileRouter.infer_profile(recon_target_type=ctx.target_type)
        if _inferred.target_type != TargetType.FULL_SWEEP:
            preset_target = _inferred.target_type.value
            _inference_info = f"{ctx.target_type} → {preset_target}"

    if preset_target:
        try:
            tt = TargetType.from_string(preset_target)
        except ValueError:
            tt = None
        wizard_preset = SelectionPreset(
            target_type=tt,
            top_n=tiered_cfg.get("top_n", 3),
            fallback_strategy=FallbackStrategy(
                tiered_cfg.get("fallback_strategy", "sequential_asr_desc")
            ),
        )
        wizard = TieredSelectionWizard(
            enabled=False, preset=wizard_preset,
            model_name=ctx.strategy_info.get("model_name", ctx.target_model),
        )
        ctx.selection_mode_info = (
            f"自动 ({preset_target} preset, top-{tiered_cfg.get('top_n', 3)})"
            + (f", 推断: {_inference_info}" if _inference_info else "")
        )
    else:
        wizard = TieredSelectionWizard(
            enabled=interactive_enabled,
            model_name=ctx.strategy_info.get("model_name", ctx.target_model),
        )
        ctx.selection_mode_info = "交互式"

    selection_result = await wizard.select(ctx.all_seed_groups)
    ctx.selected_groups = selection_result.selected_groups
    ctx.fallback_strategy = selection_result.fallback_strategy
    ctx.fallback_chain = selection_result.fallback_chain
    ctx.planning_groups = ctx.selected_groups
    ctx.selection_result = selection_result
