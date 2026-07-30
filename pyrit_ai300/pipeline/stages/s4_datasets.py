"""
Stage 4/7: Datasets 数据载荷端
=============================

加载 + 预筛选 + 选择 + 准备。
整合 DatasetManager → CentralMemory → TieredSelection → AttackPreparator。

显示架构 (v7.0 优化):
  4a. 数据加载                    — 全量统计
  4b. target_group 驱动预筛选      — OWASP 覆盖
  4c. 种子组选择与排序             — 选择结果 + ASR 先验排序 (合并旧 4c/4d)
  4d. 攻击计划生成                 — 计划数 + P编号 + 传递信息 (合并旧 4e/传递)
"""

from pathlib import Path

from pipeline.context import PipelineContext
from pipeline.display import info_box, stage_header
from src.payloads import (
    DatasetManager, SeedGroupSelector, AttackPreparator,
    SeedPromptAdapter, plan_attacks,
    TargetType, TieredSelectionWizard, SelectionPreset, FallbackStrategy,
)


async def run(ctx: PipelineContext) -> bool:
    """执行数据载荷阶段。返回 False 表示无数据，应终止。"""
    stage_header(4, "Datasets 数据载荷端", "加载 + 预筛选 + 选择 + 准备")

    # ── 4a: 数据加载 ──
    dm_owasp_cfg = ctx.config_loader.get_dataset_manager_owasp_config()
    dm_custom_cfg = ctx.config_loader.get_dataset_manager_custom_config()
    dm_academic_cfg = ctx.config_loader.get_dataset_manager_academic_config()
    dm_remote_cfg = ctx.config_loader.get_dataset_manager_remote_config()

    ctx.config_owasp_ids = ctx.owasp_ids if ctx.owasp_ids else dm_owasp_cfg.get("owasp_ids", [])
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
    from src.payloads.technique_name_mapper import TIER_A_THRESHOLD as _HIGH_ASR
    for _s in ctx.manager.get_seeds():
        _meta = getattr(_s, "metadata", {}) or {}
        _oid = _meta.get("owasp_id", "unknown")
        ctx.owasp_counts[_oid] = ctx.owasp_counts.get(_oid, 0) + 1
        _tg = _meta.get("technique_group", _meta.get("technique", "unknown"))
        ctx.technique_counts[_tg] = ctx.technique_counts.get(_tg, 0) + 1
        _asr = _meta.get("asr_baseline", {})
        if _asr:
            _numeric = [v for v in _asr.values() if isinstance(v, (int, float))]
            if _numeric and max(_numeric) >= _HIGH_ASR:
                ctx.asr_high_count += 1

    load_lines = [
        f"总计: {ctx.total_seeds} seeds, {ctx.total_groups} seed groups",
        f"OWASP: {len(ctx.owasp_counts)} 分类 | 技术: {len(ctx.technique_counts)} 种 | "
        f"高ASR: {ctx.asr_high_count} seed",
    ]
    if include_academic:
        load_lines.append("学术载荷: data/academic/ (本地缓存)")
    if include_remote:
        load_lines.append(
            f"远程数据集: {', '.join(remote_dataset_names) if remote_dataset_names else '全部已注册'}"
        )
    info_box("4a. 数据加载", load_lines)

    if ctx.total_groups == 0:
        print("  [!] 未加载到任何种子数据，跳过攻击")
        return False

    # ── 4b: 预筛选展示 ──
    if ctx.target_group:
        b_lines = [
            f"target_group: {ctx.target_group}",
            f"OWASP 覆盖: {len(ctx.owasp_counts)} 分类",
        ]
        b_lines += [f"  {oid}: {cnt} seeds" for oid, cnt in sorted(ctx.owasp_counts.items())]

        # Burp HTTP 模板 — 仅当目标类型为 HTTP 相关时展示
        _burp_dir = Path(__file__).parent.parent.parent / "data" / "burp"
        _burp_files = list(_burp_dir.glob("*.txt")) if _burp_dir.exists() else []
        if _burp_files and ("http" in ctx.target_type or "burp" in ctx.target_type):
            b_lines.append(f"Burp HTTP 模板: {len(_burp_files)} 个 (data/burp/)")

        info_box("4b. target_group 驱动预筛选", b_lines)

    # ── 4c: 选择 (逻辑在 _select_groups 中，展示在下方合并) ──
    ctx.all_seed_groups = ctx.manager.get_seed_groups()
    await _select_groups(ctx)
    if not ctx.selected_groups:
        print("  [!] 未选择任何种子组，跳过攻击")
        return False

    # ── 4c. 种子组选择与排序 (合并旧 4c 选择结果 + 4d ASR 排序) ──
    _tiered_cfg = ctx.config_loader.get_tiered_selection_config()
    _top_n = _tiered_cfg.get("top_n", 3)

    select_lines = []
    if ctx.selection_mode_info:
        select_lines.append(f"选择模式: {ctx.selection_mode_info}")
    select_lines.append(
        f"选中: {len(ctx.selected_groups)}/{len(ctx.all_seed_groups)} 个种子组 "
        f"(top-{_top_n})"
    )
    select_lines.append(f"降级策略: {ctx.fallback_strategy.display_name}")

    # 降级链展开 (合并旧 4e 中的降级链信息)
    if ctx.fallback_strategy != FallbackStrategy.PARALLEL and ctx.fallback_chain:
        tier_summary = []
        for tier_groups in ctx.fallback_chain:
            if not tier_groups:
                continue
            tier_val = tier_groups[0].tier.value
            tier_summary.append(f"{tier_val}={len(tier_groups)}组")
        if tier_summary:
            select_lines.append(
                f"降级链: {' → '.join(tier_summary)}"
            )

    info_box("4c. 种子组选择与排序", select_lines)

    # ASR 先验排序 (display_selection_stage 自带 box 格式，紧接 4c 展示)
    from src.scenarios.asr_strategy_display import display_selection_stage
    display_selection_stage(
        selected_groups=ctx.selected_groups,
        all_seed_groups=ctx.all_seed_groups,
        model_name=ctx.strategy_info.get("model_name", ctx.target_model),
        strategy_mode=ctx.strategy_info.get("strategy_mode", "academic"),
        warm_start_asr=ctx.warm_start_asr or None,
    )

    # ── 4d. 攻击计划生成 (合并旧 4e 攻击准备 + 传递信息) ──
    ctx.attack_groups = await AttackPreparator.prepare_batch(ctx.planning_groups)
    ctx.multi_turn_count = sum(
        1 for ag in ctx.attack_groups if AttackPreparator.is_multi_turn(ag)
    )

    ctx.prompt_batches = SeedPromptAdapter.seed_groups_to_batches(ctx.planning_groups)
    ctx.total_prompts = sum(len(b.prompts) for b in ctx.prompt_batches)
    ctx.attack_plans = plan_attacks(ctx.prompt_batches, ctx.strategy_selection)

    plan_lines = [
        f"计划: {len(ctx.attack_plans)} 个 "
        f"({ctx.multi_turn_count} 多轮 / {len(ctx.attack_groups) - ctx.multi_turn_count} 单轮)",
        f"提示词: {ctx.total_prompts} 个 | OWASP: {len(ctx.owasp_counts)} 分类",
    ]

    # P1-Pn 载荷编号列表 (合并旧传递信息中的 attack_plans 列表)
    _seen_tech = set()
    plan_lines.append("")
    for i, plan in enumerate(ctx.attack_plans):
        _tech = getattr(plan, "attack_technique", "")
        _oid = getattr(plan, "owasp_id", "") or "N/A"
        plan_lines.append(f"  P{i+1}. [{_oid}] {_tech}")
        if _tech and _tech not in _seen_tech:
            _seen_tech.add(_tech)
    plan_lines.append(f"  → {len(_seen_tech)} 种技术 → 提取用于变体池生成")
    plan_lines.append(f"  → target_group: {ctx.target_group} → Converter 链选择")

    info_box("4d. 攻击计划生成", plan_lines)

    return True


async def _select_groups(ctx: PipelineContext) -> None:
    """4c: 交互式/自动选择 — 纯逻辑，不输出展示"""
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
