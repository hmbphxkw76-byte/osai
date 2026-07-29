"""
Stage 4/8: Datasets 数据载荷端
=============================

加载 + 预筛选 + 选择 + 准备。
整合 DatasetManager → CentralMemory → TieredSelection → AttackPreparator。
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
        info_box(
            "4b. target_group 驱动预筛选",
            [f"target_group: {ctx.target_group}", f"OWASP 覆盖: {len(ctx.owasp_counts)} 分类"]
            + [f"  {oid}: {cnt} seeds" for oid, cnt in sorted(ctx.owasp_counts.items())],
        )

    # Burp HTTP 模板
    _burp_dir = Path(__file__).parent.parent.parent / "data" / "burp"
    _burp_files = list(_burp_dir.glob("*.txt")) if _burp_dir.exists() else []
    if _burp_files:
        print(f"  [OK] Burp HTTP 模板: {len(_burp_files)} 个 (data/burp/)")

    # ── 4c: 选择 ──
    ctx.all_seed_groups = ctx.manager.get_seed_groups()
    await _select_groups(ctx)
    if not ctx.selected_groups:
        print("  [!] 未选择任何种子组，跳过攻击")
        return False

    # ── 4d: ASR 排序展示 ──
    from src.scenarios.asr_strategy_display import display_selection_stage
    display_selection_stage(
        selected_groups=ctx.selected_groups,
        all_seed_groups=ctx.all_seed_groups,
        model_name=ctx.strategy_info.get("model_name", ctx.target_model),
        strategy_mode=ctx.strategy_info.get("strategy_mode", "academic"),
    )

    # ── 4e: 攻击准备 ──
    ctx.attack_groups = await AttackPreparator.prepare_batch(ctx.planning_groups)
    ctx.multi_turn_count = sum(
        1 for ag in ctx.attack_groups if AttackPreparator.is_multi_turn(ag)
    )

    ctx.prompt_batches = SeedPromptAdapter.seed_groups_to_batches(ctx.planning_groups)
    ctx.total_prompts = sum(len(b.prompts) for b in ctx.prompt_batches)
    ctx.attack_plans = plan_attacks(ctx.prompt_batches, ctx.strategy_selection)

    prep_lines = [
        f"计划: {len(ctx.attack_plans)} 个 "
        f"({ctx.multi_turn_count} 多轮 / {len(ctx.attack_groups) - ctx.multi_turn_count} 单轮)",
        f"提示词: {ctx.total_prompts} 个 | OWASP: {len(ctx.owasp_counts)} 分类",
    ]
    if ctx.fallback_strategy != FallbackStrategy.PARALLEL and ctx.fallback_chain:
        tier_summary = []
        for tier_groups in ctx.fallback_chain:
            if not tier_groups:
                continue
            tier_val = tier_groups[0].tier.value
            tier_summary.append(f"{tier_val}={len(tier_groups)}组")
        if tier_summary:
            prep_lines.append(
                f"降级链: {' → '.join(tier_summary)} ({ctx.fallback_strategy.display_name})"
            )
    info_box("4e. 攻击准备", prep_lines)

    # 构建详细的传递信息
    pass_lines = [
        f"• 选中组: {len(ctx.selected_groups)} 个",
    ]
    # 列出选中组的具体名称
    for i, sg in enumerate(ctx.selected_groups[:10]):
        _meta = {}
        for s in getattr(sg, "seeds", []):
            _meta = getattr(s, "metadata", {}) or {}
            if _meta:
                break
        _tech = _meta.get("technique_group", _meta.get("technique", "unknown"))
        _oid = _meta.get("owasp_id", "?")
        _nseeds = len(getattr(sg, "seeds", []))
        pass_lines.append(f"  {i+1}. [{_oid}] {_tech} ({_nseeds} seeds)")
    if len(ctx.selected_groups) > 10:
        pass_lines.append(f"  ... 还有 {len(ctx.selected_groups) - 10} 个")

    pass_lines.append(f"• attack_plans: {len(ctx.attack_plans)} 个")
    # 列出 attack_plans 的技术名和 OWASP ID
    _seen_tech = set()
    for plan in ctx.attack_plans:
        _tech = getattr(plan, "attack_technique", "")
        _oid = getattr(plan, "owasp_id", "?") or "?"
        if _tech and _tech not in _seen_tech:
            _seen_tech.add(_tech)
            pass_lines.append(f"  [{_oid}] {_tech}")
    pass_lines.append(f"  → 提取技术名用于变体池生成 ({len(_seen_tech)} 种技术)")
    pass_lines.append(f"• target_group: {ctx.target_group} → Converter 链选择")

    info_box("传递到自适应匹配", pass_lines)

    return True


async def _select_groups(ctx: PipelineContext) -> None:
    """4c: 交互式/自动选择"""
    tiered_cfg = ctx.config_loader.get_tiered_selection_config()
    tiered_enabled = tiered_cfg.get("enabled", True)
    interactive_cfg = ctx.config_loader.get_interactive_selection_config()
    interactive_enabled = ctx.config_loader.get_interactive_selection_enabled()

    if not tiered_enabled:
        # 旧版 SeedGroupSelector 路径
        print("  [OK] 选择模式: 旧版 SeedGroupSelector (向后兼容)")
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
        print(f"  [OK] 用户选择: {len(ctx.selected_groups)}/{len(ctx.all_seed_groups)} 个种子组")
        return

    # 三层渐进式选择路径
    preset_target = tiered_cfg.get("target_type")

    # 优先级：config target_type > recon target_type 推断 > 交互模式
    if not preset_target and ctx.target_type:
        from src.payloads.target_profile_router import TargetProfileRouter
        _inferred = TargetProfileRouter.infer_profile(recon_target_type=ctx.target_type)
        if _inferred.target_type != TargetType.FULL_SWEEP:
            preset_target = _inferred.target_type.value
            print(f"  [OK] 侦察推断目标类型: {ctx.target_type} → {preset_target}")

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
    else:
        wizard = TieredSelectionWizard(
            enabled=interactive_enabled,
            model_name=ctx.strategy_info.get("model_name", ctx.target_model),
        )

    selection_result = await wizard.select(ctx.all_seed_groups)
    ctx.selected_groups = selection_result.selected_groups
    ctx.fallback_strategy = selection_result.fallback_strategy
    ctx.fallback_chain = selection_result.fallback_chain
    ctx.planning_groups = ctx.selected_groups

    info_box("4c. 选择结果", [
        f"目标类型: {selection_result.target_profile.target_type.display_name}",
        f"选中: {len(ctx.selected_groups)}/{len(ctx.all_seed_groups)} 个种子组 "
        f"(top-{tiered_cfg.get('top_n', 3)})",
        f"降级策略: {ctx.fallback_strategy.display_name}",
    ])
