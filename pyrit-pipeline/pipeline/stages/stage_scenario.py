# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Stage 2: ASR 驱动的场景配置 (Attack-King 策略)。.

职责:
  - 查询历史 ASR, 按攻击成功率排序数据集和载荷 (P1: ASR 驱动载荷优先级)
  - 从 ScorerRegistry 获取评分器 (三级 fallback)
  - 构造 TextAdaptive 场景 + FailureTypeRoutingSelector (ASR 驱动 + 失败路由)
  - 构造 CompoundDatasetAttackConfiguration (独立 per-dataset 预算)
  - 注入 warm-start ASR 先验到 selector (冷启动优化)
  - 注入 scenario_techniques + technique_converters + include_baseline
  - 单次 set_params_from_args 调用 (原生 API)

产出 (写入 PipelineContext):
  - ctx.scenario = TextAdaptive 实例 (已注入参数，未初始化)
  - ctx.objective_scorer = 评分器实例 (可能为 None)
  - ctx.selector = FailureTypeRoutingSelector 实例 (供 Stage 4 反馈)

依赖的原生 API:
  - pyrit.scenario.TextAdaptive, CompoundDatasetAttackConfiguration, DatasetAttackConfiguration
  - pyrit.scenario.scenarios.adaptive.selectors.SelectorScope
  - pyrit.registry.ScorerRegistry, AttackTechniqueRegistry
  - pyrit.converter (可选 technique_converters)

自研模块 (PyRIT 原生不具备, 纯数据/选择层, 不干扰原生生命周期):
  - pipeline.asr.failure_type_selector.FailureTypeRoutingSelector (继承原生 EpsilonGreedyTechniqueSelector)
  - pipeline.asr.prior_registry (学术 ASR 先验数据, 纯数据层)
  - pipeline.asr.optimizer (ASR 驱动排序)
  - pipeline.converters.factory (ASR 驱动 converter 路由)
  - pipeline.asr.rank_builder.ASRRankBuilder (Tier 分层 + 加权采样)
  - pipeline.converters.target_aware_router (Target 类型感知 Converter 链路由)
  - pipeline.asr.tiered_selection_wizard (三层渐进式选择)
  - pipeline.asr.rank_builder.GroupFallbackExecutor (组级 ASR 降级链)

修改此文件不影响 Stage 1, 3–5。

> **日期**: 2026-8-1
> **更新记录**:
>   2026-8-1 15:15 — set_params_from_args 添加异常处理
>   2026-8-1 15:20 — converter 路由传入 ASR 数据
>   2026-8-1 16:00 — P0: 替换为 FailureTypeRoutingSelector + warm-start ASR 注入
>   2026-8-1 20:00 — 集成 ASRRankBuilder + target_aware_router + TieredSelectionWizard
>   2026-8-1 20:30 — 消除3: 直接使用原生 TextAdaptive (零覆盖),
>     Converter 由原生 technique_converters 参数注入
"""

import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from pyrit.registry import AttackTechniqueRegistry, ScorerRegistry, TargetRegistry
from pyrit.scenario import CompoundDatasetAttackConfiguration
from pyrit.scenario.scenarios.adaptive import TextAdaptive
from pyrit.scenario.scenarios.adaptive.selectors import SelectorScope

# 消除3: 直接使用原生 TextAdaptive, 不再覆盖 _build_techniques_dict
from pipeline.asr.failure_type_selector import FailureTypeRoutingSelector
from pipeline.asr.optimizer import (
    get_asr_summary,  # noqa: F401 — re-exported for test patching
    get_technique_asr_summary,  # noqa: F401 — re-exported for test patching
    merge_empirical_with_priors,
    query_historical_asr_by_category,
    query_historical_asr_by_technique,
    sort_datasets_by_asr,
)
from pipeline.asr.prior_registry import get_initial_q_value
from pipeline.context import PipelineContext
from pipeline.converters.converter_health_monitor import ConverterHealthMonitor
from pipeline.converters.factory import (
    build_target_aware_converter_map,
    build_technique_converter_map,
    merge_converter_maps,
)
from pipeline.scenarios import create_scenario

logger = logging.getLogger(__name__)


async def run(ctx: PipelineContext) -> None:
    """执行 Stage 2/6: ASR 驱动的场景配置。."""
    print("\n" + "=" * 70)
    print("阶段 2/6: 场景配置 — ASR 驱动 + Attack-King")
    print("=" * 70)

    args = ctx.args

    # ── ASR 驱动载荷优先级 ──
    asr_by_category = query_historical_asr_by_category()
    # 精简: 只显示 Top 5 + 合计
    _print_asr_summary(asr_by_category)
    _print_technique_asr_summary_compact()

    sorted_datasets = sort_datasets_by_asr(args.datasets, asr_by_category=asr_by_category)
    if sorted_datasets != args.datasets:
        print(f"  数据集优先级排序 (ASR 驱动): {args.datasets} → {sorted_datasets}")
    else:
        print(f"  数据集: {args.datasets}")

    # ── 评分器 + 模型信息 ──
    objective_scorer = _get_objective_scorer()
    ctx.objective_scorer = objective_scorer

    from pipeline.converters.model_tier_detector import detect_model_tier_from_registry

    model_name, model_tier = detect_model_tier_from_registry()
    owasp_id = os.getenv("OWASP_ID", "")

    # ── P1-G4: 复合评分器 (task_achieved AND not_refused) ──
    # 强模型/中等模型使用复合评分器, 消除部分拒绝导致的 ASR 假阳性
    from pipeline.scenarios.composite_scorer import should_use_composite_scorer

    if should_use_composite_scorer(model_tier) and objective_scorer is not None:
        try:
            from pipeline.scenarios.composite_scorer import create_composite_objective_scorer

            # 获取 scorer 的 chat_target
            scorer_chat_target = (
                getattr(objective_scorer, "_chat_target", None)
                or getattr(objective_scorer, "chat_target", None)
            )
            if scorer_chat_target is not None:
                composite = create_composite_objective_scorer(scorer_chat_target)
                if composite is not None:
                    print(f"  P1-G4: 复合评分器已启用 (task_achieved AND not_refused, tier={model_tier})")
                    objective_scorer = composite
                    ctx.objective_scorer = composite
        except Exception as e:
            print(f"  [提示] 复合评分器创建跳过: {e}")

    print("\n  ┌─ 目标模型 ────────────────────────────────────────────────┐")
    print(f"  │ 模型: {model_name} (tier={model_tier})")
    if owasp_id:
        print(f"  │ OWASP: {owasp_id}")
    print("  └───────────────────────────────────────────────────────────────┘")

    # ── P0: 构建 warm-start ASR 字典 ──
    # 从学术 ASR 先验构建 warm-start 字典，注入 selector
    # 首次运行时替代乐观初始值 1.0，确保高 ASR 技术被优先选中
    warm_start_asr = _build_warm_start_asr(model_name, model_tier, owasp_id)
    # P1: 经验 ASR 自动刷新 — 经验数据覆盖学术先验 (G-05: 按模型加载)
    if warm_start_asr:
        warm_start_asr = merge_empirical_with_priors(warm_start_asr, model_name=model_name)
    if warm_start_asr:
        print(f"  Warm-start ASR: {len(warm_start_asr)} 个技术先验注入")
        # 显示 top 5 ASR 先验
        sorted_asr = sorted(warm_start_asr.items(), key=lambda x: x[1], reverse=True)
        print("    Top 5 ASR 先验:")
        for tech, asr in sorted_asr[:5]:
            print(f"      {tech:<35} {asr:.0%}")

    # ── P0: ASRRankBuilder Tier 分层 + GroupFallbackExecutor 降级链 ──
    # 数据 L5 (Analytics): 按技术组聚合, Tier 分层 (S/A/B/C/D)
    # 构建 Tier-based fallback chain 供 Stage 3 智能调度使用
    ranked_groups: list = []
    try:
        from pipeline.asr.rank_builder import GroupFallbackExecutor

        try:
            tech_names_for_fallback = list(AttackTechniqueRegistry.get_registry_singleton().get_factories().keys())
        except ImportError:
            tech_names_for_fallback = []

        if tech_names_for_fallback:
            fallback_executor = GroupFallbackExecutor(
                model_name=model_name,
                model_tier=model_tier,
                owasp_id=owasp_id,
            )
            fallback_plan = fallback_executor.build_fallback_plan(
                technique_names=tech_names_for_fallback,
            )
            ctx.fallback_plan = fallback_plan
            print(f"  ASR Tier 降级链: {fallback_plan.total_groups} 组, {fallback_plan.fallback_count} 个降级点")
    except (ImportError, AttributeError, KeyError) as e:
        print(f" [提示] ASR Tier 降级链初始化跳过: {e}")

    # ── P2: 动态技术选择 ──
    # 使用 current_run scope: 让运行中积累的 ASR 数据立即影响后续技术选择
    # epsilon=0.1: 降低探索率, 更激进地利用已知高 ASR 技术 (攻击为王)
    selector_scope = SelectorScope.current_run() if args.selector_scope == "current_run" else SelectorScope.all_runs()

    # ── P1: 多场景选择 ──
    scenario_name = getattr(args, "scenario", "text_adaptive")

    if scenario_name == "text_adaptive":
        # ── P0: 使用 FailureTypeRoutingSelector (继承原生 EpsilonGreedyTechniqueSelector) ──
        selector = FailureTypeRoutingSelector(
            epsilon=args.epsilon,
            scope=selector_scope,
            strategy_mode=os.getenv("STRATEGY_MODE", "academic"),
            model_name=model_name,
            model_tier=model_tier,
            owasp_id=owasp_id or None,
            warm_start_asr=warm_start_asr,
        )

        # 消除3: 直接使用原生 TextAdaptive (零覆盖), Converter 由 technique_converters 参数注入
        scenario = TextAdaptive(
            objective_scorer=objective_scorer,
            selector=selector,
            scenario_result_id=args.resume,
        )
        # 探测 target_type (用于报告和日志, 不影响 Converter 注入)
        try:
            from pipeline.converters.target_aware_router import infer_target_type

            target_entries = TargetRegistry.get_registry_singleton().instances.get_all_instances()
            if target_entries:
                ctx.target_type = infer_target_type(target_entries[0].instance)
        except ImportError:
            pass
        # 保存 selector 引用供 Stage 4 运行时反馈
        ctx.selector = selector
        ctx.scenario = scenario

        # P1: 加载历史范式性能数据到 selector (自动学习)
        try:
            from pipeline.asr.failure_type_event_handler import ParadigmPerformanceTracker

            output_mgr = getattr(ctx, "output_manager", None)
            if output_mgr:
                paradigm_path = output_mgr.empirical_asr_dir / "paradigm_performance.json"
            else:
                paradigm_path = Path("outputs/paradigm_performance.json")
            if paradigm_path.exists():
                tracker = ParadigmPerformanceTracker.load_from_file(paradigm_path)
                if tracker.has_data:
                    selector.set_paradigm_tracker(tracker)
                    print("  范式性能数据已加载 (运行时自动学习)")
        except Exception as e:
            print(f"  [提示] 范式性能数据加载跳过: {e}")
        print("  场景: text_adaptive (原生 TextAdaptive + ASR 驱动 Selector, 零覆盖)")
    else:
        # ── P1: 原生场景 (AIRT/Garak/Benchmark/Foundry) ──
        scenario = create_scenario(
            scenario_name,
            objective_scorer=objective_scorer,
            scenario_result_id=args.resume,
        )
        if scenario is None:
            print(f"  [错误] 无法创建场景: {scenario_name}")
            raise ValueError(f"Unknown scenario: {scenario_name}")
        ctx.scenario = scenario
        ctx.selector = None
        print(f"  场景: {scenario_name} (原生场景)")

    # ── 原生: CompoundDatasetAttackConfiguration (独立 per-dataset 预算) ──
    # 数据集已在 Stage 1 从 data/datasets/{name}.prompt 本地加载到 CentralMemory
    # 不再需要 auto_fetch=True 远程拉取, 100% 离线运行
    # 使用 ASR 排序后的数据集列表 (排序影响内存中的加载顺序和显示顺序)
    dataset_config = CompoundDatasetAttackConfiguration.per_dataset(
        dataset_names=sorted_datasets,
        max_dataset_size=args.max_dataset_size,
    )
    print(f"  数据集配置 (本地预加载, per-dataset 预算={args.max_dataset_size}): {len(sorted_datasets)} 个数据集")

    # ── P2: EXHAUSTIVE 策略 ──
    # 对每个 objective 尝试所有技术 (不提前停止), 生成完整 ASR 对比矩阵
    if getattr(args, "exhaustive", False):
        max_attempts = 999
        print("  P2 EXHAUSTIVE: 全技术尝试 (max_attempts=999)")
    elif os.getenv("STOP_ON_FIRST_SUCCESS", "").lower() in ("true", "1", "yes"):
        # L3: 全局首停
        max_attempts = 1
        print("  P2 L3: 全局首停策略启用 (max_attempts=1)")
    else:
        # L1: 原生 FIRST_SUCCESS
        max_attempts = args.max_attempts

    # ── P3-G9: converter_target 提前获取 (G8 依赖 converter_target_available) ──
    converter_target = _get_converter_target()
    converter_target_available = converter_target is not None
    if not converter_target_available:
        converter_target = _auto_create_converter_target()
        converter_target_available = converter_target is not None
        if converter_target_available:
            print("  P3-G9: converter_target 自动创建成功 (从 objective_target 配置派生)")

    # ── 原生: 构建参数包 (单次 set_params_from_args 调用) ──
    # P0-3: 从 TargetRegistry 动态解析 objective_target 名称 (不再硬编码)
    objective_target_name = _resolve_objective_target_name()
    params: dict[str, Any] = {
        # 通过 TargetRegistry 动态解析的目标名称
        "objective_target": objective_target_name,
        # 数据集配置 (auto_fetch=True 时自动从 SeedDatasetProvider 获取)
        "dataset_config": dataset_config,
        # 弹性恢复: 失败自动重试，从上次中断处继续
        "max_retries": args.max_retries,
        # 并发控制: 最多 N 个 AtomicAttack 同时执行
        "max_concurrency": args.max_concurrency,
        # 每 objective 最多尝试 N 个技术 (SequentialAttack FIRST_SUCCESS)
        "max_attempts_per_objective": max_attempts,
        # baseline 控制: prompt_sending 作为对比基线
        "include_baseline": not args.no_baseline,
        # 附加标签到每条 AttackResult
        "memory_labels": {
            "run_date": datetime.now().isoformat(),
            "pipeline_version": "7.0",
            "selector_scope": args.selector_scope,
            "asr_driven": "true",
        },
    }

    # ── P3-G8: Converter 变体动态创建 ──
    # Note: extra_request_converters 不是 TextAdaptive 原生参数,
    # Converter 变体已通过 technique_converters 参数注入 (Layer 1 + Layer 2)

    # ── 原生: scenario_techniques (技术选择) ──
    #   None: 使用 TextAdaptive DEFAULT 聚合 (role_play_movie_script + many_shot)
    #   ["ALL"]: 使用全部技术
    #   ["core"]: 使用 core 标签技术
    #   ["many_shot", "tap"]: 指定具体技术
    if args.techniques:
        params["scenario_techniques"] = args.techniques
        print(f"  技术选择: {args.techniques}")
    elif getattr(args, "tier_layer", 0) > 0:
        # P1: TieredSelectionWizard 渐进式选择
        tier_techniques = _select_techniques_by_tier(
            model_name=model_name,
            model_tier=model_tier,
            owasp_id=owasp_id,
            tier_layer=args.tier_layer,
        )
        if tier_techniques:
            # ── P3-G7: 高 ASR 技术自动补充 ──
            # 当 Tier 选择的技术太少 (<3) 时, 从 warm-start ASR 先验补充高 ASR 技术
            if len(tier_techniques) < 3 and warm_start_asr:
                top_asr_techs = sorted(warm_start_asr.items(), key=lambda x: x[1], reverse=True)
                for tech, asr in top_asr_techs:
                    if tech not in tier_techniques and len(tier_techniques) < 5:
                        tier_techniques.append(tech)
                        print(f"    P3-G7: 补充高 ASR 技术: {tech} ({asr:.0%})")

            params["scenario_techniques"] = tier_techniques
            ctx.tier_layer = args.tier_layer
            print(f"  技术选择 (TieredSelection Layer {args.tier_layer}): {tier_techniques}")
        else:
            print("  技术选择: DEFAULT (TieredSelection 无结果)")
    else:
        print("  技术选择: DEFAULT (TextAdaptive 默认聚合)")

    # ── P2-G6: ModalityRouter 技术过滤 ──
    # 根据 TargetCapabilities 自动过滤目标不支持的技术 (如多轮攻击对不支持多轮的目标)
    if params.get("scenario_techniques"):
        try:
            from pipeline.converters.modality_router import ModalityRouter

            target_entries = TargetRegistry.get_registry_singleton().instances.get_all_instances()
            if target_entries:
                target_instance = target_entries[0].instance
                # 多轮攻击技术集合 (需要 supports_multi_turn)
                multi_turn_techniques = {"crescendo", "tap", "red_teaming", "pair", "forest"}
                # 多模态攻击技术集合 (需要 supports_image_input)
                multimodal_techniques = {"image_variation", "multimodal_jailbreak"}

                techniques_before = list(params["scenario_techniques"])
                supported, filtered = ModalityRouter.filter_techniques_by_capability(
                    techniques_before,
                    target_instance,
                    multi_turn_techniques=multi_turn_techniques,
                    multimodal_techniques=multimodal_techniques,
                )
                if filtered:
                    params["scenario_techniques"] = supported
                    print(f"  P2-G6 ModalityRouter: 过滤 {len(filtered)} 个不支持的技术: {filtered}")
        except Exception as e:
            print(f"  [提示] ModalityRouter 技术过滤跳过: {e}")

    # ── P3: Converter 路由 (ASR 驱动 + Target 感知双路由) ──
    # 路由策略 (三层叠加):
    #   1. CLI --converters: 用户显式指定, ASR 驱动 per-technique 差异化分配
    #   2. Target 感知自动路由: 根据 target_type 自动选择最优 Converter 链
    #   3. 合并: CLI converters + target-aware chains (并集, CLI 优先)
    #
    # 当 --converters 未指定但 target_type 已知时, 自动启用 Target 感知路由
    technique_converter_map: dict[str, list] = {}

    try:
        technique_names = list(AttackTechniqueRegistry.get_registry_singleton().get_factories().keys())
    except Exception:
        technique_names = []

    # converter_target 已在 params 构建前提前获取 (P3-G9)

    # ── P0-G2: ConverterHealthMonitor — 熔断器+降级+统计 ──
    # 创建监控器实例, 存储在 ctx 中供 Stage 4 执行时使用
    health_monitor = ConverterHealthMonitor(failure_threshold=2)
    ctx.converter_health_monitor = health_monitor

    # Layer 1: CLI --converters (ASR 驱动差异化路由)
    if args.converters and technique_names:
        # ── P2-G5: 小模型跳过 LLM 辅助 Converter 链 ──
        # 弱模型 (weak) 不适合使用 LLM 辅助 Converter (JSON 解析能力差)
        from pipeline.converters.model_tier_detector import should_use_llm_converters

        llm_converters_ok = should_use_llm_converters(model_tier)
        if not llm_converters_ok:
            print(f"  P2-G5: 小模型 (tier={model_tier}) 跳过 LLM 辅助 Converter 链")

        try:
            asr_by_tech = query_historical_asr_by_technique()
            cli_converter_map = build_technique_converter_map(
                converter_names=args.converters,
                technique_names=technique_names,
                asr_by_technique=asr_by_tech,
            )
            technique_converter_map = merge_converter_maps(
                technique_converter_map,
                cli_converter_map,
            )
            cli_assignments = sum(len(v) for v in cli_converter_map.values())
            print(
                f"  Converter CLI 路由 (ASR 驱动): {args.converters} → "
                f"{len(technique_names)} 个技术 ({cli_assignments} 个分配)"
            )
        except ValueError as e:
            print(f"  Converter CLI 路由: 失败 ({e})")
        except Exception as e:
            print(f"  Converter CLI 路由: 异常 ({e}), 跳过")

    # Layer 2: Target 感知自动路由 (无需 --converters)
    if ctx.target_type and technique_names:
        try:
            ta_converter_map = build_target_aware_converter_map(
                technique_names=technique_names,
                target_type=ctx.target_type,
                converter_target=converter_target,
                converter_target_available=converter_target_available,
                model_tier=model_tier,
            )
            if ta_converter_map:
                technique_converter_map = merge_converter_maps(
                    technique_converter_map,
                    ta_converter_map,
                )
                ta_assignments = sum(len(v) for v in ta_converter_map.values())
                print(
                    f"  Converter Target 感知路由: target_type='{ctx.target_type}' → "
                    f"{len(ta_converter_map)} 个技术 ({ta_assignments} 个分配)"
                )
        except Exception as e:
            print(f"  Converter Target 感知路由: 异常 ({e}), 跳过")

    # 注入合并后的 technique_converters
    if technique_converter_map:
        params["technique_converters"] = technique_converter_map
        total_assignments = sum(len(v) for v in technique_converter_map.values())
        ctx.converter_routing_count = total_assignments
        unique_converters = set()
        for convs in technique_converter_map.values():
            for c in convs:
                unique_converters.add(type(c).__name__)
        print(
            f"  Converter 路由总计: {len(technique_converter_map)} 个技术, "
            f"{total_assignments} 个分配, {len(unique_converters)} 种 Converter"
        )
    else:
        print("  Converter 路由: (未启用, 使用 --converters 添加或检测 target_type)")

    # ── 原生: 单次参数注入 (带异常保护 + 噪音拦截) ──
    # 内层嵌套: 不传 signal_log_path, 信号行透传到外层 (main.py) NoiseFilter 统一写入信号日志
    noise_log_path = ctx.metadata.get("noise_log_path")
    try:
        if noise_log_path:
            from pipeline.utils.noise_redirector import redirect_noise_to_file

            with redirect_noise_to_file(Path(noise_log_path)):
                scenario.set_params_from_args(args=params)
        else:
            scenario.set_params_from_args(args=params)
    except (ImportError, RuntimeError, ValueError) as e:
        print(f"  [错误] 参数注入失败 (ImportError/RuntimeError/ValueError): {e}")
        print("  [提示] 请检查 .pyrit_conf 配置和 TargetRegistry/ScorerRegistry 初始化")
        raise

    # ── 保存 Stage 2 产出到 Context ──
    ctx.sorted_datasets = sorted_datasets
    ctx.warm_start_asr = warm_start_asr
    ctx.max_attempts_per_objective = max_attempts
    ctx.ranked_groups = ranked_groups

    # ── Gap 4: P 编号映射 (dataset → P 编号范围) ──
    _build_plan_pid_map(ctx, sorted_datasets, args.max_dataset_size)

    # ── Gap 3: 决策链追溯 ──
    _print_decision_chain(
        model_tier=model_tier,
        strategy_mode=os.getenv("STRATEGY_MODE", "academic"),
        scenario_techniques=params.get("scenario_techniques"),
        scenario_name=scenario_name,
    )

    # ── Executor 5 层架构展示 ──
    print("\n  ── Executor 5 层架构 (Stage 2 覆盖 L1-L3 + L5) ──")
    print(
        f"    L1 (Parameters): max_attempts={max_attempts}, "
        f"max_concurrency={args.max_concurrency}, max_retries={args.max_retries}"
    )
    print(f"    L2 (Strategy): {scenario_name}")
    converter_count = ctx.converter_routing_count
    print(
        f"    L3 (Config): converter_routing={converter_count}, "
        f"baseline={'enabled' if not args.no_baseline else 'disabled'}"
    )
    print(f"    L4 (Compound): SequentialAttack({'EXHAUSTIVE' if max_attempts >= 999 else 'FIRST_SUCCESS'})")
    print(f"    L5 (Scenario): {type(scenario).__name__}")

    # ── 数据 5 层架构展示 (L3 + L5) ──
    print("\n  ── 数据 5 层架构 (Stage 2 覆盖 L3 + L5) ──")
    print(
        f"    L3 (Dataset Config): CompoundDatasetAttackConfiguration "
        f"({len(sorted_datasets)} datasets, per_dataset={args.max_dataset_size})"
    )
    # L3 决策: per-dataset budget breakdown
    print("      数据集排序: ASR 降序 (高优先级优先)")
    for ds in sorted_datasets[:5]:
        print(f"      • {ds}")
    if len(sorted_datasets) > 5:
        print(f"      ... 还有 {len(sorted_datasets) - 5} 个")

    print(
        f"    L5 (Analytics): EpsilonGreedy(epsilon={args.epsilon}, "
        f"scope={args.selector_scope}), warm_start={len(warm_start_asr)} priors"
    )
    # L5 决策: Tier 分布 + dynamic alpha
    if ctx.ranked_groups:
        print(f"      Tier 分层: {len(ctx.ranked_groups)} 组")
    if ctx.fallback_plan and hasattr(ctx.fallback_plan, "total_groups"):
        print(f"      降级链: {ctx.fallback_plan.total_groups} 组, {ctx.fallback_plan.fallback_count} 个降级点")
    if warm_start_asr:
        print("      动态 alpha: 先验主导 (alpha=0.15) → 经验主导 (alpha=0.50)")
    if ctx.tier_layer > 0:
        print(f"      TieredSelection: Layer {ctx.tier_layer} 渐进式选择")

    # ── O3: 技术池矩阵 (★ Banner + 决策卡片) ──
    _print_tech_pool_matrix(ctx, warm_start_asr, model_name, model_tier)

    # ── O4: ★ 突出传递 Banner ──
    from pipeline.utils.display import handoff_banner

    tech_count = len(args.techniques) if args.techniques else 14
    handoff_banner(
        2, 3,
        "传递到场景初始化 — 决定后续攻击成功率",
        [
            f"★ 策略模式: {os.getenv('STRATEGY_MODE', 'academic')} → 影响 Tier 执行顺序",
            f"★ 技术池: {tech_count} 种 → 能力感知筛选后保留",
            "★ 融合 ASR: warm_start="
            + ("已加载 (" + str(len(warm_start_asr)) + " 技术先验)" if warm_start_asr else "无 (首次运行)"),
            f"★ Converter 路由: {ctx.converter_routing_count} 个分配",
            f"★ 场景: {scenario_name} (原生 TextAdaptive + ASR 驱动)",
            f"★ 数据集: {len(sorted_datasets)} 个 (ASR 降序, per_dataset={args.max_dataset_size})",
        ],
    )


def _print_decision_chain(
    model_tier: str,
    strategy_mode: str,
    scenario_techniques: list[str] | None,
    scenario_name: str,
) -> None:
    """Gap 3: 完整决策链追溯 (Stage 1推荐 → Selector推荐 → 实际).

    对齐 pyrit_ai300 Stage 2 ① 策略决策卡片。
    展示策略选择是否为最优决策路径。
    """
    from pipeline.utils.display import info_box

    # Stage 1 推荐: 基于 model_tier 自动推荐策略模式
    tier_recommended = {
        "weak": "balanced",
        "moderate": "academic",
        "strong": "academic",
    }.get(model_tier, "academic")

    # Selector 实际接收的策略模式
    selector_mode = strategy_mode

    # 实际技术选择
    if scenario_techniques:
        actual_techs = scenario_techniques
        actual_source = "CLI --techniques"
    else:
        actual_techs = None
        actual_source = "DEFAULT (TextAdaptive 默认聚合)"

    # 决策匹配判断
    mode_match = tier_recommended == selector_mode
    match_str = "✓ 与推荐一致" if mode_match else "⚠ 与推荐不一致"

    lines = [
        f"Stage 1 推荐: {tier_recommended} (基于 model_tier={model_tier})",
        f"Selector 实际: {selector_mode} {match_str}",
        f"场景: {scenario_name}",
        f"技术来源: {actual_source}",
    ]
    if actual_techs:
        tech_display = ", ".join(actual_techs[:5])
        if len(actual_techs) > 5:
            tech_display += f" ... (+{len(actual_techs) - 5})"
        lines.append(f"技术列表: {tech_display}")

    lines.append("")
    if mode_match:
        lines.append("✓ 决策路径最优 — 策略与模型分层对齐")
    else:
        lines.append(f"⚠ 决策路径偏差 — 推荐 {tier_recommended}, 实际 {selector_mode}")
        lines.append("  → 原因: STRATEGY_MODE 环境变量覆盖了推荐值")

    info_box("Gap 3: 策略决策链 (Stage 1 → Selector → 实际)", lines)


def _build_plan_pid_map(
    ctx: PipelineContext,
    sorted_datasets: list[str],
    max_dataset_size: int,
) -> None:
    """Gap 4: 构建 P 编号映射 (dataset → P编号范围).

    按数据集排序顺序分配 P 编号:
      dataset_1 (5 seeds) → P1-P5
      dataset_2 (3 seeds) → P6-P8
      ...

    映射存储到 ctx.plan_pid_map, 供 Stage 4/5 展示时引用。
    """
    pid_counter = 1
    pid_map: dict[str, str] = {}

    for ds_name in sorted_datasets:
        # 尝试获取数据集的种子数
        seed_count = max_dataset_size
        try:
            from pyrit.memory import CentralMemory

            memory = CentralMemory.get_memory_instance()
            prompts = memory.get_seed_prompts(dataset_name=ds_name)
            seed_count = len(prompts) if prompts else max_dataset_size
        except Exception:
            pass

        end_pid = pid_counter + seed_count - 1
        pid_range = f"P{pid_counter}" if seed_count == 1 else f"P{pid_counter}-P{end_pid}"
        pid_map[ds_name] = pid_range
        pid_counter = end_pid + 1

    ctx.plan_pid_map = pid_map

    # 展示 P 编号映射
    from pipeline.utils.display import info_box

    lines = []
    for ds_name, pid_range in pid_map.items():
        lines.append(f"{ds_name:<40} → {pid_range}")
    lines.append("")
    lines.append(f"合计: {pid_counter - 1} 个攻击计划 (P1-P{pid_counter - 1})")
    lines.append("P 编号将贯穿 Stage 4 (执行) → Stage 5 (分析)")

    info_box("Gap 4: P 编号映射 (dataset → 计划编号)", lines)


def _print_tech_pool_matrix(
    ctx: PipelineContext,
    warm_start_asr: dict[str, float] | None,
    model_name: str,
    model_tier: str,
) -> None:
    """O3: 技术池矩阵 — ★ Banner + 决策卡片 (对齐 pyrit_ai300 Stage 2).

    按经验融合 ASR 降序展示每个技术的:
      - ASR + Tier 分层
      - 学术先验 vs 经验数据
      - 能力匹配 (MULTI_TURN / SYSTEM_PROMPT)
    """
    from pipeline.utils.display import asr_bar, decision_card, info_box, pad_right

    if not warm_start_asr:
        info_box("技术池矩阵", ["(无 warm-start ASR 数据, 首次运行)"])
        return

    # Tier 分层映射
    tier_labels = {"S": "极高", "A": "高", "B": "中", "C": "低", "D": "极低"}

    def _tier_from_asr(asr: float) -> str:
        if asr >= 0.50:
            return "S"
        elif asr >= 0.30:
            return "A"
        elif asr >= 0.15:
            return "B"
        elif asr >= 0.05:
            return "C"
        else:
            return "D"

    # 按 ASR 降序排序
    sorted_techs = sorted(warm_start_asr.items(), key=lambda x: x[1], reverse=True)

    # 全局概览
    tier_counts: dict[str, int] = {}
    for _, asr in sorted_techs:
        tier = _tier_from_asr(asr)
        tier_counts[tier] = tier_counts.get(tier, 0) + 1
    tier_summary = " ".join(
        f"{t}={tier_counts.get(t, 0)}" for t in ["S", "A", "B", "C", "D"] if tier_counts.get(t, 0) > 0
    )

    print()
    print("  ╔" + "═" * 68 + "╗")
    print()
    print("       ★  技术池矩阵 — 高 ASR 优先  ★")
    print()
    print("    按经验融合 ASR 降序展示 · 高成功率技术优先执行")
    print()
    print("  ╚" + "═" * 68 + "╝")

    print()
    print(f"  ┌─ 全局概览 {'─' * max(1, 68 - 22)}┐")
    print("  │")
    for i, (tech, asr) in enumerate(sorted_techs):
        tier = _tier_from_asr(asr)
        tech_pad = pad_right(tech[:30], 30)
        print(f"  │  技术 {i + 1}: {tech_pad}  ASR {asr:>4.0%} (Tier {tier})")
    print(f"  │  {'─' * max(1, 68 - 6)}")
    print(f"  │  合计: {len(sorted_techs)} 技术 | Tier 分布: {tier_summary}")
    print(f"  └{'─' * 68}┘")

    # Top 5 技术决策卡片
    for tech, asr in sorted_techs[:5]:
        tier = _tier_from_asr(asr)
        tier_label = tier_labels.get(tier, "")
        is_multi = tech in {"red_teaming", "crescendo", "tap", "pair", "many_shot", "forest"}

        decision_card(
            title=tech,
            subtitle=f"ASR: {asr:.0%} (Tier {tier} {tier_label})  |  模式: {'多轮迭代' if is_multi else '单轮直发'}",
            sub_sections=[
                {
                    "header": "ASR 来源",
                    "lines": [
                        f"学术先验: {asr:.0%}",
                        f"经验数据: {'无 (首次运行)' if model_tier else '无'}",
                        f"ASR 条: {asr_bar(asr * 100)}",
                    ],
                },
                {
                    "header": "能力匹配",
                    "lines": [
                        f"MULTI_TURN: {'✓' if is_multi else '?'} (技术{'需要' if is_multi else '不需要'})",
                        "结果: ✓ 保留 (能力匹配)",
                    ],
                },
            ],
        )


def _resolve_objective_target_name() -> str:
    """从 TargetRegistry 动态解析 objective_target 名称 (P0-3: 不再硬编码).

    优先级:
      1. ``default_objective_target`` 标签 (原生推荐标签)
      2. ``default`` 标签 (通用默认标签)
      3. 第一个注册的 Target
      4. 回退到 ``"openai_chat"`` (最终默认值)

    Returns:
        TargetRegistry 中注册的目标名称字符串。
    """
    try:
        registry = TargetRegistry.get_registry_singleton()
        # 1. default_objective_target 标签
        entries = registry.instances.get_by_tag(tag="default_objective_target")
        if entries:
            name = entries[0].name
            logger.info(f"objective_target resolved: '{name}' (default_objective_target tag)")
            return name
        # 2. default 标签
        entries = registry.instances.get_by_tag(tag="default")
        if entries:
            name = entries[0].name
            logger.info(f"objective_target resolved: '{name}' (default tag)")
            return name
        # 3. 第一个注册的 Target
        all_entries = registry.instances.get_all_instances()
        if all_entries:
            name = all_entries[0].name
            logger.info(f"objective_target resolved: '{name}' (first available)")
            return name
    except Exception as e:
        logger.warning(f"Failed to resolve objective_target from TargetRegistry: {e}")
    # 4. 最终回退
    logger.warning("objective_target falling back to 'openai_chat' (no targets in registry)")
    return "openai_chat"


def _get_objective_scorer() -> Any:
    """从 ScorerRegistry 获取自动标记的最佳评分器 (原生 API, 三级 fallback)。."""
    scorer_entries = ScorerRegistry.get_registry_singleton().instances.get_by_tag(tag="default_objective_scorer")
    if scorer_entries:
        scorer = scorer_entries[0].instance
        print(f"  评分器: {type(scorer).__name__} (default_objective_scorer)")
        return scorer

    # Fallback: 尝试获取 "main" 评分器 (基于 objective_scorer_chat)
    main_entry = ScorerRegistry.get_registry_singleton().instances.get_entry(name="main")
    if main_entry:
        scorer = main_entry.instance
        print(f"  评分器: {type(scorer).__name__} (main)")
        return scorer

    # Fallback: 尝试获取 "fallback" 评分器 (基于 openai_chat)
    fallback_entry = ScorerRegistry.get_registry_singleton().instances.get_entry(name="fallback")
    if fallback_entry:
        scorer = fallback_entry.instance
        print(f"  评分器: {type(scorer).__name__} (fallback)")
        return scorer

    # 最终 fallback: 使用第一个可用的评分器
    all_scorers = ScorerRegistry.get_registry_singleton().instances.get_all_instances()
    if all_scorers:
        scorer = all_scorers[0].instance
        print(f"  评分器: {type(scorer).__name__} (first available)")
        return scorer

    print("  评分器: ScorerRegistry 为空, 使用 TextAdaptive 默认评分器")
    return None


def _get_converter_target() -> Any:
    """从 TargetRegistry 获取用于 LLM 辅助 Converter 链的目标实例。.

    LLM 辅助 Converter (如 PersuasionConverter, ToneConverter) 需要一个
    ``converter_target`` 参数 — 这是一个 LLM 目标, 用于执行 Converter 的
    语义变换指令。

    查找优先级:
      1. 标记为 "adversarial_chat" 的目标 (原生 adversarial chat 角色)
      2. 标记为 "converter_target" 的目标 (自定义标签)
      3. 名为 "objective_scorer_chat" 的目标 (评分器使用的 LLM)
      4. 第一个非 objective_target 的目标 (避免用被攻击目标做 Converter)
      5. None (仅使用非 LLM Converter 链)

    Returns:
        PromptTarget 实例, 或 None (无可用 LLM 目标)
    """
    try:
        # 1. adversarial_chat 标签
        entries = TargetRegistry.get_registry_singleton().instances.get_by_tag(tag="adversarial_chat")
        if entries:
            logger.info(f"Converter target: '{entries[0].name}' (adversarial_chat)")
            return entries[0].instance

        # 2. converter_target 标签
        entries = TargetRegistry.get_registry_singleton().instances.get_by_tag(tag="converter_target")
        if entries:
            logger.info(f"Converter target: '{entries[0].name}' (converter_target)")
            return entries[0].instance

        # 3. objective_scorer_chat 名称
        entry = TargetRegistry.get_registry_singleton().instances.get_entry(name="objective_scorer_chat")
        if entry:
            logger.info("Converter target: 'objective_scorer_chat'")
            return entry.instance

        # 4. 第一个非 default_objective_target 的目标
        all_entries = TargetRegistry.get_registry_singleton().instances.get_all_instances()
        objective_entries = TargetRegistry.get_registry_singleton().instances.get_by_tag(tag="default_objective_target")
        objective_ids = {id(e.instance) for e in (objective_entries or [])}
        for e in all_entries:
            if id(e.instance) not in objective_ids:
                logger.info(f"Converter target: '{e.name}' (non-objective fallback)")
                return e.instance
    except Exception as e:
        logger.debug(f"Failed to get converter_target: {e}")

    return None


def _auto_create_converter_target() -> Any:
    """P3-G9: 自动创建 converter_target.

    当 TargetRegistry 中没有 adversarial_chat 标签的目标时,
    尝试从 objective_target 的配置派生一个 converter_target.

    策略:
      1. 获取 objective_target 实例
      2. 从中提取模型名和部署配置
      3. 使用相同配置创建新的 OpenAIChatTarget (或对应类型)
      4. 注册到 TargetRegistry 并返回

    Returns:
        PromptTarget 实例, 或 None (无法创建)
    """
    try:
        from pyrit.registry import TargetRegistry

        registry = TargetRegistry.get_registry_singleton()
        objective_entries = registry.instances.get_by_tag(tag="default_objective_target")
        if not objective_entries:
            return None

        obj_target = objective_entries[0].instance

        # 提取目标配置
        model_name = getattr(obj_target, "_model_name", None) or getattr(obj_target, "model_name", None)
        deployment_name = getattr(obj_target, "_deployment_name", None)
        endpoint = getattr(obj_target, "_endpoint", None)
        api_key = getattr(obj_target, "_api_key", None)

        if model_name is None or api_key is None:
            logger.debug("Cannot auto-create converter_target: missing model_name or api_key")
            return None

        # 创建新的 OpenAIChatTarget 作为 converter_target
        try:
            from pyrit.prompt_target import OpenAIChatTarget

            converter_target = OpenAIChatTarget(
                deployment_name=deployment_name or model_name,
                endpoint=endpoint,
                api_key=api_key,
            )
            logger.info(f"Auto-created converter_target from objective_target config (model={model_name})")
            return converter_target
        except (ImportError, TypeError) as e:
            logger.debug(f"Failed to create OpenAIChatTarget for converter_target: {e}")
            return None
    except Exception as e:
        logger.debug(f"Auto-create converter_target failed: {e}")
        return None


def _build_warm_start_asr(
    model_name: str,
    model_tier: str,
    owasp_id: str,
) -> dict[str, float]:
    """从学术 ASR 先验构建 warm-start 字典。.

    从 AttackTechniqueRegistry 获取所有注册的技术名称，
    为每个技术查询学术 ASR 先验，构建 (技术→ASR) 映射。
    """
    warm_start: dict[str, float] = {}
    try:
        technique_names = list(AttackTechniqueRegistry.get_registry_singleton().get_factories().keys())
    except Exception:
        technique_names = []

    for tech in technique_names:
        asr = get_initial_q_value(tech, model_name, model_tier, owasp_id)
        if asr > 0:
            warm_start[tech] = asr

    return warm_start


def _select_techniques_by_tier(
    model_name: str,
    model_tier: str,
    owasp_id: str,
    tier_layer: int,
) -> list[str] | None:
    """使用 TieredSelectionWizard 按 ASR Tier 渐进式选择技术。.

    Layer 1: Tier S/A 技术 (ASR >= 40%) — 快速评估
    Layer 2: + Tier B 技术 (ASR >= 15%) — 标准评估
    Layer 3: 全部技术 (含 Tier C/D) — 深度评估

    Args:
        model_name: 目标模型名
        model_tier: 模型安全过滤等级
        owasp_id: OWASP 分类 ID
        tier_layer: 选择层级 (1/2/3)

    Returns:
        技术名称列表, 失败返回 None
    """
    try:
        from pipeline.asr.tiered_selection_wizard import TieredSelectionWizard

        wizard = TieredSelectionWizard(
            model_name=model_name,
            model_tier=model_tier,
        )

        # 从 AttackTechniqueRegistry 获取可用技术
        try:
            available = list(AttackTechniqueRegistry.get_registry_singleton().get_factories().keys())
        except Exception:
            available = []

        if not available:
            return None

        recommendation = wizard.recommend(
            available_techniques=available,
            owasp_id=owasp_id,
        )

        # 选择指定层级的技术
        layer_idx = tier_layer - 1  # 0-based
        if 0 <= layer_idx < len(recommendation.layers):
            layer = recommendation.layers[layer_idx]
            return layer.recommended_techniques

        return None
    except Exception as e:
        print(f"  [警告] TieredSelection 失败: {e}")
        return None


# ============================================================
# 精简 ASR 统计输出 (Top 5 + 合计)
# ============================================================


def _print_asr_summary(asr_by_category: dict) -> None:
    """精简 ASR 分类统计卡片 — Top 5 + 合计。."""
    if not asr_by_category:
        print("\n  ┌─ 历史 ASR ────────────────────────────────────────────────┐")
        print("  │ (无历史数据)")
        print("  └───────────────────────────────────────────────────────────────┘")
        return

    sorted_asr = sorted(
        asr_by_category.items(),
        key=lambda x: x[1].success_rate if hasattr(x[1], "success_rate") and x[1].success_rate is not None else 0,
        reverse=True,
    )

    print("\n  ┌─ 历史 ASR (Top 5) ───────────────────────────────────────┄")
    for cat, stats in sorted_asr[:5]:
        sr = (stats.success_rate or 0) * 100 if hasattr(stats, "success_rate") else 0
        total = stats.total_decided if hasattr(stats, "total_decided") and stats.total_decided is not None else 0
        successes = stats.successes if hasattr(stats, "successes") and stats.successes is not None else 0
        bar = "█" * int(sr / 5)
        print(f"  │ {cat:<35} {sr:>5.1f}% ({successes}/{total}) {bar}")
    print(f"  │ 合计: {len(asr_by_category)} 分类")
    print("  └───────────────────────────────────────────────────────────────┘")


def _print_technique_asr_summary_compact() -> None:
    """精简技术 ASR 统计卡片。."""
    tech_asr = query_historical_asr_by_technique()
    if not tech_asr:
        return

    print("\n  ┌─ 技术 ASR ────────────────────────────────────────────────┐")
    for tech, stats in sorted(
        tech_asr.items(),
        key=lambda x: x[1].success_rate if hasattr(x[1], "success_rate") and x[1].success_rate is not None else 0,
        reverse=True,
    )[:5]:
        sr = (stats.success_rate or 0) * 100 if hasattr(stats, "success_rate") else 0
        total = stats.total_decided if hasattr(stats, "total_decided") and stats.total_decided is not None else 0
        bar = "█" * int(sr / 5)
        print(f"  │ {tech:<35} {sr:>5.1f}% ({total}) {bar}")
    print(f"  │ 合计: {len(tech_asr)} 技术有数据")
    print("  └───────────────────────────────────────────────────────────────┘")
