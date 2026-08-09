# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Stage 3: 场景初始化 + ASR 驱动的智能调度 + 同次运行 ASR 反馈闭环。.

职责:
  - 调用 ``scenario.initialize_async()`` 构建 AtomicAttack + SequentialAttack
  - **P1-闭环: 同次运行 ASR 反馈** — 查询当前运行中已完成的 AttackResult ASR,
    写入 ``ctx.metadata["current_run_asr"]`` 供后续阶段使用
    (实现 Stage 3 → Stage 2/4 的动态调参闭环)
  - P4: 初始化后, 按 ASR 优先级重排 AtomicAttack 执行顺序
    (高 ASR 的攻击优先执行, 快速获取结果信号)

产出 (写入 PipelineContext):
  - ctx.metadata["current_run_asr"] = 当前运行 ASR 统计 (dict)
  - 无新字段 (scenario 内部状态已更新)

依赖的原生 API:
  - TextAdaptive.initialize_async() (间接调用 _build_atomic_attacks_async)
  - pipeline.asr.optimizer (ASR 驱动排序 + 同次运行反馈)

修改此文件不影响 Stage 1–2, 4–6。

> **日期**: 2026-8-1
> **更新记录**:
>   2026-8-8 — 红队视角展示: 新增攻击装弹清单 + 决策过滤摘要 + Converter 链总览 + handoff 增强
>   2026-8-1 15:25 — 添加同次运行 ASR 反馈闭环 (query_current_run_asr_by_technique)
>   2026-8-1 22:00 — P0-1: 修复 _feedback_current_run_asr() 死代码, 在 run() 中调用
>   2026-8-1 22:00 — P1-5: 消除直接访问 scenario._atomic_attacks, 使用 getattr/setattr
"""

import hashlib
import logging
from typing import Any

from pipeline.analysis.technique_name_mapper import map_class_name_to_technique
from pipeline.asr.optimizer import (  # noqa: F401 — re-exported for test patching
    get_current_run_asr_summary,
    query_current_run_asr_by_technique,
    query_historical_asr_by_technique,
)
from pipeline.context import PipelineContext
from pipeline.utils.display import core_card, info_box, trunc

logger = logging.getLogger(__name__)


async def run(ctx: PipelineContext) -> None:
    """执行 Stage 3/6: 场景初始化 + ASR 智能调度。."""
    print("\n" + "=" * 70)
    print("阶段 3/6: 场景初始化 — ASR 智能调度 + AtomicAttack 构建")
    print("=" * 70)

    # ── 原生: 场景初始化 ──
    # G1 修复: initialize_async 内部会校验 objective hash 唯一性,
    # 跨数据集重复 seed 会导致 baseline AtomicAttack 校验失败.
    # 策略: 先正常初始化, 若遇 duplicate hash 错误则关闭 baseline 重试
    try:
        await ctx.scenario.initialize_async()
    except ValueError as e:
        if "duplicate objective hash" in str(e):
            print("  [G1 修复] 检测到跨数据集重复 objective hash, 关闭 baseline 重试...")
            # 修改 scenario 参数: 关闭 baseline
            params = getattr(ctx.scenario, "params", None) or getattr(ctx.scenario, "_params", None) or {}
            params = {"include_baseline": False} if not params else dict(params)
            params["include_baseline"] = False
            try:
                ctx.scenario.set_params_from_args(args=params)
                await ctx.scenario.initialize_async()
                print("  [G1 修复] baseline 关闭后初始化成功")
            except Exception as e2:
                print(f"  [G1 修复] 关闭 baseline 后仍失败: {e2}")
                raise
        else:
            raise

    raw_attack_count = len(getattr(ctx.scenario, "_atomic_attacks", []))
    atomic_attacks = getattr(ctx.scenario, "_atomic_attacks", [])

    # ── P0-G1: SHA256 跨数据集种子去重 ──
    # 跨数据集可能存在相同 objective 的种子, 导致 AtomicAttack 校验失败
    # 在重排序前去重, 保留首次出现的种子
    atomic_attacks = _dedup_atomic_attacks(atomic_attacks)

    # ── O5: DoS 攻击运行时拦截 (双重保险第二层) ──
    # 即使数据集被加载到 CentralMemory, 此处检查 AtomicAttack 的 objective,
    # 过滤掉 DoS 攻击载荷 (如 "Repeat the following text exactly 1000 times")
    if not getattr(ctx.args, "enable_dos_attack", False):
        _dos_signatures = [
            "repeat the following text exactly",
            "repeat exactly 1000 times",
            "unbounded consumption",
        ]
        _before_runtime = len(atomic_attacks)
        atomic_attacks = [
            a for a in atomic_attacks
            if not any(
                sig in str(getattr(a, "objective", "") or _extract_attack_payload(a)).lower()
                for sig in _dos_signatures
            )
        ]
        _removed_runtime = _before_runtime - len(atomic_attacks)
        if _removed_runtime > 0:
            print(f"  [DoS] 运行时拦截: 排除 {_removed_runtime} 个 DoS 攻击 ( owasp_llm10)")

    _safe_set_atomic_attacks(ctx.scenario, atomic_attacks)
    sequential_count = sum(1 for a in atomic_attacks if hasattr(a, "child_attacks") or hasattr(a, "attack_sequence"))
    standalone_count = len(atomic_attacks) - sequential_count
    strategy = "EXHAUSTIVE" if ctx.max_attempts_per_objective >= 999 else "FIRST_SUCCESS"

    # ── 区块 B: Stage 2→3 决策过滤摘要 ──
    _print_stage2_to_3_filter_summary(ctx, atomic_attacks, raw_attack_count)

    print("\n  ┌─ AtomicAttack 构建 ──────────────────────────────────────┄")
    print(f"  │ AtomicAttack 总数: {len(atomic_attacks)}")
    print(f"  │ SequentialAttack (复合): {sequential_count}")
    print(f"  │ 独立 AtomicAttack: {standalone_count}")
    print(f"  │ 停止策略: {strategy} (max_attempts={ctx.max_attempts_per_objective})")
    print(f"  │ 并发控制: {ctx.args.max_concurrency if ctx.args else 'N/A'}")
    print("  └───────────────────────────────────────────────────────────────┄")

    # ── P0: 同次运行 ASR 反馈闭环 (必须在重排序之前执行, 提供动态反馈数据) ──
    _feedback_current_run_asr(ctx)

    # ── ASR 智能调度 ──
    _reorder_attacks_by_asr(ctx)

    # 重排后重新获取 (排序可能已改变)
    atomic_attacks = getattr(ctx.scenario, "_atomic_attacks", [])

    # ── 区块 A: 攻击装弹清单 (core_card) ──
    _print_attack_loadout_card(ctx, atomic_attacks)

    # ── 区块 C: Converter 链实例化总览 ──
    _print_converter_instantiation_overview(ctx, atomic_attacks)

    # ── 衔接块: ★ 突出传递 Banner (区块 D 增强) ──
    from pipeline.utils.display import handoff_banner

    # 计算增强/baseline 分布
    enhanced_count = _count_enhanced_attacks(ctx, atomic_attacks)
    baseline_count = len(atomic_attacks) - enhanced_count
    tech_names = sorted({_extract_technique_name_from_attack(a) for a in atomic_attacks})
    conv_names = _collect_unique_converter_names(ctx, atomic_attacks)
    model_name = ctx.metadata.get("model_name", "?")
    model_tier = ctx.metadata.get("model_tier", "?")

    handoff_banner(
        3, 4,
        "传递到 PyRIT 原生执行 — AtomicAttack 并发执行",
        [
            f"★ 攻击弹药: {len(atomic_attacks)} 个 ({enhanced_count} 增强 + {baseline_count} baseline)",
            f"★ 技术覆盖: {', '.join(tech_names[:5])}",
            f"★ Converter: {len(conv_names)} 种 ({' › '.join(conv_names[:3])}...)",
            (f"★ 执行策略: {strategy} (max_attempts={ctx.max_attempts_per_objective})"
            f" | 并发: {ctx.args.max_concurrency if ctx.args else 3}"),
            f"★ 目标模型: {model_name} (tier={model_tier})",
        ],
    )


def _feedback_current_run_asr(ctx: PipelineContext) -> None:
    """同次运行 ASR 反馈闭环。.

    查询当前运行中已完成的 AttackResult ASR, 写入 ctx.metadata:
      - ``ctx.metadata["current_run_asr"]``: 当前运行 ASR (by technique)

    在 resume 场景下, 已有部分 AttackResult 完成, 这部分 ASR 数据:
      1. 供 Stage 4 做动态展示
      2. 供 EpsilonGreedyTechniqueSelector (current_run scope) 做动态调参
      3. 供用户了解当前运行的进度和 ASR 趋势

    冷启动 (首次运行) 时无已完成结果, 返回空字典, 不影响后续流程。

    参考:
      - arXiv:2310.04451 (PAIR) — 自适应策略选择
      - arXiv:2406.16241 (TAP) — 基于搜索的攻击优化
    """
    scenario_result_id = ctx.args.resume or getattr(ctx.scenario, "_scenario_result_id", None)
    if not scenario_result_id:
        print("  同次运行 ASR 反馈: (首次运行, 无 resume ID)")
        ctx.metadata["current_run_asr"] = {}
        return

    asr_by_tech = query_current_run_asr_by_technique(scenario_result_id)
    ctx.metadata["current_run_asr"] = asr_by_tech

    if asr_by_tech:
        print(get_current_run_asr_summary(asr_by_tech))
        # 趋势分析: 当前运行 ASR vs 历史 ASR
        historical = query_historical_asr_by_technique()
        if historical:
            print("\n  ASR 趋势分析 (当前运行 vs 历史):")
            for tech, current_stats in sorted(
                asr_by_tech.items(),
                key=lambda x: x[1].success_rate or 0,
                reverse=True,
            ):
                if current_stats.total_decided > 0:
                    hist_stats = historical.get(tech)
                    current_sr = current_stats.success_rate or 0
                    if hist_stats and hist_stats.total_decided > 0:
                        hist_sr = hist_stats.success_rate or 0
                        trend = "↑" if current_sr > hist_sr else ("↓" if current_sr < hist_sr else "→")
                        print(f"    {tech:<35} 当前 {current_sr * 100:>5.1f}% vs 历史 {hist_sr * 100:>5.1f}% {trend}")
    else:
        print("  同次运行 ASR 反馈: (冷启动, 无已完成结果)")


def _reorder_attacks_by_asr(ctx: PipelineContext) -> None:
    """按 ASR 优先级重排 scenario._atomic_attacks 列表。.

    排序依据 (优先级递减):
      1. GroupFallbackExecutor 降级链 (S→A→B→C→D, Stage 2 已构建)
      2. 当前运行 ASR (动态反馈)
      3. 历史 ASR (Laplace 平滑)
      4. 中等优先级 0.5 (无数据)

    安全性:
      - 仅重排列表顺序, 不修改任何 AtomicAttack 内容
      - resume 场景下, 已完成的攻击会被 _get_remaining_atomic_attacks_async 过滤
      - 重排不影响 ScenarioResult 的 attack_results 字典 (key 为 attack_name)
    """
    scenario = ctx.scenario
    atomic_attacks = getattr(scenario, "_atomic_attacks", None)
    if not atomic_attacks or len(atomic_attacks) <= 1:
        return

    # 1. 优先使用 GroupFallbackExecutor 降级链 (Stage 2 构建)
    fallback_plan = getattr(ctx, "fallback_plan", None)
    if fallback_plan and fallback_plan.execution_order:
        order_map = {tech: i for i, tech in enumerate(fallback_plan.execution_order)}

        def _fallback_priority(attack: Any) -> float:
            tech_name = _extract_technique_name_from_attack(attack)
            base_tech = tech_name.split("+")[0] if "+" in tech_name else tech_name
            return order_map.get(base_tech, 99)

        original_order = [a.atomic_attack_name for a in atomic_attacks]
        sorted_attacks = sorted(atomic_attacks, key=_fallback_priority)
        _safe_set_atomic_attacks(scenario, sorted_attacks)
        new_order = [a.atomic_attack_name for a in sorted_attacks]

        if new_order != original_order:
            print("\n  ASR 智能调度 (GroupFallbackExecutor 降级链):")
            print(f"    原始顺序 (前 5): {original_order[:5]}")
            print(f"    优化顺序 (前 5): {new_order[:5]}")

            # 按技术分组聚合 + Top 5 明细
            _print_attack_grouping(sorted_attacks, order_map=order_map)
        else:
            print("  ASR 智能调度: 顺序未变 (降级链已是最优)")
        return

    # 2. 回退: 原始 ASR + Laplace 平滑
    asr_by_tech = query_historical_asr_by_technique()
    current_run_asr: dict = ctx.metadata.get("current_run_asr", {})

    def _attack_priority(attack: Any) -> float:
        """计算 AtomicAttack 的优先级分数 (越高越优先执行)。."""
        tech_name = _extract_technique_name_from_attack(attack)

        # 优先使用当前运行 ASR (动态反馈)
        current_stats = current_run_asr.get(tech_name)
        if current_stats and current_stats.total_decided > 0:
            return (current_stats.successes + 1) / (current_stats.total_decided + 2)

        # 回退到历史 ASR
        stats = asr_by_tech.get(tech_name)
        if stats is None or stats.total_decided == 0:
            return 0.5  # 无历史数据: 中等优先级 (Laplace 平滑)
        # Laplace 平滑: (successes + 1) / (total + 2)
        return (stats.successes + 1) / (stats.total_decided + 2)

    # 按优先级降序排列
    original_order = [a.atomic_attack_name for a in atomic_attacks]
    sorted_attacks = sorted(atomic_attacks, key=_attack_priority, reverse=True)
    _safe_set_atomic_attacks(scenario, sorted_attacks)
    new_order = [a.atomic_attack_name for a in sorted_attacks]

    if new_order != original_order:
        print("\n  ASR 智能调度 (执行顺序优化):")
        print(f"    原始顺序 (前 5): {original_order[:5]}")
        print(f"    优化顺序 (前 5): {new_order[:5]}")

        # 按技术分组聚合 + Top 5 明细 (含 ASR)
        _print_attack_grouping(
            sorted_attacks,
            asr_by_tech=asr_by_tech,
            current_run_asr=current_run_asr,
        )
    else:
        print("  ASR 智能调度: 顺序未变 (无历史数据或已是最优)")

    _print_stage3_summary(ctx)


def _safe_set_atomic_attacks(scenario: Any, sorted_attacks: list) -> None:
    """安全设置 scenario 的 _atomic_attacks 属性。.

    P1-5: 使用 setattr 替代直接赋值, 避免上游属性名变更时断裂。
    如果 scenario 不支持 _atomic_attacks 属性, 记录警告但不崩溃。
    """
    if hasattr(scenario, "_atomic_attacks"):
        scenario._atomic_attacks = sorted_attacks
    else:
        logger.warning(
            "Scenario %s has no _atomic_attacks attribute, reorder skipped. "
            "This may indicate an upstream PyRIT version change.",
            type(scenario).__name__,
        )


def _print_attack_grouping(
    sorted_attacks: list,
    *,
    order_map: dict[str, int] | None = None,
    asr_by_tech: dict | None = None,
    current_run_asr: dict | None = None,
) -> None:
    """按技术分组聚合 + Top 5 明细 — 替代 72 行全量堆叠.

    输出格式:
      技术聚合:
        many_shot       36 个载荷 | 降级链 #12 | ASR 5% (C)
        prompt_sending  36 个载荷 | baseline  | ASR —

      明细 (Top 5):
        #1  many_shot       | owasp_llm02     | #12
        #2  many_shot       | owasp_llm07     | #12
        ...
    """
    order_map = order_map or {}
    asr_by_tech = asr_by_tech or {}
    current_run_asr = current_run_asr or {}

    # ── 技术聚合 ──
    tech_counts: dict[str, int] = {}
    for attack in sorted_attacks:
        tech_name = _extract_technique_name_from_attack(attack)
        tech_counts[tech_name] = tech_counts.get(tech_name, 0) + 1

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

    print("\n    技术聚合:")
    for tech, count in sorted(tech_counts.items(), key=lambda x: x[1], reverse=True):
        base_tech = tech.split("+")[0] if "+" in tech else tech
        idx = order_map.get(base_tech, 99)
        chain_str = f"降级链 #{idx}" if idx < 99 else "baseline"

        # ASR 显示
        asr_str = "ASR —"
        current_stats = current_run_asr.get(tech)
        if current_stats and current_stats.total_decided > 0:
            sr = current_stats.success_rate or 0
            tier = _tier_from_asr(sr)
            asr_str = f"ASR {sr * 100:.1f}% ({tier}) [当前]"
        else:
            stats = asr_by_tech.get(tech)
            if stats and stats.total_decided > 0:
                sr = stats.success_rate or 0
                tier = _tier_from_asr(sr)
                asr_str = f"ASR {sr * 100:.1f}% ({tier}) [历史]"

        print(f"      {tech:<25} {count:>3} 个载荷 | {chain_str:<14} | {asr_str}")

    # ── Top 5 明细 ──
    print("\n    明细 (Top 5):")
    for i, attack in enumerate(sorted_attacks[:5]):
        tech_name = _extract_technique_name_from_attack(attack)
        base_tech = tech_name.split("+")[0] if "+" in tech_name else tech_name
        idx = order_map.get(base_tech, 99)
        chain_str = f"#{idx}" if idx < 99 else "—"
        short_name = _shorten_attack_name(getattr(attack, "atomic_attack_name", ""))
        print(f"      #{i + 1}  {tech_name:<25} | {short_name:<20} | {chain_str}")
    total = len(sorted_attacks)
    if total > 5:
        print(f"      (共 {total} 个, 展示前 5)")


def _print_stage3_summary(ctx: PipelineContext) -> None:
    """Stage 3 summary — already printed in run(), kept for compatibility."""


# ============================================================
# 红队视角展示: 攻击装弹清单 + 决策过滤 + Converter 总览
# ============================================================


def _extract_technique_name_from_attack(attack: Any) -> str:
    """从 AtomicAttack 实例提取真正的攻击技术名.

    R-022: 消费 PyRIT 原生属性链, 不修改原生生命周期.

    数据路径:
        attack.attack_technique → AttackTechnique
        attack.attack_technique.attack → AttackStrategy (如 PromptSendingAttack)
        type(strategy).__name__ → "PromptSendingAttack"
        map_class_name_to_technique("PromptSendingAttack") → "prompt_sending"

    回退: attack.display_group (数据集名, 非技术名, 仅作兜底)

    Args:
        attack: AtomicAttack 实例

    Returns:
        规范技术名 (如 "many_shot", "prompt_sending"), 或 display_group 兜底
    """
    try:
        technique = getattr(attack, "attack_technique", None)
        if technique is not None:
            strategy = getattr(technique, "attack", None)
            if strategy is not None:
                class_name = type(strategy).__name__
                mapped = map_class_name_to_technique(class_name)
                if mapped and mapped != "unknown":
                    # P0 修复: SequentialAttack 包装了多个子攻击策略,
                    # 需穿透到 child_attacks 获取真实技术名.
                    # 否 Stage 3 卡片全部显示 "sequential",
                    # 导致 ASR/Converter/降级链查找键不匹配.
                    if mapped == "sequential":
                        # SequentialAttack stores child_attacks as _child_attacks (private)
                        child_attacks = (
                            getattr(strategy, "child_attacks", None)
                            or getattr(strategy, "_child_attacks", None)
                            or []
                        )
                        child_techs: list[str] = []
                        for child in child_attacks:
                            child_strategy = getattr(child, "strategy", None)
                            if child_strategy is not None:
                                child_cname = type(child_strategy).__name__
                                child_mapped = map_class_name_to_technique(child_cname)
                                if child_mapped and child_mapped not in ("unknown", "sequential"):
                                    child_techs.append(child_mapped)
                                elif child_cname and child_cname not in ("MagicMock", "AtomicAttack"):
                                    child_techs.append(child_cname)
                        if child_techs:
                            # 返回首个技术名 (用于 ASR/Converter/降级链查找键匹配),
                            # 多技术场景下首个技术是 SequentialAttack 的主策略
                            return child_techs[0]
                    return mapped
                # 无映射但不 MagicMock/AtomicAttack → 保留原始类名
                if class_name and class_name not in ("MagicMock", "AtomicAttack"):
                    return class_name
    except Exception:
        pass
    # 兜底: display_group 是数据集名, 非技术名, 但比空字符串好
    return getattr(attack, "display_group", "") or getattr(attack, "atomic_attack_name", "")


def _extract_attack_payload(attack: Any) -> str:
    """从 AtomicAttack 提取载荷文本 (截断展示用)."""
    try:
        seed_groups = getattr(attack, "seed_groups", None) or []
        for sg in seed_groups:
            seeds = getattr(sg, "seeds", []) or []
            for seed in seeds:
                if hasattr(seed, "value") and not hasattr(seed, "sequence"):
                    return trunc(str(seed.value), 50)
                elif hasattr(seed, "role") and getattr(seed, "role", "") == "":
                    return trunc(str(getattr(seed, "value", "")), 50)
    except Exception:
        pass
    return "(无法提取)"


def _extract_attack_converters(ctx: PipelineContext, tech_name: str) -> list[str]:
    """获取技术对应的 Converter 类名列表.

    P1 优化: 优先从 AtomicAttack 实例直接提取 (精确),
    回退到 ctx.technique_converter_map (按技术名查找).

    Args:
        ctx: PipelineContext (携带 technique_converter_map 回退用)
        tech_name: 技术名 (display_group)

    Returns:
        Converter 类名列表 (如 ["Base64Encoder", "StealthSmuggler"])
    """
    # 1. 尝试从 AtomicAttack 实例直接提取 (P1 精确路径)
    #    但 _extract_attack_converters 当前签名只接收 tech_name, 不接收 attack
    #    所以这个函数仅作为回退; 直接提取在 _extract_attack_converters_from_attack 中
    conv_map = getattr(ctx, "technique_converter_map", None) or {}
    convs = conv_map.get(tech_name, [])
    return [type(c).__name__ for c in convs]


def _extract_attack_converters_from_attack(attack: Any) -> list[str]:
    """从 AtomicAttack 实例直接提取 Converter 类名列表 (P1 精确路径).

    数据路径:
        attack.attack_technique → AttackTechnique
        attack.attack_technique.attack → AttackStrategy
        attack.attack_technique.attack.get_request_converters() → list[ConverterConfiguration]
        ConverterConfiguration.converters → list[Converter]
        type(converter).__name__ → 类名

    Args:
        attack: AtomicAttack 实例

    Returns:
        Converter 类名列表, 空列表表示 baseline (无 Converter)
    """
    names: list[str] = []
    try:
        technique = getattr(attack, "attack_technique", None)
        if technique is None:
            return names
        strategy = getattr(technique, "attack", None)
        if strategy is None:
            return names
        # 原生 API: get_request_converters() 返回 list[ConverterConfiguration]
        converter_configs = strategy.get_request_converters()
        for config in converter_configs:
            converters = getattr(config, "converters", []) or []
            for conv in converters:
                names.append(type(conv).__name__)
    except Exception:
        pass
    return names


def _count_enhanced_attacks(ctx: PipelineContext, atomic_attacks: list) -> int:
    """统计携带 Converter 增强的 AtomicAttack 数量.

    P1: 优先从 AtomicAttack 实例直接提取, 回退到 ctx.technique_converter_map.
    """
    count = 0
    for attack in atomic_attacks:
        # P1: 优先从实例直接提取
        convs = _extract_attack_converters_from_attack(attack)
        if not convs:
            # 回退: 从 ctx.technique_converter_map 查找 (使用真正技术名)
            tech = _extract_technique_name_from_attack(attack)
            convs = _extract_attack_converters(ctx, tech)
        if convs:
            count += 1
    return count


def _collect_unique_converter_names(ctx: PipelineContext, atomic_attacks: list) -> list[str]:
    """收集所有技术涉及的 Converter 类名 (去重).

    P1: 优先从 AtomicAttack 实例直接提取, 回退到 ctx.technique_converter_map.
    """
    names: set[str] = set()
    for attack in atomic_attacks:
        # P1: 优先从实例直接提取
        convs = _extract_attack_converters_from_attack(attack)
        if not convs:
            # 回退: 从 ctx.technique_converter_map 查找 (使用真正技术名)
            tech = _extract_technique_name_from_attack(attack)
            convs = _extract_attack_converters(ctx, tech)
        names.update(convs)
    return sorted(names)


def _print_stage2_to_3_filter_summary(
    ctx: PipelineContext,
    atomic_attacks: list,
    raw_count: int,
) -> None:
    """区块 B: Stage 2→3 决策过滤摘要.

    展示 Stage 2 计划的攻击数 vs Stage 3 实际构建数, 以及过滤原因.
    """
    planned = ctx.metadata.get("planned_attack_count", 0)
    actual = len(atomic_attacks)
    dedup_removed = raw_count - actual
    dataset_count = len(ctx.sorted_datasets) if ctx.sorted_datasets else 0

    lines = [
        f"计划攻击数 (Stage 2): {planned}",
        f"实际构建数 (Stage 3): {actual}",
    ]
    if dedup_removed > 0:
        lines.append(f"过滤: SHA256 去重 -{dedup_removed} (跨数据集重复种子)")
    else:
        lines.append("过滤: 无去重")
    lines.append(f"载荷覆盖: {dataset_count} 数据集, {actual} 个唯一 objective")

    info_box("Stage 2→3 决策过滤", lines)


def _shorten_attack_name(full_name: str) -> str:
    """从 AtomicAttack 全名中提取数据集短名.

    输入: adaptive_text_owasp_llm02_sensitive_info_disclosure::2c181992f065...
    输出: owasp_llm02

    输入: baseline
    输出: baseline
    """
    if "::" in full_name:
        prefix = full_name.split("::")[0]
        # 去掉 adaptive_text_ 前缀
        if prefix.startswith("adaptive_text_"):
            prefix = prefix[len("adaptive_text_"):]
        # 截取到 _ 后第一个词组 (如 owasp_llm02_sensitive_info_disclosure → owasp_llm02)
        parts = prefix.split("_")
        if len(parts) >= 2 and parts[0] in ("owasp", "cve"):
            return f"{parts[0]}_{parts[1]}"
        return prefix[:25]
    return full_name[:25] if len(full_name) > 25 else full_name


def _print_attack_loadout_card(
    ctx: PipelineContext,
    atomic_attacks: list,
) -> None:
    """区块 A: 攻击装弹清单 — 载荷 × 技术 × Converter 实例化 (core_card).

    按执行顺序展示 Top 10 AtomicAttack 的载荷预览 + 技术 + Converter + 预期 ASR.
    """
    if not atomic_attacks:
        return

    warm_start = ctx.warm_start_asr or {}
    fallback_plan = getattr(ctx, "fallback_plan", None)
    order_map: dict[str, int] = {}
    if fallback_plan and hasattr(fallback_plan, "execution_order"):
        order_map = {tech: i for i, tech in enumerate(fallback_plan.execution_order)}

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

    loadout_lines: list[str] = []
    for i, attack in enumerate(atomic_attacks[:10]):
        tech = _extract_technique_name_from_attack(attack)
        dataset = getattr(attack, "display_group", "") or "—"
        payload = _extract_attack_payload(attack)
        # P1: 优先从实例直接提取, 回退到 ctx map
        convs = _extract_attack_converters_from_attack(attack)
        if not convs:
            convs = _extract_attack_converters(ctx, tech)
        # › 表示串联管道 (pipeline): 前一个的输出→后一个的输入
        conv_str = " › ".join(convs) if convs else "(baseline)"
        asr = warm_start.get(tech, 0.0)
        tier = _tier_from_asr(asr) if asr > 0 else "—"

        # 降级链序号
        base_tech = tech.split("+")[0] if "+" in tech else tech
        chain_idx = order_map.get(base_tech)
        chain_str = f"#{chain_idx}" if chain_idx is not None else "—"

        loadout_lines.append(f'#{i + 1:02d}  [{tech} | {dataset}]  "{payload}"')
        loadout_lines.append(f"     Conv: {conv_str} | ASR {asr:>4.0%} ({tier}) | 降级链: {chain_str}")

    loadout_lines.append(f"合计: {len(atomic_attacks)} 个 AtomicAttack (展示前 {min(10, len(atomic_attacks))})")

    core_card(
        "攻击装弹清单 — 载荷 × 技术 × Converter 实例化",
        sections=[{"label": "执行序", "lines": loadout_lines}],
    )


# ── Converter 功能分类映射 (用于总览上下文) ──
_CONV_TYPE_MAP: dict[str, str] = {
    "Base64Converter": "编码",
    "ROT13Converter": "编码",
    "CaesarConverter": "编码",
    "AtbashConverter": "编码",
    "UnicodeConfusableConverter": "Unicode 混淆",
    "UnicodeSubstitutionConverter": "Unicode 混淆",
    "BidiConverter": "Unicode 混淆",
    "ZeroWidthConverter": "Unicode 混淆",
    "SuffixAppendConverter": "对抗后缀",
    "RandomCapitalLettersConverter": "大小写混淆",
    "AsciiArtConverter": "格式注入",
    "NoiseConverter": "噪声注入",
    "PersuasionConverter": "说服策略",
    "DecompositionConverter": "分解重构",
    "TranslationConverter": "语义变换",
    "ToneConverter": "语气变换",
    "TaskFramingConverter": "任务框架",
    "PolicyPuppetryConverter": "策略模仿",
    "StringJoinConverter": "字符注入",
    "BinaryConverter": "编码",
    "MorseConverter": "编码",
    "BrailleConverter": "字母表替换",
    "NatoConverter": "字母表替换",
    "LeetspeakConverter": "字符变形",
    "ZalgoConverter": "字符变形",
    "EmojiConverter": "字符替换",
    "SuperscriptConverter": "字符替换",
    "CharSwapConverter": "字符变形",
    "DiacriticConverter": "字符变形",
    "CharacterSpaceConverter": "间距混淆",
    "InsertPunctuationConverter": "标点注入",
    "RepeatTokenConverter": "令牌注入",
    "AsciiSmugglerConverter": "令牌走私",
    "SneakyBitsSmugglerConverter": "令牌走私",
    "UrlConverter": "URL 编码",
    "Base2048Converter": "高基数编码",
    "EcojiConverter": "高基数编码",
    "UnicodeReplacementConverter": "Unicode 替换",
    "TatweelConverter": "Unicode 替换",
    "SearchReplaceConverter": "关键词替换",
    "FirstLetterConverter": "首字母编码",
    "TenseConverter": "时态变换",
    "VariationConverter": "变体生成",
    "MathObfuscationConverter": "数学混淆",
    "ScientificTranslationConverter": "科学翻译",
}


def _infer_conv_types(conv_names: list[str]) -> str:
    """从 Converter 类名列表推断功能类型摘要."""
    if not conv_names:
        return "baseline 直发"
    types: list[str] = []
    seen: set[str] = set()
    for name in conv_names:
        t = _CONV_TYPE_MAP.get(name, "其他")
        if t not in seen:
            types.append(t)
            seen.add(t)
    return " + ".join(types)


def _print_converter_instantiation_overview(
    ctx: PipelineContext,
    atomic_attacks: list,
) -> None:
    """区块 C: Converter 链实例化总览.

    按技术分组展示 Converter 链 + 载荷数 + 功能类型 + ASR + 降级链.
    """
    if not atomic_attacks:
        return

    warm_start = ctx.warm_start_asr or {}
    fallback_plan = getattr(ctx, "fallback_plan", None)
    order_map: dict[str, int] = {}
    if fallback_plan and hasattr(fallback_plan, "execution_order"):
        order_map = {tech: i for i, tech in enumerate(fallback_plan.execution_order)}

    # 按技术分组统计
    tech_stats: dict[str, dict[str, Any]] = {}
    for attack in atomic_attacks:
        tech = _extract_technique_name_from_attack(attack)
        if tech not in tech_stats:
            # P1: 优先从实例直接提取, 回退到 ctx map
            convs = _extract_attack_converters_from_attack(attack)
            if not convs:
                convs = _extract_attack_converters(ctx, tech)
            tech_stats[tech] = {
                "conv_names": convs,
                "count": 0,
            }
        tech_stats[tech]["count"] += 1

    # 按载荷数降序取 Top 5
    sorted_techs = sorted(tech_stats.items(), key=lambda x: x[1]["count"], reverse=True)[:5]

    lines: list[str] = []
    for tech, stats in sorted_techs:
        convs = stats["conv_names"]
        # › 表示串联管道 (pipeline): 前一个的输出→后一个的输入
        conv_str = " › ".join(convs) if convs else "(直发)"
        type_str = _infer_conv_types(convs)
        n_layers = len(convs) if convs else 0
        layer_str = f"{n_layers} 层串联" if n_layers > 0 else "无 Converter"

        asr = warm_start.get(tech, 0.0)
        asr_str = f"ASR {asr:.0%}" if asr > 0 else "ASR —"

        base_tech = tech.split("+")[0] if "+" in tech else tech
        chain_idx = order_map.get(base_tech)
        chain_str = f"降级链 #{chain_idx}" if chain_idx is not None else "baseline"

        lines.append(f"{tech} ({stats['count']} 载荷)")
        lines.append(f"  管道: {conv_str}")
        lines.append(f"  类型: {type_str} ({layer_str}) | {asr_str} | {chain_str}")
        lines.append("")

    enhanced = _count_enhanced_attacks(ctx, atomic_attacks)
    total = len(atomic_attacks)
    baseline = total - enhanced
    coverage = f"{enhanced}/{total} 增强 ({enhanced / total * 100:.1f}%)" if total > 0 else "N/A"
    lines.append(f"覆盖: {coverage} | {baseline} baseline 对照")

    info_box("Converter 链实例化总览", lines)


def _dedup_atomic_attacks(atomic_attacks: list) -> list:
    """SHA256 cross-dataset seed deduplication — P0-G1.

    Cross-dataset seeds may have identical objectives (e.g., AdvBench and
    HarmBench overlap on harmful questions), causing AtomicAttack validation
    failure (AttackSeedGroup requires unique objective).

    Strategy:
      1. Extract objective text from each AtomicAttack
      2. Compute SHA256 hash
      3. Keep first occurrence, remove subsequent duplicates

    Academic basis:
      - HarmBench (arXiv:2402.04249): standardized datasets should dedup
      - JailbreakBench (arXiv:2402.01135): avoid duplicate counting affecting ASR

    Args:
        atomic_attacks: list of AtomicAttack objects

    Returns:
        Deduplicated list of AtomicAttack objects
    """
    if not atomic_attacks or len(atomic_attacks) <= 1:
        return atomic_attacks

    seen_hashes: set[str] = set()
    deduped: list = []
    removed_count = 0

    for attack in atomic_attacks:
        objective = ""
        seed_group = getattr(attack, "seed_group", None)
        if seed_group is not None:
            for seed in getattr(seed_group, "seeds", []):
                if hasattr(seed, "value") and not hasattr(seed, "sequence"):
                    objective = str(seed.value)
                    break
                elif hasattr(seed, "role") and getattr(seed, "role", "") == "":
                    objective = str(getattr(seed, "value", ""))
                    break

        if not objective:
            objective = getattr(attack, "atomic_attack_name", "")

        if not objective:
            objective = getattr(attack, "display_group", "")

        obj_hash = hashlib.sha256(objective.encode("utf-8")).hexdigest()

        if obj_hash in seen_hashes:
            removed_count += 1
            logger.debug(f"Seed dedup: removing duplicate attack '{getattr(attack, 'atomic_attack_name', 'unknown')}'")
        else:
            seen_hashes.add(obj_hash)
            deduped.append(attack)

    if removed_count > 0:
        print(
            f"\n  P0-G1 seed dedup: removed {removed_count} duplicate AtomicAttack "
            f"({len(atomic_attacks)} -> {len(deduped)})"
        )

    return deduped
