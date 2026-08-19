# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Stage 6: 执行后分析 — ASR 实测 vs 先验对比 + 经验写回 + 下次运行建议。.

职责:
  - 实测 ASR vs 先验对比表 (技术 | 实测 | 先验 | 差异 | 样本数)
  - Converter 韧性分析 (基线 ASR vs Converter ASR, 增量 Δ)
  - ASR 经验闭环 (经验写回 Top-N + 模型 Tier 预警)
  - 成果回溯 + 下次运行建议

产出 (写入 PipelineContext):
  - ctx.metadata["post_analysis"] = 后分析结果字典

依赖:
  - pipeline.asr.optimizer (ASR 查询 + 经验写回)
  - pipeline.asr.failure_type_event_handler (失败类型统计)

修改此文件不影响 Stage 1-4, 6-7。
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any

from pipeline.context import PipelineContext

logger = logging.getLogger(__name__)


async def run(ctx: PipelineContext) -> None:
    """执行 Stage 5/6: 执行后分析。."""
    result = ctx.result
    if result is None:
        print("  [跳过] 无执行结果")
        return

    print("\n" + "=" * 70)
    print("阶段 6/7: 执行后分析 — ASR 实测 vs 先验对比 + 经验写回")
    print("=" * 70)

    # L5 P2-1/P2-2: 决策追溯 + 事件总线
    from pipeline.utils.decision_trace import DecisionTrace
    from pipeline.utils.event_bus import EventBus

    trace = DecisionTrace.get_instance()
    bus = EventBus.get_instance()
    trace.record(
        stage="stage_5",
        layer="L5_Analytics",
        decision="post_analysis_started",
        reason=f"Overall ASR={ctx.overall_asr}%, analyzing results",
    )
    bus.publish_simple("stage_5", "post_analysis_started", overall_asr=ctx.overall_asr)

    # ── O-28: scorer_tier_stats 生产者修复 — 断端修复 ──
    # 此前 _compute_asr_breakdown() 维度4 by_scorer_agreement 读取
    # ctx.metadata.get("scorer_tier_stats") 但无任何模块写入该 key.
    # 修复: 从 CascadeScorerWrapper 实例的 tier_stats 属性写入 ctx.metadata.
    # 学术依据: LLM-as-a-Judge (arXiv:2306.05685) §4.2 评分器一致性;
    #   HarmBench (arXiv:2402.04249) §5.2 多评分器协议
    try:
        from pyrit.registry import ScorerRegistry

        _scorer_registry = ScorerRegistry.get_registry_singleton()
        _tier_stats: dict[str, int] = {}
        # 遍历所有注册的评分器, 收集 tier_stats
        for _scorer in _scorer_registry.instances.get_all_instances():
            if _scorer is not None and hasattr(_scorer, "tier_stats"):
                _ts = _scorer.tier_stats
                if isinstance(_ts, dict):
                    for _k, _v in _ts.items():
                        _tier_stats[_k] = _tier_stats.get(_k, 0) + _v
        # O-28: 将 CascadeScorerWrapper 的 tier-level 键映射为
        # _compute_asr_breakdown() 维度4 by_scorer_agreement 所期望的格式
        # T1_* (规则层) → T1_success/T1_failure; T2_* (LLM 层) → T2_success/T2_failure
        _T1_SUCCESS_KEYS = {"T1_refusal", "T1_keyword", "T1_short"}
        _T2_SUCCESS_KEYS = {"T2_llm", "T2_cache_hit", "T3_composite"}
        _t1_success = sum(_tier_stats.get(k, 0) for k in _T1_SUCCESS_KEYS)
        _t2_success = sum(_tier_stats.get(k, 0) for k in _T2_SUCCESS_KEYS)
        _t1_failure = _tier_stats.get("T1_no_match", 0) + _tier_stats.get("T0_shortcut", 0)
        _t2_failure = _tier_stats.get("T2_timeout", 0) + _tier_stats.get("T3_fallback", 0)
        # DualJudge 级别统计
        _t25_disputed = (
            _tier_stats.get("T2.5_disputed_adopt_a", 0)
            + _tier_stats.get("T2.5_disputed_adopt_b", 0)
            + _tier_stats.get("T2.5_disputed_fallback", 0)
        )
        _tier_stats["T1_success"] = _t1_success
        _tier_stats["T2_success"] = _t2_success
        _tier_stats["T1_failure"] = _t1_failure
        _tier_stats["T2_failure"] = _t2_failure
        _tier_stats["T2.5_disputed_adopt_a"] = max(
            _tier_stats.get("T2.5_disputed_adopt_a", 0), 0
        )
        _tier_stats["T2.5_disputed_adopt_b"] = max(
            _tier_stats.get("T2.5_disputed_adopt_b", 0), 0
        )
        _tier_stats["T2.5_disputed_fallback"] = max(
            _tier_stats.get("T2.5_disputed_fallback", 0), 0
        )
        if _tier_stats:
            ctx.metadata["scorer_tier_stats"] = _tier_stats
            logger.debug(
                f"O-28: scorer_tier_stats written to ctx.metadata: {_tier_stats}"
            )
    except Exception as e:
        logger.debug(f"O-28: scorer_tier_stats collection failed: {e}")

    # ── P1: 攻击结果回注ASR跟踪闭环 ──
    # 将 Crescendo/TAP/XPIA/AdvancedMCP 编排器结果回注到 ctx.asr_per_technique,
    # 使其进入经验写回 (save_empirical_asr) → 下次运行 warm-start 闭环
    # 学术依据: DART (arXiv:2407.06485) per-model ASR 应指导运行时决策
    _inject_orchestrator_results_to_asr(ctx)

    # ── v57 H-4: Browser 补充攻击 ASR 合并 ──
    # 将 Browser 补充攻击结果合并到 ctx.asr_per_technique
    # 学术依据: HarmBench (arXiv:2402.04249) 跨攻击向量 ASR 聚合
    _merge_dual_mode_asr(ctx)

    # ── 1. 执行成果概要 (P1-1: 保留 post_analysis 元数据写入, 移除冗余展示) ──
    # P3 修复: 移到 _inject_orchestrator_results_to_asr 之后,
    # 确保编排器成功 (Crescendo/TAP) 被计入汇总
    _write_post_analysis_metadata(ctx)

    # ── 2. 实测 ASR vs 先验对比 (新增信息: 先验数据) ──
    _print_asr_comparison(ctx)

    # ── 3. ASR 经验闭环 (吸收 S5-1/S5-3/S5-5 的经验写回 + Tier 预警 + 建议) ──
    _print_asr_feedback(ctx)

    # ── O7: 技术池演化追溯 (新增信息: 技术匹配率 + P编号) ──
    _print_tech_pool_evolution(ctx)

    # ── A-6: 自适应 Converter 学习器 ──
    try:
        from pipeline.converters.adaptive_router import AdaptiveConverterRouter
        from pipeline.utils.display import info_box

        _router = AdaptiveConverterRouter()
        _all_results = []
        if ctx.result:
            for _v in ctx.result.attack_results.values():
                _all_results.extend(_v)
        _model_name = ctx.metadata.get("model_name", "unknown")
        _router.learn_from_results(_all_results, model_name=_model_name)
        _adj = _router.get_adjustment_summary()
        if _adj["total_adjustments"] > 0:
            ctx.metadata["converter_adaptive_routing"] = _adj
            _router.persist()
            _lines = [
                f"分析Converter数: {_adj['total_converters_analyzed']}",
                f"调整建议: {_adj['total_adjustments']} (高优先级: {_adj['high_priority']})",
                f"提升: {_adj['promotions']} | 降级: {_adj['demotions']} | 语义层切换: {_adj['degradations']}",
            ]
            info_box("A-6: Converter 自适应路由", _lines)
            logger.info(
                f"A-6: Converter adaptive router: {_adj['total_adjustments']} adjustments"
            )
    except Exception as e:
        logger.debug(f"A-6: Converter adaptive router skipped: {e}")

    # ── D3: 修复建议生成 (新增信息: 修复优先级) ──
    _print_fix_recommendations(ctx)

    # ── D4: OWASP LLM Top10 覆盖矩阵 (新增信息: OWASP 维度) ──
    _print_owasp_matrix(ctx)

    # ── v59 P3: 替代路径攻击结果独立展示 ──
    # 学术依据: Greshake et al.(arXiv:2302.12173) 多路径攻击经验应独立追踪;
    #   NIST AI RMF 1.0 — 决策可追溯性要求替代路径结果可见
    _print_alternative_path_results(ctx)

    # ── G4: ASR 反馈循环状态 (P1-3: 精简为仅展示闭环状态) ──
    _print_asr_feedback_loop(ctx)

    # ── P3-O2: 多模型 ASR 对比矩阵 ──
    _print_multi_model_comparison(ctx)

    # ── R-023: 端到端验证报告 (自动检查 ctx.metadata 中各场景结果) ──
    _print_e2e_validation(ctx)

    # ── O3: ASR 多维度分解 (by_tier/by_converter/by_owasp/by_scorer_agreement) ──
    # 学术依据: HarmBench (arXiv:2402.04249) §5.2 多维ASR分析;
    #   JailbreakBench (arXiv:2402.01135) §4.2 评分一致性度量
    _compute_asr_breakdown(ctx)

    # ── O8: ★ 突出传递 Banner (替代单行交接) ──
    from pipeline.utils.display import handoff_banner

    post_analysis = ctx.metadata.get("post_analysis", {})
    handoff_banner(
        6, 7,
        "传递到结果输出 — 报告生成 + 证据收集",
        [
            f"★ ASR: {ctx.overall_asr}% → 决定报告严重等级",
            f"★ 成功/总计: {post_analysis.get('successes', 0)}/{post_analysis.get('total', 0)} → 证据收集范围",
            "★ 最佳技术: "
            + (max(ctx.asr_per_technique, key=ctx.asr_per_technique.get) if ctx.asr_per_technique else "N/A"),
            f"★ 经验写回: {'已保存' if _check_empirical_saved(ctx) else '⚠ 未保存'} → 下次运行 warm-start",
            "★ 任务: 证据收集 + 报告生成 + 架构汇总",
        ],
    )


# ============================================================
# 内部函数
# ============================================================


def _merge_dual_mode_asr(ctx: PipelineContext) -> None:
    """v57 H-4: 合并 Browser 补充攻击 ASR 到主流水线报告.

    将 ctx.metadata["browser_supplement_results"] 中的 Browser 补充攻击结果
    合并到 ctx.asr_per_technique, 实现双模式 (Burp + Browser) 统一 ASR 报告.

    合并策略:
      - Browser 补充攻击技术名带 [Browser] 后缀标记来源
      - 如果技术名已存在 (与 Burp 主攻击同名), 取最大 ASR
      - 如果技术名不存在, 新增到 asr_per_technique

    展示:
      - 打印 Browser 补充攻击 ASR 汇总
      - 在 post_analysis metadata 中记录双模式标记

    学术依据:
      - HarmBench (arXiv:2402.04249): 跨攻击向量 ASR 聚合标准化
      - JailbreakBench (arXiv:2402.01135): 统一证据包
      - Greshake et al. (arXiv:2302.12173): 多入口覆盖提升攻击有效性
    """
    supplement_results = ctx.metadata.get("browser_supplement_results", [])
    if not supplement_results:
        return

    merged_count = 0
    for r in supplement_results:
        tech = r.get("technique", "unknown")
        achieved = r.get("achieved", False)
        supplement_asr = 100.0 if achieved else 0.0

        # 带 [Browser] 后缀标记来源
        tech_key = f"{tech} [Browser]"
        current_asr = ctx.asr_per_technique.get(tech_key)
        if current_asr is not None:
            # 已有该技术, 取最大值
            if supplement_asr > current_asr:
                ctx.asr_per_technique[tech_key] = supplement_asr
        else:
            ctx.asr_per_technique[tech_key] = supplement_asr
        merged_count += 1

    # 记录到 post_analysis metadata
    pa = ctx.metadata.get("post_analysis", {})
    pa["browser_supplement"] = {
        "total_attacks": len(supplement_results),
        "success_count": ctx.metadata.get("browser_supplement_success_count", 0),
        "merged_to_asr": merged_count,
    }
    ctx.metadata["post_analysis"] = pa

    success_count = ctx.metadata.get("browser_supplement_success_count", 0)
    total = len(supplement_results)
    print(
        f"\n  [H-4] Browser 补充 ASR 合并: {merged_count} 项技术 → "
        f"ctx.asr_per_technique ({success_count}/{total} 成功)"
    )

    logger.info(
        f"H-4: Merged {merged_count} browser supplement ASR entries "
        f"({success_count}/{total} succeeded)"
    )


def _inject_orchestrator_results_to_asr(ctx: PipelineContext) -> None:
    """将编排器攻击结果回注到 ASR 跟踪系统。.

    将 Crescendo/TAP/XPIA/AdvancedMCP 编排器的执行结果从 ctx.metadata
    回注到 ctx.asr_per_technique, 使其进入:
      1. save_empirical_asr() → 经验写回 → 下次运行 warm-start
      2. ASR 对比表 → 实测 vs 先验对比
      3. 报告 → 技术池演化追溯

    学术依据:
      - DART (arXiv:2407.06485): per-model ASR 应指导运行时决策
      - HarmBench (arXiv:2402.04249): 经验数据覆盖学术先验

    回注的编排器结果:
      - crescendo_result: CrescendoAttack (arXiv:2402.12109, ASR=82%)
      - tap_result: TAPAttack (arXiv:2312.02191, 树搜索)
      - xpia_result: XPIAWorkflow (arXiv:2302.12173, 间接注入)
      - advanced_mcp_attack_report: SequentialAttack Kill Chain (arXiv:2307.00929)
    """
    injected_count = 0

    # Crescendo 结果回注
    cres_data = ctx.metadata.get("crescendo_result")
    if cres_data and isinstance(cres_data, dict):
        achieved = cres_data.get("achieved", False)
        winning_turn = cres_data.get("winning_turn", 0)
        max_turns = cres_data.get("max_turns", 10)
        # ASR = 1.0 if achieved, else winning_turn/max_turns (部分成功)
        asr_val = 100.0 if achieved else (winning_turn / max(max_turns, 1)) * 100.0
        ctx.asr_per_technique["crescendo"] = asr_val
        injected_count += 1
        auto = ctx.metadata.get("crescendo_auto_triggered", False)
        logger.info(
            f"Orchestrator ASR injection: crescendo={asr_val:.1f}%"
            f" (achieved={achieved}, turn={winning_turn}/{max_turns}"
            f"{' [auto]' if auto else ''})"
        )

    # O-30: post_crescendo_results 消费 — Crescendo 补充攻击结果回注
    # Stage 4 Crescendo 补充攻击结果写入 ctx.metadata["post_crescendo_results"]
    # 但此前 _inject_orchestrator_results_to_asr 仅检查 crescendo_result,
    # 不检查 post_crescendo_results → 补充攻击 ASR 丢失.
    # 修复: 检查 post_crescendo_results 按 achieved 计算 ASR, 写入
    # ctx.asr_per_technique["crescendo_supplement"]
    # 学术依据: Russinovich et al. (arXiv:2402.12109) §4.2 Crescendo 渐进升级;
    #   DART (arXiv:2407.06485) per-technique ASR 经验写回
    post_cres_data = ctx.metadata.get("post_crescendo_results")
    if post_cres_data and isinstance(post_cres_data, list):
        post_success = sum(1 for r in post_cres_data if r.get("achieved", False))
        post_total = len(post_cres_data)
        if post_total > 0:
            post_asr = (post_success / post_total) * 100.0
            ctx.asr_per_technique["crescendo_supplement"] = post_asr
            injected_count += 1
            logger.info(
                f"O-30: post_crescendo ASR injection: "
                f"crescendo_supplement={post_asr:.1f}% "
                f"({post_success}/{post_total} succeeded)"
            )
    elif post_cres_data and isinstance(post_cres_data, dict):
        achieved = post_cres_data.get("achieved", False)
        winning_turn = post_cres_data.get("winning_turn", 0)
        max_turns = post_cres_data.get("max_turns", 10)
        asr_val = 100.0 if achieved else (winning_turn / max(max_turns, 1)) * 100.0
        ctx.asr_per_technique["crescendo_supplement"] = asr_val
        injected_count += 1
        logger.info(
            f"O-30: post_crescendo ASR injection: "
            f"crescendo_supplement={asr_val:.1f}% (achieved={achieved})"
        )

    # TAP 结果回注
    tap_data = ctx.metadata.get("tap_result")
    if tap_data and isinstance(tap_data, dict):
        achieved = tap_data.get("achieved", False)
        best_score = tap_data.get("best_score", 0)
        nodes_explored = tap_data.get("nodes_explored", 0)
        # ASR = 1.0 if achieved, else best_score/10 (部分成功)
        asr_val = 100.0 if achieved else min(best_score / 10.0 * 100.0, 100.0)
        ctx.asr_per_technique["tap"] = asr_val
        injected_count += 1
        auto = ctx.metadata.get("tap_auto_triggered", False)
        logger.info(
            f"Orchestrator ASR injection: tap={asr_val:.1f}%"
            f" (achieved={achieved}, best_score={best_score}, nodes={nodes_explored}"
            f"{' [auto]' if auto else ''})"
        )

    # XPIA 结果回注
    xpia_data = ctx.metadata.get("xpia_result")
    if xpia_data and isinstance(xpia_data, dict):
        vectors = xpia_data.get("injection_vectors", [])
        if vectors:
            successes = sum(1 for v in vectors if v.get("success", False))
            asr_val = (successes / len(vectors)) * 100.0
            ctx.asr_per_technique["xpia"] = asr_val
            injected_count += 1
            auto = ctx.metadata.get("xpia_auto_triggered", False)
            logger.info(
                f"Orchestrator ASR injection: xpia={asr_val:.1f}%"
                f" ({successes}/{len(vectors)} vectors"
                f"{' [auto]' if auto else ''})"
            )

    # Advanced MCP Kill Chain 结果回注
    mcp_data = ctx.metadata.get("advanced_mcp_attack_report")
    if mcp_data and isinstance(mcp_data, dict):
        probes = mcp_data.get("probes", [])
        if probes:
            successes = sum(1 for p in probes if p.get("success", False))
            asr_val = (successes / len(probes)) * 100.0
            ctx.asr_per_technique["advanced_mcp"] = asr_val
            injected_count += 1
            auto = ctx.metadata.get("advanced_mcp_auto_triggered", False)
            logger.info(
                f"Orchestrator ASR injection: advanced_mcp={asr_val:.1f}%"
                f" ({successes}/{len(probes)} probes"
                f"{' [auto]' if auto else ''})"
            )

    # v59: 替代路径攻击结果回注
    # 学术依据: DART (arXiv:2407.06485) per-model ASR 应指导运行时决策;
    #   Greshake et al. (arXiv:2302.12173) 多路径攻击经验应沉淀
    alt_path_results = ctx.metadata.get("alternative_path_results", [])
    if alt_path_results:
        # 按路径技术名分组计算 ASR
        path_stats: dict[str, dict[str, int]] = {}
        for r in alt_path_results:
            tech = r.get("technique", "unknown")
            if tech not in path_stats:
                path_stats[tech] = {"total": 0, "success": 0}
            path_stats[tech]["total"] += 1
            if r.get("achieved"):
                path_stats[tech]["success"] += 1

        for tech, stats in path_stats.items():
            if stats["total"] > 0:
                asr_val = (stats["success"] / stats["total"]) * 100.0
                # 用 alt_path_ 前缀避免与主攻击技术 ASR 混淆
                asr_key = f"alt_path_{tech}"
                ctx.asr_per_technique[asr_key] = asr_val
                # v60+: 收集样本数供 warm-start 置信度标注
                if "alt_path_sample_counts" not in ctx.metadata:
                    ctx.metadata["alt_path_sample_counts"] = {}
                ctx.metadata["alt_path_sample_counts"][asr_key] = stats["total"]
                injected_count += 1
                logger.info(
                    f"v59 Orchestrator ASR injection: {asr_key}={asr_val:.1f}%"
                    f" ({stats['success']}/{stats['total']} attempts)"
                )

    if injected_count > 0:
        print(
            f"  攻击结果回注 ASR 闭环: {injected_count} 个编排器结果"
            f" → ctx.asr_per_technique → 经验写回"
        )


def _check_empirical_saved(ctx: PipelineContext) -> bool:
    """检查经验 ASR 文件是否已保存。."""
    try:
        from pipeline.asr.optimizer import _get_empirical_asr_path

        model_name = ctx.metadata.get("model_name", "unknown")
        return _get_empirical_asr_path(model_name).exists()
    except Exception:
        return False


def _write_post_analysis_metadata(ctx: PipelineContext) -> None:
    """写入 post_analysis 元数据 (P1-1: 从 _print_execution_summary 精简, 移除冗余展示)."""
    result = ctx.result
    total = sum(len(v) for v in result.attack_results.values())

    from pyrit.models import AttackOutcome

    successes = sum(1 for v in result.attack_results.values() for ar in v if ar.outcome == AttackOutcome.SUCCESS)
    failures = sum(
        1 for v in result.attack_results.values() for ar in v if ar.outcome and ar.outcome != AttackOutcome.SUCCESS
    )

    # P3 修复: 合并编排器结果 (Crescendo/TAP/RedTeaming)
    # _inject_orchestrator_results_to_asr 将 ASR 注入 ctx.asr_per_technique,
    # 但未更新 ctx.result.attack_results. 这里从 ctx.metadata 提取编排器成功数.
    cres_data = ctx.metadata.get("crescendo_result")
    if cres_data and isinstance(cres_data, dict):
        if cres_data.get("achieved", False):
            successes += 1
        total += 1
        failures += 0 if cres_data.get("achieved", False) else 1

    tap_data = ctx.metadata.get("tap_result")
    if tap_data and isinstance(tap_data, dict):
        if tap_data.get("achieved", False):
            successes += 1
        total += 1
        failures += 0 if tap_data.get("achieved", False) else 1

    # RedTeaming 编排器结果
    redteam_data = ctx.metadata.get("redteam_result")
    if redteam_data and isinstance(redteam_data, dict):
        rt_success = redteam_data.get("successes", 0)
        rt_total = redteam_data.get("total", 0)
        successes += rt_success
        total += rt_total
        failures += rt_total - rt_success

    # P3 修复: 更新 overall_asr 以包含编排器结果
    if total > 0:
        ctx.overall_asr = round((successes / total) * 100, 1)

    ctx.metadata["post_analysis"] = {
        "total": total,
        "successes": successes,
        "failures": failures,
    }


def _print_asr_comparison(ctx: PipelineContext) -> None:
    """实测 ASR vs 先验对比卡片 (P2-1: 使用 info_box 统一格式)."""
    from pipeline.utils.display import info_box

    if not ctx.asr_per_technique:
        info_box("实测 ASR vs 先验", ["(无技术数据)"])
        return

    from pipeline.asr.optimizer import query_historical_asr_by_technique

    historical = query_historical_asr_by_technique()

    lines: list[str] = []
    lines.append(f"{'技术':<35} {'实测':>6} {'先验':>6} {'差异':>6} {'样本':>4}")
    lines.append(f"{'─' * 35} {'─' * 6} {'─' * 6} {'─' * 6} {'─' * 4}")
    for tech, asr in sorted(ctx.asr_per_technique.items(), key=lambda x: x[1], reverse=True):
        hist_stats = historical.get(tech)
        prior = (hist_stats.success_rate or 0) * 100 if hist_stats else 0
        samples = hist_stats.total_decided if hist_stats else 0
        diff = asr - prior
        arrow = "↑" if diff > 0 else ("↓" if diff < 0 else "=")
        lines.append(f"  {tech:<35} {asr:>5.1f}% {prior:>5.1f}% {diff:>+5.1f}% {samples:>4} {arrow}")
    info_box("实测 ASR vs 先验", lines)


def _print_asr_feedback(ctx: PipelineContext) -> None:
    """ASR 经验闭环卡片 (P2-1: info_box 统一格式; P1-1: 吸收 S5-5 成果回溯建议)."""
    from pipeline.utils.display import info_box

    model_name = ctx.metadata.get("model_name", "unknown")
    model_tier = ctx.metadata.get("model_tier", "unknown")
    overall = ctx.overall_asr

    lines: list[str] = []
    lines.append(f"模型: {model_name} (Tier: {model_tier}) | 整体 ASR: {overall}%")

    # 经验写回 (G-05: 按模型分文件存储)
    if ctx.asr_per_technique:
        try:
            from pipeline.asr.optimizer import save_empirical_asr

            # v60+: 传递样本数供 warm-start 置信度标注
            _sample_counts = ctx.metadata.get("alt_path_sample_counts", {})
            save_empirical_asr(
                ctx.asr_per_technique,
                model_name=model_name,
                sample_counts=_sample_counts or None,
            )
            top3 = sorted(ctx.asr_per_technique.items(), key=lambda x: x[1], reverse=True)[:3]
            lines.append("经验写回 Top-3:")
            for tech, asr in top3:
                lines.append(f"  {tech:<35} {asr:.1f}%")
        except Exception as e:
            logger.warning(f"Failed to save empirical ASR: {e}", exc_info=True)

    # O-31: 自适应经验写回 — 将 adaptive_* 系列参数写入经验文件供下次运行消费
    # 学术依据: DART (arXiv:2407.06485) 自适应攻击链经验复用;
    #   Boyd (1987) OODA Observe→Orient→Decide 跨运行闭环
    _adaptive_keys = [
        "adaptive_crescendo_trigger",
        "adaptive_converter_preference",
        "adaptive_max_concurrency",
        "adaptive_paradigm_shift",
        "adaptive_filter_bypass",
    ]
    _adaptive_snapshot = {
        k: ctx.metadata.get(k) for k in _adaptive_keys if ctx.metadata.get(k) is not None
    }
    if _adaptive_snapshot:
        try:
            import json

            from pipeline.asr.optimizer import _get_empirical_asr_path

            _asr_path = _get_empirical_asr_path(model_name)
            _existing = json.loads(_asr_path.read_text(encoding="utf-8")) if _asr_path.exists() else {}
            _existing["adaptive_params"] = _adaptive_snapshot
            _asr_path.write_text(
                json.dumps(_existing, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            logger.info(f"O-31: adaptive params written to empirical ASR: {_adaptive_snapshot}")
        except Exception as e:
            logger.debug(f"O-31: adaptive params write-back failed: {e}")

    # P1: 种子级 ASR 收集 (per-seed, 用于精简时按种子排名)
    try:
        from pipeline.asr.optimizer import collect_seed_level_asr_from_memory

        seed_asr = collect_seed_level_asr_from_memory(model_name=model_name)
        if seed_asr:
            lines.append(f"种子级 ASR: {len(seed_asr)} 个种子已收集")
        else:
            lines.append("种子级 ASR: ⚠ 无数据 (详见日志)")
    except Exception as e:
        logger.warning(f"Failed to collect seed-level ASR: {e}", exc_info=True)
        lines.append("种子级 ASR: ⚠ 收集失败 (详见日志)")

    # 数据集级 ASR 收集 (per-dataset, 用于下次运行数据集优先级排序)
    dataset_names = getattr(ctx.args, "datasets", []) or []
    try:
        from pipeline.asr.optimizer import collect_dataset_level_asr_from_memory

        ds_asr = collect_dataset_level_asr_from_memory(
            model_name=model_name, dataset_names=dataset_names,
        )
        if ds_asr:
            top_ds = sorted(ds_asr.items(), key=lambda x: x[1].get("asr", 0), reverse=True)[:3]
            ds_str = ", ".join(f"{n}={v['asr']:.0%}" for n, v in top_ds)
            lines.append(f"数据集级 ASR: {len(ds_asr)} 个数据集已收集 (Top 3: {ds_str})")
        else:
            lines.append("数据集级 ASR: ⚠ 无数据 (详见日志)")
    except Exception as e:
        logger.warning(f"Failed to collect dataset-level ASR: {e}", exc_info=True)
        lines.append("数据集级 ASR: ⚠ 收集失败 (详见日志)")

    # G-07: ParadigmTracker 跨运行持久化
    failure_stats = ctx.metadata.get("failure_stats", {})
    paradigm_data = failure_stats.get("paradigm_performance", {})
    if paradigm_data:
        try:
            from pathlib import Path

            from pipeline.asr.failure_type_event_handler import ParadigmPerformanceTracker

            tracker = ParadigmPerformanceTracker.from_dict(paradigm_data)
            tracker_path = Path("outputs/empirical_asr") / "paradigm_performance.json"
            tracker.save_to_file(tracker_path)
            lines.append(f"范式性能跟踪器已持久化 ({len(paradigm_data)} 失败类型)")
        except (OSError, ValueError) as e:
            logger.warning(f"Failed to save paradigm tracker: {e}")

    # P1-1: 吸收 S5-5 成果回溯 — 下次运行建议
    failure_dist = failure_stats.get("failure_distribution", {})
    lines.append("")
    lines.append("下次运行建议:")
    if overall < 10:
        lines.append("  → ASR < 10%: 启用多轮攻击策略 (STRATEGY_MODE=balanced)")
        lines.append("  → 增加高 ASR 数据集 (airt.jailbreak)")
    elif overall < 30:
        lines.append("  → ASR 中等: 增加 Converter 变体池")
        lines.append("  → 检查 Converter 模型配置")
    else:
        lines.append("  → ASR 良好: 维持当前策略")

    if failure_dist:
        top_failure = max(failure_dist, key=failure_dist.get)
        if "timeout" in top_failure:
            lines.append("  → timeout 频繁: 降低 max_concurrency 或增加 --rate-limit")
        if "objective_not_achieved" in top_failure:
            lines.append("  → objective_not_achieved: 升级到更高 ASR 技术或增加变体")

    # Tier 预警
    if overall < 20:
        lines.append(f"⚠ {model_tier} 模型 ASR < 20% — 建议升级到多轮攻击策略")
    elif overall < 50:
        lines.append(f"→ {model_tier} 模型 ASR 中等 — 考虑增加 Converter 变体")

    info_box("ASR 经验闭环", lines)


def _print_tech_pool_evolution(ctx: PipelineContext) -> None:
    """O7 + Gap 4: 技术池演化追溯 + P编号贯穿.

    展示技术池从 Stage 2 → Stage 4 → Stage 5 的变化,
    同时展示 P 编号在分析端的消费:
      - Stage 2 策略选择的技术数 + P编号定义
      - Stage 4 实际执行的技术数 (从 AttackResult 提取技术名)
      - Stage 5 执行后有 ASR 数据的技术数

    R-022: 使用 AttackResultAnalyzer.extract_technique_name() 原生 API 提取技术名,
    不使用 get_display_groups() 的数据集名。
    """
    from pipeline.utils.display import info_box

    # Stage 2: warm-start ASR 中的技术数
    stage2_techs = set()
    warm_start = getattr(ctx, "warm_start_asr", None) or {}
    if warm_start:
        stage2_techs = set(warm_start.keys())

    # Stage 4: 执行结果中的技术数 (从 AttackResult 提取真正技术名)
    # Round 20+ 增强: 两遍遍历 — 第一遍构建 eval_hash_map, 第二遍用 Path 4/5 解析 unknown
    stage4_techs: set[str] = set()
    if ctx.result:
        with contextlib.suppress(Exception):
            from pipeline.analysis.attack_result_analyzer import AttackResultAnalyzer

            groups = ctx.result.get_display_groups()
            # 收集所有 AttackResult
            flat_results: list[Any] = []
            for _ds_name, attack_results in groups.items():
                flat_results.extend(attack_results)
            # 第一遍: 构建 eval_hash → technique 映射
            eval_hash_map = AttackResultAnalyzer.build_eval_hash_map(flat_results)
            # 第二遍: 用 eval_hash_map 解析所有结果 (含 Path 4/5)
            for ar in flat_results:
                tech = AttackResultAnalyzer.extract_technique_name(ar, eval_hash_map=eval_hash_map)
                if tech and tech != "unknown":
                    stage4_techs.add(tech)

    # Stage 5: 有 ASR 数据的技术数
    stage5_techs = set(ctx.asr_per_technique.keys()) if ctx.asr_per_technique else set()

    lines = [
        f"Stage 2 策略选择: {len(stage2_techs)} 种 (warm-start ASR 先验)",
    ]

    # P 编号贯穿: 展示 plan_pid_map
    pid_map = getattr(ctx, "plan_pid_map", {})
    if pid_map:
        pid_summary = " | ".join(
            f"{ds}={rng}" for ds, rng in list(pid_map.items())[:3]
        )
        if len(pid_map) > 3:
            pid_summary += f" ... (+{len(pid_map) - 3})"
        lines.append(f"Stage 2 P编号定义: {len(pid_map)} 个数据集 ({pid_summary})")

    # 匹配分析
    if stage2_techs and stage4_techs:
        matched = stage2_techs & stage4_techs
        unmatched = stage2_techs - stage4_techs
        extra = stage4_techs - stage2_techs

        if matched:
            matched_str = ", ".join(sorted(list(matched))[:5])
            if len(matched) > 5:
                matched_str += f" ... (+{len(matched) - 5})"
            lines.append(f"Stage 4 技术匹配: {len(matched)} 种 ✓ ({matched_str})")
        if unmatched:
            unmatched_str = ", ".join(sorted(list(unmatched))[:5])
            if len(unmatched) > 5:
                unmatched_str += f" ... (+{len(unmatched) - 5})"
            lines.append(
                f"Stage 4 未执行:  {len(unmatched)} 种 ✗ ({unmatched_str}) ← 无载荷/未触发"
            )
        if extra:
            extra_str = ", ".join(sorted(list(extra))[:5])
            if len(extra) > 5:
                extra_str += f" ... (+{len(extra) - 5})"
            lines.append(f"Stage 4 额外:    {len(extra)} 种 (载荷自带: {extra_str})")
    else:
        lines.append(f"Stage 4 技术执行: {len(stage4_techs)} 种")

    lines.append(f"Stage 5 执行:    {len(stage5_techs)} 种 (有 ASR 数据)")

    # P 编号分析端消费: 展示成功的 P 编号分布
    if ctx.result and pid_map:
        from pyrit.models import AttackOutcome

        groups = ctx.result.get_display_groups()
        all_results = []
        for group_name, attack_results in groups.items():
            for ar in attack_results:
                success = ar.outcome == AttackOutcome.SUCCESS
                all_results.append((group_name, success, ar))

        success_count = sum(1 for _, s, _ in all_results if s)
        total_count = len(all_results)
        lines.append(
            f"P编号结果: {success_count}/{total_count} 成功 "
            f"({success_count * 100 // max(total_count, 1)}%)"
        )

    # 演化洞察
    if stage2_techs and stage5_techs:
        success_rate = len(stage5_techs & stage2_techs) / max(len(stage2_techs), 1)
        lines.append("")
        if success_rate < 0.5:
            # v39 F-3: 区分"实例化率"和"执行率" — epsilon-greedy 策略下
            # 低执行率是正常行为 (max_attempts=2 时主要选择高 ASR 技术)
            lines.append(f"ℹ 技术执行率 {success_rate:.0%} — epsilon-greedy 策略正常行为")
            lines.append("  → 实例化率 100% (catalog 全覆盖), 执行率低因 max_attempts 限制")
            lines.append(f"  → 高 ASR 技术 ({', '.join(sorted(list(stage5_techs))[:3])}) 被优先选择")
            lines.append("  → 建议: 增大 max_attempts 或使用 --techniques 显式指定低频技术")
        else:
            lines.append(f"✓ 技术匹配率 {success_rate:.0%} — 策略技术与载荷对齐")

    info_box("技术池演化 + P编号 (Stage 2 → 4 → 5)", lines)


# 修复建议生成


def _print_fix_recommendations(ctx: PipelineContext) -> None:
    """D3+S5-3: 基于攻击结果生成修复建议 — 按攻击向量分组.

    S5-3 增强: 按攻击向量 (OWASP 分类) 分组, 每组展示主攻技术+突破方式+修复建议.
    高 ASR 技术 → 高优先级修复建议.
    """
    from pipeline.utils.display import info_box

    if not ctx.asr_per_technique:
        info_box("修复建议 (按攻击向量分组)", ["(无 ASR 数据)"])
        return

    # 按成功率排序
    sorted_asr = sorted(ctx.asr_per_technique.items(), key=lambda x: x[1], reverse=True)

    # S5-3: 按攻击向量分组 — G2 修复: 从 YAML 配置加载
    from pathlib import Path as _Path
    config_path = _Path(__file__).parent.parent.parent / "data" / "setting" / "display_config.yaml"
    tech_to_vector: dict[str, str] = {}
    tech_to_breakthrough: dict[str, str] = {}
    try:
        import yaml as _yaml
        with open(config_path, encoding="utf-8") as f:
            display_cfg = _yaml.safe_load(f)
        tech_to_vector = display_cfg.get("tech_to_vector", {})
        tech_to_breakthrough = display_cfg.get("tech_to_breakthrough", {})
    except Exception as e:
        logger.debug(f"G2 display_config.yaml load failed: {e}")

    lines: list[str] = []
    current_vector = ""
    for tech, asr in sorted_asr[:8]:
        vector = tech_to_vector.get(tech, "其他")
        if vector != current_vector:
            current_vector = vector
            lines.append(f"【{vector}】")

        if asr >= 50:
            severity = "🔴 严重"
            action = "立即修复"
        elif asr >= 25:
            severity = "🟠 高"
            action = "优先修复"
        elif asr >= 10:
            severity = "🟡 中"
            action = "计划修复"
        else:
            severity = "🟢 低"
            action = "持续监控"

        breakthrough = tech_to_breakthrough.get(tech, "—")
        lines.append(f"  {severity} {tech}: ASR={asr:.0f}% → {action}")
        lines.append(f"    突破方式: {breakthrough}")
        if asr >= 10:
            lines.append(f"    修复建议: 加强对 {breakthrough} 的检测和防御")
        elif asr < 10 and asr > 0:
            lines.append("    修复建议: 维持当前防御, 持续监控")
        else:
            lines.append("    修复建议: 防御有效, 保持当前策略")

    if not lines:
        lines.append("(无有效建议)")
    info_box("修复建议 (按攻击向量分组)", lines)


# OWASP LLM Top10 覆盖矩阵


def _extract_owasp_from_attack_result(ar: Any) -> str:
    """从 AttackResult 提取 OWASP ID (回退路径).

    提取路径 (R-022 PyRIT 原生优先):
      1. ar.memory_labels["owasp_id"] — 原生 memory_labels
      2. ar.atomic_attack_identifier.params["display_group"] — 原生标识符参数
      3. ar.metadata["dataset_name"] — 元数据回退

    Args:
        ar: AttackResult 实例

    Returns:
        OWASP ID (如 "LLM01"), 空字符串表示未找到
    """
    import re

    # 路径 1: memory_labels.owasp_id
    labels = getattr(ar, "memory_labels", None) or {}
    if isinstance(labels, dict):
        owasp_id = labels.get("owasp_id", "")
        if owasp_id:
            return owasp_id.upper()

    # 路径 2: atomic_attack_identifier.params.display_group
    try:
        aai = getattr(ar, "atomic_attack_identifier", None)
        if aai is not None:
            params = getattr(aai, "params", None) or {}
            if isinstance(params, dict):
                dg = params.get("display_group", "")
                if dg:
                    match = re.search(r"(llm\d{2}|asi\d{2})", dg, re.IGNORECASE)
                    if match:
                        return match.group(1).upper()
    except Exception:
        pass

    # 路径 3: metadata.dataset_name
    try:
        metadata = getattr(ar, "metadata", None) or {}
        if isinstance(metadata, dict):
            ds_name = metadata.get("dataset_name", "") or metadata.get("display_group", "")
            if ds_name:
                match = re.search(r"(llm\d{2}|asi\d{2})", ds_name, re.IGNORECASE)
                if match:
                    return match.group(1).upper()
    except Exception:
        pass

    return ""


def _print_owasp_matrix(ctx: PipelineContext) -> None:
    """D4: OWASP LLM Top10 (2025) 覆盖矩阵 (L5 P3-1: 使用原生 display_group 映射).

    L5 P3-1 修复: 不再使用硬编码 tech_to_owasp 映射,
    而是从 PyRIT 原生 get_display_groups() 的组名中提取 OWASP ID,
    与 EvidenceCollector._extract_owasp_id_from_display_group() 对齐。
    """
    from pipeline.reporting.owasp_data import OWASP_LLM_DETAILS
    from pipeline.utils.display import info_box

    # P0-1: 从 owasp_data.py 导入 OWASP 2025 官方定义 (消除硬编码 2023 版标签)

    owasp_categories = {k: v["name"] for k, v in OWASP_LLM_DETAILS.items()}

    # P0-2: 分离 LLM 和 ASI 计数 (修复覆盖率 > 100%)
    owasp_asi_categories = {
        "ASI01": "Agent Identity Spoofing",
        "ASI02": "Tool Misuse",
        "ASI03": "Unauthorized Access",
        "ASI04": "Data Exfiltration",
        "ASI05": "Privilege Escalation",
        "ASI06": "Memory Poisoning",
        "ASI07": "Cross Agent Injection",
        "ASI08": "Cascading Failure",
        "ASI09": "Trust Boundary Violation",
        "ASI10": "Rogue Agent",
    }

    # L5 P3-1: 从 PyRIT 原生 display_groups 提取 OWASP ID
    covered: set[str] = set()
    owasp_attack_counts: dict[str, int] = {}
    owasp_success_counts: dict[str, int] = {}

    if ctx.result:
        import re

        from pyrit.models import AttackOutcome

        groups = ctx.result.get_display_groups()
        for group_name, attack_results in groups.items():
            # 从组名提取 OWASP ID (与 evidence_collector._extract_owasp_id_from_display_group 对齐)
            # 使用 re.search 而非 re.match, 支持 "owasp_llm01_prompt_injection" 等带前缀的组名
            match = re.search(r"(llm\d{2}|asi\d{2})", group_name, re.IGNORECASE)
            if match:
                owasp_id = match.group(1).upper()
                covered.add(owasp_id)
                owasp_attack_counts[owasp_id] = owasp_attack_counts.get(owasp_id, 0) + len(attack_results)
                successes = sum(1 for ar in attack_results if ar.outcome == AttackOutcome.SUCCESS)
                owasp_success_counts[owasp_id] = owasp_success_counts.get(owasp_id, 0) + successes
            else:
                # 回退 1: 从每个 AttackResult 的 atomic_attack_identifier.params.display_group 提取
                for ar in attack_results:
                    ar_owasp = _extract_owasp_from_attack_result(ar)
                    if ar_owasp:
                        covered.add(ar_owasp)
                        owasp_attack_counts[ar_owasp] = owasp_attack_counts.get(ar_owasp, 0) + 1
                        if ar.outcome == AttackOutcome.SUCCESS:
                            owasp_success_counts[ar_owasp] = owasp_success_counts.get(ar_owasp, 0) + 1
                # 回退 2: 如果 AttackResult 也没有 OWASP 信息, 从技术名匹配
                if not any(
                    _extract_owasp_from_attack_result(ar) for ar in attack_results
                ):
                    tech_lower = group_name.lower()
                    fallback_map = {
                        "prompt_injection": "LLM01",
                        "jailbreak": "LLM01",
                        "encoding": "LLM01",
                        "payload_smuggling": "LLM01",
                        "red_teaming": "LLM01",
                        "information_disclosure": "LLM06",
                        "data_exfiltration": "LLM06",
                        "dan": "LLM08",
                        "actor_attack": "LLM08",
                    }
                    for key, owasp_id in fallback_map.items():
                        if key in tech_lower:
                            covered.add(owasp_id)
                            owasp_attack_counts[owasp_id] = owasp_attack_counts.get(owasp_id, 0) + len(attack_results)
                            successes = sum(1 for ar in attack_results if ar.outcome == AttackOutcome.SUCCESS)
                            owasp_success_counts[owasp_id] = owasp_success_counts.get(owasp_id, 0) + successes
                            break

    # S5-2: 计划态覆盖 (从 sorted_datasets 获取)
    planned_coverage: set[str] = set()
    sorted_datasets = ctx.sorted_datasets or []
    if sorted_datasets:
        for ds_name in sorted_datasets:
            # 从数据集名提取 OWASP ID (P2-3: 区分 LLM 和 ASI 前缀)
            import re as _re
            m = _re.match(r"^owasp_(llm|asi)(\d{2})_", ds_name, _re.IGNORECASE)
            if m:
                prefix = m.group(1).upper()
                planned_coverage.add(f"{prefix}{m.group(2)}")

    # v58 P2-D: 拓扑推荐覆盖 (从 attack_surface_topology.recommended_owasp 获取)
    # 学术依据: HarmBench (arXiv:2402.04249) — 拓扑推荐但未触发 = 攻击面发现但未利用
    topology_recommended_owasp: set[str] = set()
    _topology = ctx.metadata.get("attack_surface_topology")
    if _topology is not None:
        _topo_owasp = getattr(_topology, "recommended_owasp", []) or []
        topology_recommended_owasp = set(_topo_owasp)

    # v61 P3: 能力探测 OWASP 映射 — 从 ctx.metadata 读取能力探测发现的 OWASP 分类
    # 学术依据: NIST AI RMF 1.0 — 探测→推荐→攻击→覆盖闭环;
    #   OWASP ASI01-10 — 能力探测→威胁分类映射
    capability_probe_owasp: set[str] = set(
        ctx.metadata.get("capability_probe_owasp", [])
    )

    # P0-2: 分离 LLM 和 ASI 覆盖率计算
    llm_covered = covered & set(owasp_categories.keys())
    asi_covered = covered & set(owasp_asi_categories.keys())

    lines: list[str] = []
    lines.append("[LLM Top 10]")
    for owasp_id, name in owasp_categories.items():
        is_planned = owasp_id in planned_coverage
        is_actual = owasp_id in llm_covered
        is_topo_recommended = owasp_id in topology_recommended_owasp
        attack_count = owasp_attack_counts.get(owasp_id, 0)
        success_count = owasp_success_counts.get(owasp_id, 0)

        if is_actual and attack_count > 0:
            rate = success_count / attack_count * 100
            planned_str = str(attack_count) if is_planned else "0"
            line = (
                f"  ✓ {owasp_id} {name:<30} 计划 {planned_str} "
                f"→ 实际 {attack_count} | {success_count} 成功 ({rate:.0f}%)"
            )
            lines.append(line)
        elif is_planned:
            lines.append(f"  ─ {owasp_id} {name:<30} 计划有 → 实际 0 (未触发)")
        elif is_topo_recommended:
            # v58 P2-D: 拓扑推荐但未在计划中 → 攻击面发现但未利用
            lines.append(f"  ⚑ {owasp_id} {name:<30} 拓扑推荐 → 未利用 (攻击面未覆盖)")
        else:
            lines.append(f"  ✗ {owasp_id} {name:<30} 未覆盖")

    # ASI 条件扩展: v61 P3 能力探测发现的 ASI 分类也需展示
    if (
        asi_covered
        or any(asi_id in planned_coverage for asi_id in owasp_asi_categories)
        or any(asi_id in topology_recommended_owasp for asi_id in owasp_asi_categories)
        or any(asi_id in capability_probe_owasp for asi_id in owasp_asi_categories)
    ):
        lines.append("")
        lines.append("[Agentic AI Top 10]")
        for owasp_id, name in owasp_asi_categories.items():
            is_planned = owasp_id in planned_coverage
            is_actual = owasp_id in asi_covered
            is_topo_recommended = owasp_id in topology_recommended_owasp
            is_probe_detected = owasp_id in capability_probe_owasp
            attack_count = owasp_attack_counts.get(owasp_id, 0)
            success_count = owasp_success_counts.get(owasp_id, 0)

            if is_actual and attack_count > 0:
                rate = success_count / attack_count * 100
                planned_str = str(attack_count) if is_planned else "0"
                lines.append(
                    f"  ✓ {owasp_id} {name:<30} 计划 {planned_str} "
                    f"→ 实际 {attack_count} | {success_count} 成功 ({rate:.0f}%)"
                )
            elif is_planned:
                lines.append(f"  ─ {owasp_id} {name:<30} 计划有 → 实际 0 (未触发)")
            elif is_topo_recommended:
                lines.append(f"  ⚑ {owasp_id} {name:<30} 拓扑推荐 → 未利用 (攻击面未覆盖)")
            elif is_probe_detected:
                # v61 P3: 能力探测发现但未在拓扑推荐/计划中 → 探测发现
                lines.append(f"  🔍 {owasp_id} {name:<30} 探测发现 → 未利用 (能力风险未覆盖)")
            else:
                lines.append(f"  ✗ {owasp_id} {name:<30} 未覆盖")

    # P0-2: 分别计算 LLM 和 ASI 覆盖率
    llm_coverage = len(llm_covered) / len(owasp_categories) * 100
    asi_coverage = len(asi_covered) / len(owasp_asi_categories) * 100 if owasp_asi_categories else 0
    success_categories = sum(1 for v in owasp_success_counts.values() if v > 0)
    lines.append("")
    lines.append(
        f"  LLM 覆盖率: {len(llm_covered)}/{len(owasp_categories)} ({llm_coverage:.0f}%)"
    )
    if asi_covered:
        lines.append(
            f"  ASI 覆盖率: {len(asi_covered)}/{len(owasp_asi_categories)} ({asi_coverage:.0f}%)"
        )
    lines.append(f"  有成功攻击的分类: {success_categories}/{len(covered)}")

    # v58 P2-D: 拓扑推荐覆盖统计
    topo_not_covered = topology_recommended_owasp - covered
    if topo_not_covered:
        lines.append("")
        lines.append(
            f"  ⚠ 拓扑推荐但未利用: {len(topo_not_covered)} 个 "
            f"({', '.join(sorted(topo_not_covered))})"
        )
        lines.append("     → 攻击面已发现但未转化为实际攻击 (建议扩大种子集)")

    # v61 P3: 能力探测发现但未覆盖的统计
    probe_not_covered = capability_probe_owasp - covered - topology_recommended_owasp
    if probe_not_covered:
        lines.append("")
        lines.append(
            f"  🔍 探测发现但未覆盖: {len(probe_not_covered)} 个 "
            f"({', '.join(sorted(probe_not_covered))})"
        )
        lines.append("     → 能力探测发现的风险未被攻击覆盖 (建议增加针对性载荷)")

    info_box("OWASP LLM Top10 (2025) 覆盖矩阵", lines)

    # L5 P2-1: 决策追溯 — OWASP 矩阵计算
    from pipeline.utils.decision_trace import DecisionTrace

    trace = DecisionTrace.get_instance()
    trace.record(
        stage="stage_5",
        layer="L5_Analytics",
        decision="owasp_matrix_computed",
        reason=(
            f"LLM: {len(llm_covered)}/{len(owasp_categories)} ({llm_coverage:.0f}%), "
            f"ASI: {len(asi_covered)}/{len(owasp_asi_categories)}"
        ),
        covered_ids=sorted(covered),
        coverage_pct=round(llm_coverage, 1),
    )


# ============================================================
# G4: ASR 反馈循环可视化
# ============================================================


def _print_asr_feedback_loop(ctx: PipelineContext) -> None:
    """G4: ASR 反馈循环状态 (P1-3: 精简为仅展示闭环状态, 不重复 ASR 数值).

    P1-3 优化: 移除先验 ASR / 实测 ASR / 数据集 ASR 三个重复段落,
    仅展示闭环状态 (写回状态 + warm-start 技术数 + 最大差异)。
    ASR 数值已在 S5-2 实测 vs 先验对比 和 S5-4 经验闭环 中展示。
    """
    from pipeline.utils.display import core_card

    if not ctx.asr_per_technique:
        return

    warm_start = getattr(ctx, "warm_start_asr", {}) or {}
    measured = ctx.asr_per_technique

    # 经验写回状态
    empirical_saved = False
    seed_level_saved = False
    dataset_level_saved = False
    try:
        from pipeline.asr.optimizer import (
            _get_dataset_level_asr_path,
            _get_empirical_asr_path,
            _get_seed_level_asr_path,
        )

        model_name = ctx.metadata.get("model_name", "unknown")
        empirical_saved = _get_empirical_asr_path(model_name).exists()
        seed_level_saved = _get_seed_level_asr_path(model_name).exists()
        dataset_level_saved = _get_dataset_level_asr_path(model_name).exists()
    except Exception:
        pass

    status_lines: list[str] = []
    status_lines.append(
        f"经验写回: {'✅ 已保存' if empirical_saved else '⚠ 未保存'} "
        f"| 种子级: {'✅' if seed_level_saved else '⚠'} "
        f"| 数据集级: {'✅' if dataset_level_saved else '⚠'}"
    )
    status_lines.append(f"warm-start: {len(warm_start)} 技术 → 下次运行优先级调整")
    status_lines.append(f"实测技术: {len(measured)} → 经验闭环")

    # 最大差异技术 (仅展示差异最大的技术, 不重复全部 ASR)
    max_diff_tech = ""
    max_diff_val = 0
    for tech, actual_asr in measured.items():
        prior_asr = warm_start.get(tech, 0)
        diff = abs(actual_asr - prior_asr)
        if diff > max_diff_val:
            max_diff_val = diff
            max_diff_tech = tech
    if max_diff_tech:
        status_lines.append(f"最大差异: {max_diff_tech[:30]} (Δ={max_diff_val:.1f}%) — 先验严重低估")

    core_card(
        "ASR 反馈循环状态",
        sections=[{"label": "闭环状态", "lines": status_lines}],
    )


# ============================================================
# P3-O2: 多模型 ASR 对比矩阵
# ============================================================


def _print_multi_model_comparison(ctx: PipelineContext) -> None:
    """P3-O2: 多模型 ASR 对比矩阵 — 跨模型攻击成功率分析。."""
    try:
        from pipeline.asr.multi_model_matrix import MultiModelASRMatrix

        matrix = MultiModelASRMatrix()
        loaded = matrix.load_all_models()

        if loaded < 2:
            # 少于 2 个模型无法对比, 静默跳过
            return

        # 打印摘要
        matrix.print_summary()

        # 存入 ctx.metadata
        ctx.metadata["multi_model_comparison"] = matrix.generate_report()
    except Exception as e:
        logger.debug(f"Multi-model comparison skipped: {e}")


def _print_e2e_validation(ctx: PipelineContext) -> None:
    """R-023: 端到端验证报告 — 自动检查 ctx.metadata 中各场景结果的完整性.

    验证项清单 (22 项):
      - MCP 探针 / 多轮会话 / 盲推理 / 后门探测
      - 控制模式感知 / Secret 验证 / Crescendo / TAP
      - 高级 MCP Kill Chain / XPIA / ASI03/09/10 / 多 Agent
      - 三框架评估 / AI-VSS / 实时 ASR / 动态 Converter
      - Converter 链反馈 / 成功传播 / 安全过滤 / 多模型对比

    R-022 分类: 数据层增强 — 消费 ctx.metadata, 不修改原生生命周期。
    """
    try:
        from pipeline.validation.e2e_validator import run_e2e_validation

        report = run_e2e_validation(ctx.metadata)
        ctx.metadata["e2e_validation"] = report.to_dict()
    except Exception as e:
        logger.debug(f"E2E validation skipped: {e}")


# ── O3: ASR 多维度分解 ──
# 学术依据: HarmBench (arXiv:2402.04249) §5.2 多维ASR分析;
#   JailbreakBench (arXiv:2402.01135) §4.2 评分一致性度量
# 文档 Phase 7 要求: asr_breakdown.json 按4维分解

# Tier 分类映射
_TIER_1_TECHS = {"prompt_sending"}
_TIER_2_TECHS = {"red_teaming"}
_TIER_3_TECHS = {"crescendo", "crescendo_simulated", "tap", "pair",
                 "crescendo_movie_director", "crescendo_history_lecture",
                 "crescendo_journalist_interview"}
_TIER_4_TECHS = {"xpia", "context_bomb", "data_poisoning", "vector_db_injection",
                 "hallucination_injection", "backdoor_probe"}


def _classify_tier(tech_name: str) -> str:
    """将技术名映射到攻击 Tier 层级."""
    base = tech_name.split("+")[0] if "+" in tech_name else tech_name
    if base in _TIER_1_TECHS:
        return "tier_1_baseline"
    if base in _TIER_2_TECHS:
        return "tier_2_adaptive"
    if base in _TIER_3_TECHS:
        return "tier_3_deep"
    if base in _TIER_4_TECHS:
        return "tier_4_xpia"
    return "tier_unclassified"


def _compute_asr_breakdown(ctx: PipelineContext) -> dict[str, Any]:
    """计算 ASR 多维度分解 — 4维交叉分析.

    维度:
      1. by_attack_tier: Tier 1/2/3/4 ASR
      2. by_converter: none/base64/translation/homoglyph/multi_layer
      3. by_owasp_category: LLM01-10 + ASI01-10
      4. by_scorer_agreement: both_agree_success/disagreement

    学术依据: HarmBench (arXiv:2402.04249) §5.2 要求多维ASR分析;
      JailbreakBench (arXiv:2402.01135) §4.2 评分一致性度量

    Returns:
        asr_breakdown 字典
    """
    asr_per_tech = ctx.asr_per_technique or {}
    if not asr_per_tech:
        return {}

    breakdown: dict[str, Any] = {"overall_asr": f"{ctx.overall_asr:.1f}%"}

    # ── 维度1: by_attack_tier ──
    tier_stats: dict[str, dict[str, int]] = {}
    for tech, asr in asr_per_tech.items():
        tier = _classify_tier(tech)
        if tier not in tier_stats:
            tier_stats[tier] = {"success": 0, "total": 0}
        # 从 asr_per_technique 提取 success/total (asr = success/total*100)
        # 由于 asr_per_technique 只有百分比, 我们用近似
        tier_stats[tier]["total"] += 1
        if asr > 0:
            tier_stats[tier]["success"] += 1

    by_tier: dict[str, str] = {}
    for tier, stats in sorted(tier_stats.items()):
        rate = stats["success"] / stats["total"] * 100 if stats["total"] > 0 else 0
        by_tier[tier] = f"{rate:.1f}% ({stats['success']}/{stats['total']})"
    breakdown["by_attack_tier"] = by_tier

    # ── 维度2: by_converter ──
    # 从 ctx.metadata 获取 Converter 信息
    converter_log = ctx.metadata.get("converter_log", {})
    converter_stats: dict[str, dict[str, int]] = {"none": {"success": 0, "total": 0}}
    if converter_log and isinstance(converter_log, dict):
        for entry in converter_log.get("entries", []):
            conv_name = entry.get("converter", "none") or "none"
            if conv_name not in converter_stats:
                converter_stats[conv_name] = {"success": 0, "total": 0}
            converter_stats[conv_name]["total"] += 1
            if entry.get("success"):
                converter_stats[conv_name]["success"] += 1

    by_converter: dict[str, str] = {}
    for conv, stats in sorted(converter_stats.items()):
        rate = stats["success"] / stats["total"] * 100 if stats["total"] > 0 else 0
        by_converter[conv] = f"{rate:.1f}%"
    breakdown["by_converter"] = by_converter

    # ── 维度3: by_owasp_category ──
    # 从 ctx.metadata 获取 OWASP 映射
    owasp_stats: dict[str, dict[str, int]] = {}
    evidence_collection = ctx.metadata.get("evidence_collection", {})
    if evidence_collection and isinstance(evidence_collection, dict):
        for finding in evidence_collection.get("findings", []):
            owasp_id = finding.get("owasp_id", "unknown")
            owasp_stats.setdefault(owasp_id, {"success": 0, "total": 0})
            owasp_stats[owasp_id]["total"] += 1
            if finding.get("score_value"):
                owasp_stats[owasp_id]["success"] += 1

    by_owasp: dict[str, str] = {}
    for owasp_id, stats in sorted(owasp_stats.items()):
        rate = stats["success"] / stats["total"] * 100 if stats["total"] > 0 else 0
        by_owasp[owasp_id] = f"{rate:.1f}%"
    breakdown["by_owasp_category"] = by_owasp

    # ── 维度4: by_scorer_agreement ──
    # 从 cascade_scorer 的 tier_stats 获取评分一致性
    scorer_stats = ctx.metadata.get("scorer_tier_stats", {})
    agreement: dict[str, Any] = {
        "both_agree_success": scorer_stats.get("T1_success", 0) + scorer_stats.get("T2_success", 0),
        "both_agree_failure": scorer_stats.get("T1_failure", 0) + scorer_stats.get("T2_failure", 0),
        "disagreement": scorer_stats.get("T2.5_disputed_adopt_a", 0)
        + scorer_stats.get("T2.5_disputed_adopt_b", 0)
        + scorer_stats.get("T2.5_disputed_fallback", 0),
    }
    breakdown["by_scorer_agreement"] = agreement

    # 写入 ctx.metadata
    ctx.metadata["asr_breakdown"] = breakdown

    # 打印摘要
    print("\n  --- O3: ASR 多维度分解 ---")
    print(f"  Overall ASR: {breakdown['overall_asr']}")
    if by_tier:
        print("  By Attack Tier:")
        for tier, val in by_tier.items():
            print(f"    {tier}: {val}")
    if by_converter:
        print("  By Converter:")
        for conv, val in by_converter.items():
            print(f"    {conv}: {val}")
    if by_owasp:
        print("  By OWASP Category:")
        for owasp, val in by_owasp.items():
            print(f"    {owasp}: {val}")
    if agreement:
        print("  By Scorer Agreement:")
        for key, val in agreement.items():
            print(f"    {key}: {val}")

    return breakdown


# ============================================================
# v59 P3: 替代路径攻击结果独立展示
# ============================================================


def _print_alternative_path_results(ctx: PipelineContext) -> None:
    """v59 P3: 替代路径攻击结果独立展示 — Stage 5 中用 core_card 展示.

    将 ctx.metadata["alternative_path_results"] 中的替代路径攻击结果
    结构化展示, 包含路径名/技术/OWASP分类/成功状态/评分方式.

    学术依据:
      - Greshake et al.(arXiv:2302.12173): 多路径攻击经验应独立追踪
      - NIST AI RMF 1.0 — 决策可追溯性要求替代路径结果可见
      - DART (arXiv:2407.06485) — per-model ASR 指导运行时决策
    """
    alt_results = ctx.metadata.get("alternative_path_results", [])
    if not alt_results:
        return

    from pipeline.utils.display import core_card

    # 按路径分组统计
    path_stats: dict[str, dict[str, Any]] = {}
    for r in alt_results:
        pid = r.get("path_id", "unknown")
        if pid not in path_stats:
            path_stats[pid] = {
                "technique": r.get("technique", "?"),
                "owasp": r.get("owasp_id", "?"),
                "total": 0,
                "success": 0,
                "score_methods": set(),
            }
        path_stats[pid]["total"] += 1
        if r.get("achieved"):
            path_stats[pid]["success"] += 1
        sm = r.get("score_method", "?")
        if sm:
            path_stats[pid]["score_methods"].add(sm)

    # 构建展示 sections
    sections: list[dict[str, Any]] = []

    # Section 1: 总览
    total_attacks = len(alt_results)
    total_success = sum(1 for r in alt_results if r.get("achieved"))
    overall_alt_asr = (total_success / total_attacks * 100) if total_attacks > 0 else 0
    overview_lines = [
        f"总攻击数: {total_attacks}",
        f"成功: {total_success} | 失败: {total_attacks - total_success}",
        f"替代路径整体 ASR: {overall_alt_asr:.1f}%",
    ]
    sections.append({"label": "总览", "lines": overview_lines})

    # Section 2: 按路径分组
    path_lines: list[str] = []
    for pid, stats in sorted(path_stats.items()):
        asr = (stats["success"] / stats["total"] * 100) if stats["total"] > 0 else 0
        methods = ", ".join(sorted(stats["score_methods"])) if stats["score_methods"] else "N/A"
        path_lines.append(
            f"{pid}: {stats['technique']} [{stats['owasp']}] "
            f"{stats['success']}/{stats['total']} ({asr:.0f}%)"
        )
        path_lines.append(f"  评分: {methods}")
    sections.append({"label": "路径明细", "lines": path_lines})

    # Section 3: 洞察
    insight_lines: list[str] = []
    if overall_alt_asr > 0:
        # 找到最佳路径
        best_path = max(path_stats.items(), key=lambda x: x[1]["success"] / max(x[1]["total"], 1))
        insight_lines.append(
            f"最佳路径: {best_path[0]} "
            f"(ASR={best_path[1]['success'] / max(best_path[1]['total'], 1) * 100:.0f}%)"
        )
    if total_success > 0:
        insight_lines.append("→ 替代路径有效突破主攻击失败的 objective")
        insight_lines.append("→ 经验已回注 ctx.asr_per_technique → warm-start 闭环")
    else:
        insight_lines.append("→ 替代路径未突破 — 建议增大 --max-attempts 或尝试 --tier-layer")
    sections.append({"label": "洞察", "lines": insight_lines})

    core_card("v59 替代路径攻击结果", sections)
