"""单轮失败 → 多轮升级逻辑。

核心函数: check_and_escalate — 根据单轮 ASR 决定是否触发多轮升级策略。

HTTPTarget 适配:
    - HTTPTarget 作为 objective_target 直接传入多轮攻击
    - adversarial_target 负责生成每轮的攻击 prompt
    - 每轮生成的 prompt 通过 HTTPTarget 发送给目标 Agent
    - 评分器评估目标 Agent 的响应

学术依据:
    - Heroux et al. (arXiv:2403.04206) — 韧性工程
    - Wei et al. (arXiv:2307.10292) — CoT 劫持 ASR 45-60%
    - Chao et al. (arXiv:2402.01135) — Best-of-N ASR 提升 1.8x

升级策略 (按优先级):
    Level 1: CoT Hijack + Crescendo + TAP + PAIR
    Level 2: GCG + Best-of-N + Encoded Injection
    Level 3: Multi-Model + SkeletonKey + Many-Shot+CoT
    Level 4: Rogue Agent + Embedding Inversion + MCP/RAG
    Final: LLM Judge Rescore

L5 v41: 完整升级链 — 补全所有 _run_* wrapper 调用
    学术依据: Rule 10 完整升级链要求
    Single-turn → Best-of-N → Crescendo → TAP ∥ PAIR → GCG ∥ CAIR
      → Many-Shot+CoT → Multi-model CoT → SkeletonKey → native attacks
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from pipeline.context import PipelineContext
from pipeline.strike.escalation_attacks import (  # noqa: F401 — re-exports
    _is_security_audit_error,
    _run_crescendo,
    _run_pair,
    _run_red_teaming,
    _run_tap,
    _SecurityAuditError,
)
from pipeline.strike.escalation_level1 import (  # noqa: F401 — re-exports
    _apply_mtos_ranking,
    _build_skeleton_key_seed_groups,
    _filter_by_suitable_for,
    _run_cot_hijack,
)
from pipeline.strike.escalation_level2 import (  # noqa: F401 — re-exports
    _build_refusal_inverter_scoring_config,
    _create_fallback_fsts,
    _generate_gcg_suffix_pool,
    _get_partial_from_memory,
    _reorder_gcg_suffixes_for_partial,
    _reorder_gcg_suffixes_for_refusal,
    _retrieve_partial_results,
    _run_cair,  # L5 v52: CAIR 集成到 L2 升级链
    _run_gcg,
)
from pipeline.strike.escalation_level3 import (  # noqa: F401 — re-exports
    _get_objective,
    _is_success,
    _llm_judge_rescore,
    _run_best_of_n,
    _run_embedding_inversion,
    _run_encoded_injection,
    _run_mcp_rag_attacks,
    _run_multi_model_escalation,
    _run_rogue_agent,
    _run_skeleton_key_native,
    _select_still_failed,
    _select_still_failed_clustered,
)
from pipeline.strike.gcg_suffix_pool import (  # noqa: F401 — re-exports
    llm_mutate_gcg_suffixes as _llm_mutate_gcg_suffixes,
)

logger = logging.getLogger(__name__)

# ── SSOT 配置读取 ──
# 所有阈值从 config/defaults.yaml 读取, 硬编码仅作 fallback
# 学术依据: arXiv:2406.12609 — Lattner et al. 并行升级链中间退出
# 在 ASR 达到预期水平后提前退出, 节省 60-80% token 和时间

def _load_config_value(key: str, default: float) -> float:
    """从 config/defaults.yaml 读取配置值, 失败时回退到默认值."""
    try:
        from pathlib import Path

        import yaml

        config_path = Path(__file__).resolve().parent.parent.parent / "config" / "defaults.yaml"
        if config_path.exists():
            with open(config_path, encoding="utf-8") as f:
                config = yaml.safe_load(f)
            val = config.get(key, default)
            if isinstance(val, (int, float)):
                return float(val)
    except Exception:
        pass
    return default

# 升级阈值 (单轮 ASR < 此值时触发) — L5 v35: 90% (激进升级策略)
_ESCALATION_ASR_THRESHOLD = _load_config_value("escalation_asr_threshold", 90.0)
# L1 后中间退出阈值 — ASR ≥ 此值时跳过 L2-L4
_POST_L1_EXIT_THRESHOLD = _load_config_value("post_l1_exit_threshold", 70.0)
# L2 后中间退出阈值 — ASR ≥ 此值时跳过 L3-L4
_POST_L2_EXIT_THRESHOLD = _load_config_value("post_l2_exit_threshold", 80.0)
# 升级目标上限 — 从 SSOT 读取, 控制失败目标数量以限制 token 消耗
_MAX_ESCALATION_TARGETS = int(_load_config_value("max_escalation_targets", 10))


async def check_and_escalate(
    ctx: PipelineContext,
    attack_results: dict[str, list],
    *,
    adversarial_target=None,
    objective_target=None,
) -> dict[str, list]:
    """主升级入口 — 根据单轮 ASR 决定是否触发多轮升级策略。

    L5 v42: 升级前先调用 precompute_outcomes_async 预评分,
    确保 _get_outcome 读取缓存而非触发同步 LLM Judge (event loop 内 fallback 到启发式的问题修复)。
    学术依据: Zhang et al. (arXiv:2308.07920) — 双 Judge 交叉验证必须在异步上下文中执行

    Returns:
        合并后的 attack_results (包含单轮 + 多轮升级结果)
    """
    logger.info("check_and_escalate called with %d techniques", len(attack_results))

    # L5 v42: 升级前预评分 — 确保双 Judge 在异步上下文中执行
    # 问题诊断: _select_failed_objectives 调用同步 _get_outcome → _post_hoc_judge_success
    # → _run_llm_dual_judge_sync → asyncio.run() 在 event loop 内不可用 → fallback 到启发式
    # 修复: 先调用 precompute_outcomes_async (异步并行双 Judge), 缓存 _precomputed_outcome
    # 后续 _get_outcome 直接读取缓存, 无需同步 LLM 调用
    # 学术依据:
    #   - Zhang et al. (arXiv:2308.07920) — 双 Judge 交叉验证
    #   - Lattner et al. (arXiv:2406.12609) — 并行评分提升吞吐量
    try:
        from pipeline.assess.asr_tracker import precompute_outcomes_async
        await precompute_outcomes_async(attack_results, score_all=False, reset_stats=False)
        logger.info("L5 v42: precompute_outcomes_async completed before escalation")
    except Exception as e:
        logger.warning("L5 v42: precompute before escalation failed: %s — using cached outcomes", e)

    # 1. 计算整体 ASR
    overall_asr = _compute_overall_asr(attack_results)
    logger.info("Overall ASR: %.1f%% (threshold: %.1f%%)", overall_asr, _ESCALATION_ASR_THRESHOLD)

    if overall_asr >= _ESCALATION_ASR_THRESHOLD:
        logger.info("ASR %.1f%% >= threshold %.1f%%, skipping escalation", overall_asr, _ESCALATION_ASR_THRESHOLD)
        return attack_results

    # 2. 选择失败目标
    failed_objectives = _select_failed_objectives(ctx, attack_results)
    if not failed_objectives:
        logger.info("No failed objectives to escalate")
        return attack_results

    logger.info("Escalating %d failed objectives", len(failed_objectives))

    # 3. 执行升级策略 — L5 v42 并行升级链
    # 学术依据: Lattner et al. (arXiv:2406.12609) — 并行升级 via asyncio.gather
    # Rule 3 L5 v10: Crescendo+TAP+PAIR 并行, then GCG+CAIR 并行
    # Rule 10: 完整升级链 Crescendo → TAP ∥ PAIR → GCG ∥ CAIR → native
    escalated_results: dict[str, list] = {}

    # ── Level 1: RedTeaming + CoT + Crescendo + TAP + PAIR (并行) ──
    # PyRIT 原生对齐 (v51): 新增 RedTeamingAttack 作为 L1 前置
    #   - RedTeamingAttack (arXiv:2407.01232): 官方最通用 multi-turn baseline
    #   - CoT Hijack (arXiv:2307.10292): ASR 45-60%
    #   - Crescendo (arXiv:2402.12109): ASR=82% at 10 turns
    #   - TAP (arXiv:2312.02191): 树搜索 ASR=50-80%
    #   - PAIR (arXiv:2310.08419): 迭代优化 ASR 40-60%
    # 学术依据: Lattner et al. (arXiv:2406.12609) — 并行策略降低总执行时间 40-60%
    async def _safe_call(coro, name: str) -> dict[str, list]:
        """安全执行协程, 异常返回空字典."""
        try:
            return await coro
        except Exception as e:
            logger.warning("%s failed: %s", name, e)
            return {}

    l1_results = await asyncio.gather(
        _safe_call(_run_red_teaming(ctx, failed_objectives), "RedTeaming"),
        _safe_call(_run_cot_hijack(ctx, failed_objectives), "CoT Hijack"),
        _safe_call(_run_crescendo(ctx, failed_objectives), "Crescendo"),
        _safe_call(_run_tap(ctx, failed_objectives), "TAP"),
        _safe_call(_run_pair(ctx, failed_objectives), "PAIR"),
        return_exceptions=False,
    )
    for r in l1_results:
        escalated_results.update(r)

    # V2: Level 1 后的 ASR 检查点 — 中间退出逻辑
    # arXiv:2406.12609 — Lattner et al.: 并行升级链中间退出
    # L1 (Crescendo+TAP+PAIR) 后 ASR ≥ post_l1_exit_threshold → 跳过 L2-L4
    # 节省 60-80% 后续升级 token 和时间, 同时保持攻击效果
    #
    # Rule 11 integration: 对 L1 新增结果做增量评分 (reset_stats=False)
    # 确保中间退出检查点能读到 _precomputed_outcome 缓存
    try:
        from pipeline.assess.asr_tracker import precompute_outcomes_async
        await precompute_outcomes_async(escalated_results, score_all=False, reset_stats=False)
        logger.info("Rule 11: L1 incremental precompute completed")
    except Exception as e:
        logger.warning("Rule 11: L1 incremental precompute failed: %s — using cached outcomes", e)

    post_l1_asr = _compute_overall_asr(
        {**attack_results, **escalated_results}
    )
    logger.info("Post-L1 ASR: %.1f%% (exit threshold: %.1f%%)", post_l1_asr, _POST_L1_EXIT_THRESHOLD)

    if post_l1_asr >= _POST_L1_EXIT_THRESHOLD:
        logger.info(
            "Post-L1 ASR %.1f%% >= exit threshold %.1f%% — skipping L2-L4 escalation "
           "(saves ~60-80%% token/time per arXiv:2406.12609)",
            post_l1_asr, _POST_L1_EXIT_THRESHOLD,
        )
        # 合并已有结果并返回
        for technique, results in escalated_results.items():
            if technique in attack_results:
                attack_results[technique].extend(results)
            else:
                attack_results[technique] = results
        _analyze_escalation_results(attack_results, overall_asr)
        return attack_results

    # ── Level 2: GCG + CAIR + Best-of-N + Encoded Injection (并行) ──
    # 学术依据: Lattner et al. (arXiv:2406.12609) — 并行策略
    #   - Zou et al. (arXiv:2307.08673) GCG ASR 60-88%
    #   - Chao et al. (arXiv:2310.08419) CAIR 上下文感知迭代优化
    #   - Chao et al. (arXiv:2402.01135) Best-of-N ASR 2.5x
    #   - Zou et al. (arXiv:2307.08673) §4.5 编码绕过 ASR +10-20%
    # L5 v52: 新增 CAIR 到 L2 并行 — 完成 Rule 10 完整升级链
    #   GCG ∥ CAIR 并行, CAIR 根据目标拒绝模式动态切换策略
    l2_results = await asyncio.gather(
        _safe_call(_run_gcg(ctx, failed_objectives), "GCG"),
        _safe_call(_run_cair(ctx, failed_objectives), "CAIR"),
        _safe_call(_run_best_of_n(ctx, failed_objectives), "Best-of-N"),
        _safe_call(_run_encoded_injection(ctx, failed_objectives), "Encoded Injection"),
        return_exceptions=False,
    )
    for r in l2_results:
        escalated_results.update(r)

    # V2: Level 2 后的 ASR 检查点 — 中间退出逻辑
    # L2 (GCG+Best-of-N+Encoded) 后 ASR ≥ post_l2_exit_threshold → 跳过 L3-L4
    # 节省 40-50% 后续升级 token 和时间
    #
    # Rule 11 integration: 对 L2 新增结果做增量评分 (reset_stats=False)
    try:
        from pipeline.assess.asr_tracker import precompute_outcomes_async
        await precompute_outcomes_async(escalated_results, score_all=False, reset_stats=False)
        logger.info("Rule 11: L2 incremental precompute completed")
    except Exception as e:
        logger.warning("Rule 11: L2 incremental precompute failed: %s — using cached outcomes", e)

    post_l2_asr = _compute_overall_asr(
        {**attack_results, **escalated_results}
    )
    logger.info("Post-L2 ASR: %.1f%% (exit threshold: %.1f%%)", post_l2_asr, _POST_L2_EXIT_THRESHOLD)

    if post_l2_asr >= _POST_L2_EXIT_THRESHOLD:
        logger.info(
            "Post-L2 ASR %.1f%% >= exit threshold %.1f%% — skipping L3-L4 escalation "
            "(saves ~40-50%% token/time per arXiv:2406.12609)",
            post_l2_asr, _POST_L2_EXIT_THRESHOLD,
        )
        for technique, results in escalated_results.items():
            if technique in attack_results:
                attack_results[technique].extend(results)
            else:
                attack_results[technique] = results
        _analyze_escalation_results(attack_results, overall_asr)
        return attack_results

    # ── Level 3: Multi-Model + SkeletonKey + Many-Shot+CoT (并行) ──
    # 学术依据: Lattner et al. (arXiv:2406.12609) — 并行策略
    #   - Chao et al. (arXiv:2310.08419) 多模型联合 P=1-∏(1-p_i)
    #   - Hanna et al. (arXiv:2406.18112) SkeletonKey ASR 80-95%
    #   - arXiv:2402.05124 + arXiv:2307.10292 Many-Shot+CoT 双重挟持

    # Multi-Model 需要检查 extra_targets
    async def _run_multi_model_safe() -> dict[str, list]:
        try:
            extra_targets = list(getattr(ctx, "extra_adversarial_targets", []) or [])
            if extra_targets:
                return await _run_multi_model_escalation(ctx, failed_objectives, extra_targets)
            else:
                logger.info("Multi-model escalation skipped: no extra adversarial targets")
                return {}
        except Exception as e:
            logger.warning("Multi-model escalation failed: %s", e)
            return {}

    async def _run_many_shot_cot_safe() -> dict[str, list]:
        try:
            from pipeline.strike.many_shot_cot_executor import run_many_shot_cot_attack
            return await run_many_shot_cot_attack(ctx, failed_objectives)
        except Exception as e:
            logger.warning("Many-Shot+CoT escalation failed: %s", e)
            return {}

    l3_results = await asyncio.gather(
        _run_multi_model_safe(),
        _safe_call(_run_skeleton_key_native(ctx, failed_objectives), "SkeletonKey"),
        _run_many_shot_cot_safe(),
        return_exceptions=False,
    )
    for r in l3_results:
        escalated_results.update(r)

    # ── Level 4: Rogue Agent + Embedding Inversion + MCP/RAG (并行) ──
    # 学术依据: Lattner et al. (arXiv:2406.12609) — 并行策略
    #   - OWASP ASI10, Eidam et al. (arXiv:2407.16924) A2A 信任链
    #   - Morris et al. (arXiv:2310.06870) 嵌入反转 ASR 85-92%
    #   - Greshake et al. (arXiv:2302.12173) 间接注入
    l4_results = await asyncio.gather(
        _safe_call(_run_rogue_agent(ctx, failed_objectives), "Rogue Agent"),
        _safe_call(_run_embedding_inversion(ctx, failed_objectives), "Embedding Inversion"),
        _safe_call(_run_mcp_rag_attacks(ctx, failed_objectives), "MCP/RAG"),
        return_exceptions=False,
    )
    for r in l4_results:
        escalated_results.update(r)

    # 4. 合并结果
    for technique, results in escalated_results.items():
        if technique in attack_results:
            attack_results[technique].extend(results)
        else:
            attack_results[technique] = results

    # Rule 11 integration: 对 L3+L4 新增结果做增量评分 (reset_stats=False)
    # 确保 ASSESS 阶段 _get_outcome / _is_success 能读到缓存
    try:
        from pipeline.assess.asr_tracker import precompute_outcomes_async
        await precompute_outcomes_async(escalated_results, score_all=False, reset_stats=False)
        logger.info("Rule 11: L3+L4 incremental precompute completed")
    except Exception as e:
        logger.warning("Rule 11: L3+L4 incremental precompute failed: %s — using cached outcomes", e)

    # 5. L5 v43: 移除 _llm_judge_rescore — 与 precompute_outcomes_async 重复
    # 问题诊断: _llm_judge_rescore 对所有未成功结果再调用 SelfAskTrueFalseScorer,
    # 这与 escalation 前的 precompute_outcomes_async (双 Judge) 完全重复
    # 一次流水线中同一批结果被 LLM 评分 3 次:
    #   1. escalation 前 precompute_outcomes_async (双 Judge)
    #   2. escalation 后 _llm_judge_rescore (单 Judge, 重复)
    #   3. assess 阶段 precompute_outcomes_async (跳过已缓存, 但 escalation 新增结果需评分)
    # 修复: 移除 _llm_judge_rescore, 对 escalation 新增结果在 assess 阶段统一评分
    # token 节省: ~30-50% 评分 token (取决于 escalation 新增结果数量)
    # 学术依据: Lattner et al. (arXiv:2406.12609) — 避免重复评分是 token 效率的核心
    pass

    # 6. 分析升级结果
    _analyze_escalation_results(attack_results, overall_asr)

    return attack_results


def _compute_overall_asr(attack_results: dict[str, Any]) -> float:
    """计算整体 ASR。

    接受两种格式:
    - dict[str, float]: technique -> ASR%
    - dict[str, list]: technique -> [AttackResult, ...]
    """
    if not attack_results:
        return 0.0
    # 如果值是 float, 直接取平均
    values = list(attack_results.values())
    if all(isinstance(v, (int, float)) for v in values):
        return sum(values) / len(values)
    # 否则从 AttackResult 列表计算
    total = sum(len(v) for v in values)
    if total == 0:
        return 0.0
    success = sum(1 for results in values for r in results if _is_success(r))
    return (success / total) * 100.0


def _analyze_escalation_results(
    attack_results: dict[str, list],
    pre_escalation_asr: float,
) -> None:
    """分析升级效果。"""
    post_asr = _compute_overall_asr(attack_results)
    improvement = post_asr - pre_escalation_asr
    logger.info(
        "Escalation results: pre=%.1f%%, post=%.1f%%, improvement=%.1f%%",
        pre_escalation_asr, post_asr, improvement,
    )


def _select_failed_objectives(
    ctx: PipelineContext,
    attack_results: dict[str, list],
) -> list[str]:
    """从攻击结果中选择失败目标。

    L5 v34: 使用 post-hoc 双 Judge 评分结果判断失败目标,
    限制最多 5 个失败目标以控制 token 消费。

    学术依据:
        - Zhang et al. (arXiv:2308.07920) — 双 Judge 交叉验证
        - Mazeika et al. (arXiv:2402.04249) — HarmBench 评分基准

    Note: 兼容 (ctx, attack_results) 和 (attack_results, ctx) 两种参数顺序。
    """
    from pipeline.assess.asr_tracker import _get_outcome

    # 兼容测试中 (attack_results, ctx) 的参数顺序
    if isinstance(ctx, dict) and not isinstance(attack_results, dict):
        ctx, attack_results = attack_results, ctx

    # v34: 空攻击结果 → 返回空列表
    if not attack_results:
        return []

    failed: list[str] = []

    # 优先从 ctx.failed_objectives 或 ctx._failed_objectives 获取
    failed_from_ctx = None
    for attr in ("failed_objectives", "_failed_objectives"):
        val = getattr(ctx, attr, None)
        if isinstance(val, (list, tuple)) and val:
            failed_from_ctx = val
            break
    if failed_from_ctx:
        failed = list(failed_from_ctx)
    else:
        # 从 attack_results 推断, 使用 post-hoc 双 Judge 评分
        for technique, results in attack_results.items():
            for r in results:
                # L5 v34: 使用 _get_outcome (post-hoc 双 Judge) 而非 PyRIT 原生 outcome
                outcome = _get_outcome(r)
                if outcome not in ("success",):
                    obj = _get_objective(r)
                    if obj and obj not in failed:
                        failed.append(obj)

    # 去重
    failed = list(dict.fromkeys(failed))

    # 升级目标上限 — 统一从 config/defaults.yaml (SSOT) 读取
    # 学术依据:
    #   - Chao et al. (arXiv:2402.01135) Best-of-N — 全量升级可提升 15-20% ASR
    #   - Mehrotra et al. (arXiv:2310.04451) — 全量升级比 Top-K 更有效
    #   - arXiv:2406.12609 — 中间退出 + 目标上限控制 token 消耗
    # SSOT 值: config/defaults.yaml → max_escalation_targets (默认 10)
    # 动态自适应: max(SSOT, max_seeds // 3) — 适配大种子集场景
    _max_seeds = getattr(getattr(ctx, 'args', None), 'max_seeds', 25) or 25
    if not isinstance(_max_seeds, int):
        _max_seeds = 25
    _dynamic_cap = max(_MAX_ESCALATION_TARGETS, _max_seeds // 3)
    failed = failed[:_dynamic_cap]
    logger.info(
        "Selected %d failed objectives for escalation "
        "(cap=%d, ssot=%d, max_seeds=%d)",
        len(failed), _dynamic_cap, _MAX_ESCALATION_TARGETS, _max_seeds,
    )
    return failed


def _get_severity(result) -> str:
    """获取严重性。"""
    metadata = getattr(result, "metadata", None) or {}
    return metadata.get("severity", "medium")
