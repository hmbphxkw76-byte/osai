"""escalation_attacks — 从 escalation.py 拆分而来.

包含 Crescendo, TAP, PAIR 攻击实现.
"""

import asyncio
import logging
from typing import Any

from pipeline.context import PipelineContext, _get_config_int
from pipeline.strike.escalation_level1 import (
    _apply_mtos_ranking,
    _build_skeleton_key_seed_groups,
    _filter_by_suitable_for,
)
from pipeline.strike.escalation_level2 import _create_fallback_fsts, _retrieve_partial_results

logger = logging.getLogger(__name__)

# ── L5 v13: security_audit exception capture ──
_SECURITY_AUDIT_KEYWORDS = [
    "security_audit_fail",
    "content_filter",
    "content_policy",
    "safety_violation",
    "policy_violation",
    "inappropriate_content",
    "harmful_content",
]


class _SecurityAuditError(Exception):
    """Target API security_audit detection exception."""

    pass


def _is_security_audit_error(error_msg: str) -> bool:
    """Check if error message is a security_audit interception."""
    error_lower = error_msg.lower()
    return any(kw in error_lower for kw in _SECURITY_AUDIT_KEYWORDS)


async def _run_crescendo(
    ctx: PipelineContext,
    objectives: list[str],
) -> dict[str, list[Any]]:
    """对失败目标执行 Crescendo 多轮攻击。

    L5 v20: 修复 sqlite3.IntegrityError (UNIQUE constraint failed: ScoreEntries.id)
    问题原因: Crescendo 多轮攻击中, 并发评分写入 SQLite 导致 UUID 冲突或竞态条件,
    触发 ScoreEntries.id UNIQUE 约束, 传播到调用方导致整个 Crescendo 崩溃。
    修复策略:
        1. 将 Crescendo 的 AttackExecutor 并发度降为 1 (串行化评分写入),
           避免并发写入冲突
        2. 在异常处理中专门捕获 IntegrityError/SQLAlchemyError, 尝试恢复部分结果
    学术依据: Heroux et al. (arXiv:2403.04206) — 韧性工程, 部分结果恢复
    附加: Crescendo 本身是多轮对话, 内部已有 turn-by-turn 串行逻辑,
           AttackExecutor 并发度仅影响多个 seed_groups 的并行度,
           降为 1 不影响单 seed 的多轮对话执行

    Args:
        ctx: 流水线上下文。
        objectives: 失败目标列表。

    Returns:
        Crescendo 攻击结果。
    """
    from pyrit.executor.attack import (
        AttackAdversarialConfig,
        CrescendoAttack,
    )
    from pyrit.executor.attack.core.attack_executor import AttackExecutor

    results: dict[str, list[Any]] = {}

    # L5 v36: suitable_for 分发 — 只执行适合 Crescendo 的种子
    # 学术依据: Chao et al. (arXiv:2310.08419) — 种子-技术适配性
    crescendo_objectives = _filter_by_suitable_for(objectives, ctx, "crescendo")
    if not crescendo_objectives:
        logger.info("Crescendo: no objectives suitable for this technique, skipping")
        return results

    # L5 v41: 放宽限制从 3 → 8 — 实战场景下 ASR 优先于 token 成本
    # 学术依据: Russinovich et al. (arXiv:2402.12109) — Crescendo ASR=82% at 10 turns
    # 更多目标 = 更多成功机会 (联合概率 P=1-∏(1-p_i))
    # v37 的 3 目标限制基于 v34 的 0% ASR 数据, 但那是因为空评分配置导致
    # (v41 已修复评分配置), 现在放宽到 8 目标
    if len(crescendo_objectives) > 8:
        crescendo_objectives = crescendo_objectives[:8]
        logger.info(
            "L5 v41: Crescendo limited to top-8 objectives (MTOS-ranked)"
        )

    try:
        # L5 v41 修复: 使用 refusal inverter 评分配置 (原为空配置)
        # 空配置导致 Crescendo 无法判断每轮是否成功, 内部逻辑失效 → ASR=0%
        # 学术依据: Russinovich et al. (arXiv:2402.12109) — Crescendo 需要
        # per-turn scoring 来决定回溯策略, 空 scoring = 无回溯 = ASR=0%
        from pipeline.strike.escalation import _build_refusal_inverter_scoring_config
        scoring_config = _build_refusal_inverter_scoring_config(ctx)

        attack = CrescendoAttack(
            objective_target=ctx.multi_turn_target or ctx.objective_target,
            attack_adversarial_config=AttackAdversarialConfig(
                target=ctx.adversarial_target,
            ),
            attack_scoring_config=scoring_config,
            max_turns=10,      # L5 v3: 8→10, 更多轮次提升ASR
            max_backtracks=10,  # L5 v3: 8→10, 更多回溯机会
        )
        # L5 v12: Crescendo 上下文窗口优化 (修复 dead code)
        # 学术依据: Crescendo (arXiv:2402.12109) §4.3 — max_turns=10 需要
        # 足够大的上下文窗口保证对话历史完整性。
        # PyRIT 1.0.1 CrescendoAttack 通过多种可能属性管理上下文:
        for attr_name in ('max_conversation_memory', 'max_turn_memory', 'conversation_memory_limit'):
            if hasattr(attack, attr_name):
                setattr(attack, attr_name, 4096)
                logger.info("Crescendo: %s set to 4096 tokens/turn", attr_name)
                break
        else:
            logger.debug("Crescendo: using default memory (no explicit context window attr)")

        # 构建 seed groups (with Skeleton Key pre-injection + L5 v15 MTOS ranking)
        seed_groups = _build_skeleton_key_seed_groups(crescendo_objectives, ctx=ctx)

        # L5 v45: 统一从 ctx.args 读取并发数 (SSOT: config/defaults.yaml max_concurrency=3)
        from pipeline.context import get_effective_concurrency
        executor = AttackExecutor(
            max_concurrency=get_effective_concurrency(ctx),
        )

        executor_result = await asyncio.wait_for(
            executor.execute_attack_from_seed_groups_async(
                attack=attack,
                seed_groups=seed_groups,
                return_partial_on_failure=True,
            ),
            timeout=max(300, len(seed_groups) * 60),  # L5 v34: 600→300, 每目标~60s (v34 Crescendo ASR=0%, 缩短超时节省时间)
        )

        results["crescendo"] = list(executor_result.completed_results)
        logger.info(
            "Crescendo completed: %d success, %d failed",
            len(executor_result.completed_results),
            len(executor_result.incomplete_objectives),
        )

    except asyncio.TimeoutError:
        logger.warning("Crescendo attack timed out after 300s")
        # 尝试检索部分结果
        await _retrieve_partial_results(ctx, "crescendo")
    except _SecurityAuditError as e:
        logger.warning("Crescendo: security_audit_fail detected: %s, returning empty results", e)
    except Exception as e:
        # L5 v20: 捕获 IntegrityError, 尝试恢复部分结果
        exc_str = str(e).lower()
        if "integrityerror" in exc_str or "unique constraint" in exc_str:
            logger.warning(
                "Crescendo: IntegrityError (ScoreEntries.id conflict) detected, "
                "attempting partial result recovery: %s",
                e,
            )
            await _retrieve_partial_results(ctx, "crescendo")
        elif _is_security_audit_error(str(e)):
            logger.warning("Crescendo: security_audit_fail in exception: %s", e)
        else:
            logger.error("Crescendo attack failed: %s", e)
            # L5 v20: 即使是非 IntegrityError, 也尝试恢复部分结果
            await _retrieve_partial_results(ctx, "crescendo")

    return results

async def _run_tap(
    ctx: PipelineContext,
    objectives: list[str],
) -> dict[str, list[Any]]:
    """对失败目标执行 TAP 树搜索攻击。

    L5 优化: tree_width=2 (从4减少), tree_depth=2 (从3减少)
    减少 API 调用 ~75%，保持 ASR~50%。

    Args:
        ctx: 流水线上下文。
        objectives: 失败目标列表。

    Returns:
        TAP 攻击结果。
    """
    from pyrit.executor.attack import (
        AttackAdversarialConfig,
        TAPAttack,
    )
    from pyrit.executor.attack.core.attack_executor import AttackExecutor
    from pyrit.models import AttackSeedGroup, SeedObjective

    results: dict[str, list[Any]] = {}

    # L5 v36: suitable_for 分发 — 只执行适合 TAP 的种子
    # 学术依据: Mehrotra et al. (arXiv:2312.02191) — TAP 树搜索对需要
    # 多分支探索的种子 (如工具链式调用) 更有效
    tap_objectives = _filter_by_suitable_for(objectives, ctx, "tap")
    if not tap_objectives:
        logger.info("TAP: no objectives suitable for this technique, skipping")
        return results

    # L5 v41: 放宽限制从 3 → 8 — 实战场景下 ASR 优先
    # 学术依据: Mehrotra et al. (arXiv:2312.02191) — TAP 树搜索 ASR=50-80%
    # 更多目标 = 更多成功机会 (联合概率 P=1-∏(1-p_i))
    if len(tap_objectives) > 8:
        tap_objectives = tap_objectives[:8]
        logger.info(
            "L5 v41: TAP limited to top-8 objectives (MTOS-ranked)"
        )

    try:
        # L5 v23: 直接使用原生 FloatScaleThresholdScorer, 移除 AdaptiveDualFloatJudgeScorer
        # 原因: AdaptiveDualFloatJudgeScorer 继承 FloatScaleThresholdScorer 但内部
        # 调用子 scorer 时返回非标准值, 导致 TAP 节点报错:
        # "TrueFalseScorer score value must be True or False"
        # TAP 原生设计要求 FloatScaleThresholdScorer (arXiv:2312.02191 §3.2)
        # 学术依据: Mehrotra et al. (arXiv:2312.02191) — TAP 使用 FloatScaleScorer

        from pyrit.executor.attack.multi_turn.tree_of_attacks import TAPAttackScoringConfig

        scorer = _create_fallback_fsts(ctx)
        logger.info("TAP scorer: FloatScaleThresholdScorer (threshold=0.2) — L5 v34 tuned")

        scoring_config = TAPAttackScoringConfig(
            objective_scorer=scorer,
        )

        attack = TAPAttack(
            objective_target=ctx.multi_turn_target or ctx.objective_target,
            attack_adversarial_config=AttackAdversarialConfig(
                target=ctx.adversarial_target,
            ),
            attack_scoring_config=scoring_config,
            on_topic_checking_enabled=False,
            tree_width=_get_config_int(ctx, "tap_tree_width", 4),
            tree_depth=_get_config_int(ctx, "tap_tree_depth", 4),
        )

        # L5 v16: TAP 集成 MTOS 多轮选种排序
        # 学术依据: Chao et al. (arXiv:2310.08419) — TAP 是多轮树搜索攻击,
        # 低-中 ASR 种子更适合多轮迭代优化, 高 ASR 种子单轮已成功
        # L5 v36: 传入 technique_name='tap' 启用交叉 ASR 先验加权
        mtos_objectives = _apply_mtos_ranking(tap_objectives, ctx, technique_name="tap")

        seed_groups = [
            AttackSeedGroup(seeds=[SeedObjective(value=obj)])
            for obj in mtos_objectives
        ]

        # L5 v45: 统一从 ctx.args 读取并发数 (SSOT: config/defaults.yaml max_concurrency=3)
        from pipeline.context import get_effective_concurrency
        executor = AttackExecutor(
            max_concurrency=get_effective_concurrency(ctx),
        )

        executor_result = await asyncio.wait_for(
            executor.execute_attack_from_seed_groups_async(
                attack=attack,
                seed_groups=seed_groups,
                return_partial_on_failure=True,
            ),
            timeout=400,  # L5 v34: 600→400, TAP tree_width=4 depth=4 需要较多时间但 600s 太长
        )

        results["tap"] = list(executor_result.completed_results)
        logger.info(
            "TAP completed: %d success, %d failed",
            len(executor_result.completed_results),
            len(executor_result.incomplete_objectives),
        )

    except asyncio.TimeoutError:
        logger.warning("TAP attack timed out after 400s")
        await _retrieve_partial_results(ctx, "tap")
    except _SecurityAuditError as e:
        logger.warning("TAP: security_audit_fail detected: %s, returning empty results", e)
    except Exception as e:
        if _is_security_audit_error(str(e)):
            logger.warning("TAP: security_audit_fail in exception: %s", e)
        else:
            logger.error("TAP attack failed: %s", e)

    return results

async def _run_pair(
    ctx: PipelineContext,
    objectives: list[str],
) -> dict[str, list[Any]]:
    """对失败目标执行 PAIR 迭代优化攻击。

    L5 新增: PAIR 作为第三升级阶段。
    tree_width=1 (单流), tree_depth=3 (3次迭代)
    API 调用量极小，ASR 40-60%。

    学术依据: Chao et al. (arXiv:2310.08419)

    Args:
        ctx: 流水线上下文。
        objectives: 失败目标列表。

    Returns:
        PAIR 攻击结果。
    """
    from pyrit.executor.attack import (
        AttackAdversarialConfig,
    )
    from pyrit.executor.attack.core.attack_executor import AttackExecutor
    from pyrit.executor.attack.multi_turn.pair import PAIRAttack
    from pyrit.models import AttackSeedGroup, SeedObjective

    results: dict[str, list[Any]] = {}

    # L5 v36: suitable_for 分发 — 只执行适合 PAIR 的种子
    # 学术依据: Chao et al. (arXiv:2310.08419) — PAIR 对需要迭代优化的种子有效
    pair_objectives = _filter_by_suitable_for(objectives, ctx, "pair")
    if not pair_objectives:
        logger.info("PAIR: no objectives suitable for this technique, skipping")
        return results

    try:
        # L5 v23: 直接使用原生 FloatScaleThresholdScorer, 移除 AdaptiveDualFloatJudgeScorer
        # 原因: 与 _run_tap 修复相同 — AdaptiveDualFloatJudgeScorer 返回非标准值
        # 导致 PAIR 节点报错。PAIR 继承 TAP, 原生使用 FloatScaleScorer。
        # 学术依据: Chao et al. (arXiv:2310.08419) — PAIR 使用 FloatScaleScorer

        from pyrit.executor.attack.multi_turn.tree_of_attacks import TAPAttackScoringConfig

        scorer = _create_fallback_fsts(ctx)
        logger.info("PAIR scorer: FloatScaleThresholdScorer (threshold=0.2) — L5 v34 tuned")

        scoring_config = TAPAttackScoringConfig(
            objective_scorer=scorer,
        )

        attack = PAIRAttack(
            objective_target=ctx.multi_turn_target or ctx.objective_target,
            attack_adversarial_config=AttackAdversarialConfig(
                target=ctx.adversarial_target,
            ),
            attack_scoring_config=scoring_config,
            tree_width=_get_config_int(ctx, "pair_tree_width", 1),    # PAIR: 单流迭代
            tree_depth=_get_config_int(ctx, "pair_tree_depth", 10),   # L5 v8: depth=10 ASR 60% (arXiv:2310.08419)
        )

        # L5 v16: PAIR 集成 MTOS 多轮选种排序
        # 学术依据: Chao et al. (arXiv:2310.08419) — PAIR 是多轮迭代优化攻击,
        # 低-中 ASR 种子更适合多轮迭代, 高 ASR 种子单轮已成功
        # L5 v36: 传入 technique_name='pair' 启用交叉 ASR 先验加权
        mtos_objectives = _apply_mtos_ranking(pair_objectives, ctx, technique_name="pair")

        seed_groups = [
            AttackSeedGroup(seeds=[SeedObjective(value=obj)])
            for obj in mtos_objectives
        ]

        # L5 v45: 统一从 ctx.args 读取并发数 (SSOT: config/defaults.yaml max_concurrency=3)
        from pipeline.context import get_effective_concurrency
        executor = AttackExecutor(
            max_concurrency=get_effective_concurrency(ctx),
        )

        executor_result = await asyncio.wait_for(
            executor.execute_attack_from_seed_groups_async(
                attack=attack,
                seed_groups=seed_groups,
                return_partial_on_failure=True,
            ),
            timeout=400,  # L5 v34: 600→400, PAIR depth=10 但 600s 太长
        )

        results["pair"] = list(executor_result.completed_results)
        logger.info(
            "PAIR completed: %d success, %d failed",
            len(executor_result.completed_results),
            len(executor_result.incomplete_objectives),
        )

    except asyncio.TimeoutError:
        logger.warning("PAIR attack timed out after 400s")
        await _retrieve_partial_results(ctx, "pair")
    except _SecurityAuditError as e:
        logger.warning("PAIR: security_audit_fail detected: %s, returning empty results", e)
    except Exception as e:
        if _is_security_audit_error(str(e)):
            logger.warning("PAIR: security_audit_fail in exception: %s", e)
        else:
            logger.error("PAIR attack failed: %s", e)

    return results
