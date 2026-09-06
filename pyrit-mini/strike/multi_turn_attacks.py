# arXiv:2402.01135 — Chao et al., Best-of-N (N=5 ASR 1.8x)
# arXiv:2402.12109 — Russinovich et al., Crescendo
"""multi_turn_attacks — 多轮攻击策略模块.

提供 Best-of-N 等多轮攻击的异步包装函数。
使用 VariationConverter + PersuasionConverter 生成 N 个独立变体,
通过 PyRIT 原生 PromptSendingAttack 并行执行, 任一成功即标记为成功.

数据流:
    escalation_chain.py → run_best_of_n_attack() → _best_of_n_retry()
    → ctx.attack_results["best_of_n_retry"] → assess 阶段评分

学术依据:
    - Best-of-N (arXiv:2402.01135): N=5 ASR 1.8x
    - Wei et al. (arXiv:2307.15043): 串联 >2 层 ASR 从 12% 降至 4%
      → 每 ConverterConfiguration 仅 1 个 converter (不变量 I1)
    - Zeng et al. (arXiv:2402.19181): Persuasion authority ASR 38.4% 最高
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)


async def run_best_of_n_attack(
    ctx: PipelineContext,
    objectives: list[str],
    n: int = 5,
) -> dict[str, list[Any]]:
    """Best-of-N 采样攻击包装.

    对每个 objective, 生成 N 个独立 converter 变体路径,
    通过 PyRIT 原生 PromptSendingAttack 并行执行.
    任一变体成功即标记该 objective 为成功.

    Args:
        ctx: 流水线上下文, 需包含 objective_target, converter_target, scoring_config.
        objectives: 失败目标列表 (需要 Best-of-N 重试的 objective 字符串).
        n: Best-of-N 变体数量 (默认 5, 从 config/defaults.yaml best_of_n_retries 读取).

    Returns:
        dict[str, list[Any]]: {objective: [AttackResult, ...]} 格式的结果字典,
        成功攻击返回完整结果列表, 失败攻击返回空列表.

    学术依据: Chao et al. (arXiv:2402.01135) — N=5 ASR 1.8x

    C2 合规: 此函数仅作为 wrapper 委托给 _best_of_n_retry 实现,
    不添加任何内容过滤或安全护栏, ASR 至上.
    """
    if not objectives:
        logger.info("Best-of-N: no objectives to retry, returning empty")
        return {}

    if ctx.objective_target is None:
        logger.warning("Best-of-N: objective_target is None, cannot execute")
        return {}

    logger.info("Best-of-N: launching retry for %d objectives (n=%d)", len(objectives), n)

    # 构造 failed_objectives 格式: list[tuple[str, Any]]
    # _best_of_n_retry 期望 (objective, last_result) 元组格式
    failed_objectives: list[tuple[str, Any]] = [(obj, None) for obj in objectives]

    try:
        # 委托给 adaptive_executor._best_of_n_retry (已有完整实现)
        # 该函数会修改 ctx.attack_results, 添加 "best_of_n_retry" 键
        from strike.adaptive_executor import _best_of_n_retry

        # 使用自定义的 n (覆盖配置默认值)
        # _best_of_n_retry 内部通过 _get_best_of_n_retries 读取配置,
        # 但 n 参数影响并行变体数, 我们通过设置 ctx._best_of_n_override 传入
        setattr(ctx, "_best_of_n_override", n)
        await _best_of_n_retry(ctx, failed_objectives)
        # 清理临时属性
        if hasattr(ctx, "_best_of_n_override"):
            delattr(ctx, "_best_of_n_override")

        # 收集结果: 从 ctx.attack_results["best_of_n_retry"] 按 objective 分组
        bon_results = ctx.attack_results.get("best_of_n_retry", [])
        results_by_objective: dict[str, list[Any]] = {}

        for result in bon_results:
            # 提取 objective (从原始 prompt 或 metadata)
            objective_value = _extract_objective_from_result(result)
            if objective_value:
                results_by_objective.setdefault(objective_value, []).append(result)

        # 确保所有 objectives 都有条目 (即使失败)
        for obj in objectives:
            if obj not in results_by_objective:
                results_by_objective[obj] = []

        logger.info(
            "Best-of-N: completed for %d objectives, %d have results",
            len(objectives),
            sum(1 for r in results_by_objective.values() if r),
        )
        return results_by_objective

    except asyncio.TimeoutError:
        logger.warning("Best-of-N: timeout for %d objectives", len(objectives))
        return {obj: [] for obj in objectives}
    except Exception as e:
        logger.error("Best-of-N: execution failed: %s", e, exc_info=True)
        # R-H2 合规: 不静默吞错, 返回空结果但保留日志记录
        return {obj: [] for obj in objectives}


def _extract_objective_from_result(result: Any) -> str | None:
    """从攻击结果中提取 objective 值.

    PyRIT 的 AttackResult 包含.conversation_id 和原始 prompt,
    通过 seed_prompt_value 或首位 prompt 提取 objective.
    """
    # 尝试从 seed_prompt_value 提取
    seed_prompt = getattr(result, "seed_prompt_value", None)
    if seed_prompt:
        return seed_prompt

    # 尝试从 conversation 提取
    conversation = getattr(result, "conversation", None)
    if conversation and hasattr(conversation, "messages"):
        messages = conversation.messages
        if messages:
            first_msg = messages[0]
            content = getattr(first_msg, "content", None)
            if content:
                return content

    # 尝试从原始 prompt 提取
    original_prompt = getattr(result, "original_prompt_value", None)
    if original_prompt:
        return original_prompt

    return None
