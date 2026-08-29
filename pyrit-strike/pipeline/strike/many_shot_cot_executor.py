"""Many-Shot CoT 攻击执行器 — 拆分自 many_shot_cot.py。

包含 run_many_shot_cot_attack 和 run_multi_model_cot_cross_validation。
拆分自 many_shot_cot.py (727行 → ~400+~325)。
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from pipeline.context import get_effective_concurrency
from pipeline.strike.cot_hijack import _COT_TEMPLATES
from pipeline.strike.many_shot_cot import (
    generate_many_shot_cot_prompt,
    select_adaptive_template,
)

logger = logging.getLogger(__name__)


async def run_many_shot_cot_attack(
    ctx: Any,
    objectives: list[str],
    *,
    mode: str = "inject",
    n_shots: int = 128,
) -> dict[str, list[Any]]:
    """执行 Many-Shot + CoT 组合攻击。

    学术依据:
        - arXiv:2402.05124 — Many-Shot ICI 挟持
        - arXiv:2307.10292 — CoT 推理惯性劫持
        - arXiv:2404.05133 — Long-Context Hijacking
        双重挟持: ICI + CoT

    PyRIT 原生引擎:
        使用 PromptSendingAttack + AttackExecutor 执行,
        本模块仅负责 prompt 生成 (增强层, 非替代)。

    策略:
        1. 为每个 objective 生成 Many-Shot + CoT 组合 prompt
        2. 使用 PyRIT 原生 AttackExecutor 批量执行
        3. 失败后切换组合模式重试 (inject → interleaved → suffix)
        4. 自适应模板选择根据目标关键词优化

    Args:
        ctx: PipelineContext。
        objectives: 失败目标列表。
        mode: 初始组合模式。
        n_shots: Many-Shot Q&A 对数量。

    Returns:
        攻击结果字典 {"many_shot_cot": [results]}。
    """
    from pyrit.executor.attack import PromptSendingAttack
    from pyrit.executor.attack.core.attack_executor import AttackExecutor
    from pyrit.models import (
        AttackOutcome,
        AttackSeedGroup,
        SeedObjective,
    )

    results: dict[str, list[Any]] = {}
    all_results: list[Any] = []

    # L5 v23: 改用 RefusalScorer 反转 — 对 SSE 响应评分更准
    # 学术依据: Zheng et al. (arXiv:2306.05685) — LLM-as-a-Judge
    from pipeline.strike.escalation import _build_refusal_inverter_scoring_config
    scoring_config = _build_refusal_inverter_scoring_config(ctx)

    # v51: 注入 prepended_conversation (SkeletonKey 前置注入)
    from pipeline.strike.executor import _build_prepended_conversation
    msc_prepended = _build_prepended_conversation(ctx)
    msc_attack_kwargs: dict[str, Any] = {
        "objective_target": ctx.objective_target,
        "attack_scoring_config": scoring_config,
    }
    if msc_prepended:
        msc_attack_kwargs["prepended_conversation"] = msc_prepended
    attack = PromptSendingAttack(**msc_attack_kwargs)

    # L5 v26: 恢复并发度=2 (SQLite WAL 模式下安全)
    executor = AttackExecutor(
        max_concurrency=get_effective_concurrency(ctx),
    )

    # 组合模式优先级: inject → interleaved → suffix → prefix
    mode_priority = ["inject", "interleaved", "suffix", "prefix"]
    if mode not in mode_priority:
        mode_priority = [mode] + [m for m in mode_priority if m != mode]

    # L5 v23: 移除 [:5] 截断, 处理所有失败目标
    # 学术依据: Chao et al. (arXiv:2402.01135) — 截断会遗漏可能成功的目标
    for obj in objectives:
        for round_idx, combo_mode in enumerate(mode_priority[:3]):
            # 自适应模板选择
            template_name = select_adaptive_template(obj)

            prompt = generate_many_shot_cot_prompt(
                obj,
                n_shots=n_shots,
                mode=combo_mode,
                template_name=template_name,
                seed=round_idx,  # 不同 round 不同 seed
            )

            seed_groups = [
                AttackSeedGroup(seeds=[SeedObjective(value=prompt)])
            ]

            try:
                executor_result = await asyncio.wait_for(
                    executor.execute_attack_from_seed_groups_async(
                        attack=attack,
                        seed_groups=seed_groups,
                        return_partial_on_failure=True,
                    ),
                    timeout=180,  # 3 分钟 (Many-Shot prompt 较长)
                )

                if executor_result.completed_results:
                    result = executor_result.completed_results[0]
                    all_results.append(result)

                    outcome = getattr(result, "outcome", None)
                    if outcome == AttackOutcome.SUCCESS:
                        logger.info(
                            "Many-Shot+CoT: success on round %d "
                            "(mode=%s, template=%s) for: %s...",
                            round_idx + 1,
                            combo_mode,
                            template_name,
                            obj[:60],
                        )
                        break  # 成功就跳到下一个目标
                    else:
                        logger.info(
                            "Many-Shot+CoT: failed round %d (mode=%s), trying next...",
                            round_idx + 1,
                            combo_mode,
                        )

            except asyncio.TimeoutError:
                logger.warning(
                    "Many-Shot+CoT: timeout round %d (mode=%s)",
                    round_idx + 1,
                    combo_mode,
                )
            except Exception as e:
                logger.warning(
                    "Many-Shot+CoT: error round %d (mode=%s): %s",
                    round_idx + 1,
                    combo_mode,
                    e,
                )

    if all_results:
        results["many_shot_cot"] = all_results
        logger.info(
            "Many-Shot+CoT completed: %d results",
            len(all_results),
        )

    return results


async def run_multi_model_cot_cross_validation(
    ctx: Any,
    objectives: list[str],
    *,
    n_shots: int = 64,
) -> dict[str, list[Any]]:
    """多模型 CoT 交叉验证 — 不同 adversarial LLM 生成不同 CoT 路径。

    学术依据:
        - Chao et al. (arXiv:2310.08419) — 不同 LLM 在越狱 prompt
          生成方面有互补性, 多模型并行使 ASR 提升 ~20%。
        - Wei et al. (arXiv:2307.10292) — 不同 LLM 生成的 CoT
          推理路径差异较大, 联合概率 P(任一成功) 显著提升。
        - Lapid et al. (arXiv:2310.04775) — LLM 辅助变异在
          黑盒场景下替代梯度优化, 不同模型产生语义不同的变体。

    策略:
        1. 获取 ctx.extra_adversarial_targets (多个 LLM)
        2. 对每个目标, 使用不同 LLM 生成不同 CoT 拆分路径
        3. 使用 PyRIT 原生 PromptSendingAttack 并行执行
        4. FIRST_SUCCESS: 任一 LLM 生成的路径成功即算成功
        联合概率: P = 1 - ∏(1-p_i), 3 模型 p=0.5 → P=0.875

    PyRIT 原生引擎:
        使用 PromptSendingAttack + AttackExecutor 执行,
        本模块仅负责 prompt 生成 (增强层)。

    Args:
        ctx: PipelineContext (需有 extra_adversarial_targets)。
        objectives: 失败目标列表。
        n_shots: Many-Shot Q&A 对数量 (减少到 64 以节省 token)。

    Returns:
        攻击结果字典 {"multi_model_cot": [results]}。
    """
    from pyrit.executor.attack import PromptSendingAttack
    from pyrit.executor.attack.core.attack_executor import AttackExecutor
    from pyrit.models import (
        AttackOutcome,
        AttackSeedGroup,
        SeedObjective,
    )

    results: dict[str, list[Any]] = {}
    all_results: list[Any] = []

    # 获取多个 adversarial targets
    extra_targets = getattr(ctx, "extra_adversarial_targets", [])
    if not extra_targets:
        # 回退到单模型模式
        logger.info(
            "Multi-model CoT: no extra targets, falling back to single-model"
        )
        return await run_many_shot_cot_attack(ctx, objectives, n_shots=n_shots)

    # L5 v23: 改用 RefusalScorer 反转 — 对 SSE 响应评分更准
    # 学术依据: Zheng et al. (arXiv:2306.05685) — LLM-as-a-Judge
    from pipeline.strike.escalation import _build_refusal_inverter_scoring_config
    scoring_config = _build_refusal_inverter_scoring_config(ctx)

    # v51: 注入 prepended_conversation (SkeletonKey 前置注入)
    from pipeline.strike.executor import _build_prepended_conversation
    mm_prepended = _build_prepended_conversation(ctx)
    mm_attack_kwargs: dict[str, Any] = {
        "objective_target": ctx.objective_target,
        "attack_scoring_config": scoring_config,
    }
    if mm_prepended:
        mm_attack_kwargs["prepended_conversation"] = mm_prepended
    attack = PromptSendingAttack(**mm_attack_kwargs)

    # L5 v26: 恢复并发度=2 (SQLite WAL 模式下安全)
    executor = AttackExecutor(
        max_concurrency=get_effective_concurrency(ctx),
    )

    # 对每个目标, 使用不同 LLM 生成不同 CoT 路径
    # 不同 LLM 使用不同模板, 产生不同推理路径
    template_names = [t["name"] for t in _COT_TEMPLATES]
    all_targets = [ctx.adversarial_target] + list(extra_targets)

    for obj in objectives[:3]:  # 最多 3 个目标
        # 并行生成不同模型的 CoT 路径
        prompts: list[str] = []

        for model_idx, adv_target in enumerate(all_targets[:3]):
            # 每个模型使用不同模板
            template_name = template_names[model_idx % len(template_names)]

            # 使用 VariationConverter 让不同 LLM 生成变体
            # (如果 converter_target 可用)
            converter_target = getattr(ctx, "converter_target", None)

            if converter_target and adv_target:
                try:
                    from pyrit.converter import VariationConverter
                    var_converter = VariationConverter(
                        converter_target=converter_target,
                    )
                    base_prompt = generate_many_shot_cot_prompt(
                        obj,
                        n_shots=n_shots,
                        mode="inject",
                        template_name=template_name,
                        seed=model_idx,
                    )
                    # 对 base prompt 进行 LLM 变异
                    result = var_converter.convert(prompt=base_prompt)
                    if result and hasattr(result, "output_text"):
                        mutated_prompt = result.output_text
                        if mutated_prompt and len(mutated_prompt) > 50:
                            prompts.append(mutated_prompt)
                        else:
                            prompts.append(base_prompt)
                    else:
                        prompts.append(base_prompt)
                except Exception:
                    prompts.append(
                        generate_many_shot_cot_prompt(
                            obj,
                            n_shots=n_shots,
                            mode="inject",
                            template_name=template_name,
                            seed=model_idx,
                        )
                    )
            else:
                # 无 converter, 直接使用不同模板和 seed
                prompts.append(
                    generate_many_shot_cot_prompt(
                        obj,
                        n_shots=n_shots,
                        mode="inject",
                        template_name=template_name,
                        seed=model_idx,
                    )
                )

        # 并行执行所有变体 (PyRIT 原生 AttackExecutor)
        seed_groups = [
            AttackSeedGroup(seeds=[SeedObjective(value=p)])
            for p in prompts
        ]

        try:
            executor_result = await asyncio.wait_for(
                executor.execute_attack_from_seed_groups_async(
                    attack=attack,
                    seed_groups=seed_groups,
                    return_partial_on_failure=True,
                ),
                timeout=240,  # 4 分钟 (多模型并行)
            )

            if executor_result.completed_results:
                # FIRST_SUCCESS: 任一成功即算成功
                for result in executor_result.completed_results:
                    all_results.append(result)
                    outcome = getattr(result, "outcome", None)
                    if outcome == AttackOutcome.SUCCESS:
                        logger.info(
                            "Multi-model CoT: success for: %s...",
                            obj[:60],
                        )
                        break

        except asyncio.TimeoutError:
            logger.warning(
                "Multi-model CoT: timeout for: %s...",
                obj[:60],
            )
        except Exception as e:
            logger.warning(
                "Multi-model CoT: error for: %s...: %s",
                obj[:60],
                e,
            )

    if all_results:
        results["multi_model_cot"] = all_results
        logger.info(
            "Multi-model CoT completed: %d results from %d models",
            len(all_results),
            len(all_targets),
        )

    return results
