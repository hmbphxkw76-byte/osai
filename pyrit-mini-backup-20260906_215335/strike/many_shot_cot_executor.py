# arXiv:2402.05124 — Anthropic, Many-Shot Jailbreaking
# arXiv:2307.10292 — Wei et al., CoT Hijacking (ASR 45-60%)
# arXiv:2407.01232 — PyRIT, native attack patterns
# arXiv:2302.12173 — Greshake et al., PromptSendingAttack
# arXiv:2402.14266 — SKELETONKEY, SkeletonKey
"""many_shot_cot_executor — Many-Shot Jailbreak + CoT 攻击模块。

使用 PyRIT 原生 ManyShotJailbreakAttack 执行多示例注入攻击。
Many-Shot Jailbreak 通过在 prompt 前缀注入大量 faux Q/A 对话,
利用模型的 in-context learning 能力绕过安全过滤。

R2 (PyRIT Native First): 使用原生 ManyShotJailbreakAttack 类, 不自行实现
R6 §6.4: 原生攻击策略之一

学术依据:
    - Anthropic (arXiv:2402.05124) — Many-Shot Jailbreaking, 100 shots ASR 显著提升
    - PyRIT (arXiv:2407.01232) — 原生 ManyShotJailbreakAttack 类
    - Wei et al. (arXiv:2307.10292) — CoT Hijack ASR 45-60%
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from core.context import _get_config_int

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)


async def run_many_shot_cot_attack(
    ctx: PipelineContext,
    objectives: list[str],
) -> dict[str, list[Any]]:
    """Many-Shot Jailbreak 原生攻击包装 — 使用 PyRIT 原生 ManyShotJailbreakAttack.

    学术依据: Anthropic (arXiv:2402.05124) — 多示例注入显著提升 ASR

    使用 PyRIT 原生 ManyShotJailbreakAttack 执行多示例注入攻击:
        1. 加载 PyRIT 内置 many-shot 示例数据集
        2. 将目标 prompt 与 faux Q/A 模板拼接
        3. 作为单轮 PromptSendingAttack 子类发送

    R2 (PyRIT native first): 使用原生 ManyShotJailbreakAttack 类, 不自行实现
    R6 §6.4: 原生攻击策略

    Args:
        ctx: 流水线上下文 (包含 objective_target, scoring_target).
        objectives: 失败目标列表.

    Returns:
        {technique_name: [AttackResult, ...]} 格式的攻击结果。
        如果 ManyShotJailbreakAttack 不可用或执行失败, 返回空字典 (调用方优雅降级)。
    """
    if not objectives:
        return {}

    if ctx.objective_target is None:
        logger.warning("ManyShotJailbreakAttack: objective_target not configured, skipping")
        return {}

    try:
        from pyrit.executor.attack import ManyShotJailbreakAttack
    except ImportError as e:
        logger.warning("ManyShotJailbreakAttack not available (%s), skipping", e)
        return {}

    # 构建评分配置 (0-token FIRST_SUCCESS scorer, 与 executor.py 一致)
    from strike.executor import _build_first_success_scoring_config
    first_success_scoring = _build_first_success_scoring_config(ctx)

    # v53: prepended_conversation (SkeletonKey) — via execute_async broadcast_fields
    # ManyShotJailbreakAttack inherits PromptSendingAttack but does not expose
    # prepended_conversation_config in its __init__. Pass prepended_conversation
    # (config._messages) via execute_async kwargs, which maps to AttackParameters.prepended_conversation.
    from strike.executor import _build_prepended_conversation_config as _build_prepended_config_safe
    prepended_config = _build_prepended_config_safe(ctx)
    prepended_conv = prepended_config._messages if prepended_config else None

    results: list[Any] = []
    incomplete: list[tuple[str, Any]] = []

    # L5 v41: 限制目标数量 (与 Crescendo/TAP 一致)
    ms_objectives = objectives[:8]
    if len(objectives) > 8:
        logger.info("ManyShotJailbreak: limited to top-8 objectives")

    for objective in ms_objectives:
        if not objective:
            continue

        try:
            # 构建 ManyShotJailbreakAttack
            # PyRIT 原生: 加载内置 many-shot 示例, 拼接目标 prompt
            # arXiv:2402.05124 — 100 shots 在大上下文窗口模型上 ASR 显著提升
            attack = ManyShotJailbreakAttack(
                objective_target=ctx.objective_target,
                attack_scoring_config=first_success_scoring,
                example_count=_get_config_int(ctx, "many_shot_example_count", 100),  # arXiv:2402.05124 — 100 shots
            )

            # ManyShotJailbreakAttack 继承 PromptSendingAttack,
            # 通过 execute_async(objective=...) 执行
            # prepended_conversation 作为 SkeletonKey 前置注入
            execute_kwargs: dict[str, Any] = {"objective": objective}
            if prepended_conv:
                execute_kwargs["prepended_conversation"] = prepended_conv

            result = await asyncio.wait_for(
                attack.execute_async(**execute_kwargs),
                timeout=getattr(ctx.args, "scenario_timeout", 1200),
            )
            results.append(result)

            # 检查 outcome
            from pyrit.models import AttackOutcome
            ms_outcome = getattr(result, "outcome", None)
            if ms_outcome != AttackOutcome.SUCCESS:
                incomplete.append((objective, result))

        except asyncio.TimeoutError:
            logger.warning("ManyShotJailbreakAttack: timed out for objective: %s...", objective[:60])
            incomplete.append((objective, None))
        except Exception as e:
            logger.warning("ManyShotJailbreakAttack: failed for objective: %s — %s", objective[:60], e)
            incomplete.append((objective, None))

    if results:
        logger.info(
            "ManyShotJailbreakAttack: %d/%d objectives completed (%d incomplete)",
            len(results), len(ms_objectives), len(incomplete),
        )

    return {"many_shot_jailbreak": results} if results else {}
