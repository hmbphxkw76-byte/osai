# arXiv:2407.01232 — PyRIT, native multi-turn attack patterns
# arXiv:2302.12173 — Greshake et al., indirect prompt injection
"""chunked_attack — ChunkedRequestAttack 原生攻击模块.

使用 PyRIT 原生 ChunkedRequestAttack 执行分块提取攻击。
该攻击通过请求特定字符范围的信息片段,
绕过长度过滤或输出截断, 逐步重建完整值。

在 CTF 红队测试中发现: 目标拒绝完整揭示秘密值,
但会揭示特定片段, 组合后可重建完整值。

R2 (PyRIT Native First): 使用原生 ChunkedRequestAttack 类, 不自行实现
R6 §6.4: 原生攻击策略之一

学术依据:
    - PyRIT (arXiv:2407.01232) — 原生 ChunkedRequestAttack 类
    - Greshake et al. (arXiv:2302.12173) — 间接注入与信息提取
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from core.context import _get_config_int

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)


async def run_chunked_request_attack(
    ctx: PipelineContext,
    objectives: list[str],
) -> dict[str, list[Any]]:
    """ChunkedRequestAttack 原生攻击包装.

    学术依据: PyRIT (arXiv:2407.01232) — 原生 ChunkedRequestAttack

    使用 PyRIT 原生 ChunkedRequestAttack 执行分块提取攻击:
        1. 将目标拆分为多个字符范围请求
        2. 依次发送分块请求到目标
        3. 收集所有分块响应并组合
        4. 对组合结果评分

    R2 (PyRIT native first): 使用原生 ChunkedRequestAttack 类
    R6 §6.4: 原生攻击策略

    Args:
        ctx: 流水线上下文 (包含 multi_turn_target, objective_target, scoring_target).
        objectives: 失败目标列表.

    Returns:
        {technique_name: [AttackResult, ...]} 格式的攻击结果。
    """
    if not objectives:
        return {}

    multi_turn_target = getattr(ctx, "multi_turn_target", None) or ctx.objective_target
    if multi_turn_target is None:
        logger.warning("ChunkedRequestAttack: no target configured, skipping")
        return {}

    try:
        from pyrit.executor.attack import ChunkedRequestAttack
    except ImportError as e:
        logger.warning("ChunkedRequestAttack not available (%s), skipping", e)
        return {}

    # 构建评分配置 (0-token FIRST_SUCCESS scorer)
    from strike.executor import _build_first_success_scoring_config
    first_success_scoring = _build_first_success_scoring_config(ctx)

    # v53: prepended_conversation (SkeletonKey) — via execute_async broadcast_fields
    # ChunkedRequestAttack does not support prepended_conversation_config in __init__.
    # Pass prepended_conversation (config._messages) via execute_async kwargs.
    from strike.executor import _build_prepended_conversation_config as _build_prepended_config_safe
    prepended_config = _build_prepended_config_safe(ctx)
    prepended_conv = prepended_config._messages if prepended_config else None

    results: list[Any] = []

    # 限制目标数量
    chunked_objectives = objectives[:8]
    if len(objectives) > 8:
        logger.info("ChunkedRequest: limited to top-8 objectives")

    for objective in chunked_objectives:
        if not objective:
            continue

        try:
            # 构建 ChunkedRequestAttack
            # arXiv:2407.01232 — chunk_size and total_length from config/defaults.yaml
            # 4 个分块请求, 逐步提取完整信息
            attack = ChunkedRequestAttack(
                objective_target=multi_turn_target,
                attack_scoring_config=first_success_scoring,
                chunk_size=_get_config_int(ctx, "chunked_request_chunk_size", 50),       # arXiv:2407.01232 — 默认 50 字符/块
                total_length=_get_config_int(ctx, "chunked_request_total_length", 200),    # arXiv:2407.01232 — 默认 200 字符总长
                chunk_type="characters",
            )

            # 通过 execute_async 执行
            execute_kwargs: dict[str, Any] = {"objective": objective}
            if prepended_conv:
                execute_kwargs["prepended_conversation"] = prepended_conv

            # L5 fix: per-objective timeout = api_timeout * max_chunks (4 chunks default)
            # scenario_timeout is for entire pipeline, not per-attack in a loop
            _api_to = _get_config_int(ctx, "api_timeout", 90)
            _chunk_total = _get_config_int(ctx, "chunked_request_total_length", 200)
            _chunk_size = _get_config_int(ctx, "chunked_request_chunk_size", 50)
            _num_chunks = max(1, (_chunk_total + _chunk_size - 1) // _chunk_size)
            _per_obj_to = _api_to * _num_chunks * 2  # 2x safety margin
            result = await asyncio.wait_for(
                attack.execute_async(**execute_kwargs),
                timeout=_per_obj_to,
            )
            results.append(result)

        except asyncio.TimeoutError:
            logger.warning("ChunkedRequestAttack: timed out for objective: %s...", objective[:60])
        except Exception as e:
            logger.warning("ChunkedRequestAttack: failed for objective: %s — %s", objective[:60], e)

    if results:
        logger.info(
            "ChunkedRequestAttack: %d/%d objectives completed",
            len(results), len(chunked_objectives),
        )

    return {"chunked_request": results} if results else {}
