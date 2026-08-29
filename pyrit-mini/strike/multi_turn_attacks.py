# arXiv:2402.01135 — Chao et al., Best-of-N (N=5 ASR 1.8x)
# arXiv:2402.12109 — Russinovich et al., Crescendo
"""multi_turn_attacks — 多轮攻击策略模块.

提供 Best-of-N 等多轮攻击的异步包装函数。
当前为 stub 实现，返回空结果以保持管道兼容性。
"""

from __future__ import annotations

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
    """Best-of-N 采样攻击包装 (stub).

    学术依据: Chao et al. (arXiv:2402.01135) — N=5 ASR 1.8x

    TODO: 实现多 temperature 重复采样逻辑。
    当前返回空结果，调用方的 try/except 会优雅降级。
    """
    logger.info("multi_turn_attacks.run_best_of_n_attack: stub called (n=%d), returning empty", n)
    return {}
