"""攻击策略编排模块 — L5 专家级预设 + 目标推荐."""

from pipeline.strategy.presets import (
    STRATEGY_PRESETS,
    get_strategy_args,
    recommend_strategy,
)

__all__ = [
    "STRATEGY_PRESETS",
    "recommend_strategy",
    "get_strategy_args",
]
