"""策略路由层 — 将攻击策略映射到具体执行器。

高频策略优先支持（考试期间常用）：
  - PROBE: 基础探测
  - BASE64: Base64 编码混淆
  - ROT13: ROT13 编码混淆
  - ROLEPLAY: 角色扮演越狱
  - STEALTH: 术语混淆/隐身
  - CRESCENDO: 多轮渐进式攻击
  - FRONTIER: 前沿漏洞攻击

策略路由逻辑：
  - 基础策略 → NativeAttackRunner（单轮）
  - 多轮策略 → 专用 Runner（Crescendo/TAP）
  - 前沿漏洞 → FrontierAdapter

使用方式：
  router = StrategyRouter()
  runner = router.get_runner(AttackStrategy.BASE64)
  result = runner.send_prompt(payload)
"""
from __future__ import annotations

import logging
from enum import Enum
from typing import Optional

from redteam.attack.core.runner import NativeAttackRunner
from redteam.core.models import AuthContext

logger = logging.getLogger(__name__)


class AttackStrategy(str, Enum):
    """系统内置攻击策略 — 考试期间高频策略优先。"""

    PROBE = "probe"
    BASE64 = "base64"
    ROT13 = "rot13"
    ROLEPLAY = "roleplay"
    STEALTH = "stealth"
    BRUTEFORCE = "bruteforce"
    TRANSLATION = "translation"
    ENCODING = "encoding"
    CRESCENDO = "crescendo"
    PAIR = "pair"
    TAP = "tap"
    FLIP = "flip"
    FRONTIER = "frontier"


STRATEGY_CONVERTER_MAP: dict[AttackStrategy, str] = {
    AttackStrategy.BASE64: "base64",
    AttackStrategy.ROT13: "rot13",
    AttackStrategy.ROLEPLAY: "roleplay",
    AttackStrategy.STEALTH: "academic",
    AttackStrategy.BRUTEFORCE: "roleplay",
    AttackStrategy.TRANSLATION: "translation",
    AttackStrategy.ENCODING: "base64",
}


class StrategyRouter:
    """策略路由层 — 将 AttackStrategy 映射到具体执行器。"""

    HIGH_FREQUENCY_STRATEGIES = {
        AttackStrategy.PROBE,
        AttackStrategy.BASE64,
        AttackStrategy.ROT13,
        AttackStrategy.ROLEPLAY,
        AttackStrategy.STEALTH,
        AttackStrategy.CRESCENDO,
        AttackStrategy.FRONTIER,
    }

    def __init__(
        self,
        target_url: str,
        auth: AuthContext | None = None,
        timeout: float = 30.0,
    ):
        self._target_url = target_url
        self._auth = auth
        self._timeout = timeout
        self._runners: dict[str, NativeAttackRunner] = {}

    def get_runner(self, strategy: AttackStrategy) -> NativeAttackRunner:
        """根据策略获取对应的执行器。

        Args:
            strategy: 攻击策略

        Returns:
            NativeAttackRunner 实例
        """
        runner_key = self._get_runner_key(strategy)

        if runner_key not in self._runners:
            converters = self._get_converters(strategy)
            self._runners[runner_key] = NativeAttackRunner(
                target_url=self._target_url,
                auth=self._auth,
                converters=converters,
                timeout=self._timeout,
                attack_type=strategy.value,
            )

        return self._runners[runner_key]

    def _get_runner_key(self, strategy: AttackStrategy) -> str:
        """生成执行器缓存键。"""
        converters = self._get_converters(strategy)
        return f"{strategy.value}_{'_'.join(converters) if converters else 'none'}"

    def _get_converters(self, strategy: AttackStrategy) -> list[str]:
        """根据策略获取关联的转换器列表。"""
        converter_name = STRATEGY_CONVERTER_MAP.get(strategy)
        if converter_name:
            return [converter_name]
        return []

    def is_high_frequency(self, strategy: AttackStrategy) -> bool:
        """判断策略是否为高频策略。"""
        return strategy in self.HIGH_FREQUENCY_STRATEGIES

    def get_high_frequency_strategies(self) -> list[AttackStrategy]:
        """获取所有高频策略列表。"""
        return sorted(list(self.HIGH_FREQUENCY_STRATEGIES), key=lambda s: s.value)

    def execute_strategy(
        self,
        strategy: AttackStrategy,
        payload: str,
        objective: str = "",
    ) -> dict:
        """执行指定策略的攻击。

        Args:
            strategy: 攻击策略
            payload: 攻击载荷
            objective: 攻击目标描述（可选）

        Returns:
            攻击结果字典
        """
        runner = self.get_runner(strategy)

        formatted_payload = payload.format(objective=objective) if "{objective}" in payload else payload

        result = runner.send_prompt(formatted_payload)

        return {
            "strategy": strategy.value,
            "payload": formatted_payload,
            "success": result.success,
            "response_preview": result.response_preview,
            "guardrail_triggered": result.guardrail_triggered,
            "extracted_info": result.extracted_info,
        }
