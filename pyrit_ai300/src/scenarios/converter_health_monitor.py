"""
Converter Health Monitor — L5 执行韧性 Layer 2
=================================================

五层韧性体系的第二层：Converter 级韧性。

解决核心问题:
  日志显示 13/23 错误 (56%) 来自 DecompositionConverter 的
  EmptyResponseException (204)。安全对齐模型对 Converter 的
  JSON 分解请求返回空响应，但当前代码让此错误传播到整个
  SequentialAttack，最终触发 ExceptionGroup + max_retries
  无效重试。

设计:
  1. 健康检查 — 执行前预检 LLM converter 可用性
  2. 熔断器 — 连续失败 N 次后禁用 converter (circuit breaker)
  3. 错误降级 — converter 失败时跳过而非崩溃
  4. 统计 — 记录每个 converter 的成功/失败率

学术依据:
  Circuit Breaker Pattern (Michael Nygard, "Release It!")
  - closed: 正常运行，记录失败计数
  - open: 失败达到阈值，拒绝新请求
  - half-open: 探测性恢复（本实现不使用 half-open，
    因为 converter 在同一次 pipeline 运行中状态不变）
"""

import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# 默认熔断阈值: 连续失败 2 次即禁用
_DEFAULT_FAILURE_THRESHOLD = 2

# 从错误消息中提取 Converter 名称的正则模式
_CONVERTER_NAME_PATTERNS = [
    re.compile(r"converter identifier: (\w+)::", re.IGNORECASE),
    re.compile(r"converter\s+(\w+)\s+", re.IGNORECASE),
    re.compile(r"(\w+Converter)\b", re.IGNORECASE),
    re.compile(r"Component: converter.*?identifier: (\w+)", re.IGNORECASE),
]


@dataclass
class ConverterStats:
    """单个 Converter 的运行时统计"""
    name: str
    attempts: int = 0
    successes: int = 0
    failures: int = 0
    errors: int = 0
    consecutive_failures: int = 0
    disabled: bool = False
    failure_reason: str = ""

    @property
    def success_rate(self) -> float:
        """成功率（0.0-1.0）"""
        if self.attempts == 0:
            return 0.0
        return self.successes / self.attempts

    @property
    def is_healthy(self) -> bool:
        """是否健康（未禁用）"""
        return not self.disabled


class ConverterHealthMonitor:
    """
    Converter 健康监控器 — 执行韧性 Layer 2

    功能:
    1. 预检: 执行前验证 LLM converter 可用性
    2. 熔断: 连续失败 N 次后禁用 converter (circuit breaker)
    3. 错误降级: converter 失败时跳过而非让整个 SequentialAttack 崩溃
    4. 统计: 记录每个 converter 的成功/失败率

    集成方式:
    - AI300AdaptiveScenario._build_techniques_dict: 创建变体时检查 is_disabled
    - ScenarioEventHandler.on_event_async: ON_ERROR 时 record_failure
    - adaptive_runner: 执行后 get_stats 生成健康报告
    """

    def __init__(self, failure_threshold: int = _DEFAULT_FAILURE_THRESHOLD):
        """
        Args:
            failure_threshold: 连续失败 N 次后熔断该 converter
        """
        self._failure_threshold = failure_threshold
        self._stats: Dict[str, ConverterStats] = {}

    def register(self, converter_name: str) -> None:
        """注册一个 Converter 到监控"""
        if converter_name not in self._stats:
            self._stats[converter_name] = ConverterStats(name=converter_name)

    def is_disabled(self, converter_name: str) -> bool:
        """检查 Converter 是否已被熔断"""
        stats = self._stats.get(converter_name)
        if stats is None:
            return False
        return stats.disabled

    def record_success(self, converter_name: str) -> None:
        """记录 Converter 成功"""
        stats = self._stats.get(converter_name)
        if stats is None:
            stats = ConverterStats(name=converter_name)
            self._stats[converter_name] = stats
        stats.attempts += 1
        stats.successes += 1
        stats.consecutive_failures = 0  # 重置连续失败计数

    def record_failure(self, converter_name: str, error_msg: str = "") -> None:
        """
        记录 Converter 失败

        连续失败达到阈值后自动熔断。
        """
        stats = self._stats.get(converter_name)
        if stats is None:
            stats = ConverterStats(name=converter_name)
            self._stats[converter_name] = stats
        stats.attempts += 1
        stats.failures += 1
        stats.consecutive_failures += 1
        if error_msg:
            stats.failure_reason = error_msg[:200]  # 截断

        # 熔断检查
        if (
            not stats.disabled
            and stats.consecutive_failures >= self._failure_threshold
        ):
            stats.disabled = True
            logger.warning(
                f"L2 Circuit Breaker: '{converter_name}' disabled after "
                f"{stats.consecutive_failures} consecutive failures "
                f"(reason: {stats.failure_reason[:100]})"
            )

    def record_error(self, converter_name: str, error_msg: str = "") -> None:
        """记录 Converter 级错误（区别于 failure: error 是系统异常）"""
        stats = self._stats.get(converter_name)
        if stats is None:
            stats = ConverterStats(name=converter_name)
            self._stats[converter_name] = stats
        stats.attempts += 1
        stats.errors += 1
        stats.consecutive_failures += 1
        if error_msg:
            stats.failure_reason = error_msg[:200]

        if (
            not stats.disabled
            and stats.consecutive_failures >= self._failure_threshold
        ):
            stats.disabled = True
            logger.warning(
                f"L2 Circuit Breaker: '{converter_name}' disabled after "
                f"{stats.consecutive_failures} consecutive errors"
            )

    def get_stats(self) -> Dict[str, Dict[str, Any]]:
        """获取所有 Converter 的统计摘要"""
        return {
            name: {
                "attempts": s.attempts,
                "successes": s.successes,
                "failures": s.failures,
                "errors": s.errors,
                "success_rate": round(s.success_rate, 3),
                "consecutive_failures": s.consecutive_failures,
                "disabled": s.disabled,
                "failure_reason": s.failure_reason,
            }
            for name, s in self._stats.items()
        }

    def get_disabled_converters(self) -> list[str]:
        """获取所有被熔断的 Converter 名称列表"""
        return [name for name, s in self._stats.items() if s.disabled]

    def filter_chains(
        self,
        chain_names: list[str],
    ) -> tuple[list[str], list[str]]:
        """
        过滤 Converter 链列表，移除被熔断的链

        Returns:
            (enabled_chains, disabled_chains)
        """
        enabled = []
        disabled = []
        for chain in chain_names:
            if self.is_disabled(chain):
                disabled.append(chain)
            else:
                enabled.append(chain)
        return enabled, disabled

    def reset(self) -> None:
        """重置所有统计（新 run 时调用）"""
        for stats in self._stats.values():
            stats.consecutive_failures = 0
            stats.disabled = False
            stats.failure_reason = ""


def extract_converter_name_from_error(error_str: str) -> Optional[str]:
    """
    从错误消息中提取 Converter 名称

    PyRIT 错误消息格式示例:
      "Strategy execution failed for converter in PromptSendingAttack:
       Status Code: 204...
       converter identifier: DecompositionConverter::6de9e30a"

    Args:
        error_str: 错误消息字符串

    Returns:
        Converter 名称（如 "DecompositionConverter"），未找到返回 None
    """
    for pattern in _CONVERTER_NAME_PATTERNS:
        match = pattern.search(error_str)
        if match:
            return match.group(1)
    return None


def extract_chain_name_from_error(error_str: str) -> Optional[str]:
    """
    从错误消息中提取 Converter 链名称

    Converter 链名称和 Converter 类名不同:
      链名: "decomposition_chain"
      类名: "DecompositionConverter"

    本函数尝试从错误消息中识别链名。

    Args:
        error_str: 错误消息字符串

    Returns:
        链名称（如 "decomposition_chain"），未找到返回 None
    """
    _CONVERTER_CLASS_TO_CHAIN = {
        "decompositionconverter": "decomposition_chain",
        "persuasionconverter": "persuasion_authority",
        "toneconverter": "persuasion_authority",
        "translationconverter": "persuasion_authority",
        "taskframingconverter": "task_framing_chain",
        "suffixappendconverter": "suffix_append",
        "unicodeconfusableconverter": "unicode_attack",
        "noisebypassconverter": "noise_bypass",
        "specialcharsconverter": "special_chars",
        "randomcaseconverter": "random_case",
        "leetspeakconverter": "leetspeak_chain",
        "stealthevasionconverter": "stealth_evasion",
        "multiencodingconverter": "multi_encoding_v2",
        "encodingbypassconverter": "encoding_bypass",
    }

    converter_name = extract_converter_name_from_error(error_str)
    if converter_name:
        return _CONVERTER_CLASS_TO_CHAIN.get(converter_name.lower())
    return None
