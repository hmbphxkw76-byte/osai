"""
Failure-Type Event Handler — 运行时 ASR 反馈闭环
=================================================

P0-ASR-2: 在 AttackExecutor 执行过程中实时捕获失败类型，
并反馈到 FailureTypeRoutingSelector，实现真正的运行时学习闭环。

核心设计：
  原生 AttackExecutor 在每个 AtomicAttack 完成后触发事件回调。
  本处理器拦截这些回调，提取失败类型，实时更新 selector，
  使后续技术选择基于最新失败模式而非固定先验。

数据流：
  AtomicAttack 完成 → on_attack_result → extract_failure_type_from_result
  → selector.update_failure_type() → 下次 select_async 使用最新路由

与原生 _DefaultAttackStrategyEventHandler 的关系：
  - 原生处理器：负责 Memory 持久化 + 基础日志
  - 本处理器：负责失败类型路由 + 实时 ASR 反馈
  - 两者互补不重叠

学术依据：
  - Adaptive scenarios (PyRIT 1.0.0 文档): epsilon-greedy selector
    通过 memory 学习跨 objective 的技术选择策略
  - Chao et al. (arXiv:2310.08437): PAIR 根据 adversarial chat 的
    拒绝反馈迭代调整攻击策略
  - Russinovich et al. (arXiv:2402.12109): Crescendo 多轮渐进
    天然利用前序失败信息调整后续请求
"""

import logging
from collections import Counter
from typing import Any

logger = logging.getLogger(__name__)


class FailureTypeEventHandler:
    """
    运行时失败类型事件处理器 — 实时反馈到 selector

    注册到 AttackExecutor 的事件处理器，在每个 AtomicAttack 完成后
    被调用。提取失败类型并更新 selector，使后续技术选择基于
    最新失败模式。

    使用方式：
        handler = FailureTypeEventHandler(selector=my_selector)
        executor._register_event_handler(handler)

    回调签名（对齐原生 AttackExecutor 事件处理器协议）：
        on_attack_result(attack_result, *args, **kwargs)
    """

    def __init__(self, selector: Any = None) -> None:
        """
        Args:
            selector: FailureTypeRoutingSelector 实例
                     （需要支持 update_failure_type 方法）
        """
        self._selector = selector
        self._failure_counter: Counter = Counter()
        self._total_attacks = 0
        self._total_successes = 0
        self._total_failures = 0
        self._last_failure_type: str | None = None
        self._technique_results: dict[str, dict[str, int]] = {}

    def on_attack_result(self, attack_result: Any, *args, **kwargs) -> None:
        """
        原子攻击完成回调 — 提取失败类型并反馈到 selector

        Args:
            attack_result: AttackResult 实例
        """
        if attack_result is None:
            return

        self._total_attacks += 1

        # 提取技术名（从 identifier 或 attributions）
        technique_name = self._extract_technique_name(attack_result)

        # 判断成功/失败
        outcome = getattr(attack_result, "outcome", None)
        outcome_str = ""
        if outcome is not None:
            outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()

        if outcome_str == "SUCCESS":
            self._total_successes += 1
            if technique_name:
                self._technique_results.setdefault(technique_name, {"success": 0, "failure": 0})
                self._technique_results[technique_name]["success"] += 1
            return

        # 失败 — 提取失败类型
        self._total_failures += 1
        if technique_name:
            self._technique_results.setdefault(technique_name, {"success": 0, "failure": 0})
            self._technique_results[technique_name]["failure"] += 1

        # 使用 extract_failure_type_from_result 提取失败类型
        try:
            from src.scenarios.failure_type_selector import extract_failure_type_from_result
            failure_type = extract_failure_type_from_result(attack_result)
        except Exception as e:
            logger.debug(f"Failed to extract failure type: {e}")
            failure_type = "unknown"

        self._failure_counter[failure_type] += 1
        self._last_failure_type = failure_type

        # P0-ASR-2: 实时反馈到 selector
        if self._selector and hasattr(self._selector, "update_failure_type"):
            self._selector.update_failure_type(failure_type)
            logger.debug(
                f"P0-ASR-2: Real-time feedback — failure_type='{failure_type}' "
                f"→ selector updated (attack #{self._total_attacks})"
            )

        # 也检查 SequentialAttackResult 的子结果
        child_results = getattr(attack_result, "child_attack_results", None) or []
        for child in child_results:
            if child is None:
                continue
            child_outcome = getattr(child, "outcome", None)
            if child_outcome is not None:
                child_outcome_str = str(child_outcome.value).upper() if hasattr(child_outcome, "value") else str(child_outcome).upper()
                if child_outcome_str != "SUCCESS":
                    try:
                        from src.scenarios.failure_type_selector import extract_failure_type_from_result
                        child_failure_type = extract_failure_type_from_result(child)
                        self._failure_counter[child_failure_type] += 1
                    except Exception:
                        pass

    def _extract_technique_name(self, attack_result: Any) -> str | None:
        """从 AttackResult 提取技术名"""
        identifier = None
        if hasattr(attack_result, "get_attack_strategy_identifier"):
            identifier = attack_result.get_attack_strategy_identifier()
        if identifier is not None:
            # 优先使用 identifier.name
            name = getattr(identifier, "name", None)
            if name:
                return name
            # 回退到 identifier 的 children
            children = getattr(identifier, "children", None) or {}
            if children.get("request_converters"):
                # Converter 变体: base+chain
                base = getattr(identifier, "name", "")
                converters = children["request_converters"]
                if isinstance(converters, list) and converters:
                    conv_name = getattr(converters[0], "__class__", type(converters[0])).__name__ if not isinstance(converters[0], str) else converters[0]
                    return f"{base}+{conv_name}" if base else conv_name
        return None

    def get_runtime_asr(self) -> dict[str, float]:
        """
        获取运行时 ASR 统计

        Returns:
            技术→ASR 映射（运行时实测）
        """
        results: dict[str, float] = {}
        for tech, counts in self._technique_results.items():
            total = counts["success"] + counts["failure"]
            if total > 0:
                results[tech] = counts["success"] / total
        return results

    def get_failure_distribution(self) -> dict[str, int]:
        """获取失败类型分布"""
        return dict(self._failure_counter)

    def get_stats(self) -> dict[str, Any]:
        """获取完整统计"""
        return {
            "total_attacks": self._total_attacks,
            "total_successes": self._total_successes,
            "total_failures": self._total_failures,
            "runtime_asr": self.get_runtime_asr(),
            "failure_distribution": self.get_failure_distribution(),
            "last_failure_type": self._last_failure_type,
            "technique_results": dict(self._technique_results),
        }

    @property
    def most_common_failure_type(self) -> str | None:
        """获取最常见的失败类型"""
        if self._failure_counter:
            return self._failure_counter.most_common(1)[0][0]
        return None
