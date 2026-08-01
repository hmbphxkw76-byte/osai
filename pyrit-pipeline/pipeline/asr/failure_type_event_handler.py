# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Post-execution 失败类型扫描器 — 非侵入式 ASR 反馈收集。.

PyRIT 原生 ``AttackExecutor`` 在每个 ``AtomicAttack`` 完成后触发事件回调。
本处理器在 Stage 4 的 post-execution scan 中被调用，提取失败类型，
更新 ``FailureTypeRoutingSelector``，使下一次运行的技术选择基于最新失败模式。

**注意**: 本处理器是 post-execution 扫描，不是实时回调。
在 ``SequentialAttack(FIRST_SUCCESS)`` 模式下，失败类型反馈在当前运行的
所有 AtomicAttack 完成后才触发，主要影响下一次运行的技术排序。

数据流:
  Stage 4 run_async() 完成 → _scan_results_post_execution()
  → on_attack_result() → extract_failure_type_from_result
  → selector.update_failure_type() → 下次运行 select_async 使用最新路由

与原生事件处理器的关系:
  - 原生处理器：负责 Memory 持久化 + 基础日志
  - 本处理器：负责失败类型路由 + post-execution ASR 反馈收集
  - 两者互补不重叠

学术依据 (R-007 规则):
  - Chao et al. (arXiv:2310.08437): PAIR 根据 adversarial chat 的
    拒绝反馈迭代调整攻击策略
  - Russinovich et al. (arXiv:2402.12109): Crescendo 多轮渐进
    天然利用前序失败信息调整后续请求

> **日期**: 2026-8-1
> **更新记录**:
>   2026-8-1 19:20 — 优化3: 移除 ``_execute_scenario_async()`` 覆盖,
>     改为 post-execution scan
>   2026-8-1 19:30 — P0: 修正 docstring, 明确标注为 post-execution scan
>     而非 real-time, 消除误导性描述
"""

from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ============================================================
# P1: 范式性能跟踪器 — 从运行时数据自动推断范式有效性
# ============================================================


class ParadigmPerformanceTracker:
    """范式性能跟踪器 — 从运行时数据自动推断每个失败类型下各范式的有效性。.

    v7.0 P1: 替代静态范式切换顺序, 使用运行时 ASR 数据自动学习:
    - 跟踪 (failure_type, paradigm) → {success, failure} 计数
    - 提供 ``get_paradigm_ranking(failure_type)`` 返回按 ASR 排序的范式列表
    - 支持持久化到 JSON 文件, 跨运行累积学习

    学术依据:
      - Wei et al. (arXiv:2307.15043): 不同失败模式需要不同攻击范式
      - Chao et al. (arXiv:2310.08437): PAIR 根据拒绝反馈迭代调整
      - Russinovich et al. (arXiv:2402.12109): Crescendo 多轮渐进利用前序失败
    """

    def __init__(self) -> None:
        # (failure_type, paradigm) → {"success": int, "failure": int}
        self._data: dict[str, dict[str, dict[str, int]]] = defaultdict(
            lambda: defaultdict(lambda: {"success": 0, "failure": 0})
        )

    def record(
        self,
        *,
        failure_type: str,
        paradigm: str,
        success: bool,
    ) -> None:
        """记录一次攻击结果的范式性能数据。."""
        key = "success" if success else "failure"
        self._data[failure_type][paradigm][key] += 1

    def get_paradigm_ranking(self, failure_type: str) -> list[tuple[str, float]]:
        """获取指定失败类型下的范式 ASR 排名。.

        Returns:
            [(paradigm, asr), ...] 按 ASR 降序排列。
            无数据时返回空列表。
        """
        paradigm_data = self._data.get(failure_type, {})
        if not paradigm_data:
            return []

        rankings: list[tuple[str, float]] = []
        for paradigm, counts in paradigm_data.items():
            total = counts["success"] + counts["failure"]
            if total > 0:
                asr = counts["success"] / total
                rankings.append((paradigm, asr))

        rankings.sort(key=lambda x: x[1], reverse=True)
        return rankings

    def get_best_paradigm(self, failure_type: str) -> str | None:
        """获取指定失败类型下 ASR 最高的范式。."""
        ranking = self.get_paradigm_ranking(failure_type)
        if ranking:
            return ranking[0][0]
        return None

    def get_paradigm_switch_order(self, failure_type: str, fallback: list[str]) -> list[str]:
        """获取范式切换顺序 — 运行时数据优先, 无数据时回退到静态顺序。.

        Args:
            failure_type: 失败类型
            fallback: 静态回退顺序 (如 ["multi_turn", "persuasion", "encoding"])

        Returns:
            范式列表, 按有效性降序排列
        """
        ranking = self.get_paradigm_ranking(failure_type)
        if not ranking:
            return fallback

        # 运行时数据驱动的顺序
        runtime_order = [p for p, _ in ranking]
        # 补充运行时数据中缺失的范式 (从 fallback 中)
        for p in fallback:
            if p not in runtime_order:
                runtime_order.append(p)

        return runtime_order

    @property
    def has_data(self) -> bool:
        """是否有任何运行时数据。."""
        return bool(self._data)

    def to_dict(self) -> dict[str, Any]:
        """序列化为字典 (用于 JSON 持久化)。."""
        return {ft: {p: dict(c) for p, c in paradigms.items()} for ft, paradigms in self._data.items()}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ParadigmPerformanceTracker:
        """从字典反序列化。."""
        tracker = cls()
        for ft, paradigms in data.items():
            for p, counts in paradigms.items():
                tracker._data[ft][p] = dict(counts)
        return tracker

    def save_to_file(self, path: str | Path) -> None:
        """保存到 JSON 文件。."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
        logger.info(f"ParadigmPerformanceTracker saved to {path}")

    @classmethod
    def load_from_file(cls, path: str | Path) -> ParadigmPerformanceTracker:
        """从 JSON 文件加载, 文件不存在时返回空实例。."""
        path = Path(path)
        if not path.exists():
            return cls()
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            return cls.from_dict(data)
        except Exception as e:
            logger.warning(f"Failed to load paradigm performance from {path}: {e}")
            return cls()


class FailureTypeEventHandler:
    """Post-execution 失败类型扫描器 — 收集失败模式反馈到 selector。.

    在 Stage 4 的 ``_scan_results_post_execution`` 中被遍历调用，
    提取每个 AttackResult 的失败类型并更新 selector。
    反馈主要影响下一次运行的技术排序。

    使用方式:
        handler = FailureTypeEventHandler(selector=my_selector)
        # 在 Stage 4 post-execution scan 中遍历调用:
        for ar in attack_results:
            handler.on_attack_result(ar)
    """

    def __init__(self, selector: Any = None) -> None:
        """Args:
        selector: FailureTypeRoutingSelector 实例
                 （需要支持 update_failure_type 方法）.
        """
        self._selector = selector
        self._failure_counter: Counter = Counter()
        self._total_attacks = 0
        self._total_successes = 0
        self._total_failures = 0
        self._last_failure_type: str | None = None
        self._technique_results: dict[str, dict[str, int]] = {}
        # P1: 范式性能跟踪器
        self._paradigm_tracker = ParadigmPerformanceTracker()

    def on_attack_result(self, attack_result: Any, *args, **kwargs) -> None:
        """处理单个 AttackResult — 提取失败类型并反馈到 selector。.

        在 Stage 4 post-execution scan 中被遍历调用。
        成功结果只更新计数器，失败结果额外提取失败类型。

        Args:
            attack_result: AttackResult 实例
        """
        if attack_result is None:
            return

        self._total_attacks += 1

        # 提取技术名
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
            # P1: 记录范式性能 (成功)
            self._record_paradigm_performance(technique_name, "success", True)
            return

        # 失败 — 提取失败类型
        self._total_failures += 1
        if technique_name:
            self._technique_results.setdefault(technique_name, {"success": 0, "failure": 0})
            self._technique_results[technique_name]["failure"] += 1

        # 使用 extract_failure_type_from_result 提取失败类型
        try:
            from pipeline.asr.failure_type_selector import extract_failure_type_from_result

            failure_type = extract_failure_type_from_result(attack_result)
        except Exception as e:
            logger.debug(f"Failed to extract failure type: {e}")
            failure_type = "unknown"

        self._failure_counter[failure_type] += 1
        self._last_failure_type = failure_type

        # P1: 记录范式性能 (失败, 按失败类型分类)
        self._record_paradigm_performance(technique_name, failure_type, False)

        # 实时反馈到 selector
        if self._selector and hasattr(self._selector, "update_failure_type"):
            self._selector.update_failure_type(failure_type)
            logger.debug(
                f"Real-time feedback: failure_type='{failure_type}' → selector updated (attack #{self._total_attacks})"
            )

        # 检查 SequentialAttackResult 的子结果
        child_results = getattr(attack_result, "child_attack_results", None) or []
        for child in child_results:
            if child is None:
                continue
            child_outcome = getattr(child, "outcome", None)
            if child_outcome is not None:
                child_outcome_str = (
                    str(child_outcome.value).upper() if hasattr(child_outcome, "value") else str(child_outcome).upper()
                )
                if child_outcome_str != "SUCCESS":
                    try:
                        from pipeline.asr.failure_type_selector import (
                            extract_failure_type_from_result,
                        )

                        child_failure_type = extract_failure_type_from_result(child)
                        self._failure_counter[child_failure_type] += 1
                    except Exception:
                        pass

    def _extract_technique_name(self, attack_result: Any) -> str | None:
        """从 AttackResult 提取技术名 (委托给 AttackResultAnalyzer)。."""
        from pipeline.analysis.attack_result_analyzer import AttackResultAnalyzer

        return AttackResultAnalyzer.extract_technique_name_optional(attack_result)

    def get_runtime_asr(self) -> dict[str, float]:
        """获取运行时 ASR 统计。."""
        results: dict[str, float] = {}
        for tech, counts in self._technique_results.items():
            total = counts["success"] + counts["failure"]
            if total > 0:
                results[tech] = counts["success"] / total
        return results

    def get_failure_distribution(self) -> dict[str, int]:
        """获取失败类型分布。."""
        return dict(self._failure_counter)

    def get_stats(self) -> dict[str, Any]:
        """获取完整统计。."""
        return {
            "total_attacks": self._total_attacks,
            "total_successes": self._total_successes,
            "total_failures": self._total_failures,
            "runtime_asr": self.get_runtime_asr(),
            "failure_distribution": self.get_failure_distribution(),
            "last_failure_type": self._last_failure_type,
            "technique_results": dict(self._technique_results),
            "paradigm_performance": self._paradigm_tracker.to_dict(),
        }

    @property
    def paradigm_tracker(self) -> ParadigmPerformanceTracker:
        """获取范式性能跟踪器实例。."""
        return self._paradigm_tracker

    def _record_paradigm_performance(
        self,
        technique_name: str | None,
        failure_type: str,
        success: bool,
    ) -> None:
        """记录范式级性能数据到跟踪器。."""
        if not technique_name:
            return
        try:
            from pipeline.asr.failure_type_selector import _infer_paradigm

            paradigm = _infer_paradigm(technique_name)
            if paradigm and paradigm != "unknown":
                self._paradigm_tracker.record(
                    failure_type=failure_type,
                    paradigm=paradigm,
                    success=success,
                )
        except Exception as e:
            logger.debug(f"Failed to record paradigm performance: {e}")

    @property
    def most_common_failure_type(self) -> str | None:
        """获取最常见的失败类型。."""
        if self._failure_counter:
            return self._failure_counter.most_common(1)[0][0]
        return None
