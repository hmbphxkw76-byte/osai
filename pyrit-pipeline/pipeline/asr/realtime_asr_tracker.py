# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""实时 ASR 反馈追踪器 — 运行时动态参数调整 (R-022: PyRIT 原生优先)。

本模块是 PyRIT 原生 ``ProgressPoller`` 的**数据层增强** (R-022):
  - 不修改原生 Scenario 生命周期
  - 不覆盖原生 ``scenario.run_async()``
  - 通过 ProgressPoller 的轮询回调采集实时 ASR 数据
  - 提供运行时参数调整建议 (Converter 优先级 / 技术权重 / 重试次数)

**实时 ASR 反馈机制**:
  1. ProgressPoller 每 5 秒查询 CentralMemory 获取已完成 AttackResult
  2. RealTimeASRTracker 通过 ``on_new_results()`` 回调接收新结果
  3. 维护 per-technique running ASR (成功/失败计数)
  4. 当 ASR 偏差超过阈值时, 生成参数调整建议
  5. 调整建议存入 ``ctx.metadata["realtime_asr_adjustments"]`` 供后续使用

**参数调整策略**:
  - 高 ASR 技术 (>70%): 降低重试次数 (节省 API 调用)
  - 低 ASR 技术 (<30%): 建议 Converter 增强 (编码/变形)
  - 零 ASR 技术 (0%): 建议跳过或更换攻击角度
  - Converter 性能差异: 调整 Converter 优先级排序

学术依据:
  - Multi-Armed Bandit for Attack Strategy Selection: Liu et al. (arXiv:2402.07932)
  - Adaptive Prompt Injection: Chen et al. (arXiv:2310.18035)

> **日期**: 2026-8-5
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class TechniqueASR:
    """单技术实时 ASR 追踪。

    Attributes:
        technique: 技术名称。
        total: 总尝试次数。
        successes: 成功次数。
        failures: 失败次数。
        converter_performance: per-converter 成功/失败计数。
    """

    technique: str = ""
    total: int = 0
    successes: int = 0
    failures: int = 0
    converter_performance: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def asr(self) -> float:
        """当前 ASR (0-1)。"""
        return self.successes / self.total if self.total > 0 else 0.0

    def record(self, *, success: bool, converter_chain: str = "baseline") -> None:
        """记录一次尝试结果。"""
        self.total += 1
        if success:
            self.successes += 1
        else:
            self.failures += 1

        if converter_chain not in self.converter_performance:
            self.converter_performance[converter_chain] = {"success": 0, "failure": 0}
        key = "success" if success else "failure"
        self.converter_performance[converter_chain][key] += 1


@dataclass
class ASRAdjustment:
    """参数调整建议。

    Attributes:
        technique: 目标技术。
        adjustment_type: 调整类型 (converter_boost/retry_reduction/skip/angle_change)。
        description: 调整描述。
        current_asr: 当前 ASR。
        suggested_action: 建议动作。
    """

    technique: str
    adjustment_type: str
    description: str
    current_asr: float
    suggested_action: str = ""


class RealTimeASRTracker:
    """实时 ASR 反馈追踪器 — 运行时动态参数调整。

    本类是 PyRIT 原生 ``ProgressPoller`` 的**数据层增强** (R-022)。

    用法::

        tracker = RealTimeASRTracker()
        # 在 ProgressPoller 轮询回调中调用
        tracker.on_new_results(new_results)
        # 查询当前 ASR
        asr = tracker.get_technique_asr("jailbreak")
        # 获取调整建议
        adjustments = tracker.suggest_adjustments()
    """

    # ASR 阈值
    HIGH_ASR_THRESHOLD = 0.70
    LOW_ASR_THRESHOLD = 0.30
    ZERO_ASR_MIN_SAMPLES = 5  # 零 ASR 判断最小样本数

    def __init__(self) -> None:
        """初始化实时 ASR 追踪器。"""
        self._techniques: dict[str, TechniqueASR] = {}
        self._adjustments: list[ASRAdjustment] = []
        self._last_adjustment_count: int = 0

    @property
    def total_results(self) -> int:
        """总结果数。"""
        return sum(t.total for t in self._techniques.values())

    @property
    def overall_asr(self) -> float:
        """全局 ASR。"""
        total = self.total_results
        if total == 0:
            return 0.0
        successes = sum(t.successes for t in self._techniques.values())
        return successes / total

    def on_new_results(self, results: list[Any]) -> None:
        """处理新 AttackResult (由 ProgressPoller 回调调用)。

        Args:
            results: 新的 AttackResult 列表 (从 CentralMemory 查询)。
        """
        from pyrit.models import AttackOutcome

        for ar in results:
            technique = self._extract_technique(ar)
            outcome = getattr(ar, "outcome", None)
            is_success = outcome == AttackOutcome.SUCCESS

            converter_chain = self._extract_converter_chain(ar)

            if technique not in self._techniques:
                self._techniques[technique] = TechniqueASR(technique=technique)

            self._techniques[technique].record(
                success=is_success,
                converter_chain=converter_chain,
            )

        # 检查是否需要生成新的调整建议
        self._check_and_generate_adjustments()

    def get_technique_asr(self, technique: str) -> float:
        """获取指定技术的当前 ASR。

        Args:
            technique: 技术名称。

        Returns:
            ASR (0-1), 若无数据返回 0.0。
        """
        tech = self._techniques.get(technique)
        return tech.asr if tech else 0.0

    def get_all_asr(self) -> dict[str, float]:
        """获取所有技术的当前 ASR。

        Returns:
            技术→ASR 映射字典。
        """
        return {tech: data.asr for tech, data in self._techniques.items()}

    def get_converter_performance(self, technique: str) -> dict[str, dict[str, int]]:
        """获取指定技术的 Converter 性能数据。

        Args:
            technique: 技术名称。

        Returns:
            Converter→{success, failure} 映射。
        """
        tech = self._techniques.get(technique)
        return tech.converter_performance if tech else {}

    def suggest_adjustments(self) -> list[ASRAdjustment]:
        """获取参数调整建议。

        Returns:
            ASRAdjustment 列表。
        """
        return list(self._adjustments)

    def get_realtime_summary(self) -> dict[str, Any]:
        """获取实时 ASR 摘要 (存入 ctx.metadata)。

        Returns:
            摘要字典。
        """
        return {
            "total_results": self.total_results,
            "overall_asr": round(self.overall_asr, 4),
            "technique_count": len(self._techniques),
            "technique_asr": {
                tech: round(data.asr, 4)
                for tech, data in sorted(
                    self._techniques.items(),
                    key=lambda x: x[1].asr,
                    reverse=True,
                )
            },
            "adjustments": [
                {
                    "technique": adj.technique,
                    "type": adj.adjustment_type,
                    "description": adj.description,
                    "current_asr": round(adj.current_asr, 4),
                    "suggested_action": adj.suggested_action,
                }
                for adj in self._adjustments
            ],
        }

    def get_live_parameter_overrides(self) -> dict[str, Any]:
        """获取实时参数覆盖 (供 ProgressPoller 或下一批攻击读取)。

        这是**数据层增强** (R-022): 生成参数覆盖数据, 不修改原生 Scenario 生命周期。

        Returns:
            参数覆盖字典, 包含:
            - ``converter_priority_boost``: Converter 链 → 优先级提升值
            - ``retry_reduction``: 技术 → 重试次数缩减比例 (0-1)
            - ``technique_skip``: 技术 → 是否建议跳过
            - ``angle_change``: 技术 → 建议的替代攻击角度
        """
        converter_boost: dict[str, float] = {}
        retry_reduction: dict[str, float] = {}
        skip: dict[str, bool] = {}
        angle_change: dict[str, str] = {}

        for adj in self._adjustments:
            if adj.adjustment_type == "retry_reduction":
                # 高 ASR → 重试次数减半
                retry_reduction[adj.technique] = 0.5
            elif adj.adjustment_type == "converter_boost":
                # 低 ASR → 提升 encoding/persuasion 优先级
                converter_boost["encoding"] = 1.5
                converter_boost["persuasion"] = 1.3
            elif adj.adjustment_type == "skip_or_angle_change":
                if adj.current_asr == 0.0:
                    skip[adj.technique] = True
                else:
                    angle_change[adj.technique] = "crescendo"
            elif adj.adjustment_type == "converter_priority":
                # 从 suggested_action 中解析 best/worst chain
                action = adj.suggested_action
                if "提升" in action and "降低" in action:
                    # 解析 "提升 X 优先级, 降低 Y 优先级"
                    import re as _re

                    boost_match = _re.search(r"提升\s+(\S+)\s+优先级", action)
                    reduce_match = _re.search(r"降低\s+(\S+)\s+优先级", action)
                    if boost_match:
                        converter_boost[boost_match.group(1)] = 1.4
                    if reduce_match:
                        converter_boost[reduce_match.group(1)] = 0.6

        return {
            "converter_priority_boost": converter_boost,
            "retry_reduction": retry_reduction,
            "technique_skip": skip,
            "angle_change": angle_change,
            "generated_at": self.total_results,
        }

    def apply_to_warm_start(self, *, warm_start_config: dict[str, Any]) -> dict[str, Any]:
        """将实时 ASR 调整应用到暖启动配置 (供下一次运行使用)。

        这是**配置层增强** (R-022): 修改配置数据, 不修改原生 Scenario 生命周期。

        Args:
            warm_start_config: 暖启动配置字典 (技术→参数)。

        Returns:
            更新后的暖启动配置字典。
        """
        overrides = self.get_live_parameter_overrides()

        # 应用重试缩减
        for tech, reduction in overrides["retry_reduction"].items():
            if tech in warm_start_config:
                original = warm_start_config[tech].get("max_attempts", 3)
                warm_start_config[tech]["max_attempts"] = max(1, int(original * reduction))

        # 标记跳过技术
        for tech, should_skip in overrides["technique_skip"].items():
            if should_skip and tech in warm_start_config:
                warm_start_config[tech]["skip"] = True

        # 标记角度切换
        for tech, new_angle in overrides["angle_change"].items():
            if tech in warm_start_config:
                warm_start_config[tech]["suggested_angle"] = new_angle

        # 存储 Converter 优先级提升
        if overrides["converter_priority_boost"]:
            warm_start_config["_converter_boost"] = overrides["converter_priority_boost"]

        return warm_start_config

    def get_converter_boost_for_technique(self, technique: str) -> dict[str, float]:
        """获取指定技术的 Converter 优先级提升建议。

        Args:
            technique: 技术名称。

        Returns:
            Converter 链名 → 提升值 (>1=提升, <1=降低, 1=不变)。
        """
        tech_data = self._techniques.get(technique)
        if not tech_data or len(tech_data.converter_performance) <= 1:
            return {}

        result: dict[str, float] = {}
        total_success = sum(p["success"] for p in tech_data.converter_performance.values())
        total_fail = sum(p["failure"] for p in tech_data.converter_performance.values())
        overall = total_success / (total_success + total_fail) if (total_success + total_fail) > 0 else 0.0

        for chain, perf in tech_data.converter_performance.items():
            chain_total = perf["success"] + perf["failure"]
            if chain_total == 0:
                continue
            chain_asr = perf["success"] / chain_total
            # ASR 高于平均 → 提升, 低于平均 → 降低
            if overall > 0:
                ratio = chain_asr / overall
                # 限制在 0.5-2.0 范围内
                result[chain] = max(0.5, min(2.0, ratio))
            else:
                result[chain] = 1.0

        return result

    def _extract_technique(self, ar: Any) -> str:
        """从 AttackResult 提取技术名称。"""
        # 尝试从 labels 提取
        labels = getattr(ar, "labels", None) or {}
        if isinstance(labels, dict):
            for key in ("technique", "attack_technique", "owasp_category"):
                val = labels.get(key)
                if val:
                    return str(val)
        # 回退: 从 seed_group 提取
        seed_group = getattr(ar, "seed_group", None)
        if seed_group:
            return str(seed_group)
        # 回退: 从 objective 提取关键词
        objective = getattr(ar, "objective", "") or ""
        if objective:
            return objective[:30]
        return "unknown"

    def _extract_converter_chain(self, ar: Any) -> str:
        """从 AttackResult 提取 Converter 链名。"""
        try:
            from pipeline.converters.converter_feedback import extract_converter_chain_names

            chains = extract_converter_chain_names(ar)
            return "+".join(chains) if chains else "baseline"
        except Exception:
            return "baseline"

    def _check_and_generate_adjustments(self) -> None:
        """检查所有技术的 ASR 并生成调整建议。"""
        new_adjustments: list[ASRAdjustment] = []

        for tech_name, tech_data in self._techniques.items():
            if tech_data.total < 3:
                # 样本不足, 跳过
                continue

            asr = tech_data.asr

            # 高 ASR: 建议降低重试次数
            if asr >= self.HIGH_ASR_THRESHOLD:
                new_adjustments.append(ASRAdjustment(
                    technique=tech_name,
                    adjustment_type="retry_reduction",
                    description=f"ASR {asr:.0%} (≥{self.HIGH_ASR_THRESHOLD:.0%}), 建议降低重试次数以节省 API 调用",
                    current_asr=asr,
                    suggested_action="max_attempts_per_objective: 减半",
                ))

            # 低 ASR: 建议 Converter 增强
            elif asr < self.LOW_ASR_THRESHOLD and tech_data.total >= self.ZERO_ASR_MIN_SAMPLES:
                if asr == 0.0:
                    new_adjustments.append(ASRAdjustment(
                        technique=tech_name,
                        adjustment_type="skip_or_angle_change",
                        description=f"ASR 0% ({tech_data.total} 次尝试全部失败), 建议跳过或更换攻击角度",
                        current_asr=asr,
                        suggested_action="考虑跳过此技术或使用 Crescendo 多轮攻击",
                    ))
                else:
                    new_adjustments.append(ASRAdjustment(
                        technique=tech_name,
                        adjustment_type="converter_boost",
                        description=f"ASR {asr:.0%} (<{self.LOW_ASR_THRESHOLD:.0%}), 建议增强 Converter (编码/变形)",
                        current_asr=asr,
                        suggested_action="添加 encoding/persuasion converter 链",
                    ))

            # Converter 性能差异分析
            if len(tech_data.converter_performance) > 1:
                best_chain = None
                best_asr = -1.0
                worst_chain = None
                worst_asr = 2.0

                for chain, perf in tech_data.converter_performance.items():
                    chain_total = perf["success"] + perf["failure"]
                    if chain_total == 0:
                        continue
                    chain_asr = perf["success"] / chain_total
                    if chain_asr > best_asr:
                        best_asr = chain_asr
                        best_chain = chain
                    if chain_asr < worst_asr:
                        worst_asr = chain_asr
                        worst_chain = chain

                if best_chain and worst_chain and best_asr - worst_asr > 0.3:
                    new_adjustments.append(ASRAdjustment(
                        technique=tech_name,
                        adjustment_type="converter_priority",
                        description=(
                            f"Converter 差异: {best_chain} ASR={best_asr:.0%} vs "
                            f"{worst_chain} ASR={worst_asr:.0%}"
                        ),
                        current_asr=asr,
                        suggested_action=f"提升 {best_chain} 优先级, 降低 {worst_chain} 优先级",
                    ))

        # 只保留新生成的建议 (避免重复)
        if len(new_adjustments) > self._last_adjustment_count:
            self._adjustments = new_adjustments
            self._last_adjustment_count = len(new_adjustments)
            logger.info(
                f"RealTimeASR: generated {len(new_adjustments)} adjustments, "
                f"overall ASR={self.overall_asr:.2%}"
            )
