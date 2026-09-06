"""Capability Drift Monitor — 攻击过程中检测目标能力变化。

学术依据:
    - Chao et al. (arXiv:2310.08419) — "自适应红队: 目标可能在攻击过程中更新护栏规则,
护栏规则的更新可能导致前期的攻击方法失效"
    - Anderson et al. (arXiv:2308.02678) — EvoCheck: 同一引擎的版本差异检测
    - Perez et al. (arXiv:2202.03286) — LLMs 的动态行为变化需要持续监测

监控策略:
    1. 时间维度漂移 (Temporal Drift): 同一 probe 在不同时刻返回不同结果
    2. 护栏更新 (Guardrail Update): 前期通过的策略后期被拒
    3. 模型版本变化 (Model Version Change): model_family 发生变化
    4. 速率限制触发 (Rate Limit): 响应时间异常增加

设计原则 (Rule 2: Stealth First):
    监控行为完全通过正常测试 payload 执行 (攻击 probe),
    不发送额外的 health check (避免增加目标警觉)。
    仅在攻击结果出现"异常不一致"时触发深度分析。
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════
# 数据结构
# ════════════════════════════════════════════════════════════════════


@dataclass
class CapabilitySnapshot:
    """单次攻击的快照。

    记录攻击执行时的所有上下文信息,
    用于后续的漂移检测分析。
    """
    timestamp: float
    seed_name: str
    converter_name: str
    attack_success: bool  # 评分器判定是否成功
    refusal_detected: bool  # 是否触发护栏拒绝
    response_time_ms: float  # 响应时间
    model_family: str | None = None
    status_code: int = 200
    error_type: str | None = None  # timeout / connection_error / parse_error


@dataclass
class DriftReport:
    """漂移检测报告。

    属性:
        has_drift: 是否检测到漂移
        drift_type: 漂移类型 (guardrail_update / model_change / rate_limit / consistent)
        confidence: 漂移置信度 (0.0-1.0)
        evidence: 证据列表
        recommendations: 调整建议
    """
    has_drift: bool = False
    drift_type: str = "none"
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    recommendations: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "has_drift": self.has_drift,
            "drift_type": self.drift_type,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "recommendations": self.recommendations,
        }


# ════════════════════════════════════════════════════════════════════
# 能力漂移监控器
# ════════════════════════════════════════════════════════════════════


class CapabilityDriftMonitor:
    """能力漂移监控器。

    在攻击执行过程中记录每个 probe 的结果和能力指纹,
    定期分析快照序列以检测目标行为是否发生漂移。

    使用方式:
        >>> monitor = CapabilityDriftMonitor()
        >>> monitor.record_attack(attack_snapshot)
        >>> report = monitor.analyze_drift()
        >>> if report.has_drift:
        ...     handle_drift(report)
    """

    def __init__(self, window_size: int = 10, drift_threshold: float = 0.3) -> None:
        """初始化监控器。

        Args:
            window_size: 滑动窗口大小 (默认 10 个快照)。
            drift_threshold: 漂移判定阈值 (拒绝率变化超过此值判定为漂移)。
        """
        self._snapshots: list[CapabilitySnapshot] = []
        self._window_size = window_size
        self._drift_threshold = drift_threshold
        self._initial_model_family: str | None = None
        self._initial_refusal_rate: float = 0.0

    def record_attack(self, snapshot: CapabilitySnapshot) -> None:
        """记录一次攻击的执行快照。

        快照会追加到时间序列末尾。
        如果记录数量超过窗口大小, 旧快照会被丢弃。

        Args:
            snapshot: 攻击执行快照。
        """
        # 记录初始状态
        if len(self._snapshots) == 0:
            self._initial_model_family = snapshot.model_family

        self._snapshots.append(snapshot)

        # 维护窗口大小
        if len(self._snapshots) > self._window_size * 2:
            self._snapshots = self._snapshots[-self._window_size:]

        # 计算初始拒绝率 (前窗口)
        self._update_baseline()

    def _update_baseline(self) -> None:
        """更新基线拒绝率 (基于前 N 个快照)。"""
        if len(self._snapshots) < 3:
            return

        initial_window = self._snapshots[: min(5, len(self._snapshots) // 2)]
        if not initial_window:
            return

        refused = sum(1 for s in initial_window if s.refusal_detected)
        self._initial_refusal_rate = refused / len(initial_window)

    def analyze_drift(self) -> DriftReport:
        """分析快照序列, 检测能力漂移。

        检测逻辑:
            1. 护栏更新: 后半窗口拒绝率 > 前半窗口 + threshold
            2. 模型变化: model_family 发生变化
            3. 速率限制: 响应时间异常增加
            4. 一致: 无显著漂移

        Returns:
            DriftReport 实例。
        """
        report = DriftReport()

        if len(self._snapshots) < 5:
            report.drift_type = "insufficient_data"
            report.evidence.append(f"Only {len(self._snapshots)} snapshots, need >= 5")
            return report

        # 分割窗口 (前半 vs 后半)
        mid = len(self._snapshots) // 2
        first_half = self._snapshots[:mid]
        second_half = self._snapshots[mid:]

        # 1. 护栏更新检测
        first_refusal_rate = sum(1 for s in first_half if s.refusal_detected) / len(first_half)
        second_refusal_rate = sum(1 for s in second_half if s.refusal_detected) / len(second_half)

        if second_refusal_rate - first_refusal_rate > self._drift_threshold:
            report.has_drift = True
            report.drift_type = "guardrail_update"
            report.confidence = min(1.0, (second_refusal_rate - first_refusal_rate) * 2)
            report.evidence.append(
                f"Refusal rate increased: {first_refusal_rate:.0%} → {second_refusal_rate:.0%} "
                f"(threshold: {self._drift_threshold:.0%})"
            )
            report.recommendations = {
                "action": "slow_down_and_switch_strategy",
                "switch_to_templates": ["researcher_scenario_key_given", "chinese_academic_scenario"],
                "avoid_templates": ["system_override_skeleton_key", "direct_instruction"],
                "delay_range": [30.0, 60.0],
                "max_attempts_reduction": 0.5,
            }
            return report

        # 2. 模型变化检测
        model_families = {s.model_family for s in second_half if s.model_family}
        if model_families and self._initial_model_family:
            if any(mf != self._initial_model_family for mf in model_families):
                report.has_drift = True
                report.drift_type = "model_change"
                report.confidence = 0.85
                report.evidence.append(
                    f"Model family changed: '{self._initial_model_family}' → '{model_families}'"
                )
                report.recommendations = {
                    "action": "reidentify_and_remap_seeds",
                    "redetect_model_family": True,
                    "rebuild_seed_mapping": True,
                }
                return report

        # 3. 速率限制检测
        first_rt = sum(s.response_time_ms for s in first_half) / max(1, len(first_half))
        second_rt = sum(s.response_time_ms for s in second_half) / max(1, len(second_half))

        if second_rt > 0 and first_rt > 0:
            rt_ratio = second_rt / first_rt
            if rt_ratio > 3.0 and second_rt > 5000:  # 响应时间翻倍且 > 5s
                report.has_drift = True
                report.drift_type = "rate_limit"
                report.confidence = min(1.0, (rt_ratio - 2.0) / 5.0)
                report.evidence.append(
                    f"Response time increased: {first_rt:.0f}ms → {second_rt:.0f}ms "
                    f"(ratio: {rt_ratio:.1f}x)"
                )
                report.recommendations = {
                    "action": "exponential_backoff",
                    "delay_range": [60.0, 120.0],
                    "pause_attacks": True,
                    "resume_after_seconds": 300,
                }
                return report

        # 4. 无显著漂移
        report.drift_type = "consistent"
        report.evidence.append("No significant drift detected in recent snapshots")

        # 即使无漂移, 也提供趋势建议
        if second_refusal_rate > first_refusal_rate:
            report.recommendations = {
                "action": "monitor_closely",
                "trend": "refusal_rate_increasing_slightly",
                "suggestion": "Prepare alternative strategies",
            }
        else:
            report.recommendations = {"action": "continue_current_strategy"}

        return report

    def get_current_stats(self) -> dict[str, Any]:
        """获取当前统计信息。"""
        if not self._snapshots:
            return {"total_snapshots": 0}

        total = len(self._snapshots)
        refused = sum(1 for s in self._snapshots if s.refusal_detected)
        success = sum(1 for s in self._snapshots if s.attack_success)
        avg_rt = sum(s.response_time_ms for s in self._snapshots) / max(1, total)

        return {
            "total_snapshots": total,
            "refusal_rate": round(refused / total, 3),
            "success_rate": round(success / total, 3),
            "avg_response_time_ms": round(avg_rt, 1),
            "model_family_history": list(
                {s.model_family for s in self._snapshots if s.model_family}
            ),
            "time_range_seconds": round(
                self._snapshots[-1].timestamp - self._snapshots[0].timestamp, 1
            ) if len(self._snapshots) >= 2 else 0,
        }

    def reset(self) -> None:
        """重置监控器状态。"""
        self._snapshots.clear()
        self._initial_model_family = None
        self._initial_refusal_rate = 0.0


# ════════════════════════════════════════════════════════════════════
# 全局单例
# ════════════════════════════════════════════════════════════════════

_default_monitor: CapabilityDriftMonitor | None = None


def get_drift_monitor() -> CapabilityDriftMonitor:
    """获取全局 CapabilityDriftMonitor 单例。"""
    global _default_monitor
    if _default_monitor is None:
        _default_monitor = CapabilityDriftMonitor()
    return _default_monitor
