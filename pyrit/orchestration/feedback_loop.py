"""
===============================================================================
DynamicFeedbackLoop — 实时成功率动态调优
===============================================================================
L3 攻击执行 → L2 编排层的反馈闭环。

核心机制:
  1. 实时 ASR 监控: 按攻击类别/阶段/转换器链维度统计成功率
  2. Bandit 调度: 多臂老虎机算法动态分配攻击策略权重
  3. 早停 (Early Stop): 连续失败自动切换策略
  4. 跨用例策略共享: 成功组合自动推广到同类用例
  5. 自适应参数调优: 根据反馈自动调整 AttackConfig

与 PyRITNativeOrchestrator 协同:
  Orchestrator 每次攻击完成后调用 on_attack_complete(),
  FeedbackLoop 更新内部状态并返回策略建议。
===============================================================================
"""
from __future__ import annotations

import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from schemas.attack_models import AttackFeedback, AttackPhase, AttackCategory

logger = logging.getLogger(__name__)


@dataclass
class ComboStats:
    """单个攻击组合的统计信息。"""
    name: str
    category: str = ""
    phase: str = ""
    total: int = 0
    successes: int = 0
    last_success_time: float = 0.0
    consecutive_failures: int = 0
    avg_duration_ms: float = 0.0

    @property
    def success_rate(self) -> float:
        return self.successes / self.total if self.total > 0 else 0.0


class DynamicFeedbackLoop:
    """动态反馈闭环 — 实时成功率监控与策略调优。

    使用示例:
        loop = DynamicFeedbackLoop(enable_bandit=True, enable_early_stop=True)
        # 每次攻击完成后:
        loop.on_attack_complete(feedback)
        # 获取推荐策略:
        recommendation = loop.get_strategy_recommendation()
    """

    def __init__(
        self,
        *,
        enable_bandit: bool = True,
        enable_early_stop: bool = True,
        enable_cross_case_share: bool = True,
        early_stop_threshold: int = 3,      # 连续失败 N 次触发早停
        exploration_rate: float = 0.15,      # Bandit 探索率
        success_decay: float = 0.95,         # 历史成功率衰减因子
    ):
        self.enable_bandit = enable_bandit
        self.enable_early_stop = enable_early_stop
        self.enable_cross_case_share = enable_cross_case_share
        self.early_stop_threshold = early_stop_threshold
        self.exploration_rate = exploration_rate
        self.success_decay = success_decay

        # 统计存储
        self._combo_stats: dict[str, ComboStats] = {}
        self._category_stats: dict[str, ComboStats] = {}
        self._phase_stats: dict[str, ComboStats] = {}
        self._global_success_combos: set[str] = set()
        self._blacklisted_combos: set[str] = set()

        # 时间序列
        self._recent_feedbacks: list[AttackFeedback] = []
        self._max_recent = 100

        # 开始时间
        self._start_time = time.time()

    def on_attack_complete(self, feedback: AttackFeedback) -> None:
        """处理单次攻击完成的反馈。

        Args:
            feedback: 攻击反馈，包含结果、成功标志、耗时等
        """
        combo_name = feedback.combo_name
        success = feedback.success
        category = feedback.attack_result.category.value
        phase = feedback.attack_result.phase.value

        # ── 更新组合统计 ──
        if combo_name not in self._combo_stats:
            self._combo_stats[combo_name] = ComboStats(
                name=combo_name, category=category, phase=phase,
            )
        combo_stat = self._combo_stats[combo_name]
        combo_stat.total += 1
        if success:
            combo_stat.successes += 1
            combo_stat.last_success_time = time.time()
            combo_stat.consecutive_failures = 0
            self._global_success_combos.add(combo_name)
            # 跨用例共享
            if self.enable_cross_case_share:
                self._propagate_success(combo_name, category)
        else:
            combo_stat.consecutive_failures += 1
            # 早停检查
            if self.enable_early_stop:
                if combo_stat.consecutive_failures >= self.early_stop_threshold:
                    logger.info(
                        f"早停触发: {combo_name} 连续失败 "
                        f"{combo_stat.consecutive_failures} 次，加入黑名单"
                    )
                    self._blacklisted_combos.add(combo_name)

        # 更新平均耗时
        n = combo_stat.total
        old_avg = combo_stat.avg_duration_ms
        new_val = feedback.elapsed_ms
        combo_stat.avg_duration_ms = old_avg + (new_val - old_avg) / n if n > 0 else new_val

        # ── 更新类别统计 ──
        if category not in self._category_stats:
            self._category_stats[category] = ComboStats(name=category)
        cat_stat = self._category_stats[category]
        cat_stat.total += 1
        if success:
            cat_stat.successes += 1

        # ── 更新阶段统计 ──
        if phase not in self._phase_stats:
            self._phase_stats[phase] = ComboStats(name=phase)
        ph_stat = self._phase_stats[phase]
        ph_stat.total += 1
        if success:
            ph_stat.successes += 1

        # ── 保存最近反馈 ──
        self._recent_feedbacks.append(feedback)
        if len(self._recent_feedbacks) > self._max_recent:
            self._recent_feedbacks = self._recent_feedbacks[-self._max_recent:]

    def get_strategy_recommendation(self) -> dict:
        """获取策略推荐 — 供 Orchestrator 在下一轮攻击前调用。

        Returns:
            {
                "recommended_combos": [...],       # 推荐组合（按分数排序）
                "blacklisted_combos": [...],        # 应避免的组合
                "suggested_phase": "...",           # 建议的阶段
                "should_adjust_params": bool,        # 是否应调整参数
                "param_suggestions": {...},          # 参数调整建议
            }
        """
        # Bandit 排序
        if self.enable_bandit:
            ranked = self._bandit_rank()
        else:
            ranked = sorted(
                self._combo_stats.items(),
                key=lambda kv: kv[1].success_rate,
                reverse=True,
            )

        recommended = [
            name for name, stat in ranked
            if name not in self._blacklisted_combos
        ][:10]

        return {
            "recommended_combos": recommended,
            "blacklisted_combos": list(self._blacklisted_combos),
            "suggested_phase": self._suggest_phase(),
            "should_adjust_params": self._should_adjust(),
            "param_suggestions": self._param_suggestions(),
        }

    def get_stats(self) -> dict:
        """获取统计摘要。"""
        total = sum(s.total for s in self._combo_stats.values())
        total_success = sum(s.successes for s in self._combo_stats.values())
        overall_asr = total_success / total if total > 0 else 0.0

        # Top 5 组合
        top_combos = sorted(
            [(name, stat.success_rate) for name, stat in self._combo_stats.items()],
            key=lambda x: x[1], reverse=True,
        )[:5]

        return {
            "overall_success_rate": overall_asr,
            "total_attacks": total,
            "total_successes": total_success,
            "global_success_combos": len(self._global_success_combos),
            "blacklisted_combos": len(self._blacklisted_combos),
            "top_combos": top_combos,
            "by_category": {
                cat: stat.success_rate
                for cat, stat in self._category_stats.items()
            },
            "by_phase": {
                ph: stat.success_rate
                for ph, stat in self._phase_stats.items()
            },
        }

    def reset_combo(self, combo_name: str) -> None:
        """重置组合统计（从黑名单中移除）。"""
        self._blacklisted_combos.discard(combo_name)
        if combo_name in self._combo_stats:
            self._combo_stats[combo_name].consecutive_failures = 0

    # ═══════════════════════════════════════════════════════════
    # 内部方法
    # ═══════════════════════════════════════════════════════════

    def _bandit_rank(self) -> list[tuple[str, ComboStats]]:
        """多臂老虎机 (UCB1) 排序。

        UCB = success_rate + exploration_rate * sqrt(2 * ln(N) / n)
        平衡利用 (exploit) 和探索 (explore)。
        """
        total = sum(s.total for s in self._combo_stats.values())
        if total == 0:
            return list(self._combo_stats.items())

        ranked = []
        for name, stat in self._combo_stats.items():
            if stat.total == 0:
                ucb = float("inf")  # 未尝试的组合优先探索
            else:
                exploitation = stat.success_rate
                exploration = self.exploration_rate * math.sqrt(
                    2 * math.log(max(total, 1)) / stat.total
                )
                ucb = exploitation + exploration
            ranked.append((name, stat, ucb))

        ranked.sort(key=lambda x: x[2], reverse=True)
        return [(name, stat) for name, stat, _ in ranked]

    def _propagate_success(self, combo_name: str, category: str) -> None:
        """将成功组合推广到同类别的其他统计中。"""
        for name, stat in self._combo_stats.items():
            if name != combo_name and stat.category == category:
                # 增加虚拟成功计数（Boost 效果）
                stat.successes += 1
                stat.total += 1

    def _suggest_phase(self) -> str:
        """建议下一步攻击阶段。"""
        # 按阶段成功率排序
        ranked = sorted(
            self._phase_stats.items(),
            key=lambda kv: kv[1].success_rate,
            reverse=True,
        )
        if ranked:
            return ranked[0][0]
        return "single"

    def _should_adjust(self) -> bool:
        """判断是否需要调整参数。"""
        # 如果总体 ASR 持续低于 10%，建议调整
        total = sum(s.total for s in self._combo_stats.values())
        total_success = sum(s.successes for s in self._combo_stats.values())
        if total > 10:
            asr = total_success / total
            return asr < 0.10
        return False

    def _param_suggestions(self) -> dict:
        """生成参数调整建议。"""
        suggestions = {}

        # 如果所有组合都失败，建议增加回退次数
        all_failing = all(
            s.success_rate == 0.0 and s.total > 0
            for s in self._combo_stats.values()
            if s.total > 0
        )
        if all_failing:
            suggestions["crescendo_max_backtracks"] = 10
            suggestions["tap_tree_depth"] = 10
            suggestions["max_attempts_on_failure"] = 5

        # 如果防御很强，建议 deep 模式
        overall_success = sum(
            s.successes for s in self._combo_stats.values()
        )
        overall_total = sum(s.total for s in self._combo_stats.values())
        if overall_total > 20 and overall_success / max(overall_total, 1) < 0.05:
            suggestions["preset"] = "deep"

        return suggestions


__all__ = ["DynamicFeedbackLoop", "ComboStats"]
