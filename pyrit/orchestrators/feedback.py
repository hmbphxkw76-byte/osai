"""动态反馈闭环 — UCB1 Bandit + 早停 + 自适应参数调优.

实现实时攻击效果监控和自适应策略调优：
- ASR (Attack Success Rate) 实时跟踪
- UCB1 Multi-Armed Bandit 策略调度
- 早停机制：成功率达标后自动终止
- 跨战役策略知识共享

⚠️ 已从 orchestration/ 合并到 orchestrators/。
"""

from __future__ import annotations

import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional

from schemas.attack_models import AttackResult, AttackFeedback, AttackCategory

logger = logging.getLogger(__name__)


# ============================================================
# Config
# ============================================================

@dataclass
class FeedbackConfig:
    """反馈闭环配置."""

    exploration_rate: float = 0.2           # UCB1 探索率
    early_stop_threshold: float = 0.8       # ASR 阈值触发早停
    min_iterations: int = 3                 # 最少迭代次数
    max_iterations: int = 50                # 最多迭代次数
    convergence_window: int = 5             # 收敛判定窗口
    convergence_threshold: float = 0.01     # ASR 变化阈值
    decay_factor: float = 0.95              # 历史权重衰减
    min_samples_per_strategy: int = 2       # 每策略最少样本数


# ============================================================
# Dynamic Feedback Loop
# ============================================================

class DynamicFeedbackLoop:
    """动态反馈闭环引擎.

    核心机制：
    1. UCB1 Bandit: 平衡探索(exploration)与利用(exploitation)
    2. 早停检测: ASR 达标或收敛时终止
    3. 跨策略知识共享: 参数调整建议
    """

    def __init__(
        self,
        exploration_rate: float = 0.2,
        early_stop_threshold: float = 0.8,
        min_iterations: int = 3,
        max_iterations: int = 50,
    ):
        self.config = FeedbackConfig(
            exploration_rate=exploration_rate,
            early_stop_threshold=early_stop_threshold,
            min_iterations=min_iterations,
            max_iterations=max_iterations,
        )

        # 策略统计
        self._strategy_stats: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"attempts": 0, "successes": 0, "tokens_total": 0, "reward_sum": 0.0}
        )

        # 全局统计
        self.total_iterations: int = 0
        self.total_attempts: int = 0
        self.total_successes: int = 0
        self._asr_history: list[float] = []
        self._iteration_results: list[list[AttackResult]] = []

        # 跨战役知识库
        self._campaign_knowledge: dict[str, Any] = {}

    # ============================================================
    # Core API
    # ============================================================

    def record_result(self, result: AttackResult) -> None:
        """记录单个攻击结果."""
        sid = result.strategy_id

        stats = self._strategy_stats[sid]
        stats["attempts"] += 1
        stats["tokens_total"] += result.tokens_used
        if result.success:
            stats["successes"] += 1
            stats["reward_sum"] += result.confidence
        else:
            # 即使是失败也有部分奖励（基于 Harm Score）
            stats["reward_sum"] += result.harm_score * 0.3

    def record_batch(self, results: list[AttackResult]) -> None:
        """记录一批攻击结果."""
        self._iteration_results.append(results)
        self.total_iterations += 1

        for r in results:
            self.record_result(r)

        # 更新全局统计
        self.total_attempts += len(results)
        self.total_successes += sum(1 for r in results if r.success)

        # 记录 ASR 历史
        if len(results) > 0:
            asr = sum(1 for r in results if r.success) / len(results)
            self._asr_history.append(asr)

        logger.debug(
            f"Iteration {self.total_iterations}: "
            f"ASR={self.current_asr:.2%}, "
            f"Strategies={len(self._strategy_stats)}"
        )

    def get_feedback(self) -> Optional[AttackFeedback]:
        """获取当前反馈."""
        if self.total_iterations < 1:
            return None

        should_continue, reason = self._check_continue()

        return AttackFeedback(
            iteration=self.total_iterations,
            asr=self.current_asr,
            reward=self._calculate_reward(),
            suggested_adjustments=self._generate_adjustments(),
            should_continue=should_continue,
            early_stop_reason=reason if not should_continue else "",
        )

    def select_strategy(
        self,
        strategies: list[str],
        min_samples: int = 2,
    ) -> str:
        """使用 UCB1 Bandit 选择最优策略.

        UCB1 公式: score = avg_reward + sqrt(2 * ln(N) / n_i)
        其中 N = 总尝试次数, n_i = 策略 i 的尝试次数
        """
        if not strategies:
            return ""

        total_n = self.total_attempts + 1  # +1 避免 log(0)

        best_strategy = strategies[0]
        best_score = float("-inf")

        for sid in strategies:
            stats = self._strategy_stats.get(sid, {"attempts": 0, "reward_sum": 0.0})
            n_i = stats["attempts"]

            # 探索奖励：尝试次数越少，探索值越大
            if n_i < min_samples:
                exploration = 1.0  # 强制探索
            else:
                avg_reward = stats["reward_sum"] / n_i if n_i > 0 else 0.0
                exploration = math.sqrt(
                    self.config.exploration_rate * math.log(total_n) / n_i
                )
                score = avg_reward + exploration

                if score > best_score:
                    best_score = score
                    best_strategy = sid

        return best_strategy

    def get_top_strategies(self, n: int = 5) -> list[tuple[str, float, int]]:
        """获取 Top-N 最优策略 (id, asr, attempts)."""
        ranked = []
        for sid, stats in self._strategy_stats.items():
            if stats["attempts"] > 0:
                asr = stats["successes"] / stats["attempts"]
                ranked.append((sid, asr, stats["attempts"]))
        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked[:n]

    def export_knowledge(self) -> dict[str, Any]:
        """导出跨战役知识."""
        return {
            "total_iterations": self.total_iterations,
            "total_attempts": self.total_attempts,
            "total_successes": self.total_successes,
            "overall_asr": self.current_asr,
            "strategy_stats": {
                sid: {k: v for k, v in stats.items()}
                for sid, stats in self._strategy_stats.items()
            },
            "asr_history": list(self._asr_history),
            "campaign_knowledge": dict(self._campaign_knowledge),
            "timestamp": time.time(),
        }

    def import_knowledge(self, knowledge: dict[str, Any]) -> None:
        """导入跨战役知识."""
        self._campaign_knowledge.update(knowledge.get("campaign_knowledge", {}))

        # 合并策略统计（加权平均）
        existing = knowledge.get("strategy_stats", {})
        for sid, stats in existing.items():
            current = self._strategy_stats[sid]
            current["attempts"] += stats.get("attempts", 0)
            current["successes"] += stats.get("successes", 0)
            current["reward_sum"] += stats.get("reward_sum", 0.0)
            current["tokens_total"] += stats.get("tokens_total", 0)

        logger.info(
            f"Imported knowledge from campaign: "
            f"{knowledge.get('total_attempts', 0)} attempts"
        )

    def reset(self) -> None:
        """重置所有统计（保留跨战役知识）."""
        self._strategy_stats.clear()
        self.total_iterations = 0
        self.total_attempts = 0
        self.total_successes = 0
        self._asr_history.clear()
        self._iteration_results.clear()

    # ============================================================
    # Properties
    # ============================================================

    @property
    def current_asr(self) -> float:
        """当前整体攻击成功率."""
        if self.total_attempts == 0:
            return 0.0
        return self.total_successes / self.total_attempts

    @property
    def is_converged(self) -> bool:
        """ASR 是否已收敛."""
        if len(self._asr_history) < self.config.convergence_window:
            return False
        recent = self._asr_history[-self.config.convergence_window:]
        asr_range = max(recent) - min(recent)
        return asr_range < self.config.convergence_threshold

    @property
    def summary(self) -> dict[str, Any]:
        return {
            "iterations": self.total_iterations,
            "attempts": self.total_attempts,
            "successes": self.total_successes,
            "asr": round(self.current_asr, 4),
            "converged": self.is_converged,
            "active_strategies": len(self._strategy_stats),
            "top_strategies": [
                {"id": sid, "asr": round(asr, 4), "attempts": n}
                for sid, asr, n in self.get_top_strategies(5)
            ],
        }

    # ============================================================
    # Private
    # ============================================================

    def _check_continue(self) -> tuple[bool, str]:
        """检查是否应继续执行."""
        if self.total_iterations < self.config.min_iterations:
            return True, ""

        if self.total_iterations >= self.config.max_iterations:
            return False, f"Reached max iterations ({self.config.max_iterations})"

        if self.current_asr >= self.config.early_stop_threshold:
            return False, (
                f"ASR {self.current_asr:.2%} >= threshold "
                f"{self.config.early_stop_threshold:.2%}"
            )

        if self.is_converged:
            return False, f"ASR converged at {self.current_asr:.2%}"

        return True, ""

    def _calculate_reward(self) -> float:
        """计算当前迭代的奖励值."""
        if not self._iteration_results:
            return 0.0

        latest = self._iteration_results[-1]
        if not latest:
            return 0.0

        # 加权奖励：成功率 + 高置信度奖励
        success_count = 0
        confidence_sum = 0.0
        harm_sum = 0.0
        for r in latest:
            if r.success:
                success_count += 1
                confidence_sum += r.confidence
            harm_sum += r.harm_score

        n = len(latest)
        success_rate = success_count / n if n > 0 else 0.0
        avg_confidence = confidence_sum / success_count if success_count > 0 else 0.0
        avg_harm = harm_sum / n if n > 0 else 0.0

        return round(0.5 * success_rate + 0.3 * avg_confidence + 0.2 * avg_harm, 4)

    def _generate_adjustments(self) -> dict[str, Any]:
        """生成策略调优建议."""
        adjustments: dict[str, Any] = {}

        if self.total_attempts < 10:
            return adjustments

        # 识别低效策略
        low_performers = []
        high_performers = []
        for sid, stats in self._strategy_stats.items():
            if stats["attempts"] >= self.config.min_samples_per_strategy:
                asr = stats["successes"] / stats["attempts"]
                if asr < 0.3:
                    low_performers.append((sid, asr))
                elif asr > 0.7:
                    high_performers.append((sid, asr))

        if low_performers:
            adjustments["deprioritize"] = [
                {"strategy": sid, "asr": round(asr, 3)}
                for sid, asr in low_performers
            ]
        if high_performers:
            adjustments["prioritize"] = [
                {"strategy": sid, "asr": round(asr, 3)}
                for sid, asr in high_performers
            ]

        # 建议增加探索
        if len(high_performers) == 0 and self.total_iterations > 3:
            adjustments["action"] = "increase_exploration"

        # 建议收敛
        if self.is_converged:
            adjustments["action"] = "converged"
            adjustments["recommendation"] = "Consider stopping or changing attack dimension"

        return adjustments
