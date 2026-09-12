"""strike/budget.py — 攻击预算控制（plan Wave 2 / §4.4）。

**必须与 51 个模块接线同批落地，不得延后**：全量接入会导致攻击规模爆炸
（成本失控、被目标封禁），预算控制是接线后的必需安全阀（§8 风险表第 1 条）。

三维度控制：
    1. 数量  max_total_attacks + per_component_quota
    2. 时间  wall_clock_deadline
    3. 成本  token_budget（含 judge 消耗）

超限行为：按 `ComponentSpec.asr_prior` **降序保留**（保留高先验组件），
裁剪原因必须写入 `EvidenceCollector` 与 `orchestration_log`（反静默，C9）。

C7：所有阈值来自 `config/defaults.yaml` → `ctx.args`，本模块无效率字面量。

Academic basis:
    - Chao et al. (arXiv:2310.08419) PAIR: 攻击预算与 ASR 的边际收益
    - NIST SP 800-115 Sec4.4: 测试规模控制与授权边界
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class BudgetSnapshot:
    """预算快照（供报告与 orchestration_log 消费）。"""

    attacks_used: int = 0
    attacks_remaining: int = 0
    tokens_used: int = 0
    tokens_remaining: int = 0
    elapsed_seconds: float = 0.0
    time_remaining_seconds: float = 0.0
    per_component_used: dict[str, int] = field(default_factory=dict)
    exhausted_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attacks_used": self.attacks_used,
            "attacks_remaining": self.attacks_remaining,
            "tokens_used": self.tokens_used,
            "tokens_remaining": self.tokens_remaining,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "time_remaining_seconds": round(self.time_remaining_seconds, 2),
            "per_component_used": dict(self.per_component_used),
            "exhausted_reasons": list(self.exhausted_reasons),
        }


class BudgetController:
    """三维预算控制器（数量 / 时间 / 成本）。

    Usage:
        budget = BudgetController.from_ctx(ctx)
        if budget.consume("mcp_tool_poisoning", cost=3):
            ...
        kept = budget.trim_components(["rag_pipeline", "mcp_tool_poisoning"])
    """

    def __init__(
        self,
        *,
        max_total_attacks: int = 200,
        per_component_default_quota: int = 40,
        per_component_quota: dict[str, int] | None = None,
        per_chain_step_cost: dict[str, int] | None = None,
        wall_clock_deadline: timedelta | None = None,
        token_budget: int = 2_000_000,
        enabled: bool = True,
    ) -> None:
        self.enabled = enabled
        self.max_total_attacks = max(0, int(max_total_attacks))
        self.per_component_default_quota = max(0, int(per_component_default_quota))
        self.per_component_quota: dict[str, int] = dict(per_component_quota or {})
        self.per_chain_step_cost: dict[str, int] = dict(per_chain_step_cost or {})
        self.wall_clock_deadline = wall_clock_deadline or timedelta(hours=1)
        self.token_budget = max(0, int(token_budget))

        self._attacks_used = 0
        self._tokens_used = 0
        self._per_component_used: dict[str, int] = {}
        self._start = time.monotonic()
        self._trim_log: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # 构造
    # ------------------------------------------------------------------
    @classmethod
    def from_ctx(cls, ctx: Any) -> "BudgetController":
        """从 `ctx.args` 构造（C7：全部参数走 defaults.yaml → args 链路）。"""
        args = getattr(ctx, "args", None)
        enabled = bool(getattr(args, "budget_enabled", True)) if args is not None else True

        def _g(key: str, default: Any) -> Any:
            val = getattr(args, key, None) if args is not None else None
            return default if val is None else val

        return cls(
            max_total_attacks=int(_g("max_total_attacks", 200)),
            per_component_default_quota=int(_g("per_component_default_quota", 40)),
            wall_clock_deadline=timedelta(seconds=float(_g("wall_clock_deadline_seconds", 3600))),
            token_budget=int(_g("token_budget", 2_000_000)),
            enabled=enabled,
        )

    # ------------------------------------------------------------------
    # 消费
    # ------------------------------------------------------------------
    def consume(self, component_key: str = "", cost: int = 1, *, tokens: int = 0) -> bool:
        """尝试消费预算；True=放行，False=超限（调用方必须跳过并记录原因）。"""
        if not self.enabled:
            return True

        cost = max(0, int(cost))
        if self._attacks_used + cost > self.max_total_attacks:
            logger.warning(
                "[Budget] 攻击总数已达上限 %d（已用 %d，本次需 %d）——拒绝执行",
                self.max_total_attacks,
                self._attacks_used,
                cost,
            )
            return False

        if tokens and self._tokens_used + tokens > self.token_budget:
            logger.warning(
                "[Budget] token 预算已达上限 %d（已用 %d，本次需 %d）——拒绝执行",
                self.token_budget,
                self._tokens_used,
                tokens,
            )
            return False

        if self.is_time_exhausted():
            logger.warning("[Budget] 时间预算已耗尽（deadline=%s）——拒绝执行", self.wall_clock_deadline)
            return False

        if component_key:
            quota = self.per_component_quota.get(component_key, self.per_component_default_quota)
            used = self._per_component_used.get(component_key, 0)
            if used + cost > quota:
                logger.warning(
                    "[Budget] 组件 %s 配额已用尽 %d/%d（本次需 %d）——拒绝执行",
                    component_key,
                    used,
                    quota,
                    cost,
                )
                return False
            self._per_component_used[component_key] = used + cost

        self._attacks_used += cost
        self._tokens_used += max(0, int(tokens))
        return True

    def step_cost(self, step_id: str, default: int = 1) -> int:
        """攻击链某步骤的开销（`per_chain_step_cost` 优先，否则 default）。"""
        return int(self.per_chain_step_cost.get(step_id, default))

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------
    def elapsed(self) -> timedelta:
        return timedelta(seconds=time.monotonic() - self._start)

    def is_time_exhausted(self) -> bool:
        return self.elapsed() >= self.wall_clock_deadline

    def remaining(self) -> BudgetSnapshot:
        """当前预算快照。"""
        elapsed_s = self.elapsed().total_seconds()
        reasons: list[str] = []
        if self._attacks_used >= self.max_total_attacks:
            reasons.append("max_total_attacks")
        if self._tokens_used >= self.token_budget:
            reasons.append("token_budget")
        if self.is_time_exhausted():
            reasons.append("wall_clock_deadline")
        return BudgetSnapshot(
            attacks_used=self._attacks_used,
            attacks_remaining=max(0, self.max_total_attacks - self._attacks_used),
            tokens_used=self._tokens_used,
            tokens_remaining=max(0, self.token_budget - self._tokens_used),
            elapsed_seconds=elapsed_s,
            time_remaining_seconds=max(0.0, self.wall_clock_deadline.total_seconds() - elapsed_s),
            per_component_used=dict(self._per_component_used),
            exhausted_reasons=reasons,
        )

    def is_exhausted(self) -> bool:
        return bool(self.remaining().exhausted_reasons)

    # ------------------------------------------------------------------
    # 裁剪（plan §4.4：按 asr_prior 降序保留）
    # ------------------------------------------------------------------
    def trim_components(
        self,
        component_keys: list[str],
        *,
        asr_priors: dict[str, float] | None = None,
        keep: int | None = None,
    ) -> list[str]:
        """按 ASR 先验降序保留组件，返回保留列表；被裁组件写入 `_trim_log`。

        裁剪原因**必须**出现在报告中（DoD）：调用方读取 `trim_report()` 写入
        EvidenceCollector 与 orchestration_log。

        Args:
            component_keys: 候选组件键
            asr_priors: 组件 → ASR 先验；缺失时回落到 ComponentRegistry 声明值
            keep: 保留个数；None 表示按剩余预算自动计算

        Returns:
            保留的组件键列表（asr_prior 降序）。
        """
        priors = dict(asr_priors or {})
        if asr_priors is None:
            try:
                from core.registry import get_registry

                reg = get_registry()
                for key in component_keys:
                    spec = reg.spec(key)
                    priors[key] = spec.asr_prior if spec is not None else 0.0
            except Exception as e:
                logger.warning("[Budget] 读取 asr_prior 失败，按原序保留: %s", e)

        ordered = sorted(component_keys, key=lambda k: (-float(priors.get(k, 0.0)), k))

        if keep is None:
            keep = max(0, self.max_total_attacks - self._attacks_used)
        keep = max(0, int(keep))

        retained = ordered[:keep]
        dropped = ordered[keep:]
        if dropped:
            reason = {
                "strategy": "asr_prior_desc",
                "dropped": dropped,
                "dropped_priors": {k: priors.get(k, 0.0) for k in dropped},
                "retained": retained,
                "snapshot": self.remaining().to_dict(),
            }
            self._trim_log.append(reason)
            logger.warning(
                "[Budget] 预算裁剪：丢弃 %d 个低先验组件 %s（保留 %s）",
                len(dropped),
                ", ".join(dropped),
                ", ".join(retained) or "(无)",
            )
        return retained

    def trim_report(self) -> list[dict[str, Any]]:
        """裁剪审计记录（供 report / orchestration_log 消费，反静默）。"""
        return list(self._trim_log)
