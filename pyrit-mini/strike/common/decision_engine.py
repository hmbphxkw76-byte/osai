# -*- coding: utf-8 -*-
"""strike/common/decision_engine.py — REQ-135/136/137 全链路自主决策引擎。

统一 `determine_*_strategy` 签名；决策触发条件可配置；所有决策写入 `ctx.decision_log`；
并集成 R-DECIDE-1 安全边界（BLOCKING）。

- REQ-136 Recon 自适应决策：`determine_probe_strategy`（预算 + 目标类型 → 探测深度；
  检测到 WAF → 启用 stealth，写入 ctx.probe_level / ctx.stealth_config）。
- REQ-137 ARM+Assess+Report 决策：`determine_seed_strategy` / `determine_converter_strategy`
  / `determine_scorer_strategy` / `determine_report_strategy`（委托既有模块，安全降级）。
- REQ-135 框架：Decision 数据结构 + record_decision + 可配置 triggers。
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from strike.common.decision_safety import check_decision_safety_boundary

logger = logging.getLogger(__name__)


@dataclass
class Decision:
    """单次自主决策的不可变记录（REQ-135③ 落盘单元）。"""

    kind: str
    selected: Any
    rationale: str
    trigger: str
    metadata: dict[str, Any] = field(default_factory=dict)
    safety_check_passed: bool = True
    blocked: bool = False
    timestamp: str = ""


def record_decision(ctx: Any, decision: Decision) -> None:
    """把决策追加到 ctx.decision_log（REQ-135③）。"""
    log = getattr(ctx, "decision_log", None)
    if log is None:
        log = []
        try:
            ctx.decision_log = log
        except Exception:
            return
    entry = asdict(decision)
    if not entry.get("timestamp"):
        entry["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    log.append(entry)


# 默认触发条件：每个 decide_* 类型是否触发（REQ-135②，可经构造函数覆盖）。
DEFAULT_TRIGGERS: dict[str, Callable[..., bool]] = {
    "probe_strategy": lambda ctx, **kw: kw.get("budget") is not None or bool(kw.get("waf_detected")),
    "seed_strategy": lambda ctx, **kw: True,
    "converter_strategy": lambda ctx, **kw: bool(kw.get("techniques")),
    "scorer_strategy": lambda ctx, **kw: True,
    "report_strategy": lambda ctx, **kw: True,
}


class DecisionEngine:
    """全链路自主决策引擎（REQ-135/136/137）。"""

    def __init__(self, triggers: dict[str, Callable[..., bool]] | None = None) -> None:
        self.triggers = dict(DEFAULT_TRIGGERS)
        if triggers:
            self.triggers.update(triggers)

    # ---- 内部工具 ----
    def _triggered(self, kind: str, ctx: Any, **kw) -> bool:
        fn = self.triggers.get(kind)
        if fn is None:
            return True
        try:
            return bool(fn(ctx, **kw))
        except Exception as e:
            logger.debug("[DECISION] trigger %s eval failed: %s", kind, e)
            return True

    def _finalize(self, ctx, kind, selected, rationale, trigger, metadata, decision_output):
        safe, reason = check_decision_safety_boundary(ctx, decision_output or {})
        decision = Decision(
            kind=kind, selected=selected, rationale=rationale,
            trigger=trigger, metadata=metadata, safety_check_passed=safe,
            blocked=not safe,
        )
        record_decision(ctx, decision)
        if not safe:
            logger.warning("[DECISION] %s blocked by safety boundary: %s", kind, reason)
        return decision

    def _skip(self, ctx, kind, trigger):
        decision = Decision(kind=kind, selected=None, rationale="trigger not met", trigger=trigger)
        record_decision(ctx, decision)
        return decision

    # ---- REQ-136：Recon 自适应决策 ----
    def determine_probe_strategy(
        self, ctx, *, budget: int | None = None, target_type: str = "web_api",
        waf_detected: bool = False, severity: str = "moderate",
    ) -> Decision:
        trigger = "probe:budget_or_waf"
        if not self._triggered("probe_strategy", ctx, budget=budget, waf_detected=waf_detected):
            return self._skip(ctx, "probe_strategy", trigger)

        # 预算驱动探测深度
        if budget is None:
            level = "standard"
        elif budget >= 100:
            level = "deep"
        elif budget >= 40:
            level = "standard"
        else:
            level = "shallow"
        # 目标类型细化：模型 / Agent 至少 standard（需能力探测）
        if target_type in ("model", "agent") and level == "shallow":
            level = "standard"

        stealth_enabled = bool(waf_detected)
        stealth_config = None
        if stealth_enabled:
            try:
                from recon.stealth_config import get_stealth_manager

                mgr = get_stealth_manager()
                stealth_config = mgr.get_policy_for_guardrail(
                    {"has_guardrail": True, "severity": severity}
                )
            except Exception as e:
                logger.debug("[DECISION] stealth config build failed: %s", e)

        decision_output = {
            "strategy": "probe", "target": getattr(ctx, "target", ""),
            "level": level, "stealth": stealth_enabled,
        }
        decision = self._finalize(
            ctx, "probe_strategy",
            selected={
                "probe_level": level,
                "stealth_enabled": stealth_enabled,
                "stealth_config": "set" if stealth_config else None,
            },
            rationale=f"budget={budget} target_type={target_type} waf={waf_detected}",
            trigger=trigger,
            metadata={
                "budget": budget, "target_type": target_type,
                "waf_detected": waf_detected, "severity": severity,
            },
            decision_output=decision_output,
        )
        if decision.safety_check_passed:
            ctx.probe_level = level
            if stealth_config is not None:
                ctx.stealth_config = stealth_config
        return decision

    # ---- REQ-137①：ARM 动态种子排序 ----
    def determine_seed_strategy(self, ctx, *, techniques=None, asr_history=None) -> Decision:
        trigger = "seed:always"
        if not self._triggered("seed_strategy", ctx):
            return self._skip(ctx, "seed_strategy", trigger)
        # 有 ASR 历史 → UCB1 排序；否则类别多样性保底
        selected = "ucb1_diversity" if asr_history else "category_diversity"
        decision_output = {"strategy": "seed", "carrier": selected}
        return self._finalize(
            ctx, "seed_strategy", selected=selected,
            rationale=f"asr_history={'present' if asr_history else 'absent'}",
            trigger=trigger, metadata={"techniques": techniques},
            decision_output=decision_output,
        )

    # ---- REQ-137①：Converter 链优化 ----
    def determine_converter_strategy(self, ctx, *, techniques, capabilities=None) -> Decision:
        trigger = "converter:techniques"
        if not self._triggered("converter_strategy", ctx, techniques=techniques):
            return self._skip(ctx, "converter_strategy", trigger)
        selected: dict[str, Any] = {"technique_names": list(techniques or [])}
        # 委托既有 build_converter_map 实际产出，安全降级
        converter_map = None
        try:
            from arm.converter_presets import build_converter_map

            converter_map = build_converter_map(technique_names=list(techniques or []))
        except Exception as e:
            logger.debug("[DECISION] build_converter_map failed: %s", e)
        if converter_map is not None:
            selected["chains"] = len(converter_map)
        decision_output = {"strategy": "converter", "carrier": "converter_chain"}
        return self._finalize(
            ctx, "converter_strategy", selected=selected,
            rationale=f"{len(techniques or [])} techniques → converter chain",
            trigger=trigger, metadata={"capabilities": capabilities},
            decision_output=decision_output,
        )

    # ---- REQ-137②：Assess 评分器自适应 ----
    def determine_scorer_strategy(self, ctx, *, target_type: str = "model") -> Decision:
        trigger = "scorer:always"
        if not self._triggered("scorer_strategy", ctx):
            return self._skip(ctx, "scorer_strategy", trigger)
        selected = "dual_judge" if target_type in ("model", "agent") else "semantic"
        decision_output = {"strategy": "scorer", "carrier": selected}
        return self._finalize(
            ctx, "scorer_strategy", selected=selected,
            rationale=f"target_type={target_type} → {selected}",
            trigger=trigger, metadata={"target_type": target_type},
            decision_output=decision_output,
        )

    # ---- REQ-137③：Report 格式自适应 ----
    def determine_report_strategy(
        self, ctx, *, target_type: str = "model", format_hint=None
    ) -> Decision:
        trigger = "report:always"
        if not self._triggered("report_strategy", ctx):
            return self._skip(ctx, "report_strategy", trigger)
        if format_hint:
            selected = format_hint
        else:
            selected = "executive" if target_type in ("model", "agent") else "technical"
        decision_output = {"strategy": "report", "carrier": selected}
        return self._finalize(
            ctx, "report_strategy", selected=selected,
            rationale=f"target_type={target_type} → {selected}",
            trigger=trigger, metadata={"format_hint": format_hint},
            decision_output=decision_output,
        )
