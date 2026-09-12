# -*- coding: utf-8 -*-
"""tests/test_escalation_wiring.py — plan Wave 2.5（C2 合规）回归测试。

覆盖三件此前全部失效的事：
1. `_run_escalate_phase` 有真实调用点，且 ASR < 阈值时**真的**触发升级链；
2. ASR 量纲统一（外部百分比 / 升级链内部小数），升级收益可回写；
3. 升级产出并入 `ctx.attack_results`，不再统计性空转。

Constitution: C2（ASR 至上，ASR < 90% 必须可触发升级链）、C3（单一事实源）、
C7（配置数据流不可断：defaults.yaml → args → getattr）、C9（诚实汇报）。
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.phases.strike import (
    _adopt_escalation_results,
    _asr_as_percent,
    _run_escalate_phase,
)


def _make_ctx(overall_asr: float | None = 10.0) -> SimpleNamespace:
    """构造最小可用的 PipelineContext 替身。"""
    args = SimpleNamespace(
        escalation=True,
        # C7：由 config/defaults.yaml:escalation_asr_threshold（90）注入
        escalate_threshold=90.0,
        native_output_enabled=False,
    )
    ctx = SimpleNamespace(
        args=args,
        attack_results={"primary": []},
        orchestration_log=[],
        escalation_results=[],
    )
    if overall_asr is not None:
        ctx.overall_asr = overall_asr
    return ctx


# ── 量纲归一 ────────────────────────────────────────────────────────────────


def test_asr_as_percent_prefers_explicit_value():
    ctx = _make_ctx(overall_asr=0.9)  # 小数制的历史写入
    assert _asr_as_percent(42.0, ctx) == 42.0


def test_asr_as_percent_converts_fraction_to_percent():
    ctx = _make_ctx(overall_asr=0.9)
    assert _asr_as_percent(None, ctx) == pytest.approx(90.0)


def test_asr_as_percent_keeps_percent_scale():
    ctx = _make_ctx(overall_asr=55.0)
    assert _asr_as_percent(None, ctx) == pytest.approx(55.0)


def test_asr_as_percent_derives_from_attack_results_when_unset():
    ctx = _make_ctx(overall_asr=None)
    ok = MagicMock(outcome="success")
    bad = MagicMock(outcome="failure")
    ctx.attack_results = {"primary": [ok, bad, bad, bad]}
    assert _asr_as_percent(None, ctx) == pytest.approx(25.0)


def test_asr_as_percent_zero_when_no_results():
    ctx = _make_ctx(overall_asr=None)
    ctx.attack_results = {}
    assert _asr_as_percent(None, ctx) == 0.0


# ── 升级触发判据 ────────────────────────────────────────────────────────────


def test_escalate_skipped_when_asr_at_or_above_threshold():
    ctx = _make_ctx()
    with patch("strike.common.escalation_runtime.run_escalation_chain", new=AsyncMock()) as chain:
        report = asyncio.run(_run_escalate_phase(ctx, current_asr_pct=95.0))
    assert report["status"] == "skipped"
    chain.assert_not_called()


def test_escalate_disabled_by_flag_returns_reason_not_silence():
    ctx = _make_ctx()
    ctx.args.escalation = False
    report = asyncio.run(_run_escalate_phase(ctx, current_asr_pct=10.0))
    assert report["status"] == "disabled"
    assert report["reason"]


def test_escalate_triggers_when_asr_below_threshold():
    """C2：ASR < 阈值必须真的调用升级链。"""
    ctx = _make_ctx()
    chain = AsyncMock(
        return_value={
            "status": "complete",
            "strategy": "crescendo",
            "primary_asr": 0.10,
            "escalated_asr": 0.60,
        }
    )
    with patch("strike.common.escalation_runtime.run_escalation_chain", new=chain):
        report = asyncio.run(_run_escalate_phase(ctx, current_asr_pct=10.0))

    chain.assert_awaited_once()
    assert report["status"] == "complete"


def test_escalate_threshold_consumed_from_config_c7():
    """阈值必须来自 args（defaults.yaml 注入），不得回退硬编码。"""
    ctx = _make_ctx()
    ctx.args.escalate_threshold = 5.0  # 极低阈值 → 10% 应判定为「已达标」
    with patch("strike.common.escalation_runtime.run_escalation_chain", new=AsyncMock()) as chain:
        report = asyncio.run(_run_escalate_phase(ctx, current_asr_pct=10.0))
    assert report["status"] == "skipped"
    chain.assert_not_called()


def test_escalate_passes_fraction_to_runtime_not_percent():
    """升级链内部按小数消费 ctx.overall_asr：10% 必须传成 0.10。"""
    ctx = _make_ctx()
    seen: list[float] = []

    async def _capture(c: object) -> dict:
        seen.append(c.overall_asr)  # type: ignore[attr-defined]
        return {"status": "complete", "strategy": "crescendo", "primary_asr": 0.1, "escalated_asr": 0.6}

    with patch("strike.common.escalation_runtime.run_escalation_chain", new=AsyncMock(side_effect=_capture)):
        asyncio.run(_run_escalate_phase(ctx, current_asr_pct=10.0))

    assert seen and seen[0] == pytest.approx(0.10)


# ── 升级产出回流 ────────────────────────────────────────────────────────────


def test_adopt_escalation_results_merges_into_attack_results():
    ctx = _make_ctx()
    ctx.escalation_results = [MagicMock(), MagicMock(), None]
    adopted = _adopt_escalation_results(ctx, "crescendo")

    assert adopted == 2
    assert len(ctx.attack_results["escalation_crescendo"]) == 2
    assert all(r is not None for r in ctx.attack_results["escalation_crescendo"])


def test_adopt_escalation_results_is_idempotent():
    ctx = _make_ctx()
    ctx.escalation_results = [MagicMock()]
    assert _adopt_escalation_results(ctx, "tap") == 1
    assert _adopt_escalation_results(ctx, "tap") == 0  # 已清空，不重复并入


def test_adopt_escalation_results_noop_when_empty():
    ctx = _make_ctx()
    assert _adopt_escalation_results(ctx, "crescendo") == 0
    assert "escalation_crescendo" not in ctx.attack_results


def test_escalate_adopts_results_and_reports_count():
    ctx = _make_ctx()
    ctx.escalation_results = [MagicMock(outcome="success")]

    async def _fake(c: object) -> dict:
        return {"status": "complete", "strategy": "crescendo", "primary_asr": 0.1, "escalated_asr": 1.0}

    with patch("strike.common.escalation_runtime.run_escalation_chain", new=AsyncMock(side_effect=_fake)):
        report = asyncio.run(_run_escalate_phase(ctx, current_asr_pct=10.0))

    assert report.get("adopted_results") == 1
    assert len(ctx.attack_results["escalation_crescendo"]) == 1


def test_escalate_writes_back_asr_when_nothing_adopted():
    """无有效 AttackResult 时仍需回写 ASR，否则升级收益被静默丢弃（C9）。"""
    ctx = _make_ctx()
    ctx.args.escalate_threshold = 90.0

    async def _fake(c: object) -> dict:
        return {"status": "complete", "strategy": "crescendo", "primary_asr": 0.1, "escalated_asr": 0.75}

    with patch("strike.common.escalation_runtime.run_escalation_chain", new=AsyncMock(side_effect=_fake)):
        asyncio.run(_run_escalate_phase(ctx, current_asr_pct=10.0))

    assert ctx.overall_asr == pytest.approx(75.0)


def test_escalate_error_is_reported_not_swallowed():
    ctx = _make_ctx()

    async def _boom(c: object) -> dict:
        raise RuntimeError("chain exploded")

    with patch("strike.common.escalation_runtime.run_escalation_chain", new=AsyncMock(side_effect=_boom)):
        report = asyncio.run(_run_escalate_phase(ctx, current_asr_pct=10.0))

    assert report["status"] == "error"
    assert "chain exploded" in report["error"]


# ── C7：defaults.yaml → args ────────────────────────────────────────────────


def test_defaults_yaml_injects_escalate_threshold():
    """`escalation_asr_threshold` 必须能流到 `args.escalate_threshold`（C7 不可断链）。"""
    from argparse import Namespace

    from core._config_parsers import _apply_defaults, _load_defaults

    defaults = _load_defaults()
    assert "escalation_asr_threshold" in defaults, "defaults.yaml 缺少 escalation_asr_threshold"

    args = Namespace(escalate_threshold=None)
    _apply_defaults(args, defaults)
    assert args.escalate_threshold == defaults["escalation_asr_threshold"]
