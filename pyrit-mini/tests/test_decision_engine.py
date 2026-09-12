# -*- coding: utf-8 -*-
"""tests/test_decision_engine.py — REQ-135/136/137 全链路自主决策引擎。

覆盖：
    REQ-135 ① 统一 determine_*_strategy 签名；② 触发条件可配置；③ ctx.decision_log 落盘；
             R-DECIDE-1 安全边界（BLOCKING，拦截越权目标且不写入 ctx）。
    REQ-136 Recon 自适应：预算→探测深度；WAF→启用 stealth 并写入 ctx.probe_level / ctx.stealth_config。
    REQ-137 ARM/Assess/Report：动态种子排序、Converter 链优化、评分器自适应、报告格式自适应。
"""

from __future__ import annotations

from types import SimpleNamespace

from strike.common.decision_engine import DecisionEngine


def _ctx(**kw):
    base = dict(
        decision_log=[], authorized_targets=[], target="",
        stealth_config=None, probe_level=None,
    )
    base.update(kw)
    return SimpleNamespace(**base)


# ---- REQ-135 框架 ----

def test_unified_signature_and_decision_log():
    """所有 determine_*_strategy 统一签名并把决策写入 ctx.decision_log。"""
    ctx = _ctx()
    eng = DecisionEngine()
    d = eng.determine_scorer_strategy(ctx, target_type="model")
    assert d.kind == "scorer_strategy"
    assert d.selected == "dual_judge"
    assert len(ctx.decision_log) == 1
    assert ctx.decision_log[0]["kind"] == "scorer_strategy"


def test_configurable_triggers_skip():
    """决策触发条件可配置：关闭某类型触发器 → 该决策被跳过（selected=None）。"""
    ctx = _ctx()
    eng = DecisionEngine(triggers={"scorer_strategy": lambda ctx, **kw: False})
    d = eng.determine_scorer_strategy(ctx, target_type="model")
    assert d.selected is None
    assert d.rationale == "trigger not met"


def test_r_decide_1_blocks_unauthorized_target():
    """R-DECIDE-1（BLOCKING）：越权目标决策被拦截，且不写入 ctx。"""
    ctx = _ctx(authorized_targets=["good.com"], target="evil.com")
    eng = DecisionEngine()
    d = eng.determine_probe_strategy(ctx, budget=120, target_type="web_api", waf_detected=True)
    assert d.safety_check_passed is False
    assert d.blocked is True
    assert ctx.probe_level is None
    assert ctx.stealth_config is None


# ---- REQ-136 Recon 自适应决策 ----

def test_req136_probe_level_by_budget():
    """预算驱动探测深度：高预算 → deep。"""
    ctx = _ctx(target="good.com", authorized_targets=["good.com"])
    eng = DecisionEngine()
    d = eng.determine_probe_strategy(ctx, budget=150, target_type="web_api")
    assert d.selected["probe_level"] == "deep"
    assert ctx.probe_level == "deep"
    assert d.selected["stealth_enabled"] is False


def test_req136_low_budget_shallow():
    """低预算 → shallow 探测深度。"""
    ctx = _ctx(target="good.com", authorized_targets=["good.com"])
    eng = DecisionEngine()
    d = eng.determine_probe_strategy(ctx, budget=10, target_type="web_api")
    assert d.selected["probe_level"] == "shallow"


def test_req136_waf_enables_stealth():
    """检测到 WAF → 启用 stealth 并写入 ctx.stealth_config / ctx.probe_level。"""
    ctx = _ctx(target="good.com", authorized_targets=["good.com"])
    eng = DecisionEngine()
    d = eng.determine_probe_strategy(
        ctx, budget=120, target_type="web_api", waf_detected=True, severity="strict"
    )
    assert d.selected["stealth_enabled"] is True
    assert ctx.probe_level == "deep"
    assert ctx.stealth_config is not None


# ---- REQ-137 ARM / Assess / Report 决策 ----

def test_req137_seed_strategy_branches():
    """有 ASR 历史 → UCB1 排序；否则类别多样性保底。"""
    ctx = _ctx(authorized_targets=["good.com"], target="good.com")
    eng = DecisionEngine()
    assert eng.determine_seed_strategy(ctx, asr_history={"a": 0.5}).selected == "ucb1_diversity"
    ctx2 = _ctx(authorized_targets=["good.com"], target="good.com")
    assert eng.determine_seed_strategy(ctx2).selected == "category_diversity"


def test_req137_converter_strategy_records_techniques():
    """Converter 链优化：记录 technique 并委托 build_converter_map。"""
    ctx = _ctx(authorized_targets=["good.com"], target="good.com")
    eng = DecisionEngine()
    d = eng.determine_converter_strategy(ctx, techniques=["tap", "pair"])
    assert d.selected["technique_names"] == ["tap", "pair"]


def test_req137_scorer_strategy_branches():
    """评分器自适应：模型/Agent → dual_judge；其余 → semantic。"""
    ctx = _ctx(authorized_targets=["good.com"], target="good.com")
    eng = DecisionEngine()
    assert eng.determine_scorer_strategy(ctx, target_type="model").selected == "dual_judge"
    ctx2 = _ctx(authorized_targets=["good.com"], target="good.com")
    assert eng.determine_scorer_strategy(ctx2, target_type="web_api").selected == "semantic"


def test_req137_report_strategy_adaptive():
    """报告格式自适应：模型→executive；web→technical；format_hint 优先。"""
    ctx = _ctx(authorized_targets=["good.com"], target="good.com")
    eng = DecisionEngine()
    assert eng.determine_report_strategy(ctx, target_type="model").selected == "executive"
    ctx2 = _ctx(authorized_targets=["good.com"], target="good.com")
    assert eng.determine_report_strategy(ctx2, target_type="web_api").selected == "technical"
    ctx3 = _ctx(authorized_targets=["good.com"], target="good.com")
    assert eng.determine_report_strategy(ctx3, target_type="model", format_hint="json").selected == "json"


def test_req137_all_decisions_logged():
    """REQ-137 四类决策全部落盘到 decision_log。"""
    ctx = _ctx(authorized_targets=["good.com"], target="good.com")
    eng = DecisionEngine()
    eng.determine_seed_strategy(ctx, techniques=["tap"])
    eng.determine_converter_strategy(ctx, techniques=["tap"])
    eng.determine_scorer_strategy(ctx, target_type="model")
    eng.determine_report_strategy(ctx, target_type="model")
    assert len(ctx.decision_log) == 4
