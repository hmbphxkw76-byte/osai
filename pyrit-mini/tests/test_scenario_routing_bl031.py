# -*- coding: utf-8 -*-
"""tests/test_scenario_routing_bl031.py — BL-031 技术路由闭合（technique → Executor）。

BL-031：此前 `ctx.techniques` 只喂 Converter、不选 Executor（`--techniques tap` 不强制
TAPAttack 执行）。本测试验证 technique 标签现在能驱动 AttackDispatcher 选择 Executor
策略，且不引入第二套链机制（复用 REQ-151 的 AttackDispatcher 通道，C3）。
"""

from __future__ import annotations

from types import SimpleNamespace

from strike.common.dispatcher import (
    AttackDispatcher,
    resolve_technique_strategy,
)


def test_resolve_technique_strategy_maps_tap_to_executor():
    """tap 技术标签映射到 tap 策略（TAPAttack 执行类）。"""
    assert resolve_technique_strategy(["tap"], target="mcp") == "tap"
    assert resolve_technique_strategy(["pair"], target="mcp") == "pair"


def test_resolve_technique_strategy_fallback_when_empty():
    """无 techniques 时回退默认策略。"""
    assert resolve_technique_strategy([], target="mcp") == "prompt_sending"


def test_resolve_technique_strategy_skips_incompatible():
    """与目标不兼容的技术标签不采纳，回退默认（web 不含 tap）。"""
    assert resolve_technique_strategy(["tap"], target="web") == "prompt_sending"


def test_resolve_technique_strategy_falls_through_unknown_tech():
    """非策略型技术标签（如 jailbreak_baseline）不命中，回退。"""
    assert resolve_technique_strategy(["jailbreak_baseline", "foo"], target="mcp") == "prompt_sending"


def test_bias_strategy_from_techniques_overrides_default():
    """未显式 --strike 且 techniques 含 tap → 派生 tap 策略（BL-031 核心）。"""
    ctx = SimpleNamespace(techniques=["tap"])
    d = AttackDispatcher(target="mcp", strike="prompt_sending")
    assert d.bias_strategy_from_techniques(ctx) == "tap"


def test_bias_strategy_respects_explicit_strike():
    """显式 --strike 优先于 techniques 派生。"""
    ctx = SimpleNamespace(techniques=["tap"])
    d = AttackDispatcher(target="mcp", strike="crescendo")
    assert d.bias_strategy_from_techniques(ctx) == "crescendo"


def test_bias_strategy_no_techniques_keeps_default():
    """techniques 为空时保持默认策略。"""
    ctx = SimpleNamespace(techniques=[])
    d = AttackDispatcher(target="mcp", strike="prompt_sending")
    assert d.bias_strategy_from_techniques(ctx) == "prompt_sending"
