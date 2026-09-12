# -*- coding: utf-8 -*-
"""tests/test_stealth.py — recon/stealth_config.py 单元测试（隐蔽调度 / SIEM 规避，R-STEALTH）。

Constitution: 隐蔽调度是可选能力（I5/REQ-112），默认 balanced（Rule 2: Stealth First）。
测试锁定四个预设等级与延迟/转换器准入逻辑，确保该能力在开启时行为可预测。
"""

from __future__ import annotations

from recon.stealth_config import (
    STEALTH_POLICIES,
    StealthLevelManager,
    get_stealth_manager,
)


def test_four_presets_exist():
    """四个预设等级齐备。"""
    assert set(STEALTH_POLICIES) == {
        "paranoid",
        "balanced",
        "aggressive",
        "silent_recon-only",
    }


def test_balanced_is_default_with_sane_delay():
    """balanced 为默认且延迟区间合理（5–15s）。"""
    policy = StealthLevelManager().get_policy("balanced")
    assert policy.delay_range == (5, 15)
    assert policy.jitter == 0.3


def test_get_policy_for_guardrail_mapping():
    """Guardrail 等级 → 隐蔽等级映射正确（无护栏/无检 → aggressive，strict → paranoid）。"""
    mgr = StealthLevelManager()
    assert mgr.get_policy_for_guardrail(None).name == "aggressive"  # 无护栏信息 → 最激进
    assert mgr.get_policy_for_guardrail({"has_guardrail": False}).name == "aggressive"
    assert mgr.get_policy_for_guardrail({"has_guardrail": True, "severity": "strict"}).name == "paranoid"
    assert mgr.get_policy_for_guardrail({"has_guardrail": True, "severity": "moderate"}).name == "balanced"


def test_get_delay_within_bounds():
    """balanced 延迟在 [delay_min, delay_max*(1+jitter)] 区间内且为正。"""
    mgr = StealthLevelManager()
    policy = mgr.get_policy("balanced")
    for _ in range(200):
        d = mgr.get_delay(policy)
        assert d >= 0.1
        assert d <= 15 * (1 + policy.jitter) + 1e-6


def test_is_converter_allowed_respects_blacklist():
    """balanced 不限制常用转换器；paranoid 黑名单 rot13 / leet_speak。"""
    mgr = StealthLevelManager()
    balanced = mgr.get_policy("balanced")
    paranoid = mgr.get_policy("paranoid")
    assert mgr.is_converter_allowed("base64", balanced) is True
    assert mgr.is_converter_allowed("rot13", balanced) is True
    assert mgr.is_converter_allowed("rot13", paranoid) is False
    assert mgr.is_converter_allowed("leet_speak", paranoid) is False


def test_set_policy_persists():
    """set_policy 改变管理器的当前策略。"""
    mgr = StealthLevelManager()
    mgr.set_policy("paranoid")
    assert mgr._current_policy is not None
    assert mgr._current_policy.name == "paranoid"


def test_global_manager_singleton():
    """get_stealth_manager 返回同一实例（守护进程级单例）。"""
    assert get_stealth_manager() is get_stealth_manager()
