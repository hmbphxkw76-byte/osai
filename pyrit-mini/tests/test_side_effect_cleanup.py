"""tests/test_side_effect_cleanup.py — I13 副作用清理共享基建（core/side_effect_cleanup.py）测试。

覆盖：动作注册表、preflight（dry-run / 未声明 / 未实装 / 已实装）、执行（成功 / 失败不静默 / dry-run 不执行）。
用 monkeypatch 注入声明列表，避免依赖具体组件 YAML 的已注册状态（确定性、无真实副作用）。
"""

from __future__ import annotations

import asyncio

import core.side_effect_cleanup as sec
from core.side_effect_cleanup import (
    preflight_cleanup,
    register_cleanup_action,
    run_side_effect_cleanup,
)


def test_register_cleanup_action_populates_registry():
    """装饰器把动作名写入 CLEANUP_ACTIONS 且返回原函数。"""

    @register_cleanup_action("__sec_test_reg")
    async def _fn(ctx, artifacts):
        return {"success": True}

    assert "sec_test_reg" in sec.CLEANUP_ACTIONS
    assert sec.CLEANUP_ACTIONS["__sec_test_reg"] is _fn
    del sec.CLEANUP_ACTIONS["__sec_test_reg"]


def test_preflight_dry_run_always_allowed(monkeypatch):
    """dry-run 下无论声明如何都允许，且不要求动作已实装。"""
    monkeypatch.setattr(sec, "declared_cleanup_actions", lambda k: ["not_registered"])
    pre = preflight_cleanup(None, "any", dry_run=True)
    assert pre["allowed"] is True
    assert pre["status"] == "skipped_dry_run"


def test_preflight_no_declared_blocks(monkeypatch):
    """非 dry-run 且组件未声明 cleanup → 阻断（I13）。"""
    monkeypatch.setattr(sec, "declared_cleanup_actions", lambda k: [])
    pre = preflight_cleanup(None, "cmp", dry_run=False)
    assert pre["allowed"] is False
    assert pre["status"] == "blocked"
    assert "未声明" in pre["reason"]


def test_preflight_unregistered_action_blocks(monkeypatch):
    """非 dry-run 且声明动作未实装 → 阻断并列出 missing。"""
    monkeypatch.setattr(sec, "declared_cleanup_actions", lambda k: ["__sec_missing"])
    pre = preflight_cleanup(None, "cmp", dry_run=False)
    assert pre["allowed"] is False
    assert pre["status"] == "blocked"
    assert pre["missing"] == ["__sec_missing"]


def test_preflight_all_registered_ok(monkeypatch):
    """非 dry-run 且声明动作全部已实装 → 允许。"""
    monkeypatch.setattr(sec, "declared_cleanup_actions", lambda k: ["__sec_ok"])

    @register_cleanup_action("__sec_ok")
    async def _fn(ctx, artifacts):
        return {"success": True}

    try:
        pre = preflight_cleanup(None, "cmp", dry_run=False)
        assert pre["allowed"] is True
        assert pre["status"] == "ok"
    finally:
        del sec.CLEANUP_ACTIONS["__sec_ok"]


def test_run_executes_and_records_success(monkeypatch):
    """非 dry-run 执行已实装动作 → status ok、actions 含结果、failed 空。"""
    monkeypatch.setattr(sec, "declared_cleanup_actions", lambda k: ["__sec_run"])

    @register_cleanup_action("__sec_run")
    async def _fn(ctx, artifacts):
        return {"success": True, "detail": "cleaned"}

    try:
        out = asyncio.run(run_side_effect_cleanup(None, "cmp", {}, dry_run=False))
        assert out["status"] == "ok"
        assert out["failed"] == []
        assert out["actions"]["__sec_run"]["success"] is True
    finally:
        del sec.CLEANUP_ACTIONS["__sec_run"]


def test_run_dry_run_does_not_execute(monkeypatch):
    """dry-run 下不执行任何动作，直接返回 preflight 结果。"""
    called = []

    @register_cleanup_action("__sec_dry")
    async def _fn(ctx, artifacts):
        called.append(1)
        return {"success": True}

    monkeypatch.setattr(sec, "declared_cleanup_actions", lambda k: ["__sec_dry"])
    try:
        out = asyncio.run(run_side_effect_cleanup(None, "cmp", {}, dry_run=True))
        assert out["status"] == "skipped_dry_run"
        assert called == []
    finally:
        del sec.CLEANUP_ACTIONS["__sec_dry"]


def test_run_failure_not_silent(monkeypatch):
    """动作返回 success=False → status failed 且 failed 列出动作名（C9 / R-H2 不静默）。"""
    monkeypatch.setattr(sec, "declared_cleanup_actions", lambda k: ["__sec_fail"])

    @register_cleanup_action("__sec_fail")
    async def _fn(ctx, artifacts):
        return {"success": False}

    try:
        out = asyncio.run(run_side_effect_cleanup(None, "cmp", {}, dry_run=False))
        assert out["status"] == "failed"
        assert out["failed"] == ["__sec_fail"]
    finally:
        del sec.CLEANUP_ACTIONS["__sec_fail"]
