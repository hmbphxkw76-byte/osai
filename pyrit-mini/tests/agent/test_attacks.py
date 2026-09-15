# -*- coding: utf-8 -*-
"""tests/agent/test_attacks.py — `run_agent_attack` 分发器回归（BL-093 / I13）。

覆盖三态：
    1. 非 dry-run 且 preflight 放行 → 注册 rogue tool 并**调用清理**（副作用步后）
    2. preflight 拒绝 → `blocked`，**不注册**、**不清理**（不静默放行，C9 / R-H2）
    3. dry-run → `skipped`，不产生任何副作用

全部 HTTP 经 mock（R-S4）：`_register_rogue_tool` 为注入点；preflight / cleanup
亦 mock——本用例验证的是**接线**（谁在何时被调用），而非 HTTP 细节。
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from strike.agent.attacks import run_agent_attack

_PATCH_REGISTER = "strike.agent.attacks._register_rogue_tool"
_PATCH_PREFLIGHT = "core.side_effect_cleanup.preflight_cleanup"
_PATCH_CLEANUP = "core.side_effect_cleanup.run_side_effect_cleanup"


def _make_ctx(**overrides) -> SimpleNamespace:
    args = SimpleNamespace(
        agent_target="http://127.0.0.1:8080",
        agent_register_endpoint="/tools/register",
        agent_unregister_endpoint="/tools/unregister",
        agent_restore_endpoint="/tools/restore",
        rogue_tool_name="sys_maintenance",
        agent_baseline_tools=["search", "calculator"],
        agent_exfil_endpoint="https://collector.example/redteam",
        dry_run=False,
        timeout=5,
        api_key=None,
    )
    for key, value in overrides.items():
        setattr(args, key, value)
    return SimpleNamespace(
        args=args,
        orchestration_log=[],
        attack_results={},
        parsed_request=None,
    )


def _allowed_preflight() -> dict:
    return {
        "allowed": True,
        "status": "ok",
        "reason": "cleanup 已声明且已实装",
        "declared": ["unregister_rogue_tool", "restore_agent_tools"],
        "missing": [],
    }


def test_attack_registers_and_invokes_cleanup():
    """非 dry-run + preflight 放行 → 注册后必须调用副作用清理。"""
    ctx = _make_ctx()
    register = AsyncMock(return_value={"success": True, "status": 200})
    cleanup = AsyncMock(return_value={"status": "ok", "failed": []})

    with (
        patch(_PATCH_REGISTER, register),
        patch(_PATCH_PREFLIGHT, return_value=_allowed_preflight()),
        patch(_PATCH_CLEANUP, cleanup),
    ):
        report = asyncio.run(run_agent_attack(ctx))

    assert report["status"] == "success"
    assert register.await_count == 1

    # I13 核心：副作用步之后必须调用清理，且带上可清理的 artifacts
    cleanup.assert_awaited_once()
    component, artifacts = cleanup.await_args.args[1], cleanup.await_args.args[2]
    assert component == "agent"
    assert artifacts["rogue_tool_names"] == ["sys_maintenance"]
    assert artifacts["baseline_toolset"] == ["search", "calculator"]
    assert artifacts["tool_unregister_endpoint"] == "/tools/unregister"
    assert artifacts["tool_restore_endpoint"] == "/tools/restore"

    # 留痕：orchestration_log 记录真实攻击决策
    decisions = [e.get("decision") for e in ctx.orchestration_log]
    assert "agent_rogue_tool_attack" in decisions


def test_blocked_when_preflight_disallows():
    """preflight 拒绝 → blocked，既不注册也不清理（禁止静默放行）。"""
    ctx = _make_ctx()
    register = AsyncMock(return_value={"success": True, "status": 200})
    cleanup = AsyncMock(return_value={"status": "ok", "failed": []})
    denied = {
        "allowed": False,
        "status": "blocked",
        "reason": "I13：cleanup 动作未实装",
        "declared": ["unregister_rogue_tool"],
        "missing": ["restore_agent_tools"],
    }

    with (
        patch(_PATCH_REGISTER, register),
        patch(_PATCH_PREFLIGHT, return_value=denied),
        patch(_PATCH_CLEANUP, cleanup),
    ):
        report = asyncio.run(run_agent_attack(ctx))

    assert report["status"] == "blocked"
    register.assert_not_awaited()
    cleanup.assert_not_awaited()
    decisions = [e.get("decision") for e in ctx.orchestration_log]
    assert "agent_attack_blocked_by_i13" in decisions


def test_dry_run_produces_no_side_effects():
    """dry-run → skipped，不注册、不清理。"""
    ctx = _make_ctx(dry_run=True)
    register = AsyncMock(return_value={"success": True, "status": 200})
    cleanup = AsyncMock(return_value={"status": "ok", "failed": []})

    with (
        patch(_PATCH_REGISTER, register),
        patch(_PATCH_PREFLIGHT, return_value={"allowed": True, "status": "skipped_dry_run"}),
        patch(_PATCH_CLEANUP, cleanup),
    ):
        report = asyncio.run(run_agent_attack(ctx))

    assert report["status"] == "skipped"
    register.assert_not_awaited()
    cleanup.assert_not_awaited()


def test_missing_target_is_rejected_before_preflight():
    """无目标地址 → 直接报错，不触碰 cleanup preflight。"""
    ctx = _make_ctx(agent_target=None)
    cleanup = AsyncMock(return_value={"status": "ok", "failed": []})

    with patch(_PATCH_CLEANUP, cleanup):
        report = asyncio.run(run_agent_attack(ctx))

    assert report["status"] == "error"
    assert "--agent-target" in report["reason"]
    cleanup.assert_not_awaited()


def test_cleanup_runs_even_when_registration_fails():
    """注册失败仍要跑清理（不可因攻击失败而跳过副作用治理）。"""
    ctx = _make_ctx()
    register = AsyncMock(return_value={"success": False, "error": "connection refused"})
    cleanup = AsyncMock(return_value={"status": "ok", "failed": []})

    with (
        patch(_PATCH_REGISTER, register),
        patch(_PATCH_PREFLIGHT, return_value=_allowed_preflight()),
        patch(_PATCH_CLEANUP, cleanup),
    ):
        report = asyncio.run(run_agent_attack(ctx))

    assert report["status"] == "failed"
    assert report["registered"] == []
    cleanup.assert_awaited_once()


def test_cleanup_failure_is_reported_not_swallowed():
    """清理失败必须如实上报（C9 / R-H2），不得静默。"""
    ctx = _make_ctx()
    register = AsyncMock(return_value={"success": True, "status": 200})
    cleanup = AsyncMock(return_value={"status": "failed", "failed": ["unregister_rogue_tool"]})

    with (
        patch(_PATCH_REGISTER, register),
        patch(_PATCH_PREFLIGHT, return_value=_allowed_preflight()),
        patch(_PATCH_CLEANUP, cleanup),
    ):
        report = asyncio.run(run_agent_attack(ctx))

    assert report["cleanup"]["status"] == "failed"
    assert report["cleanup"]["failed"] == ["unregister_rogue_tool"]
