# -*- coding: utf-8 -*-
"""tests/agent/test_cleanup.py — agent I13 cleanup 动作实装验证（R-S4: 全部 mock）。

确认 `unregister_rogue_tool` / `restore_agent_tools` 已注册（@register_cleanup_action），
且 `preflight_cleanup("agent")` 在 dry-run 与非 dry-run 下均 allowed（I13 满足）。
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from core.side_effect_cleanup import CLEANUP_ACTIONS, preflight_cleanup


def _ctx(dry_run: bool) -> SimpleNamespace:
    return SimpleNamespace(args=SimpleNamespace(dry_run=dry_run, timeout=5))


def test_agent_cleanup_actions_registered() -> None:
    import strike.agent  # noqa: F401 触发注册

    assert "unregister_rogue_tool" in CLEANUP_ACTIONS
    assert "restore_agent_tools" in CLEANUP_ACTIONS


def test_preflight_allows_agent_when_registered() -> None:
    import strike.agent  # noqa: F401

    dry = preflight_cleanup(_ctx(True), "agent", dry_run=True)
    assert dry["allowed"] is True

    real = preflight_cleanup(_ctx(False), "agent", dry_run=False)
    assert real["allowed"] is True
    assert real["missing"] == []


def test_unregister_handles_empty_artifacts() -> None:
    import strike.agent  # noqa: F401
    from strike.agent.cleanup import unregister_rogue_tool

    async def _go() -> None:
        out = await unregister_rogue_tool(_ctx(False), {"rogue_tool_names": []})
        assert out["skipped"] is True
        assert out["success"] is True

    asyncio.run(_go())


def test_restore_handles_empty_target() -> None:
    import strike.agent  # noqa: F401
    from strike.agent.cleanup import restore_agent_tools

    async def _go() -> None:
        out = await restore_agent_tools(_ctx(False), {"target_url": ""})
        assert out["skipped"] is True
        assert out["success"] is True

    asyncio.run(_go())
