# -*- coding: utf-8 -*-
"""tests/memory/test_techniques.py — S9 Wave 1: memory 命名技术入口接线验证。

R-S4: 全部 mock，不触真实目标。
验证 4 个目标架构登记技术（memory_poisoning / episodic_memory_injection /
cross_session_leakage / memory_extraction）存在且为真实可调用入口。
"""

from __future__ import annotations

import asyncio
import inspect

from strike.memory import (
    run_cross_session_leakage_attack,
    run_episodic_memory_injection_attack,
    run_memory_extraction_attack,
    run_memory_poisoning_attack,
)


def test_technique_entrypoints_are_coroutines() -> None:
    for fn in (
        run_memory_poisoning_attack,
        run_episodic_memory_injection_attack,
        run_cross_session_leakage_attack,
        run_memory_extraction_attack,
    ):
        assert inspect.iscoroutinefunction(fn), f"{fn.__name__} 必须是协程"


class _FakeTarget:
    """mock HTTPTarget：返回含 'note' 的响应，使读取/抽取判定为真。"""

    async def send_request_async(self, **_kwargs):
        return "note: retrieved secret leaked"


def test_memory_poisoning_attack_runs() -> None:
    async def _go():
        res = await run_memory_poisoning_attack(_FakeTarget(), payload="IGNORE PRIOR", session_id="s1")
        assert res.technique == "memory_poisoning"
        assert isinstance(res.success, bool)

    asyncio.run(_go())


def test_episodic_memory_injection_attack_runs() -> None:
    async def _go():
        res = await run_episodic_memory_injection_attack(_FakeTarget(), payload="X", session_id="s1")
        assert res.technique == "episodic_memory_injection"

    asyncio.run(_go())


def test_cross_session_leakage_attack_runs() -> None:
    async def _go():
        res = await run_cross_session_leakage_attack(_FakeTarget(), stolen_sessions=["s1", "s2"])
        assert res.technique == "cross_session_leakage"

    asyncio.run(_go())


def test_memory_extraction_attack_runs() -> None:
    async def _go():
        res = await run_memory_extraction_attack(_FakeTarget(), stolen_sessions=["s1"], data_type="notes")
        assert res.technique == "memory_extraction"

    asyncio.run(_go())
