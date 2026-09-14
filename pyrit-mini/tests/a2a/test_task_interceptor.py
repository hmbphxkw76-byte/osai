# -*- coding: utf-8 -*-
"""tests/a2a/test_task_interceptor.py — task_interception 技术实装验证（R-S4: 全部 mock）。

确认 S9 Wave 2 缺口项 `task_interception`（a2a 第 6 个 required technique）已真实实现：
- 纯解析逻辑 `intercept_task` 抽取敏感字段并改写路由（无网络）
- `generate_interception_seeds` 产出含 technique="task_interception" 的种子
- `run_task_interception(ctx)` 链入口在无 `a2a_task_endpoint` 时仅产出种子（不触网）
"""

from __future__ import annotations

from types import SimpleNamespace

from strike.a2a.task_interceptor import (
    TaskInterceptor,
    create_task_interceptor,
    run_task_interception,
)


def _ctx(**kwargs: object) -> SimpleNamespace:
    return SimpleNamespace(args=SimpleNamespace(**kwargs))


def test_intercept_task_extracts_sensitive_fields() -> None:
    interceptor = TaskInterceptor()
    task = {
        "taskId": "task-123",
        "url": "https://legit-agent.internal/a2a",
        "context": {"api_key": "sk-secret", "note": "ok"},
        "artifacts": {"url": "https://legit-agent.internal/art"},
    }
    res = interceptor.intercept_task(task)
    assert res.success is True
    assert "context.api_key" in res.sensitive_fields
    assert res.redirection_applied is True
    assert res.modified_task.get("url") == "https://attacker.com/a2a"
    assert res.modified_task["artifacts"]["url"] == "https://attacker.com/a2a"


def test_intercept_task_rejects_non_dict() -> None:
    interceptor = TaskInterceptor()
    res = interceptor.intercept_task("not-a-dict")  # type: ignore[arg-type]
    assert res.success is False
    assert res.error


def test_generate_interception_seeds_tagged() -> None:
    interceptor = TaskInterceptor()
    seeds = interceptor.generate_interception_seeds("sales-agent", "https://attacker.com/a2a")
    assert seeds
    assert all(s["metadata"].get("technique") == "task_interception" for s in seeds)


def test_run_task_interception_seeds_only_no_network() -> None:
    import asyncio

    async def _go() -> None:
        out = await run_task_interception(_ctx(a2a_target_agent="sales-agent"))
        assert "seeds" in out
        assert out["intercepted"] is None
        assert out["count"] == len(out["seeds"])
        assert out["seeds"]

    asyncio.run(_go())


def test_create_factory() -> None:
    assert isinstance(create_task_interceptor(), TaskInterceptor)
