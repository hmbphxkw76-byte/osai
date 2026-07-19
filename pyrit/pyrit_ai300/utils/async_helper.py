# -*- coding: utf-8 -*-
"""
AI-300 Framework - Async Helper v1.0
异步执行辅助器：安全地在同步代码中运行异步函数

问题背景：
- attack_orchestrator.py 中多处使用 asyncio.run() 调用异步函数
- 如果调用者已经在一个事件循环中（如 Jupyter/async 框架），asyncio.run() 会抛 RuntimeError
- target_builder.py 的 _launch_playwright_browser 也有同样问题

解决方案：
- run_async(): 检测当前是否在事件循环中
  - 如果不在事件循环中：直接 asyncio.run()
  - 如果在事件循环中：在新线程中创建独立事件循环执行

使用方式：
    from ..utils.async_helper import run_async
    result = run_async(some_async_func(arg1, arg2))
    # 替代: result = asyncio.run(some_async_func(arg1, arg2))

PyRIT 0.14.0 兼容
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import threading
from typing import Any, Coroutine, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


def _is_in_event_loop() -> bool:
    """检测当前线程是否已有运行中的事件循环"""
    try:
        loop = asyncio.get_running_loop()
        return loop is not None
    except RuntimeError:
        return False


def run_async(coro: Coroutine[Any, Any, T]) -> T:
    """
    安全地运行异步协程

    自动检测当前是否在事件循环中：
    - 不在事件循环中：直接 asyncio.run()（最快，无线程开销）
    - 在事件循环中：在新线程中创建独立事件循环执行（避免嵌套 RuntimeError）

    Args:
        coro: 协程对象（如 some_async_func(args) 的返回值）

    Returns:
        协程的返回值

    Raises:
        协程内部抛出的任何异常

    使用示例：
        # 替代 asyncio.run(my_async_func(arg))
        result = run_async(my_async_func(arg))

        # 替代 asyncio.run(_run_all())
        all_results = run_async(_run_all())
    """
    if not _is_in_event_loop():
        # 不在事件循环中，直接运行（最快路径）
        return asyncio.run(coro)

    # 已在事件循环中，需要在新线程中运行
    logger.debug("Already in event loop, running coroutine in separate thread")

    result_holder: dict = {}
    exception_holder: dict = {}

    def _run_in_thread():
        """在新线程中创建独立事件循环并运行协程"""
        try:
            new_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(new_loop)
            try:
                result_holder["value"] = new_loop.run_until_complete(coro)
            finally:
                new_loop.close()
                asyncio.set_event_loop(None)
        except Exception as e:
            exception_holder["error"] = e

    thread = threading.Thread(target=_run_in_thread, daemon=True)
    thread.start()
    thread.join()

    if "error" in exception_holder:
        raise exception_holder["error"]

    return result_holder.get("value")


def run_async_batch(coros: list[Coroutine[Any, Any, T]]) -> list[T]:
    """
    批量运行异步协程（使用 asyncio.gather）

    Args:
        coros: 协程列表

    Returns:
        结果列表（与输入顺序一致）

    使用示例：
        tasks = [_execute_one(p) for p in payloads]
        results = run_async_batch(tasks)
        # 替代: results = asyncio.run(_run_all())  其中 _run_all 内部用 asyncio.gather
    """
    async def _gather_all():
        return await asyncio.gather(*coros)

    return run_async(_gather_all())


class AsyncRunner:
    """
    异步运行器（上下文管理器模式）

    提供更优雅的异步代码包装，适合在编排器中使用。

    使用方式：
        with AsyncRunner() as runner:
            result1 = runner.run(fetch_data())
            result2 = runner.run(process_data(result1))
    """

    def __init__(self):
        self._results: list[Any] = []

    def __enter__(self) -> "AsyncRunner":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def run(self, coro: Coroutine[Any, Any, T]) -> T:
        """运行单个协程"""
        result = run_async(coro)
        self._results.append(result)
        return result

    def run_batch(self, coros: list[Coroutine[Any, Any, T]]) -> list[T]:
        """批量运行协程"""
        results = run_async_batch(coros)
        self._results.extend(results)
        return results

    @property
    def results(self) -> list[Any]:
        """获取所有运行结果"""
        return self._results
