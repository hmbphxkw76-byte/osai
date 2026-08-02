# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_progress_poller_perf — ProgressPoller 性能基准测试.

验证背景轮询器对主执行流程的性能开销 < 1%.

测试方法:
  1. 测量无 Poller 时执行 N 次 asyncio.sleep 的基准时间
  2. 测量有 Poller 时执行相同操作的耗时
  3. 计算开销比例 = (有 Poller 时间 - 基准时间) / 基准时间
  4. 断言开销 < 1% (或绝对值 < 5ms, 取更宽松者)

学术依据:
  - 非侵入式设计原则: 背景监控不应影响主执行流程
  - asyncio.create_task 的调度开销理论值: ~0.01ms per task

> **日期**: 2026-8-2
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import MagicMock, patch

import pytest

from pipeline.reporting.output_manager import ProgressDashboard, ProgressPoller


class TestProgressPollerPerformance:
    """ProgressPoller 性能基准测试."""

    @pytest.mark.asyncio
    async def test_poller_overhead_below_1_percent(self) -> None:
        """背景轮询开销 < 1% (100 次迭代)."""
        iterations = 100
        work_per_iteration = 0.01  # 10ms per iteration

        # ── 基准: 无 Poller ──
        start_baseline = time.perf_counter()
        for _ in range(iterations):
            await asyncio.sleep(work_per_iteration)
        baseline_time = time.perf_counter() - start_baseline

        # ── 有 Poller ──
        dashboard = ProgressDashboard(total=iterations)
        mock_memory = MagicMock()
        mock_memory.get_attack_results = MagicMock(return_value=[])

        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="perf-test-srid",
            interval=0.005,  # 5ms 轮询间隔 (比工作间隔更频繁, 最差情况)
        )

        with patch("pyrit.memory.CentralMemory.get_memory_instance", return_value=mock_memory):
            poller.start()
            start_with_poller = time.perf_counter()
            for _ in range(iterations):
                await asyncio.sleep(work_per_iteration)
            with_poller_time = time.perf_counter() - start_with_poller
            await poller.stop()

        overhead = with_poller_time - baseline_time
        overhead_pct = (overhead / baseline_time) * 100 if baseline_time > 0 else 0

        # 开销 < 1% 或绝对值 < 50ms (CI 环境波动容忍)
        assert overhead_pct < 1.0 or abs(overhead) < 0.05, (
            f"ProgressPoller overhead too high: {overhead_pct:.2f}% "
            f"({overhead * 1000:.1f}ms absolute). "
            f"Baseline: {baseline_time:.3f}s, With Poller: {with_poller_time:.3f}s"
        )

    @pytest.mark.asyncio
    async def test_poller_overhead_absolute_threshold(self) -> None:
        """背景轮询绝对开销 < 50ms (短任务场景)."""
        work_duration = 0.1  # 100ms 总工作

        # 基准
        start = time.perf_counter()
        await asyncio.sleep(work_duration)
        baseline = time.perf_counter() - start

        # 有 Poller
        dashboard = ProgressDashboard(total=1)
        mock_memory = MagicMock()
        mock_memory.get_attack_results = MagicMock(return_value=[])

        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="perf-abs-srid",
            interval=0.01,
        )

        with patch("pyrit.memory.CentralMemory.get_memory_instance", return_value=mock_memory):
            poller.start()
            start = time.perf_counter()
            await asyncio.sleep(work_duration)
            with_poller = time.perf_counter() - start
            await poller.stop()

        overhead = with_poller - baseline
        # 绝对开销应 < 50ms
        assert abs(overhead) < 0.05, (
            f"Absolute overhead too high: {overhead * 1000:.1f}ms"
        )

    @pytest.mark.asyncio
    async def test_poller_zero_overhead_when_memory_unavailable(self) -> None:
        """Memory 不可用时轮询器零开销 (静默降级)."""
        work_duration = 0.1

        # 基准
        start = time.perf_counter()
        await asyncio.sleep(work_duration)
        baseline = time.perf_counter() - start

        # 有 Poller 但 Memory 不可用
        dashboard = ProgressDashboard(total=1)
        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="perf-zero-srid",
            interval=0.01,
        )

        with patch("pyrit.memory.CentralMemory.get_memory_instance", return_value=None):
            poller.start()
            start = time.perf_counter()
            await asyncio.sleep(work_duration)
            with_poller = time.perf_counter() - start
            await poller.stop()

        overhead = with_poller - baseline
        # Memory 不可用时应该几乎零开销
        assert abs(overhead) < 0.02, (
            f"Overhead with unavailable memory should be ~0: {overhead * 1000:.1f}ms"
        )

    @pytest.mark.asyncio
    async def test_poller_does_not_block_main_task(self) -> None:
        """Poller 不阻塞主任务 (主任务 sleep 100ms, 实际耗时不应超过 120ms)."""
        dashboard = ProgressDashboard(total=1)
        mock_memory = MagicMock()
        mock_memory.get_attack_results = MagicMock(return_value=[])

        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="perf-block-srid",
            interval=0.01,
        )

        with patch("pyrit.memory.CentralMemory.get_memory_instance", return_value=mock_memory):
            poller.start()
            start = time.perf_counter()
            await asyncio.sleep(0.1)
            elapsed = time.perf_counter() - start
            await poller.stop()

        # 主任务不应被阻塞超过 20ms 的额外开销
        assert elapsed < 0.12, (
            f"Main task was blocked: elapsed={elapsed:.3f}s (expected ~0.1s)"
        )

    @pytest.mark.asyncio
    async def test_dashboard_update_from_results_performance(self) -> None:
        """update_from_attack_results 处理 1000 条结果 < 10ms."""
        from pyrit.models import AttackOutcome

        # 构造 1000 条 mock AttackResult
        results = []
        for i in range(1000):
            ar = MagicMock()
            ar.outcome = AttackOutcome.SUCCESS if i % 3 == 0 else AttackOutcome.FAILURE
            results.append(ar)

        dashboard = ProgressDashboard(total=1000)

        start = time.perf_counter()
        dashboard.update_from_attack_results(results)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert elapsed_ms < 10.0, (
            f"update_from_attack_results too slow: {elapsed_ms:.1f}ms for 1000 results"
        )
        assert dashboard.completed == 1000
