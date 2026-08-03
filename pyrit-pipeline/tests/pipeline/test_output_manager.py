# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_output_manager — ProgressDashboard + ProgressPoller 单元测试。

覆盖:
  - ProgressDashboard 基本功能 (init, update, render, print_progress)
  - ProgressDashboard.update_from_attack_results (R-1: 实时轮询数据更新)
  - ProgressPoller 生命周期 (start, stop, 非侵入式验证)
  - ProgressPoller 静默降级 (Memory 不可用时不崩溃)

> **日期**: 2026-8-2
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest
from pyrit.models import AttackOutcome

from pipeline.reporting.output_manager import ProgressDashboard, ProgressPoller

# ============================================================
# ProgressDashboard 单元测试
# ============================================================


class TestProgressDashboard:
    """ProgressDashboard 单元测试。"""

    def test_init_default_values(self) -> None:
        """初始化默认值正确。"""
        dashboard = ProgressDashboard(total=100)
        assert dashboard.total == 100
        assert dashboard.completed == 0
        assert dashboard.succeeded == 0
        assert dashboard.failed == 0
        assert dashboard.errored == 0

    def test_update_accumulates_counts(self) -> None:
        """Update 方法累加计数。"""
        dashboard = ProgressDashboard(total=100)
        dashboard.update(succeeded=5, failed=3, errored=1)
        assert dashboard.succeeded == 5
        assert dashboard.failed == 3
        assert dashboard.errored == 1

        # 再次 update 应累加
        dashboard.update(succeeded=2, failed=1)
        assert dashboard.succeeded == 7
        assert dashboard.failed == 4
        assert dashboard.errored == 1

    def test_increment_completed(self) -> None:
        """increment_completed 递增完成数。"""
        dashboard = ProgressDashboard(total=100)
        dashboard.increment_completed()
        dashboard.increment_completed()
        assert dashboard.completed == 2

    def test_render_returns_non_empty_string(self) -> None:
        """Render 返回非空字符串。"""
        dashboard = ProgressDashboard(total=100)
        rendered = dashboard.render()
        assert isinstance(rendered, str)
        assert len(rendered) > 0
        assert "PyRIT AI Red Team" in rendered

    def test_render_with_zero_total(self) -> None:
        """total=0 时不崩溃。"""
        dashboard = ProgressDashboard(total=0)
        rendered = dashboard.render()
        assert isinstance(rendered, str)

    def test_render_with_completed(self) -> None:
        """有完成数时渲染进度条。"""
        dashboard = ProgressDashboard(total=100)
        dashboard.update(succeeded=50, failed=30)
        dashboard.completed = 80
        rendered = dashboard.render()
        assert "80/100" in rendered
        assert "80.0%" in rendered

    def test_print_progress_does_not_crash(self, capsys: pytest.CaptureFixture[str]) -> None:
        """print_progress 不崩溃且输出到 stdout。"""
        dashboard = ProgressDashboard(total=10)
        dashboard.print_progress()
        captured = capsys.readouterr()
        assert len(captured.out) > 0

    # ── R-1: update_from_attack_results ──

    def test_update_from_attack_results_success(self) -> None:
        """从成功 AttackResult 列表更新计数。"""
        dashboard = ProgressDashboard(total=100)
        results = [
            MagicMock(outcome=AttackOutcome.SUCCESS),
            MagicMock(outcome=AttackOutcome.SUCCESS),
            MagicMock(outcome=AttackOutcome.SUCCESS),
        ]
        dashboard.update_from_attack_results(results)
        assert dashboard.succeeded == 3
        assert dashboard.failed == 0
        assert dashboard.errored == 0
        assert dashboard.completed == 3

    def test_update_from_attack_results_mixed(self) -> None:
        """从混合 AttackResult 列表更新计数。"""
        dashboard = ProgressDashboard(total=100)
        results = [
            MagicMock(outcome=AttackOutcome.SUCCESS),
            MagicMock(outcome=AttackOutcome.FAILURE),
            MagicMock(outcome=AttackOutcome.ERROR),
        ]
        dashboard.update_from_attack_results(results)
        assert dashboard.succeeded == 1
        assert dashboard.failed == 1
        assert dashboard.errored == 1
        assert dashboard.completed == 3

    def test_update_from_attack_results_resets_counts(self) -> None:
        """update_from_attack_results 重置计数后重新统计。"""
        dashboard = ProgressDashboard(total=100)
        dashboard.update(succeeded=10, failed=5)  # 先设置一些值

        results = [MagicMock(outcome=AttackOutcome.SUCCESS)]
        dashboard.update_from_attack_results(results)
        assert dashboard.succeeded == 1  # 重置后重新统计
        assert dashboard.failed == 0
        assert dashboard.completed == 1

    def test_update_from_attack_results_empty_list(self) -> None:
        """空列表重置所有计数为 0。"""
        dashboard = ProgressDashboard(total=100)
        dashboard.update(succeeded=5, failed=3)
        dashboard.update_from_attack_results([])
        assert dashboard.succeeded == 0
        assert dashboard.failed == 0
        assert dashboard.errored == 0
        assert dashboard.completed == 0

    def test_update_from_attack_results_none_outcome_skipped(self) -> None:
        """Outcome 为 None 的结果被跳过。"""
        dashboard = ProgressDashboard(total=100)
        results = [
            MagicMock(outcome=AttackOutcome.SUCCESS),
            MagicMock(outcome=None),
        ]
        dashboard.update_from_attack_results(results)
        assert dashboard.succeeded == 1
        assert dashboard.completed == 1

    def test_update_from_attack_results_string_outcome(self) -> None:
        """Outcome 为字符串 (非 enum) 也能正确处理。"""
        dashboard = ProgressDashboard(total=100)

        result = MagicMock()
        result.outcome = "success"  # 字符串而非 enum
        # 配置 MagicMock 使 hasattr(outcome, 'value') 返回 False
        del result.outcome  # 移除 MagicMock 自动属性
        result.outcome = "SUCCESS"

        dashboard.update_from_attack_results([result])
        assert dashboard.succeeded == 1


# ============================================================
# ProgressPoller 单元测试
# ============================================================


class TestProgressPoller:
    """ProgressPoller 单元测试 (R-1)。"""

    def test_init_default_values(self) -> None:
        """初始化默认值正确。"""
        dashboard = ProgressDashboard(total=100)
        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-srid-001",
        )
        assert poller._dashboard is dashboard
        assert poller._scenario_result_id == "test-srid-001"
        assert poller._interval == 5.0
        assert poller._task is None
        assert poller._stopped is False

    def test_init_custom_interval(self) -> None:
        """自定义轮询间隔。"""
        dashboard = ProgressDashboard(total=100)
        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-srid-002",
            interval=0.1,
        )
        assert poller._interval == 0.1

    @pytest.mark.asyncio
    async def test_start_creates_task(self) -> None:
        """Start 创建 asyncio Task。"""
        dashboard = ProgressDashboard(total=100)
        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-srid-003",
            interval=999.0,  # 大间隔避免实际轮询
        )
        poller.start()
        assert poller._task is not None
        assert not poller._task.done()
        await poller.stop()

    @pytest.mark.asyncio
    async def test_start_idempotent(self) -> None:
        """多次 start 不创建多个 task。"""
        dashboard = ProgressDashboard(total=100)
        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-srid-004",
            interval=999.0,
        )
        poller.start()
        task1 = poller._task
        poller.start()
        task2 = poller._task
        assert task1 is task2
        await poller.stop()

    @pytest.mark.asyncio
    async def test_stop_cancels_task(self) -> None:
        """Stop 取消轮询任务。"""
        dashboard = ProgressDashboard(total=100)
        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-srid-005",
            interval=0.01,
        )
        poller.start()
        await poller.stop()
        assert poller._task is None
        assert poller._stopped is True

    @pytest.mark.asyncio
    async def test_stop_without_start_no_crash(self) -> None:
        """未 start 直接 stop 不崩溃。"""
        dashboard = ProgressDashboard(total=100)
        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-srid-006",
        )
        await poller.stop()
        assert poller._stopped is True
        assert poller._task is None

    @pytest.mark.asyncio
    async def test_poll_loop_silent_degradation_no_memory(self) -> None:
        """CentralMemory 不可用时静默降级 (不崩溃)。"""
        dashboard = ProgressDashboard(total=100)
        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-srid-007",
            interval=0.05,
        )
        # patch CentralMemory.get_memory_instance 返回 None
        with patch("pyrit.memory.CentralMemory.get_memory_instance", return_value=None):
            poller.start()
            await asyncio.sleep(0.15)
            await poller.stop()

        # 不崩溃即通过, dashboard 保持初始状态
        assert dashboard.completed == 0

    @pytest.mark.asyncio
    async def test_poll_loop_updates_dashboard(self) -> None:
        """轮询成功时更新 Dashboard 计数。"""
        dashboard = ProgressDashboard(total=100)

        # 模拟 Memory 返回 2 个成功 + 1 个失败
        mock_memory = MagicMock()
        mock_memory.get_attack_results = MagicMock(
            return_value=[
                MagicMock(outcome=AttackOutcome.SUCCESS),
                MagicMock(outcome=AttackOutcome.SUCCESS),
                MagicMock(outcome=AttackOutcome.FAILURE),
            ]
        )

        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-srid-008",
            interval=0.05,
        )

        with patch("pyrit.memory.CentralMemory.get_memory_instance", return_value=mock_memory):
            poller.start()
            await asyncio.sleep(0.15)
            await poller.stop()

        assert dashboard.succeeded == 2
        assert dashboard.failed == 1
        assert dashboard.completed == 3

    @pytest.mark.asyncio
    async def test_poll_loop_silent_degradation_on_exception(self) -> None:
        """get_attack_results 抛异常时静默降级。"""
        dashboard = ProgressDashboard(total=100)

        mock_memory = MagicMock()
        mock_memory.get_attack_results = MagicMock(side_effect=RuntimeError("DB error"))

        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-srid-009",
            interval=0.05,
        )

        with patch("pyrit.memory.CentralMemory.get_memory_instance", return_value=mock_memory):
            poller.start()
            await asyncio.sleep(0.15)
            await poller.stop()

        # 异常被捕获, dashboard 保持初始状态
        assert dashboard.completed == 0

    @pytest.mark.asyncio
    async def test_poll_loop_stops_on_cancel(self) -> None:
        """任务被取消时优雅退出。"""
        dashboard = ProgressDashboard(total=100)
        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-srid-010",
            interval=999.0,  # 大间隔, 依赖 cancel 退出
        )
        poller.start()
        await asyncio.sleep(0.01)
        await poller.stop()
        # 不崩溃即通过

    @pytest.mark.asyncio
    async def test_poll_loop_empty_results_no_update(self) -> None:
        """Memory 返回空列表时不更新 Dashboard。"""
        dashboard = ProgressDashboard(total=100)
        dashboard.update(succeeded=5)  # 预设值

        mock_memory = MagicMock()
        mock_memory.get_attack_results = MagicMock(return_value=[])

        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-srid-011",
            interval=0.05,
        )

        with patch("pyrit.memory.CentralMemory.get_memory_instance", return_value=mock_memory):
            poller.start()
            await asyncio.sleep(0.15)
            await poller.stop()

        # 空列表不触发 update_from_attack_results, 保持预设值
        assert dashboard.succeeded == 5

    @pytest.mark.asyncio
    async def test_non_intrusive_no_scenario_modification(self) -> None:
        """非侵入式验证: 不修改 scenario 内部状态。"""
        dashboard = ProgressDashboard(total=100)
        scenario = MagicMock()
        scenario._scenario_result_id = "test-srid-012"
        scenario._atomic_attacks = [MagicMock(), MagicMock()]
        original_attacks = list(scenario._atomic_attacks)

        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-srid-012",
            interval=0.05,
        )

        with patch("pyrit.memory.CentralMemory.get_memory_instance", return_value=None):
            poller.start()
            await asyncio.sleep(0.1)
            await poller.stop()

        # scenario 内部状态未被修改
        assert scenario._atomic_attacks == original_attacks
        assert scenario._scenario_result_id == "test-srid-012"

    # ── 防刷屏三合一策略测试 ──

    def test_backoff_doubles_interval(self) -> None:
        """_backoff() 翻倍轮询间隔, 上限 _MAX_INTERVAL."""
        dashboard = ProgressDashboard(total=100)
        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-backoff-001",
            interval=5.0,
        )
        assert poller._interval == 5.0

        poller._backoff()
        assert poller._interval == 10.0

        poller._backoff()
        assert poller._interval == 20.0

        poller._backoff()
        assert poller._interval == 30.0  # _MAX_INTERVAL cap

        poller._backoff()
        assert poller._interval == 30.0  # 不会超过上限

    def test_reset_interval_restores_base(self) -> None:
        """_reset_interval() 将间隔重置为基准值."""
        dashboard = ProgressDashboard(total=100)
        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-reset-001",
            interval=5.0,
        )
        poller._backoff()
        poller._backoff()
        assert poller._interval == 20.0

        poller._reset_interval()
        assert poller._interval == 5.0  # 回到 base

    def test_maybe_heartbeat_prints_after_interval(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """心跳行在 _HEARTBEAT_INTERVAL 后打印单行."""
        dashboard = ProgressDashboard(total=82)
        dashboard.update(succeeded=0, failed=2)
        dashboard.completed = 2

        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-heartbeat-001",
            interval=5.0,
        )
        # 设置心跳间隔为 0 (立即触发)
        ProgressPoller._HEARTBEAT_INTERVAL = 0.0
        try:
            poller._maybe_heartbeat()
            captured = capsys.readouterr()
            assert "⏳" in captured.out
            assert "2/82" in captured.out
            assert "✅0" in captured.out
            assert "❌2" in captured.out
        finally:
            ProgressPoller._HEARTBEAT_INTERVAL = 30.0  # 恢复

    def test_maybe_heartbeat_skips_within_interval(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """心跳间隔内不重复打印."""
        dashboard = ProgressDashboard(total=100)
        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-heartbeat-002",
            interval=5.0,
        )
        # _last_heartbeat 刚刚设置, 30s 内不应触发
        poller._maybe_heartbeat()
        captured = capsys.readouterr()
        assert captured.out == ""

    @pytest.mark.asyncio
    async def test_no_redraw_when_completed_unchanged(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """completed 无变化时不重绘完整仪表盘."""
        dashboard = ProgressDashboard(total=100)

        # 模拟 Memory 返回固定 2 个结果 (不变化)
        mock_memory = MagicMock()
        mock_memory.get_attack_results = MagicMock(
            return_value=[
                MagicMock(outcome=AttackOutcome.SUCCESS, id="r1"),
                MagicMock(outcome=AttackOutcome.FAILURE, id="r2"),
            ]
        )

        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-no-redraw-001",
            interval=0.02,
        )
        # 禁用心跳以隔离测试
        ProgressPoller._HEARTBEAT_INTERVAL = 9999.0
        try:
            with patch("pyrit.memory.CentralMemory.get_memory_instance", return_value=mock_memory):
                poller.start()
                await asyncio.sleep(0.1)
                await poller.stop()
        finally:
            ProgressPoller._HEARTBEAT_INTERVAL = 30.0

        captured = capsys.readouterr()
        # 仪表盘盒子应只出现一次 (首次状态变化 -1→2)
        box_count = captured.out.count("PyRIT AI Red Team")
        assert box_count == 1, f"Expected 1 dashboard render, got {box_count}"

    @pytest.mark.asyncio
    async def test_redraw_when_completed_changes(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """completed 变化时重绘完整仪表盘."""
        dashboard = ProgressDashboard(total=100)

        # 第一次返回 2 个结果, 第二次返回 3 个 (新增 1 个)
        results_round_1 = [
            MagicMock(outcome=AttackOutcome.SUCCESS, id="r1"),
            MagicMock(outcome=AttackOutcome.FAILURE, id="r2"),
        ]
        results_round_2 = [
            MagicMock(outcome=AttackOutcome.SUCCESS, id="r1"),
            MagicMock(outcome=AttackOutcome.FAILURE, id="r2"),
            MagicMock(outcome=AttackOutcome.SUCCESS, id="r3"),
        ]

        call_count = [0]
        mock_memory = MagicMock()

        def mock_get_results(*args, **kwargs):
            call_count[0] += 1
            return results_round_1 if call_count[0] == 1 else results_round_2

        mock_memory.get_attack_results = mock_get_results

        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-redraw-001",
            interval=0.02,
        )
        ProgressPoller._HEARTBEAT_INTERVAL = 9999.0
        try:
            with patch("pyrit.memory.CentralMemory.get_memory_instance", return_value=mock_memory):
                poller.start()
                await asyncio.sleep(0.1)
                await poller.stop()
        finally:
            ProgressPoller._HEARTBEAT_INTERVAL = 30.0

        captured = capsys.readouterr()
        box_count = captured.out.count("PyRIT AI Red Team")
        # 第一次 completed 0→2 (重绘), 第二次 completed 2→3 (重绘)
        assert box_count >= 2, f"Expected >= 2 dashboard renders, got {box_count}"
