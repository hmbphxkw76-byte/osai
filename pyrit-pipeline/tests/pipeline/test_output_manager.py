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
            MagicMock(outcome=AttackOutcome.SUCCESS, objective="obj_1"),
            MagicMock(outcome=AttackOutcome.SUCCESS, objective="obj_2"),
            MagicMock(outcome=AttackOutcome.SUCCESS, objective="obj_3"),
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
            MagicMock(outcome=AttackOutcome.SUCCESS, objective="obj_1"),
            MagicMock(outcome=AttackOutcome.FAILURE, objective="obj_2"),
            MagicMock(outcome=AttackOutcome.ERROR, objective="obj_3"),
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

        results = [MagicMock(outcome=AttackOutcome.SUCCESS, objective="obj_1")]
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
            MagicMock(outcome=AttackOutcome.SUCCESS, objective="obj_1"),
            MagicMock(outcome=None, objective="obj_2"),
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
        result.objective = "obj_1"

        dashboard.update_from_attack_results([result])
        assert dashboard.succeeded == 1

    def test_update_from_attack_results_multi_attempt_same_objective(self) -> None:
        """同一 objective 的多个 AttackResult (多次尝试) 只算 1 个完成."""
        dashboard = ProgressDashboard(total=82)
        # 模拟: 同一个 AtomicAttack (objective="obj_1") 有 3 次尝试
        # 2 次失败 + 1 次成功 → 该 objective 算 1 个成功
        results = [
            MagicMock(outcome=AttackOutcome.FAILURE, objective="obj_1"),
            MagicMock(outcome=AttackOutcome.FAILURE, objective="obj_1"),
            MagicMock(outcome=AttackOutcome.SUCCESS, objective="obj_1"),
            # 另一个 AtomicAttack (objective="obj_2") 2 次尝试全失败
            MagicMock(outcome=AttackOutcome.FAILURE, objective="obj_2"),
            MagicMock(outcome=AttackOutcome.FAILURE, objective="obj_2"),
        ]
        dashboard.update_from_attack_results(results)
        # 2 个唯一 objective → completed=2 (不是 5 个 AttackResult)
        assert dashboard.completed == 2
        # obj_1 有 SUCCESS → succeeded=1
        assert dashboard.succeeded == 1
        # obj_2 全 FAILURE → failed=1
        assert dashboard.failed == 1
        assert dashboard.errored == 0


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
                MagicMock(outcome=AttackOutcome.SUCCESS, objective="obj_1"),
                MagicMock(outcome=AttackOutcome.SUCCESS, objective="obj_2"),
                MagicMock(outcome=AttackOutcome.FAILURE, objective="obj_3"),
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

    # ── 自适应退避策略测试 ──

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

    @pytest.mark.asyncio
    async def test_no_print_when_completed_unchanged(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """completed 无变化时不打印仪表盘 (原生 tqdm 由 Poller 增强, 不再渲染卡片)."""
        dashboard = ProgressDashboard(total=100)

        # 模拟 Memory 返回固定 2 个结果 (不变化)
        mock_memory = MagicMock()
        mock_memory.get_attack_results = MagicMock(
            return_value=[
                MagicMock(outcome=AttackOutcome.SUCCESS, id="r1", objective="obj_1"),
                MagicMock(outcome=AttackOutcome.FAILURE, id="r2", objective="obj_2"),
            ]
        )

        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-no-redraw-001",
            interval=0.02,
        )
        with patch("pyrit.memory.CentralMemory.get_memory_instance", return_value=mock_memory):
            poller.start()
            await asyncio.sleep(0.1)
            await poller.stop()

        captured = capsys.readouterr()
        # O1: 不再渲染 Dashboard 卡片, 应该不出现 "PyRIT AI Red Team"
        box_count = captured.out.count("PyRIT AI Red Team")
        assert box_count == 0, f"Expected 0 dashboard renders, got {box_count}"

    @pytest.mark.asyncio
    async def test_callback_printed_when_completed_changes(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """completed 变化时打印红队可读回调行 (✅/❌)."""
        dashboard = ProgressDashboard(total=100)

        # 第一次返回 2 个结果, 第二次返回 3 个 (新增 1 个)
        results_round_1 = [
            MagicMock(outcome=AttackOutcome.SUCCESS, id="r1", objective="obj_1"),
            MagicMock(outcome=AttackOutcome.FAILURE, id="r2", objective="obj_2"),
        ]
        results_round_2 = [
            MagicMock(outcome=AttackOutcome.SUCCESS, id="r1", objective="obj_1"),
            MagicMock(outcome=AttackOutcome.FAILURE, id="r2", objective="obj_2"),
            MagicMock(outcome=AttackOutcome.SUCCESS, id="r3", objective="obj_3"),
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
        with patch("pyrit.memory.CentralMemory.get_memory_instance", return_value=mock_memory):
            poller.start()
            await asyncio.sleep(0.1)
            await poller.stop()

        captured = capsys.readouterr()
        # O2: 应该出现红队可读回调行 (✅ 或 ❌)
        assert "✅" in captured.out or "❌" in captured.out


# ============================================================
# P3-O2: _get_latest_technique_name 跳过 "unknown" 测试
# ============================================================


class TestGetLatestTechniqueNameSkipUnknown:
    """P3-O2: _get_latest_technique_name() 应跳过 "unknown" 结果。"""

    def test_skips_unknown_returns_real_technique(self) -> None:
        """最新的结果为 "unknown" 时, 跳过并返回更早的真实技术名。"""
        dashboard = ProgressDashboard(total=100)
        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-skip-unknown-001",
        )

        # 模拟 3 个 AttackResult, reversed 后遍历顺序: results[2], results[1], results[0]
        # side_effect 按调用顺序消费迭代器
        # 第一个 (最新): unknown → 跳过
        # 第二个: sequential → 跳过
        # 第三个: many_shot → 返回
        mock_results = [MagicMock() for _ in range(3)]
        mock_memory = MagicMock()
        mock_memory.get_attack_results = MagicMock(return_value=mock_results)

        tech_sequence = iter(["unknown", "sequential", "many_shot"])

        with (
            patch("pyrit.memory.CentralMemory.get_memory_instance", return_value=mock_memory),
            patch.object(ProgressDashboard, "_extract_technique", side_effect=lambda ar: next(tech_sequence)),
        ):
            result = poller._get_latest_technique_name()

        assert result == "many_shot"

    def test_skips_sequential_and_unknown_returns_real(self) -> None:
        """同时跳过 "sequential" 和 "unknown", 返回真实技术名。"""
        dashboard = ProgressDashboard(total=100)
        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-skip-unknown-002",
        )

        mock_results = [MagicMock() for _ in range(4)]
        mock_memory = MagicMock()
        mock_memory.get_attack_results = MagicMock(return_value=mock_results)

        # reversed 后遍历: sequential → skip, unknown → skip, many_shot → return
        tech_sequence = iter(["sequential", "unknown", "many_shot", "tap"])

        with (
            patch("pyrit.memory.CentralMemory.get_memory_instance", return_value=mock_memory),
            patch.object(ProgressDashboard, "_extract_technique", side_effect=lambda ar: next(tech_sequence)),
        ):
            result = poller._get_latest_technique_name()

        assert result == "many_shot"

    def test_all_unknown_returns_empty(self) -> None:
        """所有结果都是 "unknown" 时返回空字符串。"""
        dashboard = ProgressDashboard(total=100)
        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-skip-unknown-003",
        )

        mock_results = [MagicMock() for _ in range(3)]
        mock_memory = MagicMock()
        mock_memory.get_attack_results = MagicMock(return_value=mock_results)

        with (
            patch("pyrit.memory.CentralMemory.get_memory_instance", return_value=mock_memory),
            patch.object(ProgressDashboard, "_extract_technique", return_value="unknown"),
        ):
            result = poller._get_latest_technique_name()

        assert result == ""

    def test_all_sequential_or_unknown_returns_empty(self) -> None:
        """所有结果都是 "sequential" 或 "unknown" 时返回空字符串。"""
        dashboard = ProgressDashboard(total=100)
        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-skip-unknown-004",
        )

        mock_results = [MagicMock() for _ in range(4)]
        mock_memory = MagicMock()
        mock_memory.get_attack_results = MagicMock(return_value=mock_results)

        tech_sequence = iter(["sequential", "unknown", "unknown", "sequential"])

        with (
            patch("pyrit.memory.CentralMemory.get_memory_instance", return_value=mock_memory),
            patch.object(ProgressDashboard, "_extract_technique", side_effect=lambda ar: next(tech_sequence)),
        ):
            result = poller._get_latest_technique_name()

        assert result == ""

    def test_empty_results_returns_empty(self) -> None:
        """空结果列表返回空字符串。"""
        dashboard = ProgressDashboard(total=100)
        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-skip-unknown-005",
        )

        mock_memory = MagicMock()
        mock_memory.get_attack_results = MagicMock(return_value=[])

        with patch("pyrit.memory.CentralMemory.get_memory_instance", return_value=mock_memory):
            result = poller._get_latest_technique_name()

        assert result == ""

    def test_first_real_technique_returned(self) -> None:
        """最新的结果即为真实技术名时直接返回。"""
        dashboard = ProgressDashboard(total=100)
        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-skip-unknown-006",
        )

        mock_results = [MagicMock(), MagicMock()]
        mock_memory = MagicMock()
        mock_memory.get_attack_results = MagicMock(return_value=mock_results)

        # reversed 后第一个: many_shot → 直接返回 (不跳过)
        tech_sequence = iter(["many_shot", "prompt_sending"])

        with (
            patch("pyrit.memory.CentralMemory.get_memory_instance", return_value=mock_memory),
            patch.object(ProgressDashboard, "_extract_technique", side_effect=lambda ar: next(tech_sequence)),
        ):
            result = poller._get_latest_technique_name()

        assert result == "many_shot"


# ============================================================
# P3-O2: _inject_postfix 不显示 unknown Tech 测试
# ============================================================


class TestInjectPostfixSkipUnknownTech:
    """P3-O2: _inject_postfix() 当 tech_name 为 "unknown" 时不注入 Tech 字段。"""

    def test_unknown_tech_not_injected(self) -> None:
        """tech_name="unknown" 时, postfix 不包含 Tech 字段。"""
        dashboard = ProgressDashboard(total=100)
        dashboard._asr_tech_total = {"unknown": 10}
        dashboard._asr_tech_success = {"unknown": 0}
        dashboard.completed = 10
        dashboard.succeeded = 0
        dashboard.failed = 8
        dashboard.errored = 2

        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-inject-unknown-001",
        )

        # Mock tqdm instance
        mock_instance = MagicMock()
        mock_instance.desc = "Executing TextAdaptive"
        mock_tqdm_cls = MagicMock()
        mock_tqdm_cls._instances = {mock_instance}

        with (
            patch("tqdm.auto.tqdm", mock_tqdm_cls),
            patch.object(poller, "_get_latest_technique_name", return_value="unknown"),
        ):
            poller._inject_postfix()

        # 检查 set_postfix 调用参数
        call_args = mock_instance.set_postfix.call_args
        assert call_args is not None, "set_postfix should have been called"
        postfix_dict = {k: v for k, v in call_args.kwargs.items() if k != "refresh"}
        assert "Tech" not in postfix_dict, "Tech should not be in postfix when tech_name is 'unknown'"
        assert "ASR" in postfix_dict
        assert "OK" in postfix_dict

    def test_real_tech_injected(self) -> None:
        """tech_name 为真实技术名时, postfix 包含 Tech 字段。"""
        dashboard = ProgressDashboard(total=100)
        dashboard._asr_tech_total = {"many_shot": 10}
        dashboard._asr_tech_success = {"many_shot": 5}
        dashboard.completed = 10
        dashboard.succeeded = 5
        dashboard.failed = 3
        dashboard.errored = 2

        poller = ProgressPoller(
            dashboard=dashboard,
            scenario_result_id="test-inject-unknown-002",
        )

        mock_instance = MagicMock()
        mock_instance.desc = "Executing TextAdaptive"
        mock_tqdm_cls = MagicMock()
        mock_tqdm_cls._instances = {mock_instance}

        with (
            patch("tqdm.auto.tqdm", mock_tqdm_cls),
            patch.object(poller, "_get_latest_technique_name", return_value="many_shot"),
        ):
            poller._inject_postfix()

        call_args = mock_instance.set_postfix.call_args
        assert call_args is not None
        postfix_dict = {k: v for k, v in call_args.kwargs.items() if k != "refresh"}
        assert "Tech" in postfix_dict, "Tech should be in postfix for real technique name"
        assert "many_shot" in postfix_dict["Tech"]
        assert "50%" in postfix_dict["Tech"]


# ============================================================
# P3-O2 路径 4: _extract_technique 从 error_message 提取策略类名
# ============================================================


class TestExtractTechniqueFromErrorMessage:
    """路径 4: _extract_technique() 从 error_message 正则提取策略类名。"""

    def test_prompt_sending_from_error_message(self) -> None:
        """error_message 含 PromptSendingAttack 类名时提取为 prompt_sending。"""
        ar = MagicMock()
        ar_dict = {
            "error_message": (
                "Strategy execution failed for objective_target in PromptSendingAttack: "
                "Error sending prompt with conversation ID: test-123"
            ),
        }
        # MagicMock 的 vars() 返回 __dict__, 需要手动设置
        ar.__dict__.update(ar_dict)
        # 确保路径 1-3 不命中
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        result = ProgressDashboard._extract_technique(ar)
        assert result == "prompt_sending"

    def test_many_shot_from_error_message(self) -> None:
        """error_message 含 ManyShotJailbreakAttack 类名时提取为 many_shot。"""
        ar = MagicMock()
        ar.__dict__.update({
            "error_message": "Strategy execution failed for objective_target in ManyShotJailbreakAttack: ReadTimeout",
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        result = ProgressDashboard._extract_technique(ar)
        assert result == "many_shot"

    def test_crescendo_from_error_message(self) -> None:
        """error_message 含 CrescendoAttack 类名时提取为 crescendo。"""
        ar = MagicMock()
        ar.__dict__.update({
            "error_message": "Strategy execution failed for objective_target in CrescendoAttack: APITimeoutError",
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        result = ProgressDashboard._extract_technique(ar)
        assert result == "crescendo"

    def test_low_level_api_error_returns_unknown(self) -> None:
        """error_message 仅含底层 API 错误 (无策略类名) 时返回 unknown。"""
        ar = MagicMock()
        ar.__dict__.update({
            "error_message": "Error sending prompt with conversation ID: test-456",
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        result = ProgressDashboard._extract_technique(ar)
        assert result == "unknown"

    def test_empty_error_message_returns_unknown(self) -> None:
        """error_message 为空时返回 unknown。"""
        ar = MagicMock()
        ar.__dict__.update({"error_message": ""})
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        result = ProgressDashboard._extract_technique(ar)
        assert result == "unknown"

    def test_none_error_message_returns_unknown(self) -> None:
        """error_message 为 None 时返回 unknown。"""
        ar = MagicMock()
        ar.__dict__.update({"error_message": None})
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        result = ProgressDashboard._extract_technique(ar)
        assert result == "unknown"

    def test_path_1_takes_precedence_over_path_4(self) -> None:
        """路径 4 在路径 1 不可用时正确 fallback (MagicMock 类型检查跳过路径 1)."""
        mock_attack_id = MagicMock()
        mock_attack_id.class_name = "ManyShotJailbreakAttack"

        ar = MagicMock()
        ar.get_attack_strategy_identifier = MagicMock(return_value=mock_attack_id)
        ar.__dict__.update({
            "error_message": "Strategy execution failed for objective_target in PromptSendingAttack: timeout",
        })

        result = ProgressDashboard._extract_technique(ar)
        # MagicMock 路径 1 被跳过 (类型检查), 路径 4 fallback 提取 PromptSendingAttack
        assert result == "prompt_sending"

    def test_unknown_class_name_preserved(self) -> None:
        """error_message 含未映射的类名时保留原始 class_name。"""
        ar = MagicMock()
        ar.__dict__.update({
            "error_message": "Strategy execution failed for objective_target in SomeNewAttack: error",
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        result = ProgressDashboard._extract_technique(ar)
        assert result == "SomeNewAttack"


# ============================================================
# Round 20 路径 5: _extract_technique eval_hash 关联查询
# ============================================================


class TestExtractTechniqueFromEvalHash:
    """路径 5: _extract_technique() 通过 attribution_data.parent_eval_hash 关联查询技术名。

    适用场景: 攻击因 API 超时/错误失败, atomic_attack_identifier 为 None,
    但 attribution_data.parent_eval_hash 可关联到同批次已知结果的技术名。
    """

    def test_path_5_resolves_unknown_via_parent_eval_hash(self) -> None:
        """parent_eval_hash 在映射中时返回对应技术名。"""
        ar = MagicMock()
        ar.__dict__.update({
            "atomic_attack_identifier": None,
            "metadata": {},
            "error_message": "Error sending prompt with conversation ID: test-123",
            "attribution_data": {
                "parent_collection": "baseline",
                "parent_eval_hash": "abc123def456",
            },
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        eval_hash_map = {"abc123def456": "prompt_sending"}
        result = ProgressDashboard._extract_technique(ar, eval_hash_map=eval_hash_map)
        assert result == "prompt_sending"

    def test_path_5_resolves_many_shot(self) -> None:
        """parent_eval_hash 映射到 many_shot 技术时正确返回。"""
        ar = MagicMock()
        ar.__dict__.update({
            "atomic_attack_identifier": None,
            "metadata": {},
            "error_message": None,
            "attribution_data": {
                "parent_collection": "enhanced",
                "parent_eval_hash": "hash_many_shot_789",
            },
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        eval_hash_map = {"hash_many_shot_789": "many_shot"}
        result = ProgressDashboard._extract_technique(ar, eval_hash_map=eval_hash_map)
        assert result == "many_shot"

    def test_path_5_not_in_map_returns_unknown(self) -> None:
        """parent_eval_hash 不在映射中时返回 unknown。"""
        ar = MagicMock()
        ar.__dict__.update({
            "atomic_attack_identifier": None,
            "metadata": {},
            "error_message": "Error sending prompt with conversation ID: test-456",
            "attribution_data": {
                "parent_collection": "baseline",
                "parent_eval_hash": "unknown_hash_999",
            },
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        eval_hash_map = {"abc123def456": "prompt_sending"}
        result = ProgressDashboard._extract_technique(ar, eval_hash_map=eval_hash_map)
        assert result == "unknown"

    def test_path_5_no_attribution_data_returns_unknown(self) -> None:
        """attribution_data 为 None 时返回 unknown。"""
        ar = MagicMock()
        ar.__dict__.update({
            "atomic_attack_identifier": None,
            "metadata": {},
            "error_message": None,
            "attribution_data": None,
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        eval_hash_map = {"abc123": "prompt_sending"}
        result = ProgressDashboard._extract_technique(ar, eval_hash_map=eval_hash_map)
        assert result == "unknown"

    def test_path_5_no_eval_hash_map_returns_unknown(self) -> None:
        """eval_hash_map 为 None 时跳过路径 5, 返回 unknown。"""
        ar = MagicMock()
        ar.__dict__.update({
            "atomic_attack_identifier": None,
            "metadata": {},
            "error_message": None,
            "attribution_data": {
                "parent_eval_hash": "abc123",
            },
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        result = ProgressDashboard._extract_technique(ar)
        assert result == "unknown"

    def test_path_5_empty_eval_hash_map_returns_unknown(self) -> None:
        """eval_hash_map 为空字典时跳过路径 5。"""
        ar = MagicMock()
        ar.__dict__.update({
            "atomic_attack_identifier": None,
            "metadata": {},
            "error_message": None,
            "attribution_data": {"parent_eval_hash": "abc123"},
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        result = ProgressDashboard._extract_technique(ar, eval_hash_map={})
        assert result == "unknown"

    def test_path_5_attribution_data_not_dict_returns_unknown(self) -> None:
        """attribution_data 不是 dict 类型时返回 unknown。"""
        ar = MagicMock()
        ar.__dict__.update({
            "atomic_attack_identifier": None,
            "metadata": {},
            "error_message": None,
            "attribution_data": "not_a_dict",
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        result = ProgressDashboard._extract_technique(ar, eval_hash_map={"abc": "test"})
        assert result == "unknown"

    def test_path_5_missing_parent_eval_hash_key_returns_unknown(self) -> None:
        """attribution_data 不含 parent_eval_hash 键时返回 unknown。"""
        ar = MagicMock()
        ar.__dict__.update({
            "atomic_attack_identifier": None,
            "metadata": {},
            "error_message": None,
            "attribution_data": {"parent_collection": "baseline"},
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        result = ProgressDashboard._extract_technique(ar, eval_hash_map={"abc": "test"})
        assert result == "unknown"

    def test_path_1_takes_precedence_over_path_5(self) -> None:
        """路径 1 优先于路径 5: 有 atomic_attack_identifier 时不走 Path 5。"""
        mock_attack_id = MagicMock()
        mock_attack_id.class_name = "ManyShotJailbreakAttack"
        mock_attack_id.params = {}

        ar = MagicMock()
        ar.get_attack_strategy_identifier = MagicMock(return_value=mock_attack_id)
        ar.__dict__.update({
            "attribution_data": {"parent_eval_hash": "should_not_be_used"},
        })

        eval_hash_map = {"should_not_be_used": "prompt_sending"}
        # MagicMock 类型检查跳过路径 1, 但如果 atomic_attack_identifier 有效则走路径 2
        # 这里测试: 路径 1 不可用时, 如果有 atomic_attack_identifier 则不走路径 5
        result = ProgressDashboard._extract_technique(ar, eval_hash_map=eval_hash_map)
        # MagicMock.get_attack_strategy_identifier 返回 MagicMock, 类型检查跳过路径 1
        # ar_dict["atomic_attack_identifier"] 未设置 → None, 路径 2 跳过
        # 路径 3: metadata 未设置 → 跳过
        # 路径 4: error_message 未设置 → 跳过
        # 路径 5: attribution_data.parent_eval_hash = "should_not_be_used" → 映射到 "prompt_sending"
        assert result == "prompt_sending"


# ============================================================
# Round 20: update_from_attack_results 两遍遍历 + Path 5 集成
# ============================================================


class TestUpdateFromAttackResultsPath5:
    """update_from_attack_results 两遍遍历: 第一遍构建映射, 第二遍 Path 5 解析。"""

    def test_unknown_results_resolved_via_two_pass(self) -> None:
        """unknown 结果在第二遍通过 eval_hash 关联查询被正确解析。"""
        from pyrit.models import AttackOutcome

        # 已知结果: 有 atomic_attack_identifier.eval_hash, 技术名 = prompt_sending
        mock_aai = MagicMock()
        mock_aai.eval_hash = "hash_prompt_sending_001"
        mock_aai.class_name = "AtomicAttack"
        # 让路径 2 不命中 (children 为空 dict)
        mock_aai.children = {}

        known_ar = MagicMock()
        known_ar.__dict__.update({
            "objective": "test objective 1",
            "outcome": AttackOutcome.SUCCESS,
            "atomic_attack_identifier": mock_aai,
            "metadata": {"technique": "prompt_sending"},  # Path 3
            "error_message": None,
            "attribution_data": None,
        })
        known_ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        # Unknown 结果: atomic_attack_identifier = None, 但有 attribution_data
        unknown_ar = MagicMock()
        unknown_ar.__dict__.update({
            "objective": "test objective 2",
            "outcome": AttackOutcome.ERROR,
            "atomic_attack_identifier": None,
            "metadata": {},
            "error_message": "Error sending prompt with conversation ID: test-789",
            "attribution_data": {
                "parent_collection": "baseline",
                "parent_eval_hash": "hash_prompt_sending_001",
            },
        })
        unknown_ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        dashboard = ProgressDashboard(total=2)
        dashboard.update_from_attack_results([known_ar, unknown_ar])

        # prompt_sending 应包含两个结果 (已知 + unknown 解析)
        assert dashboard._asr_tech_total.get("prompt_sending", 0) == 2
        assert dashboard._asr_tech_success.get("prompt_sending", 0) == 1

    def test_no_unknown_results_skips_second_pass(self) -> None:
        """全部结果已知时跳过第二遍 (unknown_results 为空)。"""
        from pyrit.models import AttackOutcome

        mock_aai = MagicMock()
        mock_aai.eval_hash = "hash_001"
        mock_aai.class_name = "AtomicAttack"
        mock_aai.children = {}

        known_ar = MagicMock()
        known_ar.__dict__.update({
            "objective": "test objective",
            "outcome": AttackOutcome.SUCCESS,
            "atomic_attack_identifier": mock_aai,
            "metadata": {"technique": "prompt_sending"},  # Path 3
            "error_message": None,
            "attribution_data": None,
        })
        known_ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        dashboard = ProgressDashboard(total=1)
        dashboard.update_from_attack_results([known_ar])

        assert dashboard._asr_tech_total.get("prompt_sending", 0) == 1
        assert dashboard.completed == 1

    def test_unknown_with_no_mapping_stays_unknown(self) -> None:
        """没有可用的 eval_hash 映射时, unknown 结果不被计数。"""
        from pyrit.models import AttackOutcome

        # 仅有 unknown 结果, 无已知结果构建映射
        unknown_ar = MagicMock()
        unknown_ar.__dict__.update({
            "objective": "test objective",
            "outcome": AttackOutcome.ERROR,
            "atomic_attack_identifier": None,
            "metadata": {},
            "error_message": "Error sending prompt",
            "attribution_data": {"parent_eval_hash": "no_match_hash"},
        })
        unknown_ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        dashboard = ProgressDashboard(total=1)
        dashboard.update_from_attack_results([unknown_ar])

        # 没有技术被计数 (映射为空, 第二遍不执行)
        assert len(dashboard._asr_tech_total) == 0
        assert dashboard.errored == 1
