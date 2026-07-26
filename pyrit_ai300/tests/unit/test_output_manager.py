"""
Output Manager 测试
===================

测试 OutputManager 的 L5 对齐功能：
- blurred_dir 参数透传
- 双通道输出（终端 + 文件）
- include_reasoning_trace / blur_images / blur_radius 参数

遵循开发规则 1.4.9 测试先行原则
"""

import asyncio
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.reporting.output_manager import OutputManager, ProgressDashboard, SummaryTable


# ============================================================
# OutputManager 初始化测试
# ============================================================


class TestOutputManagerInit:
    """测试 OutputManager 初始化"""

    def test_init_default_params(self, tmp_path):
        """测试默认参数初始化"""
        with patch("src.reporting.output_manager.get_config_loader") as mock_loader:
            mock_loader.return_value.get_logs_dir.return_value = str(tmp_path)
            manager = OutputManager(exam_id="test_exam")
            assert manager.exam_id == "test_exam"
            assert manager.verbose is False
            assert manager.include_reasoning_trace is False
            assert manager.blur_images is False
            assert manager.blur_radius == 20
            assert manager.blurred_dir is None

    def test_init_with_blurred_dir(self, tmp_path):
        """测试 blurred_dir 参数初始化"""
        with patch("src.reporting.output_manager.get_config_loader") as mock_loader:
            mock_loader.return_value.get_logs_dir.return_value = str(tmp_path)
            blurred = tmp_path / "blurred_images"
            manager = OutputManager(
                exam_id="test_exam",
                blur_images=True,
                blurred_dir=blurred,
            )
            assert manager.blur_images is True
            assert manager.blurred_dir == str(blurred)

    def test_init_blurred_dir_none(self, tmp_path):
        """测试 blurred_dir=None 时默认值"""
        with patch("src.reporting.output_manager.get_config_loader") as mock_loader:
            mock_loader.return_value.get_logs_dir.return_value = str(tmp_path)
            manager = OutputManager(exam_id="test_exam")
            assert manager.blurred_dir is None

    def test_init_blurred_dir_string_path(self, tmp_path):
        """测试 blurred_dir 接受字符串路径"""
        with patch("src.reporting.output_manager.get_config_loader") as mock_loader:
            mock_loader.return_value.get_logs_dir.return_value = str(tmp_path)
            blurred_str = str(tmp_path / "blur_output")
            manager = OutputManager(
                exam_id="test_exam",
                blur_images=True,
                blurred_dir=blurred_str,
            )
            assert manager.blurred_dir == blurred_str

    def test_init_custom_blur_radius(self, tmp_path):
        """测试自定义 blur_radius"""
        with patch("src.reporting.output_manager.get_config_loader") as mock_loader:
            mock_loader.return_value.get_logs_dir.return_value = str(tmp_path)
            manager = OutputManager(
                exam_id="test_exam",
                blur_images=True,
                blur_radius=35,
            )
            assert manager.blur_radius == 35

    def test_init_include_reasoning_trace(self, tmp_path):
        """测试 include_reasoning_trace 参数"""
        with patch("src.reporting.output_manager.get_config_loader") as mock_loader:
            mock_loader.return_value.get_logs_dir.return_value = str(tmp_path)
            manager = OutputManager(
                exam_id="test_exam",
                include_reasoning_trace=True,
            )
            assert manager.include_reasoning_trace is True

    def test_log_path_property(self, tmp_path):
        """测试 log_path 属性返回正确路径"""
        with patch("src.reporting.output_manager.get_config_loader") as mock_loader:
            mock_loader.return_value.get_logs_dir.return_value = str(tmp_path)
            manager = OutputManager(exam_id="exam123")
            expected = tmp_path / "exam123_attacks.md"
            assert manager.log_path == expected


# ============================================================
# OutputManager output_attack_result 测试
# ============================================================


class TestOutputAttackResult:
    """测试 output_attack_result 方法"""

    @pytest.fixture
    def manager(self, tmp_path):
        """创建 OutputManager 实例"""
        with patch("src.reporting.output_manager.get_config_loader") as mock_loader:
            mock_loader.return_value.get_logs_dir.return_value = str(tmp_path)
            return OutputManager(exam_id="test", verbose=True)

    @pytest.fixture
    def mock_result(self):
        """创建模拟 AttackResult"""
        mock = MagicMock()
        mock.objective = "Test objective"
        mock.conversation_id = "conv-123"
        mock.outcome = MagicMock()
        mock.outcome.value = "success"
        return mock

    @pytest.mark.asyncio
    async def test_output_attack_result_passes_blurred_dir(self, tmp_path):
        """测试 output_attack_result 将 blurred_dir 传递给 output_attack_async"""
        with patch("src.reporting.output_manager.get_config_loader") as mock_loader:
            mock_loader.return_value.get_logs_dir.return_value = str(tmp_path)
            blurred = tmp_path / "blur"
            manager = OutputManager(
                exam_id="test",
                blur_images=True,
                blurred_dir=blurred,
            )

        mock_result = MagicMock()
        mock_result.outcome = MagicMock()
        mock_result.outcome.value = "success"

        with patch("src.reporting.output_manager.output_attack_async", new_callable=AsyncMock) as mock_output:
            await manager.output_attack_result(mock_result, to_terminal=True, to_file=True)

            # 应该调用两次（终端 + 文件）
            assert mock_output.call_count == 2

            # 检查文件通道调用是否传递了 blurred_dir
            file_call = mock_output.call_args_list[1]
            assert file_call.kwargs.get("blurred_dir") == str(blurred)

    @pytest.mark.asyncio
    async def test_output_attack_result_no_blurred_dir(self, tmp_path):
        """测试未设置 blurred_dir 时传递 None"""
        with patch("src.reporting.output_manager.get_config_loader") as mock_loader:
            mock_loader.return_value.get_logs_dir.return_value = str(tmp_path)
            manager = OutputManager(exam_id="test", verbose=True)

        mock_result = MagicMock()
        mock_result.outcome = MagicMock()
        mock_result.outcome.value = "success"

        with patch("src.reporting.output_manager.output_attack_async", new_callable=AsyncMock) as mock_output:
            await manager.output_attack_result(mock_result, to_terminal=True, to_file=True)

            # 文件通道应该传递 blurred_dir=None
            file_call = mock_output.call_args_list[1]
            assert file_call.kwargs.get("blurred_dir") is None

    @pytest.mark.asyncio
    async def test_output_attack_result_terminal_only(self, manager, mock_result):
        """测试仅终端输出"""
        with patch("src.reporting.output_manager.output_attack_async", new_callable=AsyncMock) as mock_output:
            await manager.output_attack_result(mock_result, to_terminal=True, to_file=False)
            # 只应该调用一次（终端）
            assert mock_output.call_count == 1
            assert mock_output.call_args.kwargs.get("format") == "pretty"

    @pytest.mark.asyncio
    async def test_output_attack_result_file_only(self, tmp_path):
        """测试仅文件输出"""
        with patch("src.reporting.output_manager.get_config_loader") as mock_loader:
            mock_loader.return_value.get_logs_dir.return_value = str(tmp_path)
            manager = OutputManager(exam_id="test", verbose=False)

        mock_result = MagicMock()
        mock_result.outcome = MagicMock()
        mock_result.outcome.value = "failure"  # 非成功结果不会触发终端输出

        with patch("src.reporting.output_manager.output_attack_async", new_callable=AsyncMock) as mock_output:
            await manager.output_attack_result(mock_result, to_terminal=False, to_file=True)
            # 只应该调用一次（文件）
            assert mock_output.call_count == 1
            assert mock_output.call_args.kwargs.get("format") == "markdown"

    @pytest.mark.asyncio
    async def test_output_attack_result_blur_params_passed(self, tmp_path):
        """测试 blur_images 和 blur_radius 参数正确传递"""
        with patch("src.reporting.output_manager.get_config_loader") as mock_loader:
            mock_loader.return_value.get_logs_dir.return_value = str(tmp_path)
            manager = OutputManager(
                exam_id="test",
                blur_images=True,
                blur_radius=25,
            )

        mock_result = MagicMock()
        mock_result.outcome = MagicMock()
        mock_result.outcome.value = "success"

        with patch("src.reporting.output_manager.output_attack_async", new_callable=AsyncMock) as mock_output:
            await manager.output_attack_result(mock_result, to_terminal=True, to_file=False)

            assert mock_output.call_args.kwargs.get("blur_images") is True
            assert mock_output.call_args.kwargs.get("blur_radius") == 25


# ============================================================
# OutputManager close 测试
# ============================================================


class TestOutputManagerClose:
    """测试 close 方法"""

    @pytest.mark.asyncio
    async def test_close_writes_summary(self, tmp_path):
        """测试 close 写入统计信息"""
        with patch("src.reporting.output_manager.get_config_loader") as mock_loader:
            mock_loader.return_value.get_logs_dir.return_value = str(tmp_path)
            manager = OutputManager(exam_id="test")
            manager._attack_count = 5

            await manager.close()

            # 验证文件写入
            content = manager.terminal_log_path.read_text(encoding="utf-8")
            assert "Total attacks logged: 5" in content


# ============================================================
# ProgressDashboard 测试
# ============================================================


class TestProgressDashboard:
    """测试 ProgressDashboard"""

    def test_init(self):
        """测试初始化"""
        dashboard = ProgressDashboard(total=10)
        assert dashboard.total == 10
        assert dashboard.completed == 0
        assert dashboard.succeeded == 0
        assert dashboard.failed == 0

    def test_update(self):
        """测试更新统计"""
        dashboard = ProgressDashboard(total=10)
        dashboard.update(succeeded=2, failed=1, errored=1)
        assert dashboard.succeeded == 2
        assert dashboard.failed == 1
        assert dashboard.errored == 1

    def test_increment_completed(self):
        """测试完成计数递增"""
        dashboard = ProgressDashboard(total=10)
        dashboard.increment_completed()
        dashboard.increment_completed()
        assert dashboard.completed == 2

    def test_render(self):
        """测试渲染输出包含进度信息"""
        dashboard = ProgressDashboard(total=10)
        dashboard.increment_completed()
        dashboard.update(succeeded=1)

        output = dashboard.render()
        assert "1/10" in output
        assert "OK" in output or "✅" in output


# ============================================================
# SummaryTable 测试
# ============================================================


class TestSummaryTable:
    """测试 SummaryTable"""

    def test_render_mode_table(self):
        """测试渲染模式汇总表"""
        mode_stats = {
            "prompt_sending": {"total": 5, "success": 3, "fail": 2},
            "crescendo": {"total": 3, "success": 2, "fail": 1},
        }
        output = SummaryTable.render_mode_table(mode_stats)
        assert "prompt_sending" in output
        assert "crescendo" in output
        assert "TOTAL" in output

    def test_render_mode_table_empty(self):
        """测试空统计"""
        output = SummaryTable.render_mode_table({})
        assert "TOTAL" in output
