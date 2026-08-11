# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_noise_redirector — NoiseFilter 三层路由单元测试。

覆盖:
  - _is_noise_line() 噪音行判断
  - _is_log_only_line() log-only 行判断
  - NoiseFilter._route_line() 三层路由 (signal / log-only / noise)
  - NoiseFilter.write() 集成测试 (终端可见性验证)

三层路由架构 (NIST SP 800-92 + 红队最佳实践):
  - signal: 终端 + 信号日志 (✅ 成功攻击)
  - log-only: 信号日志, 不到终端 (❌ 失败行)
  - noise: 噪音日志, 不到终端, 不到信号日志 (scorer skipping 等)

> **日期**: 2026-8-8
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from pipeline.utils.noise_redirector import (
    NoiseFilter,
    _is_log_only_line,
    _is_noise_line,
)

# ============================================================
# _is_noise_line 单元测试
# ============================================================


class TestIsNoiseLine:
    """_is_noise_line() 单元测试。"""

    def test_noise_line_skipper(self) -> None:
        """Skipping scorer 行识别为噪音。"""
        assert _is_noise_line("Skipping scorer TrueFalseScorer") is True

    def test_noise_line_loading_config(self) -> None:
        """Loading configuration file 行识别为噪音。"""
        assert _is_noise_line("Loading configuration file: .pyrit_conf") is True

    def test_signal_line_not_noise(self) -> None:
        """成功攻击回调行不是噪音。"""
        assert _is_noise_line("  ✅ AtomicAttack::abc123 | Phishing → response") is False

    def test_log_only_line_not_noise(self) -> None:
        """失败攻击回调行不是噪音 (而是 log-only)。"""
        assert _is_noise_line("  ❌ AtomicAttack::abc123 | Phishing → I'm sorry...") is False

    def test_empty_line_not_noise(self) -> None:
        """空行不是噪音。"""
        assert _is_noise_line("") is False
        assert _is_noise_line("   ") is False

    def test_json_next_message_is_noise(self) -> None:
        """JSON next_message 片段识别为噪音。"""
        assert _is_noise_line('"next_message": "Alright, let me set the scene...') is True

    def test_json_rationale_is_noise(self) -> None:
        """JSON rationale 片段识别为噪音。"""
        assert _is_noise_line('"rationale": "The collaborator responded...') is True

    def test_json_closing_brace_is_noise(self) -> None:
        """JSON 闭合花括号识别为噪音。"""
        assert _is_noise_line("}") is True

    def test_endpoint_elapsed_is_noise(self) -> None:
        """Endpoint + Elapsed time 行识别为噪音。"""
        assert _is_noise_line("Endpoint: https://api.deepseek.com. Elapsed time: 9.13 seconds. Total calls: 1") is True

    # ── 新增: PyRIT openai_target logger.exception 堆栈行 ──

    def test_api_status_error_is_noise(self) -> None:
        """APIStatusError 行 (PyRIT logger.exception 输出) 识别为噪音。"""
        assert _is_noise_line(
            "APIStatusError request_id=None status=503 "
            "error=Error code: 503 - {'code': 50508, 'message': 'System is too busy now.'}"
        ) is True

    def test_internal_server_error_is_noise(self) -> None:
        """InternalServerError 行识别为噪音。"""
        assert _is_noise_line(
            "InternalServerError request_id=None status=503 error=..."
        ) is True

    def test_bad_request_error_is_noise(self) -> None:
        """BadRequestError 行 (含 request_id) 识别为噪音。"""
        assert _is_noise_line(
            "BadRequestError request_id=req_abc123 is_content_filter=False"
        ) is True

    # ── 修复: strip 后的 traceback 行 ──

    def test_file_line_stripped_is_noise(self) -> None:
        """File " 行 strip 后仍匹配 (修复: 原 ^  File " 模式 bug)。"""
        assert _is_noise_line('  File "D:\\path\\openai_target.py", line 424') is True
        # strip 后无前导空格
        assert _is_noise_line('File "D:\\path\\openai_target.py", line 424') is True

    def test_caret_line_stripped_is_noise(self) -> None:
        r"""^^^^^ 行 strip 后仍匹配 (修复: 原 ^\s+\^+$ 模式 bug)。"""
        assert _is_noise_line("    ^^^^^^^^^^^^^^^^") is True
        # strip 后无前导空格
        assert _is_noise_line("^^^^^^^^^^^^^^^^") is True

    # ── 新增: traceback 中的 Python 代码行 ──

    def test_traceback_code_response_is_noise(self) -> None:
        """traceback 代码行 'response = await api_call()' 识别为噪音。"""
        assert _is_noise_line("    response = await api_call()") is True

    def test_traceback_code_return_is_noise(self) -> None:
        """traceback 代码行 'return await self._post(' 识别为噪音。"""
        assert _is_noise_line("    return await self._post(") is True

    def test_traceback_code_raise_is_noise(self) -> None:
        """traceback 代码行 'raise self._make_status_error' 识别为噪音。"""
        assert _is_noise_line(
            "    raise self._make_status_error_from_response(err.response) from None"
        ) is True

    def test_traceback_from_none_is_noise(self) -> None:
        """'from None' 行识别为噪音。"""
        assert _is_noise_line("from None") is True

    def test_traceback_closing_paren_is_noise(self) -> None:
        """闭合括号行 ')' 识别为噪音。"""
        assert _is_noise_line(")") is True

    # ── 防误报: 正常信号行不被误判为噪音 ──

    def test_rate_limited_target_retry_not_noise(self) -> None:
        """RateLimitedTarget 重试消息不是噪音 (是信号行)。"""
        assert _is_noise_line(
            "RateLimitedTarget: retry 2/3 after 2.5s "
            "(endpoint=https://api.siliconflow.cn/v1, "
            "error=InternalServerError, status=503, "
            "timeout=False, msg=\"System is too busy\")"
        ) is False

    def test_asr_line_not_noise(self) -> None:
        """ASR 行不是噪音。"""
        assert _is_noise_line("  │ ASR: 15% → 决定经验写回权重") is False


# ============================================================
# _is_log_only_line 单元测试
# ============================================================


class TestIsLogOnlyLine:
    """_is_log_only_line() 单元测试。"""

    def test_log_only_failure_line(self) -> None:
        """❌ 回调行识别为 log-only。"""
        assert _is_log_only_line("  ❌ AtomicAttack::abc123 | objective → response") is True

    def test_log_only_warning_line(self) -> None:
        """⚠ 回调行识别为 log-only。"""
        assert _is_log_only_line("  ⚠ AtomicAttack::abc123 | objective") is True

    def test_success_line_not_log_only(self) -> None:
        """✅ 成功行不是 log-only (而是 signal)。"""
        assert _is_log_only_line("  ✅ AtomicAttack::abc123 | objective → response") is False

    def test_noise_line_not_log_only(self) -> None:
        """噪音行不是 log-only。"""
        assert _is_log_only_line("Skipping scorer TrueFalseScorer") is False

    def test_empty_line_not_log_only(self) -> None:
        """空行不是 log-only。"""
        assert _is_log_only_line("") is False
        assert _is_log_only_line("   ") is False


# ============================================================
# _route_line 三层路由单元测试
# ============================================================


def _read_path(path: Path) -> str:
    """从 Path 读取文件内容。"""
    if not path.exists():
        return ""
    with open(path, encoding="utf-8") as f:
        return f.read()


class TestRouteLineThreeTier:
    """NoiseFilter._route_line() 三层路由测试。"""

    @pytest.fixture
    def mock_filter(self, tmp_path: Path) -> NoiseFilter:
        """创建带 mock stream 的 NoiseFilter (信号日志 + 噪音日志)。"""
        mock_stream = MagicMock(spec=io.TextIOBase)
        noise_path = tmp_path / "noise.log"
        signal_path = tmp_path / "signal.log"
        return NoiseFilter(mock_stream, noise_path, signal_path)

    def test_signal_line_goes_to_terminal_and_log(self, mock_filter: NoiseFilter, tmp_path: Path) -> None:
        """信号行 → 终端 + 信号日志。"""
        line = "  ✅ AtomicAttack::abc123 | objective → response\n"
        mock_filter._route_line(line)
        mock_filter.flush()

        # 终端可见
        mock_filter._original.write.assert_called_once_with(line)
        # 信号日志可见
        signal_content = _read_path(tmp_path / "signal.log")
        assert line.strip() in signal_content
        # 噪音日志不可见
        noise_content = _read_path(tmp_path / "noise.log")
        assert "AtomicAttack" not in noise_content

    def test_log_only_line_goes_to_signal_log_only(self, mock_filter: NoiseFilter, tmp_path: Path) -> None:
        """log-only 行 → 信号日志, 不到终端。"""
        line = "  ❌ AtomicAttack::abc123 | objective → I'm sorry...\n"
        mock_filter._route_line(line)
        mock_filter.flush()

        # 终端不可见
        mock_filter._original.write.assert_not_called()
        # 信号日志可见 (审计可追溯)
        signal_content = _read_path(tmp_path / "signal.log")
        assert "❌ AtomicAttack::abc123" in signal_content
        # 噪音日志不可见
        noise_content = _read_path(tmp_path / "noise.log")
        assert "AtomicAttack" not in noise_content

    def test_noise_line_goes_to_noise_log_only(self, mock_filter: NoiseFilter, tmp_path: Path) -> None:
        """噪音行 → 噪音日志, 不到终端, 不到信号日志。"""
        line = "Skipping scorer TrueFalseScorer\n"
        mock_filter._route_line(line)
        mock_filter.flush()

        # 终端不可见
        mock_filter._original.write.assert_not_called()
        # 信号日志不可见
        signal_content = _read_path(tmp_path / "signal.log")
        assert "Skipping" not in signal_content
        # 噪音日志可见
        noise_content = _read_path(tmp_path / "noise.log")
        assert "Skipping scorer" in noise_content

    def test_log_only_without_signal_file_passes_to_outer(self, tmp_path: Path) -> None:
        """无 signal_file (嵌套内层) 时 log-only 行透传到外层。"""
        mock_stream = MagicMock(spec=io.TextIOBase)
        noise_path = tmp_path / "noise_only.log"
        # 不传 signal_log_path → signal_file 为 None (模拟嵌套内层)
        filter_no_signal = NoiseFilter(mock_stream, noise_path, signal_log_path=None)

        line = "  ❌ AtomicAttack::abc123 | objective → response\n"
        filter_no_signal._route_line(line)
        filter_no_signal.flush()

        # 透传到外层 (mock_stream 代表外层 NoiseFilter)
        mock_stream.write.assert_called_once_with(line)
        filter_no_signal.close()

    def test_warning_line_goes_to_signal_log_only(self, mock_filter: NoiseFilter, tmp_path: Path) -> None:
        """⚠ 回调行也走 log-only 路由。"""
        line = "  ⚠ AtomicAttack::abc123 | objective\n"
        mock_filter._route_line(line)
        mock_filter.flush()

        # 终端不可见
        mock_filter._original.write.assert_not_called()
        # 信号日志可见
        signal_content = _read_path(tmp_path / "signal.log")
        assert "⚠ AtomicAttack::abc123" in signal_content


# ============================================================
# NoiseFilter.write() 集成测试
# ============================================================


class TestNoiseFilterIntegration:
    """NoiseFilter.write() 集成测试 — 终端可见性验证。"""

    def test_write_success_line_appears_on_terminal(self, tmp_path: Path) -> None:
        """write() ✅ 成功行 → 终端可见。"""
        mock_stream = MagicMock(spec=io.TextIOBase)
        noise_path = tmp_path / "noise.log"
        signal_path = tmp_path / "signal.log"
        nf = NoiseFilter(mock_stream, noise_path, signal_path)

        nf.write("  ✅ AtomicAttack::abc | Phishing → response\n")
        nf.flush()

        # 终端可见
        mock_stream.write.assert_called_once_with("  ✅ AtomicAttack::abc | Phishing → response\n")
        nf.close()

    def test_write_failure_line_not_on_terminal(self, tmp_path: Path) -> None:
        """write() ❌ 失败行 → 终端不可见, 信号日志可见。"""
        mock_stream = MagicMock(spec=io.TextIOBase)
        noise_path = tmp_path / "noise.log"
        signal_path = tmp_path / "signal.log"
        nf = NoiseFilter(mock_stream, noise_path, signal_path)

        nf.write("  ❌ AtomicAttack::abc | Phishing → I'm sorry...\n")
        nf.flush()

        # 终端不可见
        mock_stream.write.assert_not_called()
        # 信号日志可见 (审计可追溯)
        signal_content = _read_path(tmp_path / "signal.log")
        assert "❌ AtomicAttack::abc" in signal_content
        nf.close()

    def test_write_noise_line_not_on_terminal(self, tmp_path: Path) -> None:
        """write() 噪音行 → 终端不可见, 噪音日志可见。"""
        mock_stream = MagicMock(spec=io.TextIOBase)
        noise_path = tmp_path / "noise.log"
        signal_path = tmp_path / "signal.log"
        nf = NoiseFilter(mock_stream, noise_path, signal_path)

        nf.write("Skipping scorer TrueFalseScorer\n")
        nf.flush()

        # 终端不可见
        mock_stream.write.assert_not_called()
        # 噪音日志可见
        noise_content = _read_path(tmp_path / "noise.log")
        assert "Skipping scorer" in noise_content
        nf.close()

    def test_nested_context_without_signal_file(self, tmp_path: Path) -> None:
        """内层 (无 signal_log_path) 时 log-only 行透传到外层, 不崩溃。"""
        mock_stream = MagicMock(spec=io.TextIOBase)
        noise_path = tmp_path / "noise.log"
        # 内层不传 signal_log_path
        nf = NoiseFilter(mock_stream, noise_path, signal_log_path=None)

        nf.write("  ❌ AtomicAttack::abc | objective → response\n")
        nf.flush()

        # 透传到外层 (mock_stream 代表外层 NoiseFilter, 不是终端)
        mock_stream.write.assert_called_once()
        nf.close()

    def test_mixed_output_batch(self, tmp_path: Path) -> None:
        """混合输出批次: 成功行到终端, 失败行到日志, 噪音到噪音日志。"""
        mock_stream = MagicMock(spec=io.TextIOBase)
        noise_path = tmp_path / "noise.log"
        signal_path = tmp_path / "signal.log"
        nf = NoiseFilter(mock_stream, noise_path, signal_path)

        batch = (
            "Skipping scorer TrueFalseScorer\n"
            "  ✅ AtomicAttack::abc | Phishing → success response\n"
            "  ❌ AtomicAttack::def | Copyright → I'm sorry...\n"
            "  ✅ AtomicAttack::ghi | Malware → here's the code\n"
        )
        nf.write(batch)
        nf.flush()
        nf.close()

        # 终端只看到 2 行 (2 个 ✅), 不含 ❌ 和噪音
        terminal_calls: list[Any] = [str(c) for c in mock_stream.write.call_args_list]
        terminal_text = "".join(terminal_calls)
        assert "✅ AtomicAttack::abc" in terminal_text
        assert "✅ AtomicAttack::ghi" in terminal_text
        assert "❌" not in terminal_text
        assert "Skipping" not in terminal_text

        # 信号日志有 ✅ + ❌ (审计可追溯)
        signal_content = _read_path(tmp_path / "signal.log")
        assert "✅ AtomicAttack::abc" in signal_content
        assert "❌ AtomicAttack::def" in signal_content

        # 噪音日志有 Skipping
        noise_content = _read_path(tmp_path / "noise.log")
        assert "Skipping scorer" in noise_content
