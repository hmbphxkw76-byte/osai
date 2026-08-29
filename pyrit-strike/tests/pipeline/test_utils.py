"""Utils 模块测试 — display。

覆盖:
    - print_banner Banner 输出
    - print_phase 阶段信息输出
    - print_summary 摘要输出
    - format_asr_table ASR 表格格式化

注: cleaner.py 已删除, 缓存清理逻辑在 main.py 的 cleanup_temp_files 中。
"""

from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ═══════════════════════════════════════════════════════
# display: print_banner
# ═══════════════════════════════════════════════════════


class TestPrintBanner:
    """测试 print_banner."""

    def test_prints_without_error(self, capsys):
        from pipeline.utils.display import print_banner

        print_banner()
        captured = capsys.readouterr()
        assert "PyRIT-Strike" in captured.out

    def test_contains_version(self, capsys):
        from pipeline.utils.display import print_banner

        print_banner()
        captured = capsys.readouterr()
        assert "v2.0.0" in captured.out or "v" in captured.out

    def test_contains_pipeline_description(self, capsys):
        from pipeline.utils.display import print_banner

        print_banner()
        captured = capsys.readouterr()
        assert "Pipeline" in captured.out or "Burp" in captured.out


# ═══════════════════════════════════════════════════════
# display: print_phase
# ═══════════════════════════════════════════════════════


class TestPrintPhase:
    """测试 print_phase."""

    def test_prints_phase_and_description(self, capsys):
        from pipeline.utils.display import print_phase

        print_phase("RECON", "Parsing Burp request")
        captured = capsys.readouterr()
        assert "RECON" in captured.out
        assert "Parsing Burp request" in captured.out

    def test_contains_separator_lines(self, capsys):
        from pipeline.utils.display import print_phase

        print_phase("ARM", "Building attack paths")
        captured = capsys.readouterr()
        # Should contain separator lines (─)
        assert "─" in captured.out

    def test_empty_description(self, capsys):
        from pipeline.utils.display import print_phase

        print_phase("TEST", "")
        captured = capsys.readouterr()
        assert "TEST" in captured.out


# ═══════════════════════════════════════════════════════
# display: print_summary
# ═══════════════════════════════════════════════════════


class TestPrintSummary:
    """测试 print_summary."""

    def test_prints_all_fields(self, capsys):
        from pipeline.utils.display import print_summary

        print_summary(
            total_attacks=100,
            successful_attacks=42,
            overall_asr=42.0,
            report_path="/tmp/report.md",
        )
        captured = capsys.readouterr()
        assert "100" in captured.out
        assert "42" in captured.out
        assert "42.0" in captured.out or "42.0%" in captured.out
        assert "/tmp/report.md" in captured.out

    def test_contains_header(self, capsys):
        from pipeline.utils.display import print_summary

        print_summary(
            total_attacks=10,
            successful_attacks=5,
            overall_asr=50.0,
            report_path="report.md",
        )
        captured = capsys.readouterr()
        assert "Assessment Complete" in captured.out

    def test_zero_attacks(self, capsys):
        from pipeline.utils.display import print_summary

        print_summary(
            total_attacks=0,
            successful_attacks=0,
            overall_asr=0.0,
            report_path="none",
        )
        captured = capsys.readouterr()
        assert "0" in captured.out

    def test_contains_separator(self, capsys):
        from pipeline.utils.display import print_summary

        print_summary(
            total_attacks=1,
            successful_attacks=1,
            overall_asr=100.0,
            report_path="r.md",
        )
        captured = capsys.readouterr()
        assert "═" in captured.out


# ═══════════════════════════════════════════════════════
# display: format_asr_table
# ═══════════════════════════════════════════════════════


class TestFormatAsrTable:
    """测试 format_asr_table."""

    def test_returns_string(self):
        from pipeline.utils.display import format_asr_table

        result = format_asr_table({"prompt_sending": 50.0})
        assert isinstance(result, str)

    def test_contains_header(self):
        from pipeline.utils.display import format_asr_table

        result = format_asr_table({"tap": 65.0})
        assert "Technique" in result
        assert "ASR" in result

    def test_contains_technique_names(self):
        from pipeline.utils.display import format_asr_table

        result = format_asr_table({
            "prompt_sending": 30.0,
            "crescendo": 82.0,
            "tap": 65.0,
        })
        assert "prompt_sending" in result
        assert "crescendo" in result
        assert "tap" in result

    def test_contains_asr_values(self):
        from pipeline.utils.display import format_asr_table

        result = format_asr_table({"tap": 65.5})
        assert "65.5" in result

    def test_sorted_by_asr_descending(self):
        from pipeline.utils.display import format_asr_table

        result = format_asr_table({
            "low": 10.0,
            "high": 90.0,
            "mid": 50.0,
        })
        # high should appear before mid, which appears before low
        high_pos = result.index("high")
        mid_pos = result.index("mid")
        low_pos = result.index("low")
        assert high_pos < mid_pos < low_pos

    def test_empty_dict(self):
        from pipeline.utils.display import format_asr_table

        result = format_asr_table({})
        # 空字典也应返回包含表头的字符串
        assert isinstance(result, str)
        assert "Technique" in result

    def test_contains_separator(self):
        from pipeline.utils.display import format_asr_table

        result = format_asr_table({"tap": 65.0})
        assert "─" in result

    def test_single_entry(self):
        from pipeline.utils.display import format_asr_table

        result = format_asr_table({"pair": 50.0})
        assert "pair" in result
        assert "50.0" in result

    def test_multiple_entries_all_present(self):
        from pipeline.utils.display import format_asr_table

        techniques = {
            "prompt_sending": 30.0,
            "crescendo": 82.0,
            "tap": 65.0,
            "pair": 50.0,
            "gcg": 15.0,
        }
        result = format_asr_table(techniques)
        for tech in techniques:
            assert tech in result
