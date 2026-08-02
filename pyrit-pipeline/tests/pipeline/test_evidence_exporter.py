# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_evidence_exporter — EvidenceExporter 单元测试。

覆盖:
  - EvidenceExporter.__init__: 参数传递与目录创建
  - EvidenceExporter._collect_blurred_images: 模糊图片收集
  - EvidenceExporter._render_attack_summary_csv: CSV 渲染
  - EvidenceExporter._render_coverage_matrix_csv: OWASP 覆盖矩阵 CSV
  - EvidenceExporter._render_attack_timeline_csv: 时间线 CSV
  - 模块级导入: 无 try/except ImportError
  - 异常处理: export 方法使用 except Exception
  - blurred_dir 透传: 传递给所有打印机
  - _is_success_score / _format_time: 辅助函数

> **日期**: 2026-8-2
"""

from __future__ import annotations

import inspect
from pathlib import Path
from unittest.mock import MagicMock

from pipeline.reporting.evidence_exporter import (
    EvidenceExporter,
    _format_time,
    _is_success_score,
)

# ============================================================
# EvidenceExporter.__init__ 单元测试
# ============================================================


class TestEvidenceExporterInit:
    """EvidenceExporter 初始化参数测试。."""

    def test_accepts_blurred_dir_parameter(self, tmp_path: Path) -> None:
        """__init__ 接受 blurred_dir 关键字参数。."""
        exporter = EvidenceExporter(tmp_path / "evidence", blurred_dir=str(tmp_path / "blurred"))
        assert exporter.blurred_dir == str(tmp_path / "blurred")

    def test_default_blurred_dir(self, tmp_path: Path) -> None:
        """未指定 blurred_dir 时自动创建默认目录。."""
        exporter = EvidenceExporter(tmp_path / "evidence")
        assert exporter.blurred_dir is not None
        assert Path(exporter.blurred_dir).exists()

    def test_creates_subdirectories(self, tmp_path: Path) -> None:
        """初始化时创建 attacks/、conversations/、scores/ 子目录。."""
        ev_dir = tmp_path / "evidence"
        EvidenceExporter(ev_dir)
        assert (ev_dir / "attacks").is_dir()
        assert (ev_dir / "conversations").is_dir()
        assert (ev_dir / "scores").is_dir()

    def test_blur_parameters(self, tmp_path: Path) -> None:
        """blur_images 和 blur_radius 正确存储。."""
        exporter = EvidenceExporter(
            tmp_path / "evidence",
            blur_images=True,
            blur_radius=15,
        )
        assert exporter.blur_images is True
        assert exporter.blur_radius == 15

    def test_include_reasoning_trace(self, tmp_path: Path) -> None:
        """include_reasoning_trace 正确存储。."""
        exporter = EvidenceExporter(tmp_path / "evidence", include_reasoning_trace=False)
        assert exporter.include_reasoning_trace is False


# ============================================================
# EvidenceExporter._collect_blurred_images 单元测试
# ============================================================


class TestCollectBlurredImages:
    """_collect_blurred_images 方法测试。."""

    def test_method_exists(self) -> None:
        """_collect_blurred_images 方法存在。."""
        assert hasattr(EvidenceExporter, "_collect_blurred_images")

    def test_returns_empty_when_blur_disabled(self, tmp_path: Path) -> None:
        """blur_images=False 时返回空列表。."""
        exporter = EvidenceExporter(tmp_path / "evidence", blur_images=False)
        assert exporter._collect_blurred_images() == []

    def test_returns_empty_when_no_blurred_files(self, tmp_path: Path) -> None:
        """blur_images=True 但目录无文件时返回空列表。."""
        exporter = EvidenceExporter(
            tmp_path / "evidence",
            blur_images=True,
            blurred_dir=str(tmp_path / "blurred"),
        )
        assert exporter._collect_blurred_images() == []

    def test_collects_blurred_png_files(self, tmp_path: Path) -> None:
        """扫描 blurred_dir 中的 *_blurred.png 文件。."""
        blurred_dir = tmp_path / "blurred"
        blurred_dir.mkdir()

        # 创建模拟模糊图片文件
        (blurred_dir / "img1_blurred.png").write_bytes(b"fake")
        (blurred_dir / "img2_blurred.png").write_bytes(b"fake")
        (blurred_dir / "regular.png").write_bytes(b"fake")

        exporter = EvidenceExporter(
            tmp_path / "evidence",
            blur_images=True,
            blurred_dir=str(blurred_dir),
        )

        result = exporter._collect_blurred_images()
        assert len(result) == 2
        arcnames = [r[0] for r in result]
        assert "blurred/img1_blurred.png" in arcnames
        assert "blurred/img2_blurred.png" in arcnames


# ============================================================
# EvidenceExporter._render_attack_summary_csv 单元测试
# ============================================================


class TestRenderAttackSummaryCsv:
    """_render_attack_summary_csv 方法测试。."""

    def test_empty_results(self, tmp_path: Path) -> None:
        """空结果→仅含表头。."""
        exporter = EvidenceExporter(tmp_path / "evidence")
        csv_output = exporter._render_attack_summary_csv([])
        assert "attack_id" in csv_output
        assert "conversation_id" in csv_output
        lines = csv_output.strip().split("\n")
        assert len(lines) == 1  # 仅表头

    def test_with_mock_results(self, tmp_path: Path) -> None:
        """有结果→正确渲染行。."""
        ar = MagicMock()
        ar.attack_result_id = "atk-001"
        ar.conversation_id = "conv-001"
        ar.objective = "Test objective"
        ar.outcome_reason = "success"
        ar.executed_turns = 3
        ar.execution_time_ms = 1500
        ar.last_score = MagicMock(
            score_value=1.0,
            score_category="jailbreak",
            score_type="true_false",
        )
        ar.__class__.__name__ = "ManyShotJailbreak"
        # get_attack_strategy_identifier for _get_attack_type
        identifier = MagicMock()
        identifier.name = "many_shot"
        identifier.class_name = "ManyShotJailbreak"
        ar.get_attack_strategy_identifier = MagicMock(return_value=identifier)
        ar.outcome = MagicMock()
        ar.outcome.value = "success"

        exporter = EvidenceExporter(tmp_path / "evidence")
        csv_output = exporter._render_attack_summary_csv([ar])
        lines = csv_output.strip().split("\n")
        assert len(lines) == 2  # 表头 + 1 行数据
        assert "atk-001" in lines[1]


# ============================================================
# EvidenceExporter._render_coverage_matrix_csv 单元测试
# ============================================================


class TestRenderCoverageMatrixCsv:
    """_render_coverage_matrix_csv 方法测试。."""

    def test_empty_coverage(self, tmp_path: Path) -> None:
        """空覆盖数据→仅含表头。."""
        exporter = EvidenceExporter(tmp_path / "evidence")
        csv_output = exporter._render_coverage_matrix_csv({})
        assert "owasp_id" in csv_output
        lines = csv_output.strip().split("\n")
        assert len(lines) == 1

    def test_with_coverage_data(self, tmp_path: Path) -> None:
        """有覆盖数据→正确渲染行。."""
        coverage = {
            "LLM01": {
                "name": "Prompt Injection",
                "framework": "LLM",
                "severity": "high",
                "attack_count": 5,
                "success_count": 2,
                "success_rate": 40.0,
                "covered": True,
            },
        }
        exporter = EvidenceExporter(tmp_path / "evidence")
        csv_output = exporter._render_coverage_matrix_csv(coverage)
        lines = csv_output.strip().split("\n")
        assert len(lines) == 2
        assert "LLM01" in lines[1]
        assert "Prompt Injection" in lines[1]


# ============================================================
# EvidenceExporter._render_attack_timeline_csv 单元测试
# ============================================================


class TestRenderAttackTimelineCsv:
    """_render_attack_timeline_csv 方法测试。."""

    def test_empty_results(self, tmp_path: Path) -> None:
        """空结果→仅含表头。."""
        exporter = EvidenceExporter(tmp_path / "evidence")
        csv_output = exporter._render_attack_timeline_csv([])
        assert "timestamp" in csv_output
        lines = csv_output.strip().split("\n")
        assert len(lines) == 1


# ============================================================
# 模块结构验证测试 (源自 _test_evidence_fix.py)
# ============================================================


class TestModuleStructure:
    """验证 EvidenceExporter 模块结构合规性。."""

    def test_no_try_except_import(self) -> None:
        """模块导入部分不使用 try/except ImportError。."""
        import pipeline.reporting.evidence_exporter as mod

        source = inspect.getsource(mod)
        import_section = source[: source.index("class EvidenceExporter")]
        assert "try:" not in import_section, "Still using try/except for imports!"
        assert "except ImportError" not in import_section, "Still using except ImportError!"

    def test_export_methods_use_except_exception(self) -> None:
        """所有 export 方法使用 except Exception 而非窄异常。."""
        for method_name in [
            "_export_attack_markdowns",
            "_export_conversation_markdowns",
            "_export_score_markdowns",
        ]:
            method = getattr(EvidenceExporter, method_name)
            method_src = inspect.getsource(method)
            if "except" in method_src:
                assert "except Exception" in method_src, (
                    f"{method_name} does not use except Exception!"
                )

    def test_blurred_dir_passed_to_printers(self) -> None:
        """blurred_dir 传递给 Attack 和 Conversation 打印机。."""
        attack_src = inspect.getsource(EvidenceExporter._export_attack_markdowns)
        assert "blurred_dir=self.blurred_dir" in attack_src, (
            "blurred_dir not passed to attack printer!"
        )

        conv_src = inspect.getsource(EvidenceExporter._export_conversation_markdowns)
        assert "blurred_dir=self.blurred_dir" in conv_src, (
            "blurred_dir not passed to conversation printer!"
        )

    def test_collect_blurred_images_called_in_export(self) -> None:
        """_collect_blurred_images 在 export_all_evidence 中被调用。."""
        export_src = inspect.getsource(EvidenceExporter.export_all_evidence)
        assert "_collect_blurred_images" in export_src, (
            "_collect_blurred_images not called in export_all_evidence!"
        )


# ============================================================
# 辅助函数测试
# ============================================================


class TestIsSuccessScore:
    """_is_success_score 辅助函数测试。."""

    def test_true_false_with_true(self) -> None:
        """true_false 类型且 value=True→成功。."""
        score = MagicMock(score_type="true_false", score_value=True)
        assert _is_success_score(score) is True

    def test_true_false_with_false(self) -> None:
        """true_false 类型且 value=False→失败。."""
        score = MagicMock(score_type="true_false", score_value=False)
        assert _is_success_score(score) is False

    def test_float_scale_above_threshold(self) -> None:
        """float_scale 类型且 value>0.5→成功。."""
        score = MagicMock(score_type="float_scale", score_value=0.8)
        assert _is_success_score(score) is True

    def test_float_scale_below_threshold(self) -> None:
        """float_scale 类型且 value<=0.5→失败。."""
        score = MagicMock(score_type="float_scale", score_value=0.3)
        assert _is_success_score(score) is False

    def test_float_scale_invalid_value(self) -> None:
        """float_scale 类型且 value 无效→失败。."""
        score = MagicMock(score_type="float_scale", score_value="invalid")
        assert _is_success_score(score) is False

    def test_unknown_score_type(self) -> None:
        """未知类型→失败。."""
        score = MagicMock(score_type="other", score_value=1.0)
        assert _is_success_score(score) is False


class TestFormatTime:
    """_format_time 辅助函数测试。."""

    def test_none(self) -> None:
        """None→N/A。."""
        assert _format_time(None) == "N/A"

    def test_milliseconds(self) -> None:
        """小于 1000ms→显示 ms。."""
        assert _format_time(500) == "500ms"

    def test_seconds(self) -> None:
        """大于等于 1000ms→显示秒。."""
        assert _format_time(1500) == "1.50s"

    def test_invalid_value(self) -> None:
        """无效值→N/A。."""
        assert _format_time("invalid") == "N/A"
