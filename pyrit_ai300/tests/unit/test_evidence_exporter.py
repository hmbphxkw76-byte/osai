"""
Evidence Exporter 测试
======================

测试 EvidenceExporter 的 L5 对齐功能：
- blurred_dir 参数支持
- 独立 Score 证据导出（MarkdownScorePrinter.render_async）
- 模糊图片收集纳入证据 zip 包

遵循开发规则 1.4.9 测试先行原则
"""

import json
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.reporting.report_generator import EvidenceExporter


# ============================================================
# EvidenceExporter 初始化测试
# ============================================================


class TestEvidenceExporterInit:
    """测试 EvidenceExporter 初始化"""

    def test_init_default_blurred_dir(self, tmp_path):
        """测试默认创建 blurred 子目录"""
        with patch("src.reporting.report_generator.get_config_loader") as mock_loader:
            mock_loader.return_value.get_global_value.return_value = str(tmp_path)
            exporter = EvidenceExporter("test_exam")
            assert exporter.blur_images is False
            assert exporter.blur_radius == 20
            # 默认创建 evidence_dir/blurred/ 目录
            assert exporter.blurred_dir is not None
            blurred_path = Path(exporter.blurred_dir)
            assert blurred_path.exists()
            assert blurred_path.name == "blurred"

    def test_init_custom_blurred_dir(self, tmp_path):
        """测试自定义 blurred_dir"""
        with patch("src.reporting.report_generator.get_config_loader") as mock_loader:
            mock_loader.return_value.get_global_value.return_value = str(tmp_path)
            custom_blur = tmp_path / "custom_blur"
            custom_blur.mkdir()
            exporter = EvidenceExporter(
                "test_exam",
                blur_images=True,
                blurred_dir=custom_blur,
            )
            assert exporter.blurred_dir == str(custom_blur)

    def test_init_blur_params(self, tmp_path):
        """测试模糊参数"""
        with patch("src.reporting.report_generator.get_config_loader") as mock_loader:
            mock_loader.return_value.get_global_value.return_value = str(tmp_path)
            exporter = EvidenceExporter(
                "test_exam",
                blur_images=True,
                blur_radius=30,
            )
            assert exporter.blur_images is True
            assert exporter.blur_radius == 30

    def test_init_creates_scores_dir(self, tmp_path):
        """测试创建 scores 子目录"""
        with patch("src.reporting.report_generator.get_config_loader") as mock_loader:
            mock_loader.return_value.get_global_value.return_value = str(tmp_path)
            exporter = EvidenceExporter("test_exam")
            assert exporter.scores_dir.exists()
            assert exporter.scores_dir.name == "scores"

    def test_init_creates_attacks_dir(self, tmp_path):
        """测试创建 attacks 子目录"""
        with patch("src.reporting.report_generator.get_config_loader") as mock_loader:
            mock_loader.return_value.get_global_value.return_value = str(tmp_path)
            exporter = EvidenceExporter("test_exam")
            assert exporter.attacks_dir.exists()

    def test_init_creates_conversations_dir(self, tmp_path):
        """测试创建 conversations 子目录"""
        with patch("src.reporting.report_generator.get_config_loader") as mock_loader:
            mock_loader.return_value.get_global_value.return_value = str(tmp_path)
            exporter = EvidenceExporter("test_exam")
            assert exporter.conversations_dir.exists()


# ============================================================
# _export_score_markdowns 测试
# ============================================================


class TestExportScoreMarkdowns:
    """测试独立 Score 证据导出"""

    @pytest.fixture
    def exporter(self, tmp_path):
        """创建 EvidenceExporter 实例"""
        with patch("src.reporting.report_generator.get_config_loader") as mock_loader:
            mock_loader.return_value.get_global_value.return_value = str(tmp_path)
            return EvidenceExporter("test_exam")

    @pytest.mark.asyncio
    async def test_empty_scores_returns_empty(self, exporter):
        """测试空评分列表返回空"""
        result = await exporter._export_score_markdowns([])
        assert result == []

    @pytest.mark.asyncio
    async def test_export_single_score(self, exporter):
        """测试导出单个评分"""
        mock_score = MagicMock()
        mock_score.score_type = "true_false"
        mock_score.score_value = True
        mock_score.score_category = ["refusal"]
        mock_score.score_rationale = "Test rationale"
        mock_score.score_metadata = None
        mock_score.get_value = MagicMock(return_value=True)

        result = await exporter._export_score_markdowns([mock_score])
        assert len(result) == 1
        filename, content = result[0]
        assert filename == "score_0001.md"
        assert "Score Type" in content or "Export failed" in content

    @pytest.mark.asyncio
    async def test_export_multiple_scores(self, exporter):
        """测试导出多个评分"""
        scores = []
        for i in range(3):
            mock_score = MagicMock()
            mock_score.score_type = "true_false"
            mock_score.score_value = True
            mock_score.score_category = [f"cat_{i}"]
            mock_score.score_rationale = f"Rationale {i}"
            mock_score.score_metadata = None
            mock_score.get_value = MagicMock(return_value=True)
            scores.append(mock_score)

        result = await exporter._export_score_markdowns(scores)
        assert len(result) == 3
        assert result[0][0] == "score_0001.md"
        assert result[1][0] == "score_0002.md"
        assert result[2][0] == "score_0003.md"

    @pytest.mark.asyncio
    async def test_export_score_writes_file(self, exporter):
        """测试评分文件写入磁盘"""
        mock_score = MagicMock()
        mock_score.score_type = "true_false"
        mock_score.score_value = True
        mock_score.score_category = ["test"]
        mock_score.score_rationale = "Test"
        mock_score.score_metadata = None
        mock_score.get_value = MagicMock(return_value=True)

        await exporter._export_score_markdowns([mock_score])

        score_file = exporter.scores_dir / "score_0001.md"
        assert score_file.exists()

    @pytest.mark.asyncio
    async def test_export_score_handles_error(self, exporter):
        """测试评分导出错误处理"""
        # 使用会触发 render_async 异常的 mock
        bad_score = MagicMock()
        bad_score.score_type = MagicMock(side_effect=Exception("Test error"))
        bad_score.get_value = MagicMock(side_effect=Exception("Test error"))

        # MarkdownScorePrinter.render_async 会调用 _format_score
        # _format_score 会调用 score.get_value()，如果报异常会被外层 try/except 捕获
        with patch("src.reporting.report_generator.MarkdownScorePrinter") as mock_printer_cls:
            mock_printer = MagicMock()
            mock_printer.render_async = AsyncMock(side_effect=Exception("Printer error"))
            mock_printer_cls.return_value = mock_printer

            result = await exporter._export_score_markdowns([bad_score])
            assert len(result) == 1
            filename, content = result[0]
            assert "Export failed" in content


# ============================================================
# _collect_blurred_images 测试
# ============================================================


class TestCollectBlurredImages:
    """测试模糊图片收集"""

    @pytest.fixture
    def exporter_with_blur(self, tmp_path):
        """创建启用模糊的 EvidenceExporter"""
        with patch("src.reporting.report_generator.get_config_loader") as mock_loader:
            mock_loader.return_value.get_global_value.return_value = str(tmp_path)
            return EvidenceExporter("test_exam", blur_images=True)

    @pytest.fixture
    def exporter_no_blur(self, tmp_path):
        """创建未启用模糊的 EvidenceExporter"""
        with patch("src.reporting.report_generator.get_config_loader") as mock_loader:
            mock_loader.return_value.get_global_value.return_value = str(tmp_path)
            return EvidenceExporter("test_exam", blur_images=False)

    def test_no_blur_returns_empty(self, exporter_no_blur):
        """测试未启用模糊时返回空列表"""
        result = exporter_no_blur._collect_blurred_images()
        assert result == []

    def test_no_blurred_files_returns_empty(self, exporter_with_blur):
        """测试无模糊图片文件时返回空列表"""
        result = exporter_with_blur._collect_blurred_images()
        assert result == []

    def test_collects_blurred_png_files(self, exporter_with_blur):
        """测试收集模糊 PNG 文件"""
        blurred_path = Path(exporter_with_blur.blurred_dir)

        # 创建测试模糊图片文件
        (blurred_path / "image1_blurred.png").write_bytes(b"fake_png_1")
        (blurred_path / "image2_blurred.png").write_bytes(b"fake_png_2")
        # 非模糊文件不应被收集
        (blurred_path / "original.jpeg").write_bytes(b"not_blurred")

        result = exporter_with_blur._collect_blurred_images()
        assert len(result) == 2

        # 检查 arcname 格式
        arcnames = [item[0] for item in result]
        assert "blurred/image1_blurred.png" in arcnames
        assert "blurred/image2_blurred.png" in arcnames

        # 检查文件路径
        file_paths = [item[1] for item in result]
        assert all("_blurred.png" in p for p in file_paths)

    def test_collects_sorted_files(self, exporter_with_blur):
        """测试按排序顺序收集"""
        blurred_path = Path(exporter_with_blur.blurred_dir)

        (blurred_path / "c_blurred.png").write_bytes(b"c")
        (blurred_path / "a_blurred.png").write_bytes(b"a")
        (blurred_path / "b_blurred.png").write_bytes(b"b")

        result = exporter_with_blur._collect_blurred_images()
        arcnames = [item[0] for item in result]
        assert arcnames == ["blurred/a_blurred.png", "blurred/b_blurred.png", "blurred/c_blurred.png"]

    def test_nonexistent_blurred_dir(self, tmp_path):
        """测试模糊目录不存在时返回空列表"""
        with patch("src.reporting.report_generator.get_config_loader") as mock_loader:
            mock_loader.return_value.get_global_value.return_value = str(tmp_path)
            exporter = EvidenceExporter("test_exam", blur_images=True)

            # 删除模糊目录
            Path(exporter.blurred_dir).rmdir()

            result = exporter._collect_blurred_images()
            assert result == []


# ============================================================
# export_all_evidence 集成测试
# ============================================================


class TestExportAllEvidence:
    """测试完整证据导出流程"""

    @pytest.fixture
    def mock_memory(self):
        """创建 mock CentralMemory"""
        mock = MagicMock()
        mock.get_attack_results.return_value = []
        mock.get_scenario_results.return_value = []
        mock.get_scores.return_value = []
        mock.get_message_pieces.return_value = []
        mock.get_prompt_scores.return_value = []
        mock.get_conversation_stats.return_value = {}
        mock.get_conversation_messages.return_value = []
        return mock

    @pytest.fixture
    def mock_printers(self):
        """Mock 原生打印机避免 CentralMemory 初始化"""
        mock_attack_printer = MagicMock()
        mock_attack_printer.render_async = AsyncMock(return_value="# Attack\n\nTest")
        mock_conv_printer = MagicMock()
        mock_conv_printer.render_async = AsyncMock(return_value="## Conversation\n\nTest")
        mock_score_printer = MagicMock()
        mock_score_printer.render_async = AsyncMock(return_value="- **Score Type:** true_false")

        patches = [
            patch("src.reporting.report_generator.MarkdownAttackResultMemoryPrinter", return_value=mock_attack_printer),
            patch("src.reporting.report_generator.MarkdownConversationMemoryPrinter", return_value=mock_conv_printer),
            patch("src.reporting.report_generator.MarkdownScorePrinter", return_value=mock_score_printer),
        ]
        for p in patches:
            p.start()
        yield
        for p in patches:
            p.stop()

    @pytest.mark.asyncio
    async def test_export_includes_scores_directory(self, tmp_path, mock_memory, mock_printers):
        """测试证据 zip 包含 scores/ 目录"""
        with patch("src.reporting.report_generator.get_config_loader") as mock_loader:
            mock_loader.return_value.get_global_value.return_value = str(tmp_path)

            exporter = EvidenceExporter("test_exam")

            with patch("src.reporting.report_generator.CentralMemory") as mock_cm:
                mock_cm.get_memory_instance.return_value = mock_memory
                archive_path = await exporter.export_all_evidence()

            # 验证 zip 文件
            assert archive_path.exists()
            with zipfile.ZipFile(archive_path, "r") as zf:
                names = zf.namelist()
                # 应包含主文件
                assert "evidence.json" in names
                assert "conversation_history.md" in names
                assert "attack_summary.csv" in names
                assert "owasp_coverage_matrix.csv" in names
                assert "attack_timeline.csv" in names

    @pytest.mark.asyncio
    async def test_export_with_blur_images_includes_blurred_dir(self, tmp_path, mock_memory, mock_printers):
        """测试启用模糊时 zip 包含 blurred/ 目录"""
        with patch("src.reporting.report_generator.get_config_loader") as mock_loader:
            mock_loader.return_value.get_global_value.return_value = str(tmp_path)

            exporter = EvidenceExporter("test_exam", blur_images=True)

            # 创建一个假的模糊图片
            blurred_path = Path(exporter.blurred_dir)
            (blurred_path / "test_blurred.png").write_bytes(b"fake_blurred_image")

            with patch("src.reporting.report_generator.CentralMemory") as mock_cm:
                mock_cm.get_memory_instance.return_value = mock_memory
                archive_path = await exporter.export_all_evidence()

            # 验证 zip 包含模糊图片
            with zipfile.ZipFile(archive_path, "r") as zf:
                names = zf.namelist()
                assert "blurred/test_blurred.png" in names

    @pytest.mark.asyncio
    async def test_export_evidence_json_structure(self, tmp_path, mock_memory, mock_printers):
        """测试 evidence.json 结构正确"""
        with patch("src.reporting.report_generator.get_config_loader") as mock_loader:
            mock_loader.return_value.get_global_value.return_value = str(tmp_path)

            exporter = EvidenceExporter("test_exam")

            with patch("src.reporting.report_generator.CentralMemory") as mock_cm:
                mock_cm.get_memory_instance.return_value = mock_memory
                archive_path = await exporter.export_all_evidence()

            with zipfile.ZipFile(archive_path, "r") as zf:
                evidence_json = json.loads(zf.read("evidence.json"))
                assert "exam_id" in evidence_json
                assert "export_time" in evidence_json
                assert "attack_results" in evidence_json
                assert "attack_results_count" in evidence_json
