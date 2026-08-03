# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""ReconTrigger 单元测试。.

测试覆盖:
  1. ReconTriggerResult 数据模型
  2. trigger_recon 跳过逻辑 (无 --recon 且非 Web App)
  3. trigger_recon 降级逻辑 (recon-pipeline 未安装)
  4. _select_probes 探针选择策略
  5. _build_recon_summary 摘要构建

> **日期**: 2026-8-3
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from pipeline.integrations.recon_trigger import (
    ReconTriggerResult,
    _build_recon_summary,
    _select_probes,
    trigger_recon,
)
from pipeline.integrations.target_classifier import TargetClassification

# ============================================================
# ReconTriggerResult 数据模型测试
# ============================================================


class TestReconTriggerResult:
    """ReconTriggerResult 数据模型测试。"""

    def test_default_values(self) -> None:
        """默认值全部为空/False。"""
        result = ReconTriggerResult()
        assert result.success is False
        assert result.report is None
        assert result.probe_count == 0
        assert result.duration_seconds == 0.0
        assert result.error == ""
        assert result.skipped_reason == ""

    def test_success_result(self) -> None:
        """成功结果。"""
        mock_report = MagicMock()
        result = ReconTriggerResult(
            success=True,
            report=mock_report,
            probe_count=5,
            duration_seconds=12.5,
        )
        assert result.success is True
        assert result.report is mock_report
        assert result.probe_count == 5
        assert result.duration_seconds == 12.5


# ============================================================
# trigger_recon 跳过逻辑测试
# ============================================================


class TestTriggerReconSkipped:
    """trigger_recon 跳过逻辑测试。"""

    @pytest.mark.asyncio
    async def test_skip_no_recon_flag_and_not_web_app(self) -> None:
        """无 --recon 标志且目标非 Web App → 跳过。"""
        ctx = MagicMock()
        ctx.args = SimpleNamespace(recon=False)

        classification = TargetClassification(
            target_type="llm_api_platform",
            target_url="https://api.example.com/v1/chat/completions",
        )

        result = await trigger_recon(ctx, "https://api.example.com/v1/chat/completions", classification)

        assert result.success is False
        assert "跳过侦察" in result.skipped_reason

    @pytest.mark.asyncio
    async def test_skip_recon_not_installed(self) -> None:
        """recon-pipeline 未安装 → 跳过。"""
        ctx = MagicMock()
        ctx.args = SimpleNamespace(recon=True)

        classification = TargetClassification(
            target_type="llm_web_app",
            target_url="https://chat.example.com",
        )

        with patch.dict("sys.modules", {"core": None, "core.pipeline": None, "core.session": None}):
            result = await trigger_recon(ctx, "https://chat.example.com", classification)

        assert result.success is False
        assert "未安装" in result.skipped_reason


# ============================================================
# _select_probes 探针选择测试
# ============================================================


class TestSelectProbes:
    """_select_probes 探针选择策略测试。"""

    def test_web_app_with_page(self) -> None:
        """Web App + 浏览器 → 包含 DOM 和 Network 探针。"""
        classification = TargetClassification(
            target_type="llm_web_app",
            target_url="https://chat.example.com",
        )

        probes = _select_probes(classification, has_page=True)
        probe_names = [type(p).__name__ for p in probes]

        assert "DOMProbe" in probe_names
        assert "NetworkProbe" in probe_names
        assert "LLMProbe" in probe_names
        assert "RAGProbe" in probe_names

    def test_web_app_without_page(self) -> None:
        """Web App 无浏览器 → 不包含 DOM 探针。"""
        classification = TargetClassification(
            target_type="llm_web_app",
            target_url="https://chat.example.com",
        )

        probes = _select_probes(classification, has_page=False)
        probe_names = [type(p).__name__ for p in probes]

        # 不应包含需要浏览器的探针
        assert "DOMProbe" not in probe_names
        assert "NetworkProbe" not in probe_names
        # 但应包含 HTTP 探针
        assert "LLMProbe" in probe_names
        assert "RAGProbe" in probe_names

    def test_api_platform(self) -> None:
        """API Platform → 包含 Endpoint 和 LLM 探针。"""
        classification = TargetClassification(
            target_type="llm_api_platform",
            target_url="https://api.example.com/v1/chat/completions",
        )

        probes = _select_probes(classification, has_page=False)
        probe_names = [type(p).__name__ for p in probes]

        assert "LLMProbe" in probe_names
        assert "EmbeddingProbe" in probe_names

    def test_unknown_type(self) -> None:
        """unknown 类型 → 仅基础探针。"""
        classification = TargetClassification(
            target_type="unknown",
            target_url="https://example.com",
        )

        probes = _select_probes(classification, has_page=False)
        assert len(probes) >= 1


# ============================================================
# _build_recon_summary 测试
# ============================================================


class TestBuildReconSummary:
    """_build_recon_summary 摘要构建测试。"""

    def test_summary_with_empty_report(self) -> None:
        """空 ReconReport → 摘要字段全为零/空。"""
        report = MagicMock()
        report.endpoints = []
        report.injection_surfaces = []
        report.recommendations = []
        report.auth_type = ""

        summary = _build_recon_summary(report, "https://example.com")

        assert summary["target_url"] == "https://example.com"
        assert summary["endpoint_count"] == 0
        assert summary["surface_count"] == 0
        assert summary["recommendation_count"] == 0

    def test_summary_with_data(self) -> None:
        """有数据的 ReconReport → 摘要正确反映。"""
        report = MagicMock()
        report.endpoints = [MagicMock(), MagicMock(), MagicMock()]
        report.injection_surfaces = [MagicMock(), MagicMock()]
        report.recommendations = []
        report.auth_type = "same_domain"

        summary = _build_recon_summary(report, "https://example.com")

        assert summary["endpoint_count"] == 3
        assert summary["surface_count"] == 2
        assert summary["auth_type"] == "same_domain"
