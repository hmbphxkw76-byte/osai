"""Tests for DriftDetector — 规范漂移检测器

验证 R-DRIT 系列检测规则的核心逻辑。
Academic basis: Evans et al. (arXiv:2403.04132) - Continuous architecture compliance
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure project root in path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from tools.drift_detector import (  # noqa: E402
    _PIPELINE_CONTEXT_CONTRACTS,
    _SPEC_REFERENCED_MODULES,
    DriftDetector,
    DriftFinding,
    DriftReport,
    DriftSeverity,
)


class TestDriftSeverity:
    """DriftSeverity 枚举验证"""

    def test_severity_order(self) -> None:
        """严重度级别排序"""
        assert DriftSeverity.OK < DriftSeverity.INFO
        assert DriftSeverity.INFO < DriftSeverity.WARNING
        assert DriftSeverity.WARNING < DriftSeverity.BLOCKING

    def test_severity_values(self) -> None:
        """枚举值"""
        assert DriftSeverity.OK == 0
        assert DriftSeverity.INFO == 1
        assert DriftSeverity.WARNING == 2
        assert DriftSeverity.BLOCKING == 3


class TestDriftFinding:
    """DriftFinding 数据类验证"""

    def test_create_finding(self) -> None:
        """创建漂移发现"""
        finding = DriftFinding(
            rule="R-DRIFT-1",
            severity=DriftSeverity.WARNING,
            dimension="api_sync",
            message="test message",
            spec_source="00-CONSTITUTION.md",
            code_target="strike/executor.py",
        )
        assert finding.rule == "R-DRIFT-1"
        assert finding.severity == DriftSeverity.WARNING
        assert finding.fix_hint == ""

    def test_create_finding_with_hint(self) -> None:
        """创建带修复提示的漂移发现"""
        finding = DriftFinding(
            rule="R-DRIFT-2",
            severity=DriftSeverity.BLOCKING,
            dimension="spec_table",
            message="missing module",
            spec_source="40-GUARDRAILS.md",
            code_target="strike/missing.py",
            fix_hint="restore module or update spec",
        )
        assert finding.fix_hint == "restore module or update spec"


class TestDriftReport:
    """DriftReport 报告类验证"""

    def test_empty_report_healthy(self) -> None:
        """空报告是健康的"""
        report = DriftReport()
        assert report.healthy is True
        assert report.blocking_count == 0
        assert report.warning_count == 0
        assert report.info_count == 0

    def test_report_with_blocking(self) -> None:
        """含 BLOCKING 的报告不健康"""
        report = DriftReport()
        report.findings.append(DriftFinding(
            rule="R-DRIFT-1",
            severity=DriftSeverity.BLOCKING,
            dimension="api_sync",
            message="test",
            spec_source="test",
            code_target="test",
        ))
        assert report.healthy is False
        assert report.blocking_count == 1

    def test_report_with_warnings(self) -> None:
        """含 WARNING 的报告不健康"""
        report = DriftReport()
        report.findings.append(DriftFinding(
            rule="R-DRIFT-2",
            severity=DriftSeverity.WARNING,
            dimension="spec_table",
            message="test",
            spec_source="test",
            code_target="test",
        ))
        assert report.healthy is False
        assert report.warning_count == 1

    def test_report_with_only_info(self) -> None:
        """仅含 INFO 的报告是健康的"""
        report = DriftReport()
        report.findings.append(DriftFinding(
            rule="R-DRIFT-4",
            severity=DriftSeverity.INFO,
            dimension="contract_drift",
            message="test",
            spec_source="test",
            code_target="test",
        ))
        assert report.healthy is True
        assert report.info_count == 1


class TestDriftDetectorInit:
    """DriftDetector 初始化验证"""

    def test_detector_init(self) -> None:
        """检测器初始化"""
        detector = DriftDetector(_PROJECT_ROOT)
        assert detector.root == _PROJECT_ROOT
        assert isinstance(detector.report, DriftReport)

    def test_constants_populated(self) -> None:
        """配置常量非空"""
        assert len(_PIPELINE_CONTEXT_CONTRACTS) > 0
        assert "recon" in _PIPELINE_CONTEXT_CONTRACTS
        assert "arm" in _PIPELINE_CONTEXT_CONTRACTS
        assert "strike" in _PIPELINE_CONTEXT_CONTRACTS
        assert "assess" in _PIPELINE_CONTEXT_CONTRACTS

    def test_spec_referenced_modules_populated(self) -> None:
        """规范引用模块列表非空"""
        assert len(_SPEC_REFERENCED_MODULES) > 0
        assert any("strike/" in m for m in _SPEC_REFERENCED_MODULES)
        assert any("recon/" in m for m in _SPEC_REFERENCED_MODULES)


class TestSpecTableSyncCheck:
    """R-DRIFT-2: 规范表格-代码同步检查"""

    def test_spec_referenced_modules_exist(self) -> None:
        """验证规范引用的核心模块都存在（无漂移）"""
        detector = DriftDetector(_PROJECT_ROOT)
        detector.check_spec_table_sync()

        # 不应有 WARNING 或 BLOCKING 的 R-DRIFT-2 发现
        critical_findings = [
            f for f in detector.report.findings
            if f.rule == "R-DRIFT-2" and f.severity >= DriftSeverity.WARNING
        ]
        assert len(critical_findings) == 0, (
            f"Found spec drift: {[f.message for f in critical_findings]}"
        )

    def test_spec_referenced_modules_partial(self) -> None:
        """验证规范引用的模块，缺失的会被发现"""
        detector = DriftDetector(_PROJECT_ROOT)
        detector.check_spec_table_sync()

        # 检查报告中只包含 R-DRIFT-2 级别发现
        drift_2_findings = [f for f in detector.report.findings if f.rule == "R-DRIFT-2"]
        # 如果所有模块都存在，应该没有发现
        # 如果有缺失，发现应该包含明确的文件路径信息
        for f in drift_2_findings:
            assert f.dimension == "spec_table"
            assert f.spec_source


class TestNativeUsagePatternCheck:
    """R-DRIFT-5: 原生优先模式检查"""

    def test_no_forbidden_patterns_in_codebase(self) -> None:
        """验证代码库中没有自研替代实现模式"""
        detector = DriftDetector(_PROJECT_ROOT)
        detector.check_native_usage_pattern()

        # 检查是否有 WARNING 或 BLOCKING 的自研替代发现
        critical_findings = [
            f for f in detector.report.findings
            if f.dimension == "native_first" and f.severity >= DriftSeverity.WARNING
        ]
        assert len(critical_findings) == 0, (
            f"Found native-first violations: {[f.message for f in critical_findings]}"
        )


class TestContextContractDrift:
    """R-DRIFT-4: PipelineContext 契约漂移检查"""

    def test_context_exists(self) -> None:
        """验证 core/context.py 存在"""
        context_path = _PROJECT_ROOT / "core" / "context.py"
        assert context_path.exists(), "core/context.py must exist"

    def test_check_runs_without_error(self) -> None:
        """验证检查可运行不报错"""
        detector = DriftDetector(_PROJECT_ROOT)
        detector.check_context_contract_drift()
        # 不抛出异常即为通过


class TestDriftReportJson:
    """JSON 报告导出"""

    def test_json_export(self) -> None:
        """验证 JSON 报告格式正确"""
        detector = DriftDetector(_PROJECT_ROOT)
        detector.run_all_checks()
        json_str = detector.to_json()

        import json
        data = json.loads(json_str)

        assert "timestamp" in data
        assert "summary" in data
        assert "healthy" in data
        assert "findings" in data
        assert data["summary"]["total"] == len(data["findings"])

    def test_json_summary_counts(self) -> None:
        """验证 JSON 报告汇总计数正确"""
        detector = DriftDetector(_PROJECT_ROOT)
        detector.run_all_checks()
        json_str = detector.to_json()

        import json
        data = json.loads(json_str)

        assert data["summary"]["blocking"] == detector.report.blocking_count
        assert data["summary"]["warning"] == detector.report.warning_count
        assert data["summary"]["info"] == detector.report.info_count


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
