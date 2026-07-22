# -*- coding: utf-8 -*-
"""
P2 功能测试：结构化风险评估 + 动态报告节 + 框架参数传递

验证：
1. risk_assessment.py 结构化模型（RiskAssessment / RiskFinding / RedTeamingOverview）
2. report_generator.py 动态报告节（风险评估 / OWASP 覆盖矩阵 / 修复路线图）
3. deepteam/adapter.py framework 参数支持
4. pipeline/orchestrator.py framework_id 传递
"""

import pytest
import json


# ──────────────────────────────────────────────────────────────────────────────
# 1. RiskAssessment 结构化模型
# ──────────────────────────────────────────────────────────────────────────────

class TestRiskAssessment:
    """验证 RiskAssessment 结构化模型"""

    def test_risk_finding_creation(self):
        from pyrit_ai300.reporting.risk_assessment import RiskFinding
        f = RiskFinding(
            finding_id="F001",
            owasp_id="LLM01",
            owasp_title="Prompt Injection",
            category="prompt_injection",
            severity="critical",
            confidence=0.9,
            risk_category="Security",
            description="Test finding",
            evidence="evidence text",
            remediation="Fix it",
            tool="deepteam",
            source="attack",
        )
        assert f.finding_id == "F001"
        assert f.owasp_id == "LLM01"
        assert f.severity == "critical"

    def test_risk_finding_to_dict(self):
        from pyrit_ai300.reporting.risk_assessment import RiskFinding
        f = RiskFinding(
            finding_id="F001",
            owasp_id="LLM01",
            owasp_title="Prompt Injection",
            category="prompt_injection",
            severity="critical",
        )
        d = f.to_dict()
        assert d["finding_id"] == "F001"
        assert d["owasp_id"] == "LLM01"

    def test_risk_assessment_add_finding(self):
        from pyrit_ai300.reporting.risk_assessment import RiskAssessment, RiskFinding
        assessment = RiskAssessment()
        f = RiskFinding(
            finding_id="F001",
            owasp_id="LLM01",
            owasp_title="Prompt Injection",
            category="prompt_injection",
            severity="critical",
        )
        assessment.add_finding(f)
        assert assessment.total_findings == 1
        assert assessment.critical_count == 1
        assert assessment.overall_risk_level == "critical"

    def test_risk_assessment_severity_levels(self):
        from pyrit_ai300.reporting.risk_assessment import RiskAssessment, RiskFinding
        assessment = RiskAssessment()
        for i, sev in enumerate(["critical", "high", "medium", "low"]):
            assessment.add_finding(RiskFinding(
                finding_id=f"F{i}",
                owasp_id="LLM01",
                owasp_title="Test",
                category="test",
                severity=sev,
            ))
        assert assessment.total_findings == 4
        assert assessment.critical_count == 1
        assert assessment.high_count == 1
        assert assessment.medium_count == 1
        assert assessment.low_count == 1
        assert assessment.overall_risk_level == "critical"

    def test_risk_assessment_filter_by_severity(self):
        from pyrit_ai300.reporting.risk_assessment import RiskAssessment, RiskFinding
        assessment = RiskAssessment()
        assessment.add_finding(RiskFinding("F1", "LLM01", "T1", "c1", "critical"))
        assessment.add_finding(RiskFinding("F2", "LLM02", "T2", "c2", "high"))
        assessment.add_finding(RiskFinding("F3", "LLM01", "T3", "c3", "critical"))
        crit = assessment.get_findings_by_severity("critical")
        assert len(crit) == 2

    def test_risk_assessment_filter_by_owasp(self):
        from pyrit_ai300.reporting.risk_assessment import RiskAssessment, RiskFinding
        assessment = RiskAssessment()
        assessment.add_finding(RiskFinding("F1", "LLM01", "T1", "c1", "critical"))
        assessment.add_finding(RiskFinding("F2", "LLM02", "T2", "c2", "high"))
        llm01 = assessment.get_findings_by_owasp("LLM01")
        assert len(llm01) == 1

    def test_risk_assessment_severity_breakdown(self):
        from pyrit_ai300.reporting.risk_assessment import RiskAssessment, RiskFinding
        assessment = RiskAssessment()
        assessment.add_finding(RiskFinding("F1", "LLM01", "T", "c", "critical"))
        assessment.add_finding(RiskFinding("F2", "LLM02", "T", "c", "high"))
        breakdown = assessment.get_severity_breakdown()
        assert breakdown["critical"] == 1
        assert breakdown["high"] == 1
        assert breakdown["total"] == 2

    def test_risk_assessment_to_dict(self):
        from pyrit_ai300.reporting.risk_assessment import RiskAssessment, RiskFinding
        assessment = RiskAssessment()
        assessment.add_finding(RiskFinding("F1", "LLM01", "T", "c", "critical"))
        d = assessment.to_dict()
        assert d["total_findings"] == 1
        assert "severity_breakdown" in d
        assert "owasp_breakdown" in d
        assert len(d["findings"]) == 1

    def test_risk_assessment_to_json(self):
        from pyrit_ai300.reporting.risk_assessment import RiskAssessment, RiskFinding
        assessment = RiskAssessment()
        assessment.add_finding(RiskFinding("F1", "LLM01", "T", "c", "critical"))
        j = assessment.to_json()
        data = json.loads(j)
        assert data["total_findings"] == 1

    def test_build_risk_assessment_from_empty(self):
        from pyrit_ai300.reporting.risk_assessment import build_risk_assessment
        assessment = build_risk_assessment([])
        assert assessment.total_findings == 0
        assert assessment.overall_risk_level == "none"

    def test_build_risk_assessment_from_results(self):
        from pyrit_ai300.reporting.risk_assessment import build_risk_assessment
        results = [
            {
                "module": "deepteam",
                "module_name": "DeepTeam",
                "owasp_mapping": "LLM01",
                "summary": {"total_payloads": 5, "successful_payloads": 2, "failed_payloads": 3},
                "findings": [
                    {
                        "category": "prompt_injection",
                        "severity": "critical",
                        "confidence": 0.9,
                        "description": "Found prompt injection",
                        "evidence": "Evidence here",
                        "owasp_mapping": "LLM01",
                    }
                ],
            }
        ]
        assessment = build_risk_assessment(results)
        assert assessment.total_findings == 1
        assert assessment.critical_count == 1
        assert "LLM01" in assessment.owasp_coverage


# ──────────────────────────────────────────────────────────────────────────────
# 2. RedTeamingOverview
# ──────────────────────────────────────────────────────────────────────────────

class TestRedTeamingOverview:
    """验证 RedTeamingOverview 概览模型"""

    def test_from_risk_assessment(self):
        from pyrit_ai300.reporting.risk_assessment import (
            RiskAssessment, RiskFinding, RedTeamingOverview,
        )
        assessment = RiskAssessment()
        assessment.add_finding(RiskFinding("F1", "LLM01", "T", "c", "critical"))
        overview = RedTeamingOverview.from_risk_assessment(
            assessment, target="https://example.com", tools_used=["deepteam", "native_probe"]
        )
        assert overview.target == "https://example.com"
        assert overview.overall_risk_level == "critical"
        assert overview.total_findings == 1
        assert "deepteam" in overview.tools_used
        assert "native_probe" in overview.tools_used

    def test_overview_to_dict(self):
        from pyrit_ai300.reporting.risk_assessment import (
            RiskAssessment, RiskFinding, RedTeamingOverview,
        )
        assessment = RiskAssessment()
        assessment.add_finding(RiskFinding("F1", "LLM01", "T", "c", "critical"))
        overview = RedTeamingOverview.from_risk_assessment(assessment)
        d = overview.to_dict()
        assert d["overall_risk_level"] == "critical"
        assert d["total_findings"] == 1


# ──────────────────────────────────────────────────────────────────────────────
# 3. ReportGenerator 动态报告节
# ──────────────────────────────────────────────────────────────────────────────

class TestDynamicReportSections:
    """验证 report_generator.py 的 3 个动态报告节"""

    def test_risk_assessment_dynamic_with_findings(self):
        """风险评估节包含动态内容"""
        from pyrit_ai300.reporting.report_generator import ReportGenerator
        results = [
            {
                "module": "deepteam",
                "owasp_mapping": "LLM01",
                "summary": {"total_payloads": 5, "successful_payloads": 2, "failed_payloads": 3},
                "findings": [
                    {
                        "category": "prompt_injection",
                        "severity": "critical",
                        "confidence": 0.9,
                        "owasp_mapping": "LLM01",
                    }
                ],
            }
        ]
        gen = ReportGenerator(results=results)
        section = gen._risk_assessment()
        assert "CRITICAL" in section or "critical" in section.lower()
        assert "Severity Breakdown" in section or "Risk Matrix" in section

    def test_risk_assessment_dynamic_empty(self):
        """风险评估节在空结果时正常降级"""
        from pyrit_ai300.reporting.report_generator import ReportGenerator
        gen = ReportGenerator(results=[])
        section = gen._risk_assessment()
        # 应该有内容（即使是降级的静态版本）
        assert "Risk Assessment" in section

    def test_owasp_coverage_matrix_exists(self):
        """OWASP 覆盖矩阵方法存在且返回内容"""
        from pyrit_ai300.reporting.report_generator import ReportGenerator
        gen = ReportGenerator(results=[])
        assert hasattr(gen, "_owasp_coverage_matrix")
        section = gen._owasp_coverage_matrix()
        assert "OWASP Coverage" in section or "Coverage" in section

    def test_owasp_coverage_matrix_has_all_llm_ids(self):
        """OWASP 覆盖矩阵包含所有 LLM01-LLM10"""
        from pyrit_ai300.reporting.report_generator import ReportGenerator
        gen = ReportGenerator(results=[])
        section = gen._owasp_coverage_matrix()
        for i in range(1, 11):
            assert f"LLM{i:02d}" in section, f"LLM{i:02d} not in coverage matrix"

    def test_owasp_coverage_matrix_has_all_asi_ids(self):
        """OWASP 覆盖矩阵包含所有 ASI01-ASI10"""
        from pyrit_ai300.reporting.report_generator import ReportGenerator
        gen = ReportGenerator(results=[])
        section = gen._owasp_coverage_matrix()
        for i in range(1, 11):
            assert f"ASI{i:02d}" in section, f"ASI{i:02d} not in coverage matrix"

    def test_remediation_roadmap_exists(self):
        """修复路线图方法存在且返回内容"""
        from pyrit_ai300.reporting.report_generator import ReportGenerator
        gen = ReportGenerator(results=[])
        assert hasattr(gen, "_remediation_roadmap")
        section = gen._remediation_roadmap()
        assert "Remediation Roadmap" in section or "Roadmap" in section

    def test_remediation_roadmap_with_findings(self):
        """修复路线图在有发现时包含优先级排序"""
        from pyrit_ai300.reporting.report_generator import ReportGenerator
        results = [
            {
                "module": "deepteam",
                "owasp_mapping": "LLM01",
                "summary": {"total_payloads": 5, "successful_payloads": 2, "failed_payloads": 3},
                "findings": [
                    {
                        "category": "prompt_injection",
                        "severity": "critical",
                        "confidence": 0.9,
                        "owasp_mapping": "LLM01",
                    }
                ],
            }
        ]
        gen = ReportGenerator(results=results)
        section = gen._remediation_roadmap()
        assert "P0" in section or "Immediate" in section or "Critical" in section

    def test_generate_markdown_includes_new_sections(self):
        """生成的 Markdown 包含新报告节"""
        from pyrit_ai300.reporting.report_generator import ReportGenerator
        gen = ReportGenerator(results=[])
        md = gen._generate_markdown()
        assert "OWASP Coverage" in md
        assert "Remediation Roadmap" in md


# ──────────────────────────────────────────────────────────────────────────────
# 4. DeepTeam Adapter framework 参数
# ──────────────────────────────────────────────────────────────────────────────

class TestDeepTeamAdapterFramework:
    """验证 DeepTeam 适配器的 framework 参数支持"""

    def test_filter_by_depth_quick(self):
        """_filter_by_depth 正确筛选 quick 深度"""
        from pyrit_ai300.recon.adapters.deepteam.adapter import DeepTeamAdapter
        vuln_ids = ["LLM01", "LLM02", "LLM03", "LLM10", "ASI01"]
        result = DeepTeamAdapter._filter_by_depth(vuln_ids, "quick")
        assert "LLM01" in result
        assert "LLM02" in result
        assert "LLM03" not in result
        assert "ASI01" not in result

    def test_filter_by_depth_standard(self):
        """_filter_by_depth 正确筛选 standard 深度"""
        from pyrit_ai300.recon.adapters.deepteam.adapter import DeepTeamAdapter
        vuln_ids = ["LLM01", "LLM02", "LLM03", "LLM10", "ASI01"]
        result = DeepTeamAdapter._filter_by_depth(vuln_ids, "standard")
        assert "LLM01" in result
        assert "LLM03" in result
        assert "LLM10" not in result
        assert "ASI01" not in result

    def test_filter_by_depth_deep(self):
        """_filter_by_depth 正确筛选 deep 深度（全量）"""
        from pyrit_ai300.recon.adapters.deepteam.adapter import DeepTeamAdapter
        vuln_ids = ["LLM01", "LLM02", "LLM03", "LLM10", "ASI01"]
        result = DeepTeamAdapter._filter_by_depth(vuln_ids, "deep")
        assert len(result) == len(vuln_ids)


# ──────────────────────────────────────────────────────────────────────────────
# 5. Pipeline Orchestrator framework_id 传递
# ──────────────────────────────────────────────────────────────────────────────

class TestPipelineFrameworkId:
    """验证 PipelineOrchestrator 的 framework_id 参数"""

    def test_run_method_has_framework_id_param(self):
        """run() 方法接受 framework_id 参数"""
        from pyrit_ai300.pipeline.orchestrator import PipelineOrchestrator
        import inspect
        sig = inspect.signature(PipelineOrchestrator.run)
        assert "framework_id" in sig.parameters

    def test_framework_id_default_none(self):
        """framework_id 默认值为 None"""
        from pyrit_ai300.pipeline.orchestrator import PipelineOrchestrator
        import inspect
        sig = inspect.signature(PipelineOrchestrator.run)
        param = sig.parameters["framework_id"]
        assert param.default is None
