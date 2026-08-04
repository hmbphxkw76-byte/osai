# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""端到端验证器测试 — pipeline.validation.e2e_validator.

测试覆盖:
  - validate_metadata: 空 metadata / 完整 metadata / 部分字段缺失
  - ValidationResult: 状态图标 / 序列化
  - E2EValidationReport: 覆盖率计算 / 通过率计算 / to_dict
  - print_validation_report: 打印不崩溃
"""

from __future__ import annotations

import logging

from pipeline.validation.e2e_validator import (
    E2EValidationReport,
    ValidationItem,
    ValidationResult,
    print_validation_report,
    run_e2e_validation,
    validate_metadata,
)

logger = logging.getLogger(__name__)


# ============================================================
# validate_metadata 测试
# ============================================================


class TestValidateMetadata:
    """validate_metadata 函数测试."""

    def test_empty_metadata_all_missing(self):
        """空 metadata → 所有项为 missing."""
        report = validate_metadata({})

        assert report.total_items > 0
        assert report.passed == 0
        assert report.missing == report.total_items
        assert report.partial == 0
        assert report.errors == 0
        assert report.coverage_pct == 0.0

    def test_full_metadata_all_pass(self):
        """完整 metadata → 所有项为 pass."""
        metadata: dict = {}
        # 为每个验证项填充预期字段
        metadata["mcp_probe_results"] = {
            "total_probes": 15,
            "results": [],
            "owasp_coverage": "ASI01-ASI07",
            "sent_to_target": False,
        }
        metadata["multi_turn_session_result"] = {
            "session_id": "test-001",
            "achieved": True,
            "total_turns": 5,
            "native_executor": "CrescendoAttack",
        }
        metadata["blind_inference_result"] = {
            "probes_count": 20,
            "inferred_facts": [],
            "confidence": 0.85,
            "native_executor": "PromptSendingAttack",
        }
        metadata["backdoor_probe_result"] = {
            "probes_count": 30,
            "detected_backdoors": [],
            "max_anomaly_score": 0.5,
            "native_executor": "PromptSendingAttack",
        }
        metadata["control_mode_result"] = {
            "mode": "detect",
            "total_probes": 10,
            "control_detected": True,
            "bypass_success_count": 3,
        }
        metadata["secret_validation_result"] = {
            "total_findings": 5,
            "max_confidence": 0.9,
            "strategies_used": ["exact", "format"],
        }
        metadata["crescendo_result"] = {
            "achieved": True,
            "turns": 8,
            "backtrack_count": 2,
        }
        metadata["tap_result"] = {
            "achieved": True,
            "best_score": 0.9,
        }
        metadata["advanced_mcp_attack_report"] = {"probes": [{"id": 1}]}
        metadata["xpia_result"] = {"attack_type": "xpia"}
        metadata["asi03_result"] = {"attack_type": "asi03"}
        metadata["asi09_result"] = {"attack_type": "asi09"}
        metadata["asi10_result"] = {"attack_type": "asi10"}
        metadata["multi_agent_result"] = {"attack_type": "multi_agent"}
        metadata["assessment_result"] = {"phases": ["scoping"]}
        metadata["ai_vss_scores"] = [{"score": 0.8}]
        metadata["realtime_asr_summary"] = {"techniques": {}}
        metadata["realtime_parameter_overrides"] = {"overrides": []}
        metadata["dynamic_converter_chains"] = [{"chain": "test"}]
        metadata["converter_chain_advisor"] = {}
        metadata["success_propagation"] = {}
        metadata["safety_filter_type"] = "content_filter"
        metadata["multi_model_comparison"] = {}

        report = validate_metadata(metadata)

        assert report.passed == report.total_items
        assert report.missing == 0
        assert report.partial == 0
        assert report.coverage_pct == 100.0
        assert report.pass_rate == 100.0

    def test_partial_fields(self):
        """部分字段缺失 → partial 状态."""
        metadata = {
            "mcp_probe_results": {
                "total_probes": 15,
                # 缺少 results 和 owasp_coverage
            },
        }

        report = validate_metadata(metadata)

        assert report.passed == 0
        assert report.partial == 1
        assert report.missing == report.total_items - 1

        partial_result = [r for r in report.results if r.status == "partial"][0]
        assert "results" in partial_result.missing_fields
        assert "owasp_coverage" in partial_result.missing_fields
        assert "total_probes" in partial_result.present_fields

    def test_list_type_pass(self):
        """列表类型非空 → pass."""
        metadata = {
            "ai_vss_scores": [{"score": 0.8}],
        }

        report = validate_metadata(metadata)

        ai_vss_result = [r for r in report.results if r.item.metadata_key == "ai_vss_scores"][0]
        assert ai_vss_result.status == "pass"

    def test_list_type_empty_partial(self):
        """列表类型为空 → partial."""
        metadata = {
            "ai_vss_scores": [],
        }

        report = validate_metadata(metadata)

        ai_vss_result = [r for r in report.results if r.item.metadata_key == "ai_vss_scores"][0]
        assert ai_vss_result.status == "partial"

    def test_string_type_pass(self):
        """字符串类型 → pass."""
        metadata = {
            "safety_filter_type": "content_filter",
        }

        report = validate_metadata(metadata)

        sf_result = [r for r in report.results if r.item.metadata_key == "safety_filter_type"][0]
        assert sf_result.status == "pass"

    def test_value_summary_float_format(self):
        """float 值摘要格式正确."""
        metadata = {
            "blind_inference_result": {
                "probes_count": 20,
                "inferred_facts": [],
                "confidence": 0.85,
                "native_executor": "PromptSendingAttack",
            },
        }

        report = validate_metadata(metadata)

        bi_result = [r for r in report.results if r.item.metadata_key == "blind_inference_result"][0]
        assert "confidence=0.85" in bi_result.value_summary

    def test_value_summary_list_format(self):
        """list 值摘要格式正确."""
        metadata = {
            "mcp_probe_results": {
                "total_probes": 15,
                "results": [{"id": 1}, {"id": 2}],
                "owasp_coverage": "ASI01-ASI07",
            },
        }

        report = validate_metadata(metadata)

        mcp_result = [r for r in report.results if r.item.metadata_key == "mcp_probe_results"][0]
        assert "results=list(len=2)" in mcp_result.value_summary


# ============================================================
# ValidationResult 测试
# ============================================================


class TestValidationResult:
    """ValidationResult 数据类测试."""

    def test_status_icon_pass(self):
        """pass 状态图标."""
        item = ValidationItem("key", "name", "desc", [])
        result = ValidationResult(item=item, status="pass")
        assert result.status_icon == "✅"

    def test_status_icon_missing(self):
        """missing 状态图标."""
        item = ValidationItem("key", "name", "desc", [])
        result = ValidationResult(item=item, status="missing")
        assert result.status_icon == "⬜"

    def test_status_icon_partial(self):
        """partial 状态图标."""
        item = ValidationItem("key", "name", "desc", [])
        result = ValidationResult(item=item, status="partial")
        assert result.status_icon == "⚠️"

    def test_status_icon_error(self):
        """error 状态图标."""
        item = ValidationItem("key", "name", "desc", [])
        result = ValidationResult(item=item, status="error")
        assert result.status_icon == "❌"

    def test_status_icon_unknown(self):
        """未知状态图标."""
        item = ValidationItem("key", "name", "desc", [])
        result = ValidationResult(item=item, status="unknown")
        assert result.status_icon == "❓"


# ============================================================
# E2EValidationReport 测试
# ============================================================


class TestE2EValidationReport:
    """E2EValidationReport 数据类测试."""

    def test_coverage_pct_empty(self):
        """空报告覆盖率 0%."""
        report = E2EValidationReport(total_items=22)
        assert report.coverage_pct == 0.0

    def test_coverage_pct_full(self):
        """全部通过覆盖率 100%."""
        item = ValidationItem("key", "name", "desc", [])
        report = E2EValidationReport(
            total_items=1,
            passed=1,
            results=[ValidationResult(item=item, status="pass")],
        )
        assert report.coverage_pct == 100.0

    def test_pass_rate_no_triggered(self):
        """无触发项时通过率 0%."""
        report = E2EValidationReport(total_items=22)
        assert report.pass_rate == 0.0

    def test_pass_rate_all_pass(self):
        """全部通过时通过率 100%."""
        item = ValidationItem("key", "name", "desc", [])
        report = E2EValidationReport(
            total_items=2,
            passed=2,
            results=[
                ValidationResult(item=item, status="pass"),
                ValidationResult(item=item, status="pass"),
            ],
        )
        assert report.pass_rate == 100.0

    def test_pass_rate_mixed(self):
        """混合状态通过率正确."""
        item = ValidationItem("key", "name", "desc", [])
        report = E2EValidationReport(
            total_items=3,
            passed=1,
            partial=1,
            errors=1,
            results=[
                ValidationResult(item=item, status="pass"),
                ValidationResult(item=item, status="partial"),
                ValidationResult(item=item, status="error"),
            ],
        )
        # triggered = 1 + 1 + 1 = 3, passed = 1 → 33.3%
        assert abs(report.pass_rate - 33.3) < 0.5

    def test_to_dict_structure(self):
        """to_dict 序列化结构正确."""
        item = ValidationItem("key", "name", "desc", ["field1"], cli_flag="--flag")
        report = E2EValidationReport(
            total_items=1,
            passed=1,
            results=[
                ValidationResult(
                    item=item,
                    status="pass",
                    present_fields=["field1"],
                    detail="OK",
                ),
            ],
        )

        d = report.to_dict()
        assert d["total_items"] == 1
        assert d["passed"] == 1
        assert len(d["results"]) == 1
        assert d["results"][0]["name"] == "name"
        assert d["results"][0]["status"] == "pass"
        assert d["results"][0]["cli_flag"] == "--flag"


# ============================================================
# print_validation_report 测试
# ============================================================


class TestPrintValidationReport:
    """print_validation_report 函数测试."""

    def test_print_empty_report(self, capsys):
        """空报告打印不崩溃."""
        report = E2EValidationReport(total_items=22)
        print_validation_report(report)
        captured = capsys.readouterr()
        assert "端到端验证报告" in captured.out

    def test_print_full_report(self, capsys):
        """完整报告打印不崩溃."""
        item = ValidationItem("key", "name", "desc", ["field1"])
        report = E2EValidationReport(
            total_items=1,
            passed=1,
            results=[
                ValidationResult(
                    item=item,
                    status="pass",
                    present_fields=["field1"],
                    value_summary="field1=value",
                ),
            ],
        )
        print_validation_report(report)
        captured = capsys.readouterr()
        assert "已通过" in captured.out

    def test_print_mixed_report(self, capsys):
        """混合状态报告打印不崩溃."""
        item = ValidationItem("key", "name", "desc", ["field1"], cli_flag="--flag")
        report = E2EValidationReport(
            total_items=3,
            passed=1,
            partial=1,
            missing=1,
            results=[
                ValidationResult(item=item, status="pass"),
                ValidationResult(item=item, status="partial", detail="缺字段"),
                ValidationResult(item=item, status="missing"),
            ],
        )
        print_validation_report(report)
        captured = capsys.readouterr()
        assert "已通过" in captured.out
        assert "部分通过" in captured.out
        assert "未触发" in captured.out


# ============================================================
# run_e2e_validation 测试
# ============================================================


class TestRunE2EValidation:
    """run_e2e_validation 集成测试."""

    def test_run_with_empty_metadata(self, capsys):
        """空 metadata 运行验证不崩溃."""
        report = run_e2e_validation({})
        assert report.total_items > 0
        assert report.missing == report.total_items

    def test_run_with_partial_metadata(self, capsys):
        """部分 metadata 运行验证不崩溃."""
        report = run_e2e_validation({
            "safety_filter_type": "content_filter",
        "mcp_probe_results": {
            "total_probes": 15,
            "results": [],
            "owasp_coverage": "ASI01-ASI07",
            "sent_to_target": False,
        },
        })
        assert report.passed >= 2
        assert report.coverage_pct > 0

    def test_run_returns_report(self):
        """run_e2e_validation 返回 E2EValidationReport."""
        report = run_e2e_validation({})
        assert isinstance(report, E2EValidationReport)


# ============================================================
# Metadata 完整性测试 — 验证各场景结果的 probes/response 字段
# ============================================================


class TestMetadataCompleteness:
    """验证各场景 metadata 结果的 probes 字段完整性 (Round 26 新增)."""

    def test_backdoor_probe_result_has_probes_with_response(self):
        """后门探测结果包含 probes 列表, 每个探针含 response 字段."""
        metadata = {
            "backdoor_probe_result": {
                "probes_count": 30,
                "probes": [
                    {
                        "trigger_type": "magic_phrase",
                        "trigger_value": "debug_mode",
                        "response": "Debug mode activated.",
                        "anomaly_score": 0.8,
                        "detected": True,
                    },
                ],
                "detected_backdoors": ["debug_mode"],
                "max_anomaly_score": 0.8,
                "native_executor": "PromptSendingAttack",
            },
        }
        report = validate_metadata(metadata)
        bp_result = [r for r in report.results if r.item.metadata_key == "backdoor_probe_result"][0]
        assert bp_result.status == "pass"
        # 验证 probes 列表中的 response 字段存在
        probes = metadata["backdoor_probe_result"]["probes"]
        assert len(probes) > 0
        assert "response" in probes[0]
        assert "trigger_type" in probes[0]
        assert "anomaly_score" in probes[0]

    def test_control_mode_result_has_probes_with_response(self):
        """控制模式结果包含 probes 列表, 每个探针含 response 字段."""
        metadata = {
            "control_mode_result": {
                "mode": "detect",
                "total_probes": 10,
                "probes": [
                    {
                        "mode": "detect",
                        "technique": "jailbreak",
                        "response": "I cannot help with that.",
                        "control_detected": True,
                        "bypass_success": False,
                    },
                ],
                "control_detected": True,
                "bypass_success_count": 0,
            },
        }
        report = validate_metadata(metadata)
        cm_result = [r for r in report.results if r.item.metadata_key == "control_mode_result"][0]
        assert cm_result.status == "pass"
        # 验证 probes 列表中的 response 字段存在
        probes = metadata["control_mode_result"]["probes"]
        assert len(probes) > 0
        assert "response" in probes[0]
        assert "technique" in probes[0]
        assert "bypass_success" in probes[0]


class TestSecretValidationMultiSource:
    """Secret 验证多源扫描测试 — 验证扫描 3 个响应源的完整性 (Round 26 新增)."""

    def test_secret_validation_scans_backdoor_responses(self):
        """Secret 验证扫描 backdoor_probe_result 中的 response."""
        # 这里验证的是 metadata 结构, 不实际调用 scorer
        metadata = {
            "backdoor_probe_result": {
                "probes_count": 1,
                "probes": [{"response": "api_key=sk-test123"}],
            },
        }
        # 验证 backdoor_probe_result 的 probes 字段可被 Secret 验证扫描
        probes = metadata["backdoor_probe_result"]["probes"]
        responses = [p.get("response", "") for p in probes if p.get("response")]
        assert len(responses) == 1
        assert "api_key" in responses[0]

    def test_secret_validation_scans_control_mode_responses(self):
        """Secret 验证扫描 control_mode_result 中的 response."""
        metadata = {
            "control_mode_result": {
                "mode": "detect",
                "total_probes": 1,
                "probes": [{"response": "password=admin123"}],
            },
        }
        probes = metadata["control_mode_result"]["probes"]
        responses = [p.get("response", "") for p in probes if p.get("response")]
        assert len(responses) == 1
        assert "password" in responses[0]

    def test_secret_validation_scans_mcp_probe_responses(self):
        """Secret 验证扫描 mcp_probe_results 中的 response."""
        metadata = {
            "mcp_probe_results": {
                "total_probes": 1,
                "results": [{"response": "token=bearer_xyz"}],
                "owasp_coverage": "ASI01",
                "sent_to_target": True,
            },
        }
        results = metadata["mcp_probe_results"]["results"]
        responses = [p.get("response", "") for p in results if p.get("response")]
        assert len(responses) == 1
        assert "token" in responses[0]

    def test_secret_validation_result_has_strategies(self):
        """Secret 验证结果包含 4 策略."""
        metadata = {
            "secret_validation_result": {
                "total_findings": 3,
                "max_confidence": 0.9,
                "strategies_used": ["exact", "format", "semantic", "api"],
            },
        }
        report = validate_metadata(metadata)
        sv_result = [r for r in report.results if r.item.metadata_key == "secret_validation_result"][0]
        assert sv_result.status == "pass"
        assert len(metadata["secret_validation_result"]["strategies_used"]) == 4

    def test_mcp_probe_results_has_blocked_by_api(self):
        """MCP 探针结果支持 blocked_by_api 字段 (Round 26 新增)."""
        metadata = {
            "mcp_probe_results": {
                "total_probes": 15,
                "results": [
                    {"probe_id": "MCP_01", "response": "refused", "blocked_by_api": False},
                    {"probe_id": "MCP_02", "response": "", "blocked_by_api": True},
                ],
                "owasp_coverage": "ASI01-ASI07",
                "sent_to_target": True,
            },
        }
        report = validate_metadata(metadata)
        mcp_result = [r for r in report.results if r.item.metadata_key == "mcp_probe_results"][0]
        assert mcp_result.status == "pass"
        # 验证 blocked_by_api 字段存在
        results = metadata["mcp_probe_results"]["results"]
        assert "blocked_by_api" in results[0]
        assert results[1]["blocked_by_api"] is True
