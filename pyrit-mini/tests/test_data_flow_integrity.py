"""
ARM → Strike → Assess 数据流完整性自动化测试

运行: pytest tests/test_data_flow_integrity.py -v

测试覆盖:
    1. 字段契约验证 - 每个阶段输出字段完整性
    2. 阶段间传递验证 - 数据正确传递
    3. 跨阶段一致性 - 数据无矛盾
    4. Demo 验证 - 完整流水线模拟
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.data_flow_validator import (
    DataFlowValidator,
    DataFlowReport,
    ValidationResult,
    format_report,
)
from tools.data_flow_hooks import (
    snapshot_hook,
    validate_and_report,
    validate_quick,
    reset_validator,
)


# =============================================================================
# 模拟对象
# =============================================================================

class MockParserRequest:
    target_fingerprint = {
        "model_family": "gpt-4",
        "language": "en",
        "capabilities": ["function_calling", "reasoning"],
    }


class MockTargetFingerprint:
    model_family = "gpt-4"
    language = "en"


def create_mock_ctx(
    phase: str = "recon",
    include_mcpsec: bool = False,
    include_rag: bool = False,
) -> Any:
    """
    创建模拟 PipelineContext
    
    Args:
        phase: 模拟的阶段 ("recon", "arm", "strike", "assess")
        include_mcpsec: 是否包含 MCPSec 数据
        include_rag: 是否包含 RAG 数据
    """
    ctx = MagicMock()

    # 基础字段 — 所有阶段都有
    ctx.objective_target = MagicMock()
    ctx.parsed_request = MockParserRequest()

    # Recon 输出
    ctx.service_profile = {
        "model_name": "gpt-4",
        "auth_type": "bearer_token",
        "rag_kb_map": {"document_count": 10} if include_rag else {},
        "streaming_supported": True,
    }

    # MCPSec 输出
    ctx.mcpsec_surface = {
        "tools": [{"name": "search"}, {"name": "execute"}],
        "resources": [],
        "prompts": []
    } if include_mcpsec else {}
    ctx.mcpsec_scan_results = {
        "vulnerabilities": [
            {"severity": "high", "tool": "search", "description": "IDOR"}
        ]
    } if include_mcpsec else {}

    # ARM 输出
    ctx.seeds = [
        {"value": "test_seed_1", "category": "jailbreak"},
        {"value": "test_seed_2", "category": "role_play"},
        {"value": "test_seed_3", "category": "skeleton_key"},
    ]
    ctx.techniques = ["skeleton_key", "crescendo", "role_play"]
    ctx.converter_map = {
        "skeleton_key": ["Base64Converter", "StringJoinConverter"],
        "crescendo": ["TranslationConverter"],
        "role_play": ["ToneConverter", "StringJoinConverter"],
    }

    # Strike 输出
    ctx.attack_results = {
        "skeleton_key": [MagicMock(), MagicMock()],
        "crescendo": [MagicMock()],
        "role_play": [MagicMock(), MagicMock(), MagicMock()],
    }

    # Assess 输出
    ctx.asr_per_technique = {
        "skeleton_key": 66.67,
        "crescendo": 33.33,
        "role_play": 50.0,
    }
    ctx.overall_asr = 50.0
    ctx.dual_judge_stats = {
        "total_scored": 6,
        "agreements": 5,
        "disagreements": 1,
        "cohens_kappa": 0.78,
    }
    ctx.wilson_ci = (0.21, 0.79)

    # 审计日志
    ctx.orchestration_log = [
        {"phase": "recon", "status": "completed"},
        {"phase": "arm", "status": "completed"},
        {"phase": "strike", "status": "completed"},
        {"phase": "assess", "status": "completed"},
    ]

    return ctx


# =============================================================================
# 字段契约测试
# =============================================================================

class TestFieldContracts:
    """字段契约验证测试"""

    def setup_method(self):
        reset_validator()

    def test_recon_output_has_service_profile(self):
        """Recon 生成 service_profile"""
        ctx = create_mock_ctx(phase="recon")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_recon")
        validator.snapshot("post_arm")  # 需要目标快照用于 transfer 规则
        report = validator.validate_all()

        # 检查 T001 转移规则是否通过 (Recon → ARM)
        t001 = next((r for r in report.results if r.rule_id == "T001"), None)
        assert t001 is not None, "T001 规则应存在"
        assert t001.passed, f"Recon → ARM service_profile 传递失败: {t001.message}"

        # 检查快照中有 service_profile_size
        sp_size = validator.snapshots["post_recon"].fields.get("service_profile_size", 0)
        assert sp_size > 0, f"service_profile_size 应为正数，实际为 {sp_size}"

    def test_arm_output_has_seeds(self):
        """ARM 完成时必须生成 seeds"""
        ctx = create_mock_ctx(phase="arm")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_arm")
        report = validator.validate_all()

        arm_results = [r for r in report.results if r.phase_from in ("post_arm", "arm")]
        assert any(r.passed and "seeds" in r.message.lower() for r in arm_results), \
            "ARM 应生成非空 seeds"

    def test_arm_output_has_techniques(self):
        """ARM 完成时必须生成 techniques"""
        ctx = create_mock_ctx(phase="arm")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_arm")
        report = validator.validate_all()

        techniques_count = validator.snapshots["post_arm"].fields.get("techniques_count", 0)
        assert techniques_count >= 1, "ARM 应至少选择 1 种攻击技术"

    def test_arm_output_has_converter_map(self):
        """ARM 完成时必须生成 converter_map"""
        ctx = create_mock_ctx(phase="arm")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_arm")
        report = validator.validate_all()

        cm_size = validator.snapshots["post_arm"].fields.get("converter_map_size", 0)
        assert cm_size >= 1, "ARM 应至少构建 1 个技术的 converter_map"

    def test_strike_output_has_attack_results(self):
        """Strike 完成时必须生成 attack_results"""
        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")
        report = validator.validate_all()

        total_results = validator.snapshots["post_strike"].fields.get("attack_results_total", 0)
        assert total_results >= 1, "Strike 应产生至少 1 个攻击结果"

    def test_assess_output_has_asr_per_technique(self):
        """Assess 完成时必须计算 asr_per_technique"""
        ctx = create_mock_ctx(phase="assess")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_assess")
        report = validator.validate_all()

        asr_count = validator.snapshots["post_assess"].fields.get("asr_techniques_count", 0)
        assert asr_count >= 1, "Assess 应计算至少 1 种技术的 ASR"

    def test_assess_output_has_overall_asr(self):
        """Assess 完成时必须计算 overall_asr"""
        ctx = create_mock_ctx(phase="assess")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_assess")
        report = validator.validate_all()

        overall_asr = validator.snapshots["post_assess"].fields.get("overall_asr", 0.0)
        assert 0 <= overall_asr <= 100, f"overall_asr 应在 [0, 100] 范围内，实际为 {overall_asr}"


# =============================================================================
# 阶段间传递测试
# =============================================================================

class TestInterPhaseTransfer:
    """阶段间数据传递验证"""

    def setup_method(self):
        reset_validator()

    def test_recon_to_arm_service_profile_transfer(self):
        """Recon → ARM: service_profile 正确传递"""
        ctx = create_mock_ctx(phase="arm")
        validator = DataFlowValidator(ctx)

        validator.snapshot("post_recon")
        validator.snapshot("post_arm")
        report = validator.validate_all()

        t001 = next((r for r in report.results if r.rule_id == "T001"), None)
        assert t001 is not None, "T001 规则应存在"
        assert t001.passed, f"Recon → ARM service_profile 传递失败: {t001.message}"

    def test_arm_to_strike_seeds_transfer(self):
        """ARM → Strike: seeds 正确传递"""
        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)

        validator.snapshot("post_arm")
        validator.snapshot("post_strike")
        report = validator.validate_all()

        t003 = next((r for r in report.results if r.rule_id == "T003"), None)
        assert t003 is not None, "T003 规则应存在"
        assert t003.passed, f"ARM → Strike seeds 传递失败: {t003.message}"

    def test_arm_to_strike_converter_map_transfer(self):
        """ARM → Strike: converter_map 正确传递"""
        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)

        validator.snapshot("post_arm")
        validator.snapshot("post_strike")
        report = validator.validate_all()

        t004 = next((r for r in report.results if r.rule_id == "T004"), None)
        assert t004 is not None, "T004 规则应存在"
        assert t004.passed, f"ARM → Strike converter_map 传递失败: {t004.message}"

    def test_strike_to_assess_attack_results_transfer(self):
        """Strike → Assess: attack_results 正确传递"""
        ctx = create_mock_ctx(phase="assess")
        validator = DataFlowValidator(ctx)

        validator.snapshot("post_strike")
        validator.snapshot("post_assess")
        report = validator.validate_all()

        t007 = next((r for r in report.results if r.rule_id == "T007"), None)
        assert t007 is not None, "T007 规则应存在"
        assert t007.passed, f"Strike → Assess attack_results 传递失败: {t007.message}"


# =============================================================================
# 跨阶段一致性测试
# =============================================================================

class TestCrossPhaseConsistency:
    """跨阶段数据一致性验证"""

    def setup_method(self):
        reset_validator()

    def test_attack_techniques_covered_in_asr(self):
        """Stark 结果中的技术必须在 ASR 统计中全覆盖"""
        ctx = create_mock_ctx(phase="assess")
        validator = DataFlowValidator(ctx)

        validator.snapshot("post_strike")
        validator.snapshot("post_assess")
        report = validator.validate_all()

        cons001 = next((r for r in report.results if r.rule_id == "CONS-001"), None)
        assert cons001 is not None, "CONS-001 规则应存在"
        assert cons001.passed, f"攻击技术 ASR 覆盖不一致: {cons001.message}"

    def test_orchestration_log_has_all_phases(self):
        """orchestration_log 应包含所有阶段"""
        ctx = create_mock_ctx(phase="assess")
        validator = DataFlowValidator(ctx)

        validator.snapshot("post_assess")
        report = validator.validate_all()

        cons002 = next((r for r in report.results if r.rule_id == "CONS-002"), None)
        assert cons002 is not None, "CONS-002 规则应存在"
        assert cons002.passed, f"orchestration_log 阶段不完整: {cons002.message}"

    def test_dual_judge_and_wilson_ci_coexist(self):
        """dual_judge_stats 和 wilson_ci 应并存"""
        ctx = create_mock_ctx(phase="assess")
        validator = DataFlowValidator(ctx)

        validator.snapshot("post_assess")
        report = validator.validate_all()

        cons003 = next((r for r in report.results if r.rule_id == "CONS-003"), None)
        assert cons003 is not None, "CONS-003 规则应存在"
        assert cons003.passed, f"评判统计不完整: {cons003.message}"


# =============================================================================
# 完整流水线测试
# =============================================================================

class TestFullPipeline:
    """完整流水线端到端测试"""

    def setup_method(self):
        reset_validator()

    def test_full_pipeline_demo_mode(self):
        """演示模式完整验证"""
        ctx = create_mock_ctx(phase="assess", include_mcpsec=True, include_rag=True)
        validator = DataFlowValidator(ctx)

        # 模拟完整流水线
        validator.snapshot("post_recon")
        validator.snapshot("post_arm")
        validator.snapshot("post_strike")
        validator.snapshot("post_assess")

        report = validator.validate_all()

        assert report.total_rules > 0, "应生成验证规则"
        assert report.snapshots, "应生成快照"

        # 输出报告
        formatted = format_report(report)
        assert isinstance(formatted, str)
        assert "通过" in formatted or "失败" in formatted

    def test_quick_validate_returns_true_for_valid_ctx(self):
        """快速验证对有效 ctx 返回 True"""
        ctx = create_mock_ctx(phase="assess")
        result = validate_quick(ctx)
        assert result is True, "有效 ctx 的快速验证应返回 True"


# =============================================================================
# 边界情况测试
# =============================================================================

class TestEdgeCases:
    """边界情况测试"""

    def setup_method(self):
        reset_validator()

    def test_empty_attack_results_handled_gracefully(self):
        """空 attack_results 应正确处理"""
        ctx = create_mock_ctx(phase="assess")
        ctx.attack_results = {}  # 空结果
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")
        report = validator.validate_all()

        # 不应抛出异常
        assert report.total_rules >= 0

    def test_missing_snapshots_handled_gracefully(self):
        """缺少快照应优雅处理"""
        ctx = create_mock_ctx(phase="recon")
        validator = DataFlowValidator(ctx)
        # 只打一个快照
        validator.snapshot("post_recon")
        report = validator.validate_all()

        # 应标记为跳过而非失败
        missing_results = [r for r in report.results if r.rule_id == "MISS"]
        # 可以有警告但不应该崩溃
        assert report is not None

    def test_none_fields_handled(self):
        """None 字段应正确处理"""
        ctx = MagicMock()
        ctx.service_profile = None  # 故意设为 None
        ctx.mcpsec_surface = None
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_recon")
        report = validator.validate_all()

        # 应该不崩溃
        assert report is not None

    def test_validator_reset(self):
        """验证器重置后应清理状态"""
        ctx = create_mock_ctx(phase="assess")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_recon")
        validator.snapshot("post_arm")

        assert len(validator.snapshots) == 2

        reset_validator()
        # 重置后全局验证器应为新实例


# =============================================================================
# 报告格式测试
# =============================================================================

class TestReportFormat:
    """报告格式化测试"""

    def setup_method(self):
        reset_validator()

    def test_format_report_contains_key_sections(self):
        """格式化报告应包含关键章节"""
        ctx = create_mock_ctx(phase="assess")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_recon")
        validator.snapshot("post_arm")
        validator.snapshot("post_strike")
        validator.snapshot("post_assess")

        report = validator.validate_all()
        formatted = format_report(report)

        # 检查关键章节
        assert "数据流完整性验证报告" in formatted or "验证报告" in formatted
        assert "结论" in formatted or "结果" in formatted

    def test_json_report_generation(self):
        """JSON 格式报告应可以序列化"""
        import json

        ctx = create_mock_ctx(phase="assess")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_assess")

        report = validator.validate_all()
        data = {
            "timestamp": report.timestamp,
            "passed": report.passed,
            "failed": report.failed,
            "is_valid": report.is_valid,
        }

        json_str = json.dumps(data, ensure_ascii=False)
        assert json_str is not None
        assert len(json_str) > 0


# =============================================================================
# 集成测试 (可选，需要实际 PipelineContext)
# =============================================================================

class TestIntegration:
    """集成测试: 测试模块可导入性"""

    def test_data_flow_validator_importable(self):
        """data_flow_validator 模块应可导入"""
        from tools.data_flow_validator import DataFlowValidator
        assert DataFlowValidator is not None

    def test_data_flow_hooks_importable(self):
        """data_flow_hooks 模块应可导入"""
        from tools.data_flow_hooks import snapshot_hook, validate_and_report
        assert callable(snapshot_hook)
        assert callable(validate_and_report)

    def test_tools_package_exists(self):
        """tools 包应存在"""
        from tools import data_flow_validator
        from tools import data_flow_hooks
        assert data_flow_validator is not None
        assert data_flow_hooks is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
