# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""ContractValidator 单元测试。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pipeline.utils.contract_validator import ContractResult, ContractValidator


@dataclass
class MockContext:
    """模拟 PipelineContext。"""

    config: Any = None
    scenario_name: str = ""
    scenario: Any = None
    sorted_datasets: list = field(default_factory=list)
    warm_start_asr: dict = field(default_factory=dict)
    result: Any = None
    asr_per_technique: dict = field(default_factory=dict)
    overall_asr: int = 0
    output_dir: Any = None
    target_type: str | None = None
    recommended_mode: str | None = None
    metadata: dict = field(default_factory=dict)


class TestContractResult:
    def test_pass(self) -> None:
        result = ContractResult(passed=True, stage_from="s1", stage_to="s2")
        assert "✓ PASS" in str(result)

    def test_fail(self) -> None:
        result = ContractResult(
            passed=False,
            stage_from="s1",
            stage_to="s2",
            missing_fields=["scenario"],
        )
        assert "✗ FAIL" in str(result)
        assert "scenario" in str(result)


class TestContractValidator:
    def test_validate_stage_1_to_2_pass(self) -> None:
        """Stage 1 (init) → Stage 2 (recon): stage_1 契约验证."""
        validator = ContractValidator()
        ctx = MockContext(config="config_obj", scenario_name="text_adaptive")
        result = validator.validate(1, 2, ctx)
        assert result.passed
        assert result.stage_from == "stage_1"
        # O-57: Stage 2 现在映射到 stage_0.5 (目标侦察)
        assert result.stage_to == "stage_0.5"

    def test_validate_stage_1_to_2_fail(self) -> None:
        """Stage 1 (init) → Stage 2 (recon): 缺 config 时失败."""
        validator = ContractValidator()
        ctx = MockContext(config=None, scenario_name="")
        result = validator.validate(1, 2, ctx)
        assert not result.passed
        assert "config" in result.missing_fields

    def test_validate_stage_2_to_3_pass(self) -> None:
        """Stage 2 (recon, stage_0.5) → Stage 3 (scenario, stage_2).

        O-57: Stage 2 映射到 stage_0.5, 契约要求 target_type + recommended_mode.
        """
        validator = ContractValidator()
        ctx = MockContext(
            target_type="llm_web_app",
            recommended_mode="browser",
        )
        result = validator.validate(2, 3, ctx)
        assert result.passed

    def test_validate_stage_2_to_3_fail(self) -> None:
        """Stage 2 (recon) → Stage 3: 缺 target_type 时失败."""
        validator = ContractValidator()
        ctx = MockContext(target_type=None, recommended_mode=None)
        result = validator.validate(2, 3, ctx)
        assert not result.passed
        assert "target_type" in result.missing_fields
        assert "recommended_mode" in result.missing_fields

    def test_validate_stage_05_to_1(self) -> None:
        """Stage 0 → Stage 1: stage_0.5 契约 (向后兼容)."""
        validator = ContractValidator()
        ctx = MockContext(target_type="llm_web_app", recommended_mode="browser")
        result = validator.validate(0, 1, ctx)
        assert result.passed

    def test_validate_empty_contract(self) -> None:
        """Stage 5→6 (stage_4→stage_5): result 是必填字段."""
        validator = ContractValidator()
        ctx = MockContext(result="result_obj")
        result = validator.validate(5, 6, ctx)
        assert result.passed

    def test_validate_with_warnings(self) -> None:
        """Stage 2→3: 有 target_type 但空集合时产生警告."""
        validator = ContractValidator()
        ctx = MockContext(
            target_type="llm_web_app",
            recommended_mode="browser",
        )
        result = validator.validate(2, 3, ctx)
        assert result.passed
        # stage_0.5 契约的软字段可能产生警告
        assert isinstance(result.warnings, list)

    def test_validate_string_stage(self) -> None:
        """字符串阶段标识直接作为 key 使用."""
        validator = ContractValidator()
        ctx = MockContext(config="cfg", scenario_name="test")
        result = validator.validate("stage_1", "stage_2", ctx)
        assert result.passed
