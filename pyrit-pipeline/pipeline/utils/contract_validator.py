# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""阶段间数据流契约验证 — 确保阶段间数据传递完整性。.

在 handoff_banner 之后自动验证:
  发送方产出 == 接收方期望 (schema 检查)

设计原则 (R-010):
  - PyRIT 原生优先: 不修改 PyRIT 原生组件, 仅在编排层验证
  - 非侵入式: 验证失败仅警告, 不中断流水线
  - 声明式: 每个阶段的输入/输出契约以 schema 声明

> **日期**: 2026-8-3
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ContractResult:
    """契约验证结果。.

    Attributes:
        passed: 是否通过。
        stage_from: 发送阶段。
        stage_to: 接收阶段。
        missing_fields: 缺失字段列表。
        warnings: 警告列表。
    """

    passed: bool = True
    stage_from: str = ""
    stage_to: str = ""
    missing_fields: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        """返回验证结果的可读字符串表示。."""
        status = "✓ PASS" if self.passed else "✗ FAIL"
        lines = [f"  [Contract] {status}: {self.stage_from} → {self.stage_to}"]
        if self.missing_fields:
            lines.append(f"    缺失字段: {', '.join(self.missing_fields)}")
        if self.warnings:
            for w in self.warnings:
                lines.append(f"    ⚠ {w}")
        return "\n".join(lines)


class ContractValidator:
    """阶段间数据流契约验证器。.

    定义每个阶段的输出契约 (必填字段),
    在 handoff 时验证接收方是否拿到所有必填数据。

    用法::

        validator = ContractValidator()
        result = validator.validate("stage_1", "stage_2", ctx)
        if not result.passed:
            print(result)
    """

    # 阶段输出契约: stage → 必填字段列表
    # O-32: 扩展 v56~v60 新增核心 metadata key 覆盖
    #   - stage_0.5: attack_surface_topology, alternative_attack_paths
    #   - stage_2: baseline_filter_analysis (O-27), expanded_attack_seeds
    #   - stage_4: post_crescendo_results, recon_follow_up_results (O-29/O-30)
    #   - stage_5: scorer_tier_stats, asr_breakdown (O-28/O-30)
    _CONTRACTS: dict[str, list[str]] = {
        "stage_0.5": [
            "target_type",
            "recommended_mode",
            "attack_surface_topology",
            "alternative_attack_paths",
        ],
        "stage_1": ["config", "scenario_name"],
        "stage_2": [
            "scenario",
            "sorted_datasets",
            "warm_start_asr",
            "baseline_filter_analysis",
            "expanded_attack_seeds",
        ],
        "stage_3": ["scenario"],
        "stage_4": [
            "result",
            "asr_per_technique",
            "overall_asr",
            "post_crescendo_results",
            "recon_follow_up_results",
        ],
        "stage_5": [
            "scorer_tier_stats",
            "asr_breakdown",
            "post_analysis",
        ],
        "stage_6": ["output_dir"],
    }

    # O-32: 软契约字段 — 这些字段为条件性产出, 缺失时仅警告不判失败
    # (如 post_crescendo_results 仅在 Crescendo 触发时才存在)
    _SOFT_FIELDS: set[str] = {
        "attack_surface_topology",
        "alternative_attack_paths",
        "baseline_filter_analysis",
        "expanded_attack_seeds",
        "post_crescendo_results",
        "recon_follow_up_results",
        "scorer_tier_stats",
        "asr_breakdown",
        "post_analysis",
    }

    # 阶段编号映射 (PTES 七阶段: 1-7)
    _STAGE_NUM_TO_KEY: dict[int, str] = {
        1: "stage_1",
        2: "stage_0.5",  # 目标侦察+认证桥接 (原 Stage 0.5)
        3: "stage_2",
        4: "stage_3",
        5: "stage_4",
        6: "stage_5",
        7: "stage_6",
    }

    def validate(
        self,
        stage_from: int | str,
        stage_to: int | str,
        ctx: Any,
    ) -> ContractResult:
        """验证阶段间数据流契约。.

        Args:
            stage_from: 来源阶段编号或标识。
            stage_to: 目标阶段编号或标识。
            ctx: PipelineContext 实例。

        Returns:
            ContractResult 验证结果。
        """
        from_key = self._normalize_stage(stage_from)
        to_key = self._normalize_stage(stage_to)

        required_fields = self._CONTRACTS.get(from_key, [])
        if not required_fields:
            return ContractResult(passed=True, stage_from=from_key, stage_to=to_key)

        missing: list[str] = []
        warnings: list[str] = []

        for field_name in required_fields:
            value = getattr(ctx, field_name, None)
            if value is None and hasattr(ctx, "metadata"):
                value = ctx.metadata.get(field_name)
            if value is None:
                # O-32: 软契约字段缺失时仅警告, 不计入 missing
                if field_name in self._SOFT_FIELDS:
                    warnings.append(f"软契约字段 {field_name} 未设置 (条件性产出)")
                else:
                    missing.append(field_name)
            elif isinstance(value, (list, dict)) and len(value) == 0:
                warnings.append(f"{field_name} 为空集合")

        return ContractResult(
            passed=len(missing) == 0,
            stage_from=from_key,
            stage_to=to_key,
            missing_fields=missing,
            warnings=warnings,
        )

    def _normalize_stage(self, stage: int | str) -> str:
        if isinstance(stage, int):
            return self._STAGE_NUM_TO_KEY.get(stage, str(stage))
        return str(stage)
