# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""端到端验证器 — 自动检查流水线运行时各场景结果的完整性和正确性.

R-022 分类: 数据层增强 — 消费 ``ctx.metadata`` 中已有的场景结果,
不修改原生 Scenario 生命周期, 不调用任何原生执行器.

验证机制:
  1. 扫描 ``ctx.metadata`` 中各场景结果键 (mcp_probe_results, multi_turn_session_result 等)
  2. 对每个存在的键, 验证其内部结构是否包含预期字段
  3. 输出验证报告卡片
  4. 将验证结果写入 ``ctx.metadata["e2e_validation"]``

验证项清单 (对应 R-023 端到端验证追踪):

  - ``mcp_probe_results`` — MCP 探针 (total_probes/results/owasp_coverage)
  - ``multi_turn_session_result`` — 多轮会话 (session_id/achieved/total_turns/native_executor)
  - ``blind_inference_result`` — 盲推理 (probes_count/inferred_facts/confidence/system_prompt_guess)
  - ``backdoor_probe_result`` — 后门探测 (probes_count/detected_backdoors/max_anomaly_score)
  - ``control_mode_result`` — 控制模式感知 (mode/total_probes/control_detected/bypass_success_count)
  - ``secret_validation_result`` — Secret 验证 (total_findings/max_confidence/strategies_used)
  - ``crescendo_result`` — Crescendo 攻击 (achieved/turns/backtrack_count)
  - ``tap_result`` — TAP 攻击 (achieved/best_score/tree_nodes)
  - ``advanced_mcp_attack_report`` — 高级 MCP Kill Chain
  - ``xpia_result`` — XPIA 跨域注入
  - ``asi03_result`` — 身份/授权攻击
  - ``asi09_result`` — 人类信任利用
  - ``asi10_result`` — 不可追溯性
  - ``multi_agent_result`` — 多 Agent 攻击
  - ``assessment_result`` — 三框架评估
  - ``ai_vss_scores`` / ``ai_vss_summary`` — AI-VSS 评分
  - ``realtime_asr_summary`` — 实时 ASR 反馈
  - ``realtime_parameter_overrides`` — 实时参数覆盖
  - ``dynamic_converter_chains`` — 动态 Converter 链
  - ``converter_chain_advisor`` — Converter 链反馈
  - ``success_propagation`` — 成功传播跟踪
  - ``safety_filter_type`` — 安全过滤探测
  - ``multi_model_comparison`` — 多模型 ASR 对比

> **日期**: 2026-8-5
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ── 验证项定义 ──

@dataclass
class ValidationItem:
    """单个验证项定义."""

    metadata_key: str
    name: str
    description: str
    expected_fields: list[str]
    cli_flag: str = ""
    native_executor: str = ""


# 所有端到端验证项 (按 R-023 待验证清单排列)
_VALIDATION_ITEMS: list[ValidationItem] = [
    ValidationItem(
        metadata_key="mcp_probe_results",
        name="MCP 探针通用化",
        description="15 个 MCP 探针执行 + OWASP 覆盖",
        expected_fields=["total_probes", "results", "owasp_coverage", "sent_to_target"],
        cli_flag="--mcp-attack",
    ),
    ValidationItem(
        metadata_key="multi_turn_session_result",
        name="多轮会话编排器",
        description="4 阶段渐进式攻击 (CrescendoAttack)",
        expected_fields=["session_id", "achieved", "total_turns", "native_executor"],
        cli_flag="--multi-turn-session",
        native_executor="CrescendoAttack",
    ),
    ValidationItem(
        metadata_key="blind_inference_result",
        name="盲推理编排器",
        description="二分搜索系统提示推断 (PromptSendingAttack)",
        expected_fields=["probes_count", "inferred_facts", "confidence", "native_executor"],
        cli_flag="--blind-inference",
        native_executor="PromptSendingAttack",
    ),
    ValidationItem(
        metadata_key="backdoor_probe_result",
        name="后门触发器探测",
        description="3 类后门探测 + 异常评分 (PromptSendingAttack)",
        expected_fields=["probes_count", "detected_backdoors", "max_anomaly_score", "native_executor"],
        cli_flag="--backdoor-probe",
        native_executor="PromptSendingAttack",
    ),
    ValidationItem(
        metadata_key="control_mode_result",
        name="控制模式感知",
        description="3 种控制模式策略 (off/detect/mitigate)",
        expected_fields=["mode", "total_probes", "control_detected", "bypass_success_count"],
        cli_flag="--control-mode-aware",
    ),
    ValidationItem(
        metadata_key="secret_validation_result",
        name="Secret 验证评分器",
        description="4 策略验证 (exact/format/semantic/api)",
        expected_fields=["total_findings", "max_confidence", "strategies_used"],
        cli_flag="--secret-validation",
    ),
    ValidationItem(
        metadata_key="crescendo_result",
        name="Crescendo 原生编排器",
        description="原生 CrescendoAttack 渐进式攻击",
        expected_fields=["achieved", "turns", "backtrack_count"],
        cli_flag="--crescendo-objective",
        native_executor="CrescendoAttack",
    ),
    ValidationItem(
        metadata_key="tap_result",
        name="TAP 原生编排器",
        description="原生 TAPAttack 树状攻击路径",
        expected_fields=["achieved", "best_score"],
        cli_flag="--tap-objective",
        native_executor="TAPAttack",
    ),
    ValidationItem(
        metadata_key="advanced_mcp_attack_report",
        name="高级 MCP Kill Chain",
        description="6 个高级探针 + 3 个 Kill Chain",
        expected_fields=[],
        cli_flag="--advanced-mcp-attack",
    ),
    ValidationItem(
        metadata_key="xpia_result",
        name="XPIA 跨域注入",
        description="原生 XPIAWorkflow 间接注入",
        expected_fields=["attack_type"],
        cli_flag="--xpia-attack",
        native_executor="XPIAWorkflow",
    ),
    ValidationItem(
        metadata_key="asi03_result",
        name="身份/授权攻击",
        description="原生 RedTeamingAttack 身份授权",
        expected_fields=["attack_type"],
        cli_flag="--asi03-attack",
        native_executor="RedTeamingAttack",
    ),
    ValidationItem(
        metadata_key="asi09_result",
        name="人类信任利用",
        description="原生 CrescendoAttack 人类信任",
        expected_fields=["attack_type"],
        cli_flag="--asi09-attack",
        native_executor="CrescendoAttack",
    ),
    ValidationItem(
        metadata_key="asi10_result",
        name="不可追溯性",
        description="原生 PromptSendingAttack 不可追溯",
        expected_fields=["attack_type"],
        cli_flag="--asi10-attack",
        native_executor="PromptSendingAttack",
    ),
    ValidationItem(
        metadata_key="multi_agent_result",
        name="多 Agent 攻击",
        description="原生 SequentialAttack Kill Chain",
        expected_fields=["attack_type"],
        cli_flag="--multi-agent-attack",
        native_executor="SequentialAttack",
    ),
    ValidationItem(
        metadata_key="assessment_result",
        name="三框架评估",
        description="CSA + OWASP + MITRE ATLAS 三框架映射",
        expected_fields=[],
        cli_flag="--assessment-framework",
    ),
    ValidationItem(
        metadata_key="ai_vss_scores",
        name="AI-VSS 评分",
        description="AI-VSS 漏洞评分 (原生 Scorer 桥接)",
        expected_fields=[],
        cli_flag="(自动, 随攻击结果触发)",
    ),
    ValidationItem(
        metadata_key="realtime_asr_summary",
        name="实时 ASR 反馈",
        description="运行时 ASR 动态参数调整",
        expected_fields=[],
        cli_flag="(自动, 流水线执行时触发)",
    ),
    ValidationItem(
        metadata_key="realtime_parameter_overrides",
        name="实时参数覆盖",
        description="基于实时 ASR 的参数覆盖输出",
        expected_fields=[],
        cli_flag="(自动, 流水线执行时触发)",
    ),
    ValidationItem(
        metadata_key="dynamic_converter_chains",
        name="动态 Converter 链",
        description="基于失败模式的动态 Converter 创建",
        expected_fields=[],
        cli_flag="(自动, post-execution scan 触发)",
    ),
    ValidationItem(
        metadata_key="converter_chain_advisor",
        name="Converter 链反馈",
        description="D11 失败类型 → Converter 链调整建议",
        expected_fields=[],
        cli_flag="(自动, post-execution scan 触发)",
    ),
    ValidationItem(
        metadata_key="success_propagation",
        name="成功传播跟踪",
        description="D12 成功组合传播记录",
        expected_fields=[],
        cli_flag="(自动, post-execution scan 触发)",
    ),
    ValidationItem(
        metadata_key="safety_filter_type",
        name="安全过滤探测",
        description="D15 安全过滤器类型探测",
        expected_fields=[],
        cli_flag="(自动, Stage 1 预检触发)",
    ),
    ValidationItem(
        metadata_key="multi_model_comparison",
        name="多模型 ASR 对比",
        description="跨模型技术成功率对比矩阵",
        expected_fields=[],
        cli_flag="(自动, Stage 5 分析触发, 需 2+ 模型数据)",
    ),
]


# ── 验证结果 ──

@dataclass
class ValidationResult:
    """单个验证项的验证结果."""

    item: ValidationItem
    status: str  # "pass" / "missing" / "partial" / "error"
    present_fields: list[str] = field(default_factory=list)
    missing_fields: list[str] = field(default_factory=list)
    detail: str = ""
    value_summary: str = ""

    @property
    def status_icon(self) -> str:
        """状态图标."""
        return {
            "pass": "✅",
            "missing": "⬜",
            "partial": "⚠️",
            "error": "❌",
        }.get(self.status, "❓")


@dataclass
class E2EValidationReport:
    """端到端验证报告."""

    total_items: int = 0
    passed: int = 0
    missing: int = 0
    partial: int = 0
    errors: int = 0
    results: list[ValidationResult] = field(default_factory=list)

    @property
    def coverage_pct(self) -> float:
        """已触发的场景占比 (pass + partial + error) / total."""
        triggered = self.passed + self.partial + self.errors
        return triggered * 100 / max(self.total_items, 1)

    @property
    def pass_rate(self) -> float:
        """通过率 (pass / triggered)."""
        triggered = self.passed + self.partial + self.errors
        return self.passed * 100 / max(triggered, 1)

    def to_dict(self) -> dict[str, Any]:
        """序列化为字典 (写入 ctx.metadata)."""
        return {
            "total_items": self.total_items,
            "passed": self.passed,
            "missing": self.missing,
            "partial": self.partial,
            "errors": self.errors,
            "coverage_pct": round(self.coverage_pct, 1),
            "pass_rate": round(self.pass_rate, 1),
            "results": [
                {
                    "name": r.item.name,
                    "metadata_key": r.item.metadata_key,
                    "cli_flag": r.item.cli_flag,
                    "native_executor": r.item.native_executor,
                    "status": r.status,
                    "present_fields": r.present_fields,
                    "missing_fields": r.missing_fields,
                    "detail": r.detail,
                    "value_summary": r.value_summary,
                }
                for r in self.results
            ],
        }


# ── 核心验证逻辑 ──


def validate_metadata(metadata: dict[str, Any]) -> E2EValidationReport:
    """验证 ``ctx.metadata`` 中各场景结果的完整性.

    Args:
        metadata: ``ctx.metadata`` 字典.

    Returns:
        E2EValidationReport 验证报告。
    """
    report = E2EValidationReport(total_items=len(_VALIDATION_ITEMS))

    for item in _VALIDATION_ITEMS:
        result = _validate_single_item(metadata, item)
        report.results.append(result)

        if result.status == "pass":
            report.passed += 1
        elif result.status == "missing":
            report.missing += 1
        elif result.status == "partial":
            report.partial += 1
        elif result.status == "error":
            report.errors += 1

    return report


def _validate_single_item(
    metadata: dict[str, Any],
    item: ValidationItem,
) -> ValidationResult:
    """验证单个验证项."""
    # 检查 metadata 中是否存在该键
    raw_value = metadata.get(item.metadata_key)

    if raw_value is None:
        return ValidationResult(
            item=item,
            status="missing",
            detail=f"未触发 (CLI: {item.cli_flag})",
        )

    # 如果是字典, 验证预期字段
    if isinstance(raw_value, dict):
        present: list[str] = []
        missing: list[str] = []

        for field_name in item.expected_fields:
            if field_name in raw_value:
                present.append(field_name)
            else:
                missing.append(field_name)

        # 构建值摘要
        value_parts: list[str] = []
        for field_name in present[:4]:
            val = raw_value[field_name]
            if isinstance(val, (list, dict)):
                value_parts.append(f"{field_name}={type(val).__name__}(len={len(val)})")
            elif isinstance(val, float):
                value_parts.append(f"{field_name}={val:.2f}")
            else:
                value_parts.append(f"{field_name}={val}")
        value_summary = " | ".join(value_parts)

        if not missing:
            return ValidationResult(
                item=item,
                status="pass",
                present_fields=present,
                missing_fields=[],
                detail=f"字段完整 ({len(present)}/{len(item.expected_fields)})",
                value_summary=value_summary,
            )
        else:
            return ValidationResult(
                item=item,
                status="partial",
                present_fields=present,
                missing_fields=missing,
                detail=f"部分字段缺失 ({len(present)}/{len(item.expected_fields)}): {', '.join(missing)}",
                value_summary=value_summary,
            )

    # 如果是列表, 验证非空
    if isinstance(raw_value, list):
        if len(raw_value) > 0:
            return ValidationResult(
                item=item,
                status="pass",
                detail=f"列表非空 ({len(raw_value)} 项)",
                value_summary=f"len={len(raw_value)}",
            )
        else:
            return ValidationResult(
                item=item,
                status="partial",
                detail="列表为空",
                value_summary="len=0",
            )

    # 其他类型 (字符串/数字等)
    return ValidationResult(
        item=item,
        status="pass",
        detail=f"值存在 (type={type(raw_value).__name__})",
        value_summary=str(raw_value)[:100],
    )


# ── 报告打印 ──


def print_validation_report(report: E2EValidationReport) -> None:
    """打印端到端验证报告卡片.

    R-022 分类: 数据层增强 — 仅消费已有 metadata, 不修改原生生命周期。
    """
    from pipeline.utils.display import core_card

    # 构建报告内容
    sections: list[dict[str, Any]] = []

    # 概要
    summary_lines = [
        f"验证项总数: {report.total_items}",
        f"已通过: {report.passed} | 部分通过: {report.partial} | "
        f"未触发: {report.missing} | 错误: {report.errors}",
        f"场景覆盖率: {report.coverage_pct:.1f}% "
        f"({report.passed + report.partial + report.errors}/{report.total_items})",
        f"通过率: {report.pass_rate:.1f}% "
        f"({report.passed}/{report.passed + report.partial + report.errors})",
    ]
    sections.append({"label": "验证概要", "lines": summary_lines})

    # 已通过项
    passed_lines: list[str] = []
    for r in report.results:
        if r.status == "pass":
            executor_tag = f" [{r.item.native_executor}]" if r.item.native_executor else ""
            passed_lines.append(
                f"{r.status_icon} {r.item.name}{executor_tag}"
            )
            if r.value_summary:
                passed_lines.append(f"    └ {r.value_summary}")
    if passed_lines:
        sections.append({"label": "已通过", "lines": passed_lines})

    # 部分通过项
    partial_lines: list[str] = []
    for r in report.results:
        if r.status == "partial":
            partial_lines.append(f"{r.status_icon} {r.item.name} — {r.detail}")
            if r.value_summary:
                partial_lines.append(f"    └ {r.value_summary}")
    if partial_lines:
        sections.append({"label": "部分通过", "lines": partial_lines})

    # 未触发项
    missing_lines: list[str] = []
    for r in report.results:
        if r.status == "missing":
            missing_lines.append(f"{r.status_icon} {r.item.name} ({r.item.cli_flag})")
    if missing_lines:
        sections.append({"label": "未触发", "lines": missing_lines})

    core_card("端到端验证报告 (R-023)", sections=sections)


def run_e2e_validation(ctx_metadata: dict[str, Any]) -> E2EValidationReport:
    """执行端到端验证并打印报告.

    Args:
        ctx_metadata: ``ctx.metadata`` 字典.

    Returns:
        E2EValidationReport 验证报告。
    """
    try:
        report = validate_metadata(ctx_metadata)
        print_validation_report(report)
        return report
    except Exception as e:
        logger.warning(f"E2E validation failed: {e}", exc_info=True)
        return E2EValidationReport()
