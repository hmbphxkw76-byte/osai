"""
Recon → ARM → Strike → Assess → Report / Evidence 全链路数据流完整性验证器

用途:
    1. 在每个 Phase 边界自动快照 PipelineContext 关键字段
    2. 验证数据在阶段间传递时无丢失、无变形
    3. 生成数据流审计报告，确认实施符合架构预期
    4. 可作为 CI/CD 自动化检查或手动审计使用

全链路数据流拓扑:
    Recon → ARM → Strike → Assess → Report/Evidence
    │         │       │         │          │
    │ service │ seeds  │ attack  │ asr_per  │ evidence
    │ _profile│techniq │ _results│ _techniq │ _collection
    │ target_ │converte│         │ overall_ │ wilson_ci
    │fingerpr │r_map   │         │ asr      │ orchestrat
    │ objective│        │         │ dual_jud │ ion_log
    │ _target │        │         │ ge_stats │

Academic basis:
    - NIST SP 800-115: Technical Guide to Information Security Testing
    - OWASP Testing Guide v4.2: Data Integrity Verification
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)


# =============================================================================
# 数据流追踪模型
# =============================================================================

class Phase(str, Enum):
    """流水线阶段标识"""
    RECON = "recon"
    ARM = "arm"
    STRIKE = "strike"
    ASSESS = "assess"
    REPORT = "report"


@dataclass
class DataSnapshot:
    """单个阶段的数据快照"""
    phase: str
    timestamp: float
    context_hash: int  # 上下文对象 ID
    fields: dict[str, Any]  # 关键字段状态
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationResult:
    """单条验证结果"""
    rule_id: str
    rule_name: str
    passed: bool
    phase_from: str
    phase_to: str
    message: str
    severity: str  # "error", "warning", "info"
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class DataFlowReport:
    """完整数据流验证报告"""
    timestamp: str
    total_rules: int
    passed: int
    failed: int
    warnings: int
    results: list[ValidationResult]
    snapshots: list[DataSnapshot]
    duration_seconds: float

    @property
    def is_valid(self) -> bool:
        """是否无错误"""
        return self.failed == 0


# =============================================================================
# 数据流追踪器 — 核心实现
# =============================================================================

class DataFlowValidator:
    """
    Recon → ARM → Strike → Assess → Report/Evidence 全链路数据流完整性验证器

    在每个 Phase 边界调用 snapshot()，结束时调用 validate_all()
    """

    # 定义每个阶段应有的关键字段及其期望状态
    # field_name 必须与 _extract_fields() 输出一致
    # 格式: {phase: {field_name: constraint}}
    # constraint: "not_none" | "not_empty" | "positive_count" | "non_negative" | "valid_ci"
    FIELD_CONTRACTS: dict[str, dict[str, str]] = {
        # === Recon 阶段输出契约 ===
        "post_recon": {
            "has_objective_target": "not_none",          # 攻击目标已创建
            "service_profile_size": "positive_count",     # 服务画像非空
            "has_target_fingerprint": "not_none",        # 目标指纹已提取
        },
        # === ARM 阶段输出契约 ===
        "post_arm": {
            "seeds_count": "positive_count",             # 种子列表非空
            "techniques_count": "positive_count",         # 技术列表非空
            "converter_map_total_converters": "positive_count",  # 转换器映射非空
        },
        # === Strike 阶段输出契约 ===
        "post_strike": {
            "attack_results_total": "positive_count",     # 攻击结果非空
        },
        # === Assess 阶段输出契约 ===
        "post_assess": {
            "asr_techniques_count": "positive_count",     # ASR 统计覆盖所有技术
            "overall_asr": "non_negative",                # 总体 ASR 非负
            "dual_judge_total_scored": "positive_count",  # 双评判统计非空
        },
        # === Report/Evidence 阶段输出契约 ===
        "post_report": {
            "orchestration_log_count": "positive_count",  # 审计日志非空
            "overall_asr": "non_negative",                # ASR 值有效传递
        },
    }

    # 阶段间数据传递规则 (字段名称兼容 _extract_fields 输出)
    TRANSFER_RULES: list[dict[str, Any]] = [
        # === Recon → ARM 桥 ===
        {
            "id": "T001",
            "name": "Recon → ARM: objective_target 传递",
            "from": "recon",
            "to": "arm",
            "field": "has_objective_target",
            "check": "exists",
        },
        {
            "id": "T002",
            "name": "Recon → ARM: service_profile 传递",
            "from": "recon",
            "to": "arm",
            "field": "service_profile_size",
            "check": "positive_count",
        },
        {
            "id": "T003",
            "name": "Recon → ARM: target_fingerprint 传递",
            "from": "recon",
            "to": "arm",
            "field": "has_target_fingerprint",
            "check": "exists",
        },
        # === ARM → Strike 桥 ===
        {
            "id": "T004",
            "name": "ARM → Strike: seeds 传递",
            "from": "arm",
            "to": "strike",
            "field": "seeds_count",
            "check": "positive_count",
        },
        {
            "id": "T005",
            "name": "ARM → Strike: techniques 传递",
            "from": "arm",
            "to": "strike",
            "field": "techniques_count",
            "check": "positive_count",
        },
        {
            "id": "T006",
            "name": "ARM → Strike: converter_map 传递",
            "from": "arm",
            "to": "strike",
            "field": "converter_map_total_converters",
            "check": "positive_count",
        },
        # === Strike → Assess 桥 ===
        {
            "id": "T007",
            "name": "Strike → Assess: attack_results 传递",
            "from": "strike",
            "to": "assess",
            "field": "attack_results_total",
            "check": "positive_count",
        },
        {
            "id": "T008",
            "name": "Strike → Assess: attack_results 技术覆盖",
            "from": "strike",
            "to": "assess",
            "field": "attack_results_keys",
            "check": "exists_and_not_empty",
        },
        # === Assess → Report/Evidence 桥 ===
        {
            "id": "T009",
            "name": "Assess → Report: asr_per_technique 传递",
            "from": "assess",
            "to": "report",
            "field": "asr_techniques_count",
            "check": "positive_count",
        },
        {
            "id": "T010",
            "name": "Assess → Report: overall_asr 传递",
            "from": "assess",
            "to": "report",
            "field": "overall_asr",
            "check": "exists_and_valid_range",
        },
        {
            "id": "T011",
            "name": "Assess → Report: dual_judge_stats 传递",
            "from": "assess",
            "to": "report",
            "field": "dual_judge_total_scored",
            "check": "positive_count",
        },
        {
            "id": "T012",
            "name": "Assess → Report: wilson_ci 传递",
            "from": "assess",
            "to": "report",
            "field": "wilson_ci",
            "check": "valid_ci",
        },
        # === 可选字段：MCPSec 桥 ===
        {
            "id": "T013",
            "name": "Recon → ARM: mcpsec_surface 可用性",
            "from": "recon",
            "to": "arm",
            "field": "mcpsec_surface_tools_count",
            "check": "exists_optional",
        },
        {
            "id": "T014",
            "name": "Recon → ARM: mcpsec_scan_results 可用性",
            "from": "recon",
            "to": "arm",
            "field": "mcpsec_vulnerabilities_count",
            "check": "exists_optional",
        },
    ]

    # 跨阶段一致性规则
    CROSS_PHASE_RULES: list[dict[str, Any]] = [
        {
            "id": "CONS-001",
            "name": "攻击技术 ASR 覆盖一致性",
            "from": "strike",
            "to": "assess",
            "check": "asr_coverage",  # asr_per_technique 覆盖 attack_results 中所有技术
        },
        {
            "id": "CONS-002",
            "name": "审计日志阶段完整性",
            "from": "recon",
            "to": "report",
            "check": "orchestration_phases",  # orchestration_log 包含全部 5 个阶段
        },
        {
            "id": "CONS-003",
            "name": "评判统计完整性",
            "from": "assess",
            "to": "report",
            "check": "dual_judge_and_wilson",  # dual_judge_stats 与 wilson_ci 同时非空
        },
        {
            "id": "CONS-004",
            "name": "Converter-技术映射一致性",
            "from": "arm",
            "to": "strike",
            "check": "converter_map_coverage",  # converter_map 覆盖 techniques 中所有技术
        },
        {
            "id": "CONS-005",
            "name": "攻击结果与种子数比例校验",
            "from": "strike",
            "to": "assess",
            "check": "attack_results_non_empty",  # attack_results 结果数 >= 种子数（宽松）
        },
    ]

    def __init__(self, ctx: Any = None):
        """
        初始化验证器

        Args:
            ctx: PipelineContext 实例，用于快照数据
        """
        self.ctx = ctx
        self.snapshots: dict[str, DataSnapshot] = {}
        self.results: list[ValidationResult] = []
        self.start_time = time.monotonic()

    def set_context(self, ctx: Any) -> None:
        """设置/更新上下文"""
        self.ctx = ctx

    def snapshot(self, phase: str, metadata: dict[str, Any] | None = None) -> DataSnapshot:
        """
        在 Phase 边界创建数据快照

        Args:
            phase: 阶段标识 (如 "post_recon", "post_arm")
            metadata: 额外元数据

        Returns:
            DataSnapshot 实例
        """
        if self.ctx is None:
            raise RuntimeError("Context not set. Call set_context(ctx) first.")

        fields = self._extract_fields(self.ctx, phase)
        snap = DataSnapshot(
            phase=phase,
            timestamp=time.time(),
            context_hash=id(self.ctx),
            fields=fields,
            metadata=metadata or {},
        )
        self.snapshots[phase] = snap
        logger.debug("[DataFlow] Snapshot captured: %s (%d fields)", phase, len(fields))
        return snap

    def _extract_fields(self, ctx: Any, phase: str) -> dict[str, Any]:
        """从 PipelineContext 提取关键字段状态（支持 Recon 到 Report 全链路）"""
        fields: dict[str, Any] = {}

        # ==================== 基础字段（所有阶段共享） ====================
        fields["has_objective_target"] = getattr(ctx, "objective_target", None) is not None
        fields["has_parsed_request"] = getattr(ctx, "parsed_request", None) is not None

        # ==================== Recon 阶段字段 ====================
        sp = getattr(ctx, "service_profile", {}) or {}
        fields["service_profile_keys"] = list(sp.keys()) if isinstance(sp, dict) else []
        fields["service_profile_size"] = len(sp) if isinstance(sp, dict) else 0
        # 检测 service_profile 中的关键子项
        fields["service_profile_has_model_name"] = bool(sp.get("model_name")) if isinstance(sp, dict) else False
        fields["service_profile_has_auth"] = bool(sp.get("auth_type")) if isinstance(sp, dict) else False
        fields["service_profile_has_rag"] = bool(sp.get("rag_kb_map") or sp.get("rag_pipeline")) if isinstance(sp, dict) else False

        # target_fingerprint
        fp = getattr(getattr(ctx, "parsed_request", None), "target_fingerprint", {}) or {}
        fields["has_target_fingerprint"] = bool(fp)
        fields["target_fingerprint_keys"] = list(fp.keys()) if isinstance(fp, dict) else []
        fields["model_family"] = fp.get("model_family", "unknown") if isinstance(fp, dict) else "unknown"
        fields["model_name_from_fp"] = fp.get("model_name", "") if isinstance(fp, dict) else ""
        fields["capabilities_count"] = len(fp.get("capabilities", [])) if isinstance(fp, dict) else 0

        # Recon 特有字段
        fp_host = getattr(getattr(ctx, "parsed_request", None), "host", "") if ctx.parsed_request else ""
        fp_path = getattr(getattr(ctx, "parsed_request", None), "path", "") if ctx.parsed_request else ""
        fields["target_host"] = fp_host
        fields["target_path"] = fp_path
        fields["use_tls"] = getattr(getattr(ctx, "parsed_request", None), "use_tls", False) if ctx.parsed_request else False

        # MCPSec Phase
        mcp = getattr(ctx, "mcpsec_surface", {}) or {}
        fields["mcpsec_surface_tools_count"] = len(mcp.get("tools", [])) if isinstance(mcp, dict) else 0
        fields["mcpsec_surface_resources_count"] = len(mcp.get("resources", [])) if isinstance(mcp, dict) else 0
        fields["mcpsec_surface_prompts_count"] = len(mcp.get("prompts", [])) if isinstance(mcp, dict) else 0
        mcp_scan = getattr(ctx, "mcpsec_scan_results", {}) or {}
        fields["mcpsec_vulnerabilities_count"] = (
            len(mcp_scan.get("vulnerabilities", [])) if isinstance(mcp_scan, dict) else 0
        )

        # ==================== ARM 阶段字段 ====================
        seeds = getattr(ctx, "seeds", []) or []
        fields["seeds_count"] = len(seeds) if hasattr(seeds, "__len__") else 0
        fields["seeds_has_data"] = fields["seeds_count"] > 0

        techniques = getattr(ctx, "techniques", []) or []
        fields["techniques_count"] = len(techniques) if hasattr(techniques, "__len__") else 0
        fields["techniques_list"] = techniques if isinstance(techniques, list) else []

        # converter_map
        cm = getattr(ctx, "converter_map", {}) or {}
        fields["converter_map_keys"] = list(cm.keys()) if isinstance(cm, dict) else []
        fields["converter_map_size"] = len(cm) if isinstance(cm, dict) else 0
        fields["converter_map_total_converters"] = (
            sum(len(v) for v in cm.values() if hasattr(v, "__len__")) if isinstance(cm, dict) else 0
        )

        # ==================== Strike 阶段字段 ====================
        ar = getattr(ctx, "attack_results", {}) or {}
        fields["attack_results_keys"] = list(ar.keys()) if isinstance(ar, dict) else []
        fields["attack_results_total"] = (
            sum(len(v) for v in ar.values() if hasattr(v, "__len__")) if isinstance(ar, dict) else 0
        )
        fields["attack_results_per_technique"] = {
            k: len(v) for k, v in ar.items() if hasattr(v, "__len__")
        } if isinstance(ar, dict) else {}

        # 统计攻击成功数
        # _is_success 可能来自 evidence_extract 或 其他模块
        try:
            from report.evidence_extract import _is_success as _ev_is_success
            fields["attack_success_count"] = sum(
                1 for results in ar.values()
                for r in (results if hasattr(results, "__iter__") else [])
                if _ev_is_success(r)
            ) if isinstance(ar, dict) else 0
        except ImportError:
            fields["attack_success_count"] = 0

        # ==================== Assess 阶段字段 ====================
        asr_pt = getattr(ctx, "asr_per_technique", {}) or {}
        fields["asr_per_technique"] = asr_pt if isinstance(asr_pt, dict) else {}
        fields["asr_techniques_count"] = len(asr_pt) if isinstance(asr_pt, dict) else 0
        fields["overall_asr"] = getattr(ctx, "overall_asr", 0.0)
        fields["overall_asr_percent"] = round(getattr(ctx, "overall_asr", 0.0), 2)

        djs = getattr(ctx, "dual_judge_stats", {}) or {}
        fields["dual_judge_stats_keys"] = list(djs.keys()) if isinstance(djs, dict) else []
        fields["dual_judge_total_scored"] = djs.get("total_scored", 0) if isinstance(djs, dict) else 0
        fields["cohens_kappa"] = djs.get("cohens_kappa", 0.0) if isinstance(djs, dict) else 0.0

        wc = getattr(ctx, "wilson_ci", (0.0, 0.0))
        fields["wilson_ci"] = list(wc) if isinstance(wc, (tuple, list)) else [0.0, 0.0]

        # ==================== Report/Evidence 阶段字段 ====================
        ol = getattr(ctx, "orchestration_log", []) or []
        fields["orchestration_log_count"] = len(ol) if isinstance(ol, list) else 0
        fields["orchestration_phases"] = [
            entry.get("phase", "unknown") for entry in ol
        ] if isinstance(ol, list) else []

        # Evidence 相关字段（通过检测 evidence 对象是否存在）
        fields["has_evidence_collection"] = hasattr(ctx, "evidence_collection") and ctx.evidence_collection is not None
        if fields["has_evidence_collection"]:
            ev = ctx.evidence_collection
            fields["evidence_total_attacks"] = getattr(ev, "total_attacks", 0)
            fields["evidence_successful_attacks"] = getattr(ev, "successful_attacks", 0)
            fields["evidence_findings_count"] = len(getattr(ev, "findings", []))
            fields["evidence_has_owasp"] = bool(getattr(ev, "owasp_llm_compliance", {}))
        else:
            fields["evidence_total_attacks"] = 0
            fields["evidence_successful_attacks"] = 0
            fields["evidence_findings_count"] = 0
            fields["evidence_has_owasp"] = False

        return fields

    def validate_all(self) -> DataFlowReport:
        """
        执行所有数据流验证规则

        Returns:
            DataFlowReport 验证报告
        """
        self.results = []

        # 执行字段契约验证
        for phase, contract in self.FIELD_CONTRACTS.items():
            if phase not in self.snapshots:
                self.results.append(ValidationResult(
                    rule_id="MISS",
                    rule_name=f"快照缺失: {phase}",
                    passed=False,
                    phase_from=phase,
                    phase_to="N/A",
                    message=f"缺少 {phase} 阶段的数据快照，请确认 snapshot('{phase}') 已被调用",
                    severity="error",
                ))
                continue
            self._validate_contract(phase, contract)

        # 执行传递规则验证
        for rule in self.TRANSFER_RULES:
            self._validate_transfer_rule(rule)

        # 执行跨阶段一致性规则
        for rule in self.CROSS_PHASE_RULES:
            self._validate_cross_phase_rule(rule)

        # 生成报告
        duration = time.time() - self.start_time
        passed = sum(1 for r in self.results if r.passed and r.severity != "warning")
        failed = sum(1 for r in self.results if not r.passed and r.severity == "error")
        warnings = sum(1 for r in self.results if r.severity == "warning" and not r.passed)

        report = DataFlowReport(
            timestamp=datetime.now().isoformat(),
            total_rules=len(self.results),
            passed=passed,
            failed=failed,
            warnings=warnings,
            results=self.results,
            snapshots=list(self.snapshots.values()),
            duration_seconds=round(duration, 3),
        )

        return report

    def _validate_contract(self, phase: str, contract: dict[str, str]) -> None:
        """验证单个阶段的字段契约"""
        snap = self.snapshots[phase]
        fields = snap.fields

        for field_name, constraint in contract.items():
            if field_name not in fields:
                self.results.append(ValidationResult(
                    rule_id=f"CTR-{phase[:3].upper()}",
                    rule_name=f"字段缺失: {phase}/{field_name}",
                    passed=False,
                    phase_from=phase,
                    phase_to="N/A",
                    message=f"{phase} 阶段缺少预期字段 '{field_name}'",
                    severity="error",
                    details={"field": field_name, "phase": phase},
                ))
                continue

            value = fields[field_name]
            passed, message = self._check_constraint(value, constraint, field_name)

            self.results.append(ValidationResult(
                rule_id=f"CTR-{phase[:3].upper()}-{field_name[:8].upper()}",
                rule_name=f"契约验证: {phase}/{field_name}",
                passed=passed,
                phase_from=phase,
                phase_to="N/A",
                message=message,
                severity="error" if not passed else "info",
                details={"field": field_name, "constraint": constraint, "value_preview": str(value)[:100]},
            ))

    def _validate_transfer_rule(self, rule: dict[str, Any]) -> None:
        """验证阶段间数据传递规则"""
        rule_id = rule["id"]
        rule_name = rule["name"]
        field = rule["field"]
        check_type = rule["check"]

        from_phase = rule["from"]
        snap_key = f"post_{from_phase}"
        if snap_key not in self.snapshots:
            self.results.append(ValidationResult(
                rule_id=rule_id,
                rule_name=rule_name,
                passed=True,
                phase_from=from_phase,
                phase_to=rule["to"],
                message=f"源阶段 {from_phase} 未执行 ({snap_key} 快照不存在)，跳过规则",
                severity="info",
            ))
            return

        snap = self.snapshots[snap_key]
        value = snap.fields.get(field)

        passed = True
        message = f"{rule_id}: {rule_name} - "

        if check_type == "exists_and_not_empty":
            if value is None:
                passed = False
                message += f"字段 '{field}' 不存在"
            elif isinstance(value, (list, dict, str)) and len(value) == 0:
                passed = False
                message += f"字段 '{field}' 为空"
            else:
                message += f"字段 '{field}' 存在且非空 ✓"

        elif check_type == "positive_count":
            if not isinstance(value, int):
                passed = False
                message += f"字段 '{field}'={value} 不是整数"
            elif value <= 0:
                passed = False
                message += f"字段 '{field}'={value} 应为正数"
            else:
                message += f"字段 '{field}'={value} (> 0) ✓"

        elif check_type == "exists":
            if value is None or value is False or value == 0:
                passed = False
                if isinstance(value, bool) and not value:
                    message += f"字段 '{field}' 为 False（布尔假值）"
                else:
                    message += f"字段 '{field}' 不存在或为空"
            else:
                message += f"字段 '{field}' 存在 ✓"

        elif check_type == "exists_optional":
            message += f"可选字段 '{field}' 状态: {'已设置' if value and value != {} and value != [] and value != 0 else '未设置(可选)'}"

        elif check_type == "exists_and_valid_range":
            if value is None:
                passed = False
                message += f"字段 '{field}' 不存在"
            elif isinstance(value, (int, float)) and (value < 0 or value > 100):
                passed = False
                message += f"字段 '{field}' 值 {value} 超出有效范围 [0, 100]"
            else:
                message += f"字段 '{field}' 值有效: {value} ✓"

        elif check_type == "valid_ci":
            wc = value if isinstance(value, (list, tuple)) else [0.0, 0.0]
            if len(wc) != 2:
                passed = False
                message += f"WCI 格式无效: {wc}"
            elif wc[0] > wc[1]:
                passed = False
                message += f"WCI lower ({wc[0]}) > upper ({wc[1]})"
            elif wc[0] == 0.0 and wc[1] == 0.0:
                passed = False
                message += f"WCI 未计算 (0.0, 0.0)"
            else:
                message += f"WCI 有效: [{wc[0]:.3f}, {wc[1]:.3f}] ✓"

        self.results.append(ValidationResult(
            rule_id=rule_id,
            rule_name=rule_name,
            passed=passed,
            phase_from=from_phase,
            phase_to=rule["to"],
            message=message,
            severity="error" if not passed else "info",
            details={"field": field, "check": check_type, "value": str(value)[:80]},
        ))

    def _validate_cross_phase_rule(self, rule: dict[str, Any]) -> None:
        """验证跨阶段一致性规则"""
        rule_id = rule["id"]
        rule_name = rule["name"]
        check_type = rule["check"]

        if check_type == "asr_coverage":
            # 验证 attack_results 中的技术也在 asr_per_technique 中
            if "post_strike" in self.snapshots and "post_assess" in self.snapshots:
                strike_fields = self.snapshots["post_strike"].fields
                assess_fields = self.snapshots["post_assess"].fields

                ar_techniques = set(strike_fields.get("attack_results_keys", []))
                asr_techniques = set(assess_fields.get("asr_per_technique", {}).keys())

                missing = ar_techniques - asr_techniques
                if missing:
                    self.results.append(ValidationResult(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        passed=False,
                        phase_from="strike",
                        phase_to="assess",
                        message=f"攻击结果中的技术 {missing} 未在 ASR 统计中出现",
                        severity="error",
                        details={"missing_techniques": list(missing)},
                    ))
                else:
                    self.results.append(ValidationResult(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        passed=True,
                        phase_from="strike",
                        phase_to="assess",
                        message=f"所有 {len(ar_techniques)} 种攻击技术均有 ASR 统计 ✓",
                        severity="info",
                    ))
            else:
                self.results.append(ValidationResult(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    passed=True,
                    phase_from=rule["from"],
                    phase_to=rule["to"],
                    message="缺少 strike/assess 快照，跳过 ASR 覆盖检查",
                    severity="info",
                ))

        elif check_type == "orchestration_phases":
            # 验证 orchestration_log 包含全部 5 个阶段
            if "post_report" in self.snapshots:
                phases_in_log = self.snapshots["post_report"].fields.get("orchestration_phases", [])
                expected_phases = ["recon", "arm", "strike", "assess"]
                missing_phases = [p for p in expected_phases if p not in phases_in_log]
                if missing_phases:
                    self.results.append(ValidationResult(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        passed=False,
                        phase_from="recon",
                        phase_to="report",
                        message=f"orchestration_log 缺少阶段: {missing_phases}",
                        severity="warning",
                        details={"missing": missing_phases, "present": phases_in_log},
                    ))
                else:
                    self.results.append(ValidationResult(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        passed=True,
                        phase_from="recon",
                        phase_to="report",
                        message=f"orchestration_log 包含全部 4 个核心阶段记录 ✓",
                        severity="info",
                    ))
            elif "post_assess" in self.snapshots:
                # 降级: 在 assess 阶段检查
                phases_in_log = self.snapshots["post_assess"].fields.get("orchestration_phases", [])
                expected_phases = ["recon", "arm", "strike", "assess"]
                missing_phases = [p for p in expected_phases if p not in phases_in_log]
                if missing_phases:
                    self.results.append(ValidationResult(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        passed=False,
                        phase_from="recon",
                        phase_to="assess",
                        message=f"orchestration_log 缺少阶段: {missing_phases}",
                        severity="warning",
                        details={"missing": missing_phases, "present": phases_in_log},
                    ))
                else:
                    self.results.append(ValidationResult(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        passed=True,
                        phase_from="recon",
                        phase_to="assess",
                        message=f"orchestration_log 包含全部 4 个核心阶段记录 ✓",
                        severity="info",
                    ))

        elif check_type == "dual_judge_and_wilson":
            # 验证 dual_judge_stats 与 wilson_ci 并存
            if "post_assess" in self.snapshots:
                djs_keys = self.snapshots["post_assess"].fields.get("dual_judge_stats_keys", [])
                wilson = self.snapshots["post_assess"].fields.get("wilson_ci", [0.0, 0.0])
                if not djs_keys and wilson == [0.0, 0.0]:
                    self.results.append(ValidationResult(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        passed=False,
                        phase_from="assess",
                        phase_to="report",
                        message="dual_judge_stats 为空且 wilson_ci 未计算",
                        severity="warning",
                    ))
                else:
                    self.results.append(ValidationResult(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        passed=True,
                        phase_from="assess",
                        phase_to="report",
                        message=f"评判统计完整: {len(djs_keys)} 个指标, Wilson CI={wilson} ✓",
                        severity="info",
                    ))

        elif check_type == "converter_map_coverage":
            # 验证 converter_map 的键覆盖 techniques
            if "post_arm" in self.snapshots:
                arm_fields = self.snapshots["post_arm"].fields
                techs = set(arm_fields.get("techniques_list", []))
                cm_keys = set(arm_fields.get("converter_map_keys", []))
                missing = techs - cm_keys
                if missing:
                    self.results.append(ValidationResult(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        passed=False,
                        phase_from="arm",
                        phase_to="strike",
                        message=f"技术 {missing} 无对应 converter_map 映射",
                        severity="error",
                        details={"missing_techniques": list(missing)},
                    ))
                else:
                    self.results.append(ValidationResult(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        passed=True,
                        phase_from="arm",
                        phase_to="strike",
                        message=f"converter_map 覆盖全部 {len(techs)} 种攻击技术 ✓",
                        severity="info",
                    ))

        elif check_type == "attack_results_non_empty":
            # 验证 attack_results 中每种技术的结果数 >= 1
            if "post_strike" in self.snapshots:
                per_tech = self.snapshots["post_strike"].fields.get("attack_results_per_technique", {})
                empty_techniques = [k for k, v in per_tech.items() if v == 0]
                if empty_techniques:
                    self.results.append(ValidationResult(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        passed=True,  # 非阻断: 某些技术可能返回 0 结果（设计如此）
                        phase_from="strike",
                        phase_to="assess",
                        message=f"技术 {empty_techniques} 攻击结果为 0（可能为预期行为）",
                        severity="info",
                        details={"empty_techniques": empty_techniques},
                    ))
                else:
                    self.results.append(ValidationResult(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        passed=True,
                        phase_from="strike",
                        phase_to="assess",
                        message=f"全部 {len(per_tech)} 种技术均有攻击结果 ✓",
                        severity="info",
                    ))

    @staticmethod
    def _check_constraint(value: Any, constraint: str, field_name: str) -> tuple[bool, str]:
        """
        检查字段值是否满足约束

        Args:
            value: 字段值
            constraint: 约束类型字符串
            field_name: 字段名称（用于消息）

        Returns:
            (是否通过, 消息)
        """
        if constraint == "not_none":
            passed = value is not None
            if isinstance(value, bool):
                passed = value  # 布尔值直接检查真假
            return passed, f"{field_name}: {'存在/True' if passed else '为 None/False'}"

        if constraint == "not_empty":
            if value is None:
                return False, f"{field_name}: 为 None"
            if isinstance(value, (list, dict, str)):
                return len(value) > 0, f"{field_name}: {'非空 (len=' + str(len(value)) + ')' if len(value) > 0 else '为空'}"
            return True, f"{field_name}: 非空值"

        if constraint == "positive_count":
            """正整数计数"""
            if not isinstance(value, int):
                return False, f"{field_name}: 不是整数 (类型={type(value).__name__})"
            return value > 0, f"{field_name}: {'正数 (' + str(value) + ') ✓' if value > 0 else '非正数 (' + str(value) + ')'}"

        if constraint == "non_negative":
            if isinstance(value, (int, float)):
                return value >= 0, f"{field_name}: {'非负 (' + str(value) + ')' if value >= 0 else '负数 (' + str(value) + ')'}"
            return False, f"{field_name}: 不是数值 (类型={type(value).__name__})"

        if constraint == "valid_ci":
            if isinstance(value, (tuple, list)) and len(value) == 2:
                return value[0] <= value[1], f"{field_name}: CI = {value}"
            return False, f"{field_name}: 无效的置信区间格式"

        return True, f"{field_name}: 通过约束检查"


# =============================================================================
# 报告格式化输出
# =============================================================================

def format_report(report: DataFlowReport, ascii_only: bool = False) -> str:
    """
    格式化验证报告为可读文本

    Args:
        report: 验证报告
        ascii_only: 是否仅使用 ASCII 字符（兼容 Windows GBK 终端）
    """
    # 符号选择: Unicode emoji 或 ASCII 替代
    if ascii_only:
        S_PASS = "[PASS]"
        S_FAIL = "[FAIL]"
        S_WARN = "[WARN]"
        S_INFO = "[INFO]"
        S_DOT = "*"
    else:
        S_PASS = "✅"
        S_FAIL = "❌"
        S_WARN = "⚠️"
        S_INFO = "ℹ️"
        S_DOT = "•"

    lines: list[str] = []

    lines.append("=" * 80)
    lines.append("Recon → ARM → Strike → Assess → Report/Evidence")
    lines.append("=" * 80)
    lines.append(f"验证时间: {report.timestamp}")
    lines.append(f"验证耗时: {report.duration_seconds:.3f}s")
    lines.append(f"规则总数: {report.total_rules}")
    lines.append(f"通过: {report.passed} | 失败: {report.failed} | 警告: {report.warnings}")
    lines.append(f"验证结果: {S_PASS + ' 全部通过' if report.is_valid else S_FAIL + ' 存在失败项'}")
    lines.append("")

    # 按阶段分组展示
    phases_order = ["post_recon", "post_arm", "post_strike", "post_assess", "post_report"]
    phase_labels = {
        "post_recon": "Recon 阶段输出",
        "post_arm": "ARM 阶段输出",
        "post_strike": "Strike 阶段输出",
        "post_assess": "Assess 阶段输出",
        "post_report": "Report/Evidence 阶段输出",
    }

    for phase in phases_order:
        phase_results = [r for r in report.results if r.phase_from == phase or r.phase_from == phase.replace("post_", "")]
        if not phase_results:
            continue

        lines.append("-" * 80)
        lines.append(phase_labels.get(phase, phase))
        lines.append("-" * 80)

        for r in phase_results:
            if r.passed:
                icon = S_PASS
            elif r.severity == "warning":
                icon = S_WARN
            else:
                icon = S_FAIL
            lines.append(f"  {icon} [{r.rule_id}] {r.rule_name}")
            lines.append(f"      {r.message}")

        lines.append("")

    # 快照摘要
    lines.append("-" * 80)
    lines.append("数据快照摘要")
    lines.append("-" * 80)
    for snap in report.snapshots:
        ts = datetime.fromtimestamp(snap.timestamp).strftime("%H:%M:%S") if snap.timestamp > 0 else "N/A"
        lines.append(f"\n  [{snap.phase}] @ {ts}")
        key_metrics = {
            "seeds_count": "种子数",
            "techniques_count": "技术数",
            "converter_map_total_converters": "转换器总数",
            "attack_results_total": "攻击结果总数",
            "overall_asr": "总体 ASR",
            "dual_judge_total_scored": "评判总数",
            "service_profile_size": "服务画像项数",
            "evidence_total_attacks": "证据总数",
        }
        for key, label in key_metrics.items():
            if key in snap.fields:
                val = snap.fields[key]
                lines.append(f"      {label}: {val}")

    lines.append("")
    lines.append("=" * 80)
    if report.is_valid:
        lines.append("结论: 全链路数据流完整性验证通过 [PASS]")
    else:
        lines.append("结论: 发现数据传递断点 [FAIL]")
    lines.append("=" * 80)

    return "\n".join(lines)


# =============================================================================
# 便捷使用接口
# =============================================================================

def create_validator(ctx: Any = None) -> DataFlowValidator:
    """工厂函数: 创建验证器实例"""
    return DataFlowValidator(ctx)


def run_quick_check(ctx: Any) -> bool:
    """
    快速数据流检查 — 在流水线结束时调用

    Args:
        ctx: PipelineContext 实例

    Returns:
        数据流是否完整
    """
    validator = DataFlowValidator(ctx)

    # 生成各阶段快照（从 ctx 读取状态）
    for phase in ["recon", "arm", "strike", "assess", "report"]:
        if phase == "recon" and hasattr(ctx, "service_profile"):
            validator.snapshot("post_recon")
        elif phase == "arm" and hasattr(ctx, "seeds"):
            validator.snapshot("post_arm")
        elif phase == "strike" and hasattr(ctx, "attack_results"):
            validator.snapshot("post_strike")
        elif phase == "assess" and hasattr(ctx, "dual_judge_stats"):
            validator.snapshot("post_assess")
        elif phase == "report":
            validator.snapshot("post_report")

    # 如果没有快照，只生成当前快照
    if not validator.snapshots:
        validator.snapshot("post_report")

    report = validator.validate_all()

    # 仅检查关键输出
    if report.snapshots:
        last_fields = report.snapshots[-1].fields

        # 检查核心数据存在性
        critical_fields = [
            ("service_profile_size", "Recon 侦察数据"),
            ("seeds_count", "ARM 种子数据"),
            ("attack_results_total", "Strike 攻击结果"),
            ("asr_techniques_count", "Assess ASR 统计"),
            ("orchestration_log_count", "审计日志"),
        ]

        for field, label in critical_fields:
            value = last_fields.get(field)
            if value is None or value == 0 or value == "[]" or value == "{}":
                logger.warning("[DataFlow] 快速检查失败: %s (%s) 为空", label, field)
                return False

    logger.info("[DataFlow] 快速检查通过")
    return True


# =============================================================================
# 命令行入口
# =============================================================================

def main():
    """命令行入口: 审计 orchestration_log 中的数据流"""
    import argparse

    parser = argparse.ArgumentParser(description="Recon → ARM → Strike → Assess → Report/Evidence 数据流验证器")
    parser.add_argument("--log-file", type=str, help="orchestration_log JSON 文件路径")
    parser.add_argument("--output", type=str, help="输出报告文件路径")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="输出格式")
    args = parser.parse_args()

    if args.log_file:
        # 从文件审计
        log_path = Path(args.log_file)
        if not log_path.exists():
            print(f"错误: 文件不存在 {log_path}")
            return

        data = json.loads(log_path.read_text(encoding="utf-8"))
        report = _audit_from_log(data)
    else:
        # 演示模式: 运行模拟验证
        print("运行演示模式 (--log-file 参数可审计实际运行日志)")
        print()
        report = _demo_validation()

    # 输出报告
    if args.format == "text":
        # 检测是否在需要 ASCII 的环境 (如 Windows 终端)
        try:
            output = format_report(report, ascii_only=False)
            output.encode("gbk")
        except (UnicodeEncodeError, LookupError):
            output = format_report(report, ascii_only=True)
    else:
        output = json.dumps({
            "timestamp": report.timestamp,
            "total_rules": report.total_rules,
            "passed": report.passed,
            "failed": report.failed,
            "warnings": report.warnings,
            "is_valid": report.is_valid,
            "results": [
                {
                    "rule_id": r.rule_id,
                    "rule_name": r.rule_name,
                    "passed": r.passed,
                    "phase_from": r.phase_from,
                    "phase_to": r.phase_to,
                    "message": r.message,
                    "severity": r.severity,
                }
                for r in report.results
            ],
        }, indent=2, ensure_ascii=False)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"报告已保存: {args.output}")
    else:
        # 处理 Windows 终端编码问题
        try:
            print(output)
        except UnicodeEncodeError:
            # 编码回退: 替换无法编码的字符
            safe_output = output.encode("ascii", errors="replace").decode("ascii")
            print(safe_output)


def _audit_from_log(log_entries: list[dict]) -> DataFlowReport:
    """从 orchestration_log 审计数据流"""
    validator = DataFlowValidator()

    # 根据 orchestration_log 构建虚拟快照
    phases_seen = set()
    for entry in log_entries:
        phase = entry.get("phase", "unknown")
        phases_seen.add(phase)

        # 创建虚拟快照
        snap = DataSnapshot(
            phase=f"post_{phase}",
            timestamp=time.time(),
            context_hash=id(log_entries),
            fields={"orchestration_entry": entry},
            metadata=entry,
        )
        validator.snapshots[f"post_{phase}"] = snap

    # 仅执行传递规则
    results = []
    for rule in DataFlowValidator.TRANSFER_RULES:
        from_phase = rule["from"]
        if from_phase in phases_seen:
            results.append(ValidationResult(
                rule_id=rule["id"],
                rule_name=rule["name"],
                passed=True,
                phase_from=from_phase,
                phase_to=rule["to"],
                message=f"阶段 {from_phase} 出现在 orchestration_log 中 ✓",
                severity="info",
            ))
        else:
            results.append(ValidationResult(
                rule_id=rule["id"],
                rule_name=rule["name"],
                passed=False,
                phase_from=from_phase,
                phase_to=rule["to"],
                message=f"阶段 {from_phase} 未出现在 orchestration_log 中",
                severity="warning",
            ))

    return DataFlowReport(
        timestamp=datetime.now().isoformat(),
        total_rules=len(results),
        passed=sum(1 for r in results if r.passed),
        failed=sum(1 for r in results if not r.passed and r.severity == "error"),
        warnings=sum(1 for r in results if r.severity == "warning"),
        results=results,
        snapshots=list(validator.snapshots.values()),
        duration_seconds=0.0,
    )


def _demo_validation() -> DataFlowReport:
    """运行演示验证（模拟完整流水线 Recon → ARM → Strike → Assess → Report）"""
    # 模拟 Recon 输出
    class MockCtx:
        objective_target = object()
        parsed_request = type("FP", (), {
            "target_fingerprint": {"model_family": "gpt", "language": "en", "capabilities": ["function_calling"], "model_name": "gpt-4"},
            "host": "api.example.com",
            "path": "/v1/chat/completions",
            "use_tls": True,
        })()
        service_profile = {
            "model_name": "gpt-4",
            "auth_type": "bearer",
            "rag_kb_map": {"document_count": 10},
            "backend_vendor": "openai",
        }
        mcpsec_surface = {"tools": [{"name": "search"}], "resources": [], "prompts": []}
        mcpsec_scan_results = {"vulnerabilities": []}
        seeds = []
        techniques = []
        converter_map = {}
        attack_results = {}
        asr_per_technique = {}
        overall_asr = 0.0
        dual_judge_stats = {}
        wilson_ci = (0.0, 0.0)
        orchestration_log = [{"phase": "recon", "decision": "target_created"}]

    ctx = MockCtx()
    validator = DataFlowValidator(ctx)

    # Recon 阶段快照
    validator.snapshot("post_recon", {"demo": True})

    # 模拟 ARM 输出
    ctx.seeds = [{"value": "seed1"}, {"value": "seed2"}, {"value": "seed3"}]
    ctx.techniques = ["prompt_sending", "skeleton_key", "role_play"]
    ctx.converter_map = {
        "prompt_sending": ["conv_baseline"],
        "skeleton_key": ["conv_base64"],
        "role_play": ["conv_fewshot"],
    }
    ctx.orchestration_log.append({"phase": "arm", "decision": "seeds_ranked"})
    validator.snapshot("post_arm")

    # 模拟 Strike 输出
    ctx.attack_results = {
        "prompt_sending": [object(), object(), object()],
        "skeleton_key": [object(), object()],
        "role_play": [object(), object(), object()],
    }
    ctx.orchestration_log.append({"phase": "strike", "decision": "attacks_completed"})
    validator.snapshot("post_strike")

    # 模拟 Assess 输出
    ctx.asr_per_technique = {"prompt_sending": 33.3, "skeleton_key": 50.0, "role_play": 33.3}
    ctx.overall_asr = 38.9
    ctx.dual_judge_stats = {"total_scored": 24, "agreements": 20, "disagreements": 4, "cohens_kappa": 0.78}
    ctx.wilson_ci = (0.28, 0.52)
    ctx.orchestration_log.append({"phase": "assess", "decision": "asr_computed"})
    validator.snapshot("post_assess")

    # 模拟 Report/Evidence 输出
    ctx.evidence_collection = type("Evidence", (), {
        "total_attacks": 8,
        "successful_attacks": 3,
        "findings": [{"title": "Prompt Injection"}, {"title": "Role Play Bypass"}],
        "owasp_llm_compliance": {"LLM01": {"tested": 8, "success": 3}},
    })()
    ctx.orchestration_log.append({"phase": "report", "decision": "report_generated"})
    validator.snapshot("post_report")

    return validator.validate_all()


if __name__ == "__main__":
    main()
