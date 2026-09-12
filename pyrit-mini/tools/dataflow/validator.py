"""
Recon → ARM → Strike → Assess → Report / Evidence 全链路数据流完整性验证器

用途:
    1. 在每个 Phase 边界自动快照 PipelineContext 关键字段
    2. 验证数据在阶段间传递时无丢失、无变形
    3. 生成数据流审计报告，确认实施符合架构预期
    4. 可作为 CI/CD 自动化检查或手动审计使用

模块结构:
    - models.py   : Phase/DataSnapshot/ValidationResult/DataFlowReport
    - rules.py    : FIELD_CONTRACTS/TRANSFER_RULES/CROSS_PHASE_RULES
    - format.py   : format_report/report_to_json
    - cli.py      : main/audit_from_log/demo_validation

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

import logging
import time
from datetime import datetime
from typing import Any

from tools.dataflow.models import DataFlowReport, DataSnapshot, ValidationResult
from tools.dataflow.rules import CROSS_PHASE_RULES, FIELD_CONTRACTS, TRANSFER_RULES

logger = logging.getLogger(__name__)

# 向后兼容: 保持原有顶层导出
Phase = __import__("tools.dataflow.models", fromlist=["Phase"]).Phase


# =============================================================================
# 数据流追踪器 — 核心实现
# =============================================================================


class DataFlowValidator:
    """
    Recon → ARM → Strike → Assess → Report/Evidence 全链路数据流完整性验证器

    在每个 Phase 边界调用 snapshot()，结束时调用 validate_all()
    """

    # 从 rules 导入规则配置
    FIELD_CONTRACTS = FIELD_CONTRACTS
    TRANSFER_RULES = TRANSFER_RULES
    CROSS_PHASE_RULES = CROSS_PHASE_RULES

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
        fields["service_profile_has_rag"] = (
            bool(sp.get("rag_kb_map") or sp.get("rag_pipeline")) if isinstance(sp, dict) else False
        )

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
        fields["use_tls"] = (
            getattr(getattr(ctx, "parsed_request", None), "use_tls", False) if ctx.parsed_request else False
        )

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
        fields["attack_results_per_technique"] = (
            {k: len(v) for k, v in ar.items() if hasattr(v, "__len__")} if isinstance(ar, dict) else {}
        )

        # 统计攻击成功数
        try:
            from report.evidence_extract import _is_success as _ev_is_success

            fields["attack_success_count"] = (
                sum(
                    1
                    for results in ar.values()
                    for r in (results if hasattr(results, "__iter__") else [])
                    if _ev_is_success(r)
                )
                if isinstance(ar, dict)
                else 0
            )
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
        fields["orchestration_phases"] = [entry.get("phase", "unknown") for entry in ol] if isinstance(ol, list) else []

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

        # ==================== ASR Forensic Data (Why Success/Refusal) ====================
        _successful_log = getattr(ctx, "successful_evidence_log", []) or []
        fields["successful_evidence_count"] = len(_successful_log) if isinstance(_successful_log, list) else 0

        _refusal_log = getattr(ctx, "refusal_classification_log", []) or []
        fields["refusal_classification_count"] = len(_refusal_log) if isinstance(_refusal_log, list) else 0
        # Classify refusal types distribution
        if isinstance(_refusal_log, list) and _refusal_log:
            _refusal_types = {}
            for entry in _refusal_log:
                _rtype = entry.get("refusal_type", "unknown")
                _refusal_types[_rtype] = _refusal_types.get(_rtype, 0) + 1
            fields["refusal_type_distribution"] = _refusal_types
            fields["refusal_types_count"] = len(_refusal_types)
        else:
            fields["refusal_type_distribution"] = {}
            fields["refusal_types_count"] = 0

        _guardrail_triggers = getattr(ctx, "guardrail_triggers", []) or []
        fields["guardrail_triggers_count"] = len(_guardrail_triggers) if isinstance(_guardrail_triggers, list) else 0

        _timing_meta = getattr(ctx, "timing_metadata", []) or []
        fields["timing_metadata_count"] = len(_timing_meta) if isinstance(_timing_meta, list) else 0
        # Compute average response time if available
        if isinstance(_timing_meta, list) and _timing_meta:
            _times = [e.get("total_ms", 0) for e in _timing_meta if isinstance(e, dict)]
            fields["avg_response_time_ms"] = sum(_times) / len(_times) if _times else 0.0
        else:
            fields["avg_response_time_ms"] = 0.0

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
                # 可选阶段（如 post_assess_forensic）缺失不报 error，仅 info
                if phase == "post_assess_forensic":
                    self.results.append(
                        ValidationResult(
                            rule_id="MISS",
                            rule_name=f"快照缺失: {phase}",
                            passed=True,  # 可选阶段，不阻断
                            phase_from=phase,
                            phase_to="N/A",
                            message=f"可选阶段 {phase} 未快照（不影响主流程）",
                            severity="info",
                        )
                    )
                else:
                    self.results.append(
                        ValidationResult(
                            rule_id="MISS",
                            rule_name=f"快照缺失: {phase}",
                            passed=False,
                            phase_from=phase,
                            phase_to="N/A",
                            message=f"缺少 {phase} 阶段的数据快照，请确认 snapshot('{phase}') 已被调用",
                            severity="error",
                        )
                    )
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
                self.results.append(
                    ValidationResult(
                        rule_id=f"CTR-{phase[:3].upper()}",
                        rule_name=f"字段缺失: {phase}/{field_name}",
                        passed=False,
                        phase_from=phase,
                        phase_to="N/A",
                        message=f"{phase} 阶段缺少预期字段 '{field_name}'",
                        severity="error",
                        details={"field": field_name, "phase": phase},
                    )
                )
                continue

            value = fields[field_name]
            passed, message = self._check_constraint(value, constraint, field_name)

            self.results.append(
                ValidationResult(
                    rule_id=f"CTR-{phase[:3].upper()}-{field_name[:8].upper()}",
                    rule_name=f"契约验证: {phase}/{field_name}",
                    passed=passed,
                    phase_from=phase,
                    phase_to="N/A",
                    message=message,
                    severity="error" if not passed else "info",
                    details={"field": field_name, "constraint": constraint, "value_preview": str(value)[:100]},
                )
            )

    def _validate_transfer_rule(self, rule: dict[str, Any]) -> None:
        """验证阶段间数据传递规则"""
        rule_id = rule["id"]
        rule_name = rule["name"]
        field = rule["field"]
        check_type = rule["check"]

        from_phase = rule["from"]
        snap_key = f"post_{from_phase}"
        if snap_key not in self.snapshots:
            self.results.append(
                ValidationResult(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    passed=True,
                    phase_from=from_phase,
                    phase_to=rule["to"],
                    message=f"源阶段 {from_phase} 未执行 ({snap_key} 快照不存在)，跳过规则",
                    severity="info",
                )
            )
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
                message += "WCI 未计算 (0.0, 0.0)"
            else:
                message += f"WCI 有效: [{wc[0]:.3f}, {wc[1]:.3f}] ✓"

        self.results.append(
            ValidationResult(
                rule_id=rule_id,
                rule_name=rule_name,
                passed=passed,
                phase_from=from_phase,
                phase_to=rule["to"],
                message=message,
                severity="error" if not passed else "info",
                details={"field": field, "check": check_type, "value": str(value)[:80]},
            )
        )

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
                    self.results.append(
                        ValidationResult(
                            rule_id=rule_id,
                            rule_name=rule_name,
                            passed=False,
                            phase_from="strike",
                            phase_to="assess",
                            message=f"攻击结果中的技术 {missing} 未在 ASR 统计中出现",
                            severity="error",
                            details={"missing_techniques": list(missing)},
                        )
                    )
                else:
                    self.results.append(
                        ValidationResult(
                            rule_id=rule_id,
                            rule_name=rule_name,
                            passed=True,
                            phase_from="strike",
                            phase_to="assess",
                            message=f"所有 {len(ar_techniques)} 种攻击技术均有 ASR 统计 ✓",
                            severity="info",
                        )
                    )
            else:
                self.results.append(
                    ValidationResult(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        passed=True,
                        phase_from=rule["from"],
                        phase_to=rule["to"],
                        message="缺少 strike/assess 快照，跳过 ASR 覆盖检查",
                        severity="info",
                    )
                )

        elif check_type == "orchestration_phases":
            # 验证 orchestration_log 包含全部 5 个阶段
            if "post_report" in self.snapshots:
                phases_in_log = self.snapshots["post_report"].fields.get("orchestration_phases", [])
                expected_phases = ["recon", "arm", "strike", "assess"]
                missing_phases = [p for p in expected_phases if p not in phases_in_log]
                if missing_phases:
                    self.results.append(
                        ValidationResult(
                            rule_id=rule_id,
                            rule_name=rule_name,
                            passed=False,
                            phase_from="recon",
                            phase_to="report",
                            message=f"orchestration_log 缺少阶段: {missing_phases}",
                            severity="warning",
                            details={"missing": missing_phases, "present": phases_in_log},
                        )
                    )
                else:
                    self.results.append(
                        ValidationResult(
                            rule_id=rule_id,
                            rule_name=rule_name,
                            passed=True,
                            phase_from="recon",
                            phase_to="report",
                            message="orchestration_log 包含全部 4 个核心阶段记录 ✓",
                            severity="info",
                        )
                    )
            elif "post_assess" in self.snapshots:
                # 降级: 在 assess 阶段检查
                phases_in_log = self.snapshots["post_assess"].fields.get("orchestration_phases", [])
                expected_phases = ["recon", "arm", "strike", "assess"]
                missing_phases = [p for p in expected_phases if p not in phases_in_log]
                if missing_phases:
                    self.results.append(
                        ValidationResult(
                            rule_id=rule_id,
                            rule_name=rule_name,
                            passed=False,
                            phase_from="recon",
                            phase_to="assess",
                            message=f"orchestration_log 缺少阶段: {missing_phases}",
                            severity="warning",
                            details={"missing": missing_phases, "present": phases_in_log},
                        )
                    )
                else:
                    self.results.append(
                        ValidationResult(
                            rule_id=rule_id,
                            rule_name=rule_name,
                            passed=True,
                            phase_from="recon",
                            phase_to="assess",
                            message="orchestration_log 包含全部 4 个核心阶段记录 ✓",
                            severity="info",
                        )
                    )

        elif check_type == "dual_judge_and_wilson":
            # 验证 dual_judge_stats 与 wilson_ci 并存
            if "post_assess" in self.snapshots:
                djs_keys = self.snapshots["post_assess"].fields.get("dual_judge_stats_keys", [])
                wilson = self.snapshots["post_assess"].fields.get("wilson_ci", [0.0, 0.0])
                if not djs_keys and wilson == [0.0, 0.0]:
                    self.results.append(
                        ValidationResult(
                            rule_id=rule_id,
                            rule_name=rule_name,
                            passed=False,
                            phase_from="assess",
                            phase_to="report",
                            message="dual_judge_stats 为空且 wilson_ci 未计算",
                            severity="warning",
                        )
                    )
                else:
                    self.results.append(
                        ValidationResult(
                            rule_id=rule_id,
                            rule_name=rule_name,
                            passed=True,
                            phase_from="assess",
                            phase_to="report",
                            message=f"评判统计完整: {len(djs_keys)} 个指标, Wilson CI={wilson} ✓",
                            severity="info",
                        )
                    )

        elif check_type == "converter_map_coverage":
            # 验证 converter_map 的键覆盖 techniques
            if "post_arm" in self.snapshots:
                arm_fields = self.snapshots["post_arm"].fields
                techs = set(arm_fields.get("techniques_list", []))
                cm_keys = set(arm_fields.get("converter_map_keys", []))
                missing = techs - cm_keys
                if missing:
                    self.results.append(
                        ValidationResult(
                            rule_id=rule_id,
                            rule_name=rule_name,
                            passed=False,
                            phase_from="arm",
                            phase_to="strike",
                            message=f"技术 {missing} 无对应 converter_map 映射",
                            severity="error",
                            details={"missing_techniques": list(missing)},
                        )
                    )
                else:
                    self.results.append(
                        ValidationResult(
                            rule_id=rule_id,
                            rule_name=rule_name,
                            passed=True,
                            phase_from="arm",
                            phase_to="strike",
                            message=f"converter_map 覆盖全部 {len(techs)} 种攻击技术 ✓",
                            severity="info",
                        )
                    )

        elif check_type == "attack_results_non_empty":
            # 验证 attack_results 中每种技术的结果数 >= 1
            if "post_strike" in self.snapshots:
                per_tech = self.snapshots["post_strike"].fields.get("attack_results_per_technique", {})
                empty_techniques = [k for k, v in per_tech.items() if v == 0]
                if empty_techniques:
                    self.results.append(
                        ValidationResult(
                            rule_id=rule_id,
                            rule_name=rule_name,
                            passed=True,  # 非阻断: 某些技术可能返回 0 结果（设计如此）
                            phase_from="strike",
                            phase_to="assess",
                            message=f"技术 {empty_techniques} 攻击结果为 0（可能为预期行为）",
                            severity="info",
                            details={"empty_techniques": empty_techniques},
                        )
                    )
                else:
                    self.results.append(
                        ValidationResult(
                            rule_id=rule_id,
                            rule_name=rule_name,
                            passed=True,
                            phase_from="strike",
                            phase_to="assess",
                            message=f"全部 {len(per_tech)} 种技术均有攻击结果 ✓",
                            severity="info",
                        )
                    )

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
                return len(
                    value
                ) > 0, f"{field_name}: {'非空 (len=' + str(len(value)) + ')' if len(value) > 0 else '为空'}"
            return True, f"{field_name}: 非空值"

        if constraint == "positive_count":
            """正整数计数"""
            if not isinstance(value, int):
                return False, f"{field_name}: 不是整数 (类型={type(value).__name__})"
            return (
                value > 0,
                f"{field_name}: {'正数 (' + str(value) + ') ✓' if value > 0 else '非正数 (' + str(value) + ')'}",
            )

        if constraint == "non_negative":
            if isinstance(value, (int, float)):
                return (
                    value >= 0,
                    f"{field_name}: {'非负 (' + str(value) + ')' if value >= 0 else '负数 (' + str(value) + ')'}",
                )
            return False, f"{field_name}: 不是数值 (类型={type(value).__name__})"

        if constraint == "valid_ci":
            if isinstance(value, (tuple, list)) and len(value) == 2:
                return value[0] <= value[1], f"{field_name}: CI = {value}"
            return False, f"{field_name}: 无效的置信区间格式"

        return True, f"{field_name}: 通过约束检查"


# =============================================================================
# 便捷使用接口
# =============================================================================


# 延迟导入以避免循环依赖
def __getattr__(name: str):
    if name == "format_report":
        from tools.dataflow.format import format_report

        return format_report
    if name == "create_validator":
        return lambda ctx=None: DataFlowValidator(ctx)
    # W0 fix: `_run_quick_check` was removed from tools.dataflow.cli; the alias raised
    # ImportError on attribute access. Fall through to the honest AttributeError instead.
    raise AttributeError(f"module 'tools.dataflow.validator' has no attribute {name}")


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
# CLI 入口 — 委托给 tools.dataflow.cli
# =============================================================================


def main():
    """命令行入口: 委托给 tools.dataflow.cli.main"""
    from tools.dataflow.cli import main as _cli_main

    _cli_main()


if __name__ == "__main__":
    main()
