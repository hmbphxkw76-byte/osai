"""
数据流完整性验证器 — 验证规则常量

定义 FIELD_CONTRACTS / TRANSFER_RULES / CROSS_PHASE_RULES 三类规则配置。
被 DataFlowValidator 类引用，独立维护便于规则扩展和审计。

Academic basis:
    - NIST SP 800-115: Technical Guide to Information Security Testing
    - OWASP Testing Guide v4.2: Data Integrity Verification
"""

from __future__ import annotations

from typing import Any

# =============================================================================
# 字段契约: 每个阶段应有的关键字段及其期望状态
# =============================================================================

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
    # === ASR Forensic 阶段输出契约 (Why-Success Data) ===
    "post_assess_forensic": {
        "successful_evidence_count": "non_negative",       # 成功证据已提取（可为 0）
        "refusal_classification_count": "non_negative",    # 拒绝分类已提取
        "refusal_types_count": "non_negative",             # 拒绝类型多样性
        "guardrail_triggers_count": "non_negative",        # 护栏触发已归因
        "timing_metadata_count": "non_negative",           # 时序元数据已采集
    },
}

# =============================================================================
# 阶段间数据传递规则
# =============================================================================

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
    # === ASR Forensic 桥 (Strike → Report/Evidence) ===
    {
        "id": "T015",
        "name": "Strike → Report: successful_evidence 提取确认",
        "from": "strike",
        "to": "report",
        "field": "successful_evidence_count",
        "check": "exists_optional",
    },
    {
        "id": "T016",
        "name": "Strike → Report: refusal 分类确认",
        "from": "strike",
        "to": "report",
        "field": "refusal_classification_count",
        "check": "exists_optional",
    },
    {
        "id": "T017",
        "name": "Strike → Report: guardrail 触发归因确认",
        "from": "strike",
        "to": "report",
        "field": "guardrail_triggers_count",
        "check": "exists_optional",
    },
    {
        "id": "T018",
        "name": "Strike → Report: 时序元数据确认",
        "from": "strike",
        "to": "report",
        "field": "timing_metadata_count",
        "check": "exists_optional",
    },
    {
        "id": "T019",
        "name": "Strike → Report: 拒绝类型多样性",
        "from": "strike",
        "to": "report",
        "field": "refusal_types_count",
        "check": "exists_optional",
    },
]

# =============================================================================
# 跨阶段一致性规则
# =============================================================================

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
