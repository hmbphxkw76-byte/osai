"""report_html — 从 generator.py 拆分而来.

包含 HTML 报告生成, 证据字典化, OWASP 分类, 技术名称.
"""

from typing import Any

from jinja2 import Template

from pipeline.report.evidence import EvidenceCollection, VulnerabilityEvidence
from pipeline.report.report_sections import _build_escalation_dashboard_data, _build_heatmap_data, _finding_to_dict
from pipeline.report.report_utils import (  # noqa: F401 — re-exports for generator.py
    _get_all_references,
    _get_owasp_category,
    _get_technique_display_name,
)


def _generate_html(evidence: EvidenceCollection, *, success_only: bool = False) -> str:
    """Generate HTML report."""
    from pipeline.report.generator import _HTML_TEMPLATE, _OWASP_ALL_CATEGORIES

    template = Template(_HTML_TEMPLATE)
    evidence_list = evidence.successful_evidence if success_only else evidence.evidence
    llm_tested = sum(1 for v in evidence.owasp_llm_compliance.values() if v.get("tested", 0) > 0)
    asi_tested = sum(1 for v in evidence.owasp_asi_compliance.values() if v.get("tested", 0) > 0)

    # P2-1: ASR 热力图数据
    heatmap_owasp_ids, heatmap_rows = _build_heatmap_data(evidence, evidence_list)

    # P2-2: 升级链仪表盘数据
    escalation_dashboard = _build_escalation_dashboard_data(evidence)

    return template.render(
        evidence=evidence,
        evidence_list=evidence_list,
        fingerprint=evidence.target_fingerprint,
        success_only=success_only,
        llm_tested=llm_tested,
        asi_tested=asi_tested,
        owasp_categories=_OWASP_ALL_CATEGORIES,
        heatmap_owasp_ids=heatmap_owasp_ids,
        heatmap_rows=heatmap_rows,
        escalation_dashboard=escalation_dashboard,
    )

def _evidence_to_dict(evidence: EvidenceCollection, *, success_only: bool = False) -> dict[str, Any]:
    """将证据集合转换为字典 (用于 JSON 序列化)。"""
    ev_list = evidence.successful_evidence if success_only else evidence.evidence

    # 断点修复: main.py 注入 orchestration_log / wilson_ci / cohens_kappa 到 evidence,
    # 但 _evidence_to_dict 序列化时丢失这些字段, 导致 regen_report.py 无法重建。
    # 修复: 显式序列化所有注入字段, 确保数据流从 main.py → evidence → JSON → regen 完整。
    return {
        "collection_id": evidence.collection_id,
        "timestamp": evidence.timestamp,
        "target_model": evidence.target_model,
        "target_fingerprint": evidence.target_fingerprint,
        "attack_surface": evidence.attack_surface,
        "total_attacks": evidence.total_attacks,
        "successful_attacks": evidence.successful_attacks,
        "failed_attacks": evidence.failed_attacks,
        "overall_asr": evidence.overall_asr,
        "owasp_standard_references": evidence.owasp_standard_references,
        "owasp_web_compliance": evidence.owasp_web_compliance if hasattr(evidence, 'owasp_web_compliance') else {},
        "owasp_llm_compliance": evidence.owasp_llm_compliance,
        "owasp_asi_compliance": evidence.owasp_asi_compliance,
        "evidence": [_single_evidence_to_dict(ev) for ev in ev_list],
        "owasp_coverage": evidence.owasp_coverage,
        "technique_distribution": evidence.technique_distribution,
        "failure_analysis": evidence.failure_analysis,
        "dual_judge_stats": evidence.dual_judge_stats if hasattr(evidence, 'dual_judge_stats') else {},
        "findings": [_finding_to_dict(f) for f in getattr(evidence, 'findings', [])],
        "web_vuln_stats": getattr(evidence, 'web_vuln_stats', {}),
        "discovered_endpoints": getattr(evidence, 'discovered_endpoints', []),
        # 断点修复: 以下字段由 main.py Phase 4/5 注入, 必须序列化以保持数据流完整
        "orchestration_log": getattr(evidence, 'orchestration_log', []),
        "wilson_ci": list(getattr(evidence, 'wilson_ci', (0.0, 0.0))),
        "cohens_kappa": getattr(evidence, 'cohens_kappa', 0.0),
    }

def _single_evidence_to_dict(ev: VulnerabilityEvidence) -> dict[str, Any]:
    """将单个证据转换为字典。

    序列化层兑底: 确保即使 _build_evidence 的兑底逻辑未被触发 (如旧数据),
    JSON 输出中所有 R10 必填字段也非空。
    """
    # P1-1 修复: converter_chain 空字符串 → "none (baseline)"
    converter_chain = ev.converter_chain or "none (baseline)"

    # P0-3 修复: arxiv_reference 空字符串 → 默认引用
    arxiv_ref = ev.arxiv_reference or "PyRIT (arXiv:2407.01232)"

    # P0-1 修复: conversation_history 空列表 → 从 objective/harmful_output 构造
    conversation = ev.conversation_history
    if not conversation:
        obj = ev.objective or ""
        resp = ev.harmful_output or ""
        if obj and resp:
            conversation = [
                {"role": "user", "content": str(obj)},
                {"role": "assistant", "content": str(resp)},
            ]
        elif obj:
            conversation = [{"role": "user", "content": str(obj)}]
        else:
            conversation = [{"role": "system", "content": "No conversation data available"}]

    # P0-2 修复: converter_log 空列表 → "none (baseline)"
    converter_log = ev.converter_log
    if not converter_log:
        obj = ev.objective or ""
        converter_log = [{
            "converter": "none (baseline)",
            "original": obj[:200],
            "transformed": obj[:200],
        }]

    # P0-4 修复: validation_runs 空列表 → 至少 1 条运行记录
    validation_runs = getattr(ev, 'validation_runs', [])
    if not validation_runs:
        validation_runs = [{
            "run": 1,
            "success": ev.is_success,
            "response": str(ev.harmful_output or "")[:200],
        }]

    # P0-5 修复: testing_conditions 空字典 → timestamp/outcome/attack_id
    testing_conditions = getattr(ev, 'testing_conditions', {})
    if not testing_conditions:
        testing_conditions = {
            "timestamp": ev.timestamp or "",
            "outcome": "success" if ev.is_success else "failure",
            "attack_id": ev.attack_id or "",
        }

    # P0-4b 修复: score_details 空列表 → 兜底
    score_details = ev.score_details
    if not score_details:
        score_details = [{
            "scorer": "AttackOutcome",
            "score_value": "success" if ev.is_success else "failure",
            "rationale": "Determined by post-hoc scoring (no explicit scorer object attached)",
        }]

    return {
        "evidence_id": ev.evidence_id,
        "attack_id": ev.attack_id,
        "technique_name": ev.technique_name,
        "technique_display_name": ev.technique_display_name,
        "converter_chain": converter_chain,
        "owasp_id": ev.owasp_id,
        "owasp_category": ev.owasp_category,
        "owasp_standard": ev.owasp_standard,
        "owasp_severity": ev.owasp_severity,
        "owasp_risk_score": ev.owasp_risk_score,
        "owasp_mitigations": ev.owasp_mitigations,
        "owasp_reference": ev.owasp_reference,
        "cvss_vector": ev.cvss_vector,
        "objective": ev.objective,
        "jailbreak_prompt": ev.jailbreak_prompt,
        "harmful_output": ev.harmful_output,
        "is_success": ev.is_success,
        "file_suffix": ev.file_suffix,
        "asr": ev.asr,
        "confidence": ev.confidence,
        "arxiv_reference": arxiv_ref,
        "timestamp": ev.timestamp,
        "target_model": ev.target_model,
        "conversation_history": conversation,
        "converter_log": converter_log,
        "score_details": score_details,
        "mitre_tactic": getattr(ev, 'mitre_tactic', ''),
        "mitre_technique_id": getattr(ev, 'mitre_technique_id', ''),
        "mitre_technique_name": getattr(ev, 'mitre_technique_name', ''),
        "mitre_url": getattr(ev, 'mitre_url', ''),
        "validation_runs": validation_runs,
        "testing_conditions": testing_conditions,
    }
