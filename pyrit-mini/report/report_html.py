"""report_html 鈥?浠?generator.py 鎷嗗垎鑰屾潵.

鍖呭惈 HTML 鎶ュ憡鐢熸垚, 璇佹嵁瀛楀吀鍖? OWASP 鍒嗙被, 鎶€鏈悕绉?
"""

from typing import Any

from jinja2 import Template

from report.evidence import EvidenceCollection, VulnerabilityEvidence
from report.report_sections import _build_escalation_dashboard_data, _build_heatmap_data, _finding_to_dict
from report.report_utils import (  # noqa: F401 鈥?re-exports for generator.py
    _get_all_references,
    _get_owasp_category,
    _get_technique_display_name,
)


def _generate_html(evidence: EvidenceCollection, *, success_only: bool = False) -> str:
    """Generate HTML report."""
    from report.generator import _HTML_TEMPLATE, _OWASP_ALL_CATEGORIES

    template = Template(_HTML_TEMPLATE)
    evidence_list = evidence.successful_evidence if success_only else evidence.evidence
    llm_tested = sum(1 for v in evidence.owasp_llm_compliance.values() if v.get("tested", 0) > 0)
    asi_tested = sum(1 for v in evidence.owasp_asi_compliance.values() if v.get("tested", 0) > 0)

    # P2-1: ASR 鐑姏鍥炬暟鎹?
    heatmap_owasp_ids, heatmap_rows = _build_heatmap_data(evidence, evidence_list)

    # P2-2: 鍗囩骇閾句华琛ㄧ洏鏁版嵁
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
    """灏嗚瘉鎹泦鍚堣浆鎹负瀛楀吀 (鐢ㄤ簬 JSON 搴忓垪鍖?銆?"""
    ev_list = evidence.successful_evidence if success_only else evidence.evidence

    # 鏂偣淇: main.py 娉ㄥ叆 orchestration_log / wilson_ci / cohens_kappa 鍒?evidence,
    # 浣?_evidence_to_dict 搴忓垪鍖栨椂涓㈠け杩欎簺瀛楁, 瀵艰嚧 regen_report.py 鏃犳硶閲嶅缓銆?
    # 淇: 鏄惧紡搴忓垪鍖栨墍鏈夋敞鍏ュ瓧娈? 纭繚鏁版嵁娴佷粠 main.py 鈫?evidence 鈫?JSON 鈫?regen 瀹屾暣銆?
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
        # 鏂偣淇: 浠ヤ笅瀛楁鐢?main.py Phase 4/5 娉ㄥ叆, 蹇呴』搴忓垪鍖栦互淇濇寔鏁版嵁娴佸畬鏁?
        "orchestration_log": getattr(evidence, 'orchestration_log', []),
        "wilson_ci": list(getattr(evidence, 'wilson_ci', (0.0, 0.0))),
        "cohens_kappa": getattr(evidence, 'cohens_kappa', 0.0),
    }

def _single_evidence_to_dict(ev: VulnerabilityEvidence) -> dict[str, Any]:
    """灏嗗崟涓瘉鎹浆鎹负瀛楀吀銆?

    搴忓垪鍖栧眰鍏戝簳: 纭繚鍗充娇 _build_evidence 鐨勫厬搴曢€昏緫鏈瑙﹀彂 (濡傛棫鏁版嵁),
    JSON 杈撳嚭涓墍鏈?R10 蹇呭～瀛楁涔熼潪绌恒€?
    """
    # P1-1 淇: converter_chain 绌哄瓧绗︿覆 鈫?"none (baseline)"
    converter_chain = ev.converter_chain or "none (baseline)"

    # P0-3 淇: arxiv_reference 绌哄瓧绗︿覆 鈫?榛樿寮曠敤
    arxiv_ref = ev.arxiv_reference or "PyRIT (arXiv:2407.01232)"

    # P0-1 淇: conversation_history 绌哄垪琛?鈫?浠?objective/harmful_output 鏋勯€?
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

    # P0-2 淇: converter_log 绌哄垪琛?鈫?"none (baseline)"
    converter_log = ev.converter_log
    if not converter_log:
        obj = ev.objective or ""
        converter_log = [{
            "converter": "none (baseline)",
            "original": obj[:200],
            "transformed": obj[:200],
        }]

    # P0-4 淇: validation_runs 绌哄垪琛?鈫?鑷冲皯 1 鏉¤繍琛岃褰?
    validation_runs = getattr(ev, 'validation_runs', [])
    if not validation_runs:
        validation_runs = [{
            "run": 1,
            "success": ev.is_success,
            "response": str(ev.harmful_output or "")[:200],
        }]

    # P0-5 淇: testing_conditions 绌哄瓧鍏?鈫?timestamp/outcome/attack_id
    testing_conditions = getattr(ev, 'testing_conditions', {})
    if not testing_conditions:
        testing_conditions = {
            "timestamp": ev.timestamp or "",
            "outcome": "success" if ev.is_success else "failure",
            "attack_id": ev.attack_id or "",
        }

    # P0-4b 淇: score_details 绌哄垪琛?鈫?鍏滃簳
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
        # NOTE: attack_result_ref is intentionally excluded from JSON serialization
        # (it holds a live PyRIT AttackResult object reference, not serializable data)
    }

