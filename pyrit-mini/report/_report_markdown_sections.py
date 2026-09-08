"""Markdown Section Helpers - extracted from report_markdown.py

Contains _append_* helper functions for building markdown report sections:
- Evidence Cards (with Attack Chain visualization)
- Risk Heatmap (Severity x ASR)
- Pipeline Flowchart
- Orchestration Flowchart
- Weapon Loadout (ARM Phase)
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from report.evidence import EvidenceCollection, VulnerabilityEvidence

def _append_evidence_card(lines: list[str], ev: VulnerabilityEvidence) -> None:
    """Append evidence card markdown section.

    -  Jailbreak Prompt ( Objective )
    - Harmful Output  <details>
    - Conversation History
    - PoC
    - R-05:  Attack Chain  - imports Seed->Converter->Technique->Outcome
    """
    lines.append(f"### {ev.evidence_id} - {ev.owasp_id}: {ev.owasp_category}")
    lines.append("")

 # == R-05: Attack Chain Visualization ==
 # : Seed -> Converter -> Technique -> Outcome
    lines.append("**Attack Chain:**")
    attack_chain_parts = []
    attack_chain_parts.append(f"Seed({(ev.objective or 'unknown')[:30]})")
    if ev.converter_chain and ev.converter_chain != "none (baseline)":
        conv_short = ev.converter_chain.split(" -> ")[0] if " -> " in ev.converter_chain else ev.converter_chain
        attack_chain_parts.append(f"Converter({conv_short})")
    attack_chain_parts.append(f"Tech({ev.technique_name or 'baseline'})")
    outcome_icon = "[OK] PASS" if ev.is_success else "[FAIL] BLOCKED"
    attack_chain_parts.append(f"Outcome({outcome_icon})")
    lines.append(f"'{' -> '.join(attack_chain_parts)}'")
    lines.append("")

 # ()
    lines.append("| Attribute | Value |")
    lines.append("|-----------|-------|")
    lines.append(f"| Technique | {ev.technique_display_name} |")
    lines.append(f"| Severity | {ev.owasp_severity} |")
    lines.append(f"| Risk Score | {ev.owasp_risk_score}/10 |")
    lines.append(f"| Converter | {ev.converter_chain or 'none (baseline)'} |")
    outcome = "[OK] Success" if ev.is_success else "[FAIL] Failed"
    lines.append(f"| Outcome | {outcome} |")
    lines.append(f"| Confidence | {ev.confidence} |")
    lines.append(f"| MITRE | {ev.mitre_technique_id or 'N/A'} ({ev.mitre_tactic or 'N/A'}) |")
    lines.append(f"| PoC | -> 'poc/poc_{ev.evidence_id}.py' |")
    lines.append(f"| Evidence | -> 'evidence/{ev.evidence_id}.json' |")
    lines.append("")

 # Objective ()
    obj_truncated = ev.objective[:_TRUNCATE_LEN] + ("..." if len(ev.objective) > _TRUNCATE_LEN else "")
    lines.append(f"**Objective:** {obj_truncated}")
    lines.append("")

 # Jailbreak Prompt ( Objective )
    if ev.jailbreak_prompt and ev.jailbreak_prompt != ev.objective:
            ("..." if len(ev.jailbreak_prompt) > _TRUNCATE_LEN else "")
        lines.append(f"**Jailbreak Prompt (modified):** {jbp_truncated}")
        lines.append("")

 # Harmful Output ( details )
    if ev.harmful_output:
        harmful_preview = harmful_lines[0][:100] + "..." if harmful_lines else ""
        lines.append(f"**Model Response Preview:** {harmful_preview}")
        lines.append("")
        lines.append("<details>")
        lines.append(f"<summary>[MSG] Full Model Response ({len(ev.harmful_output)} chars, click to expand)</summary>")
        lines.append("")
        lines.append(ev.harmful_output)
        lines.append("")
        lines.append("</details>")
        lines.append("")

 # Validation Runs
    val_runs = getattr(ev, "validation_runs", [])
    if val_runs:
        for run in val_runs:
            lines.append("")

 # Testing Conditions
    conditions = getattr(ev, "testing_conditions", {})
    if conditions:
        for k, v in conditions.items():
            lines.append("")

 # Remediation
    lines.append("**Remediation:**")
    for mitigation in ev.owasp_mitigations:
        lines.append("")

# ================================================================
# D: (Severity x ASR )
# ================================================================

def _append_risk_heatmap(lines: list[str], evidence: EvidenceCollection) -> None:
    if not evidence.findings:

        lines.append("## Risk Heatmap (Severity x ASR)")
    lines.append("")
    lines.append("| Severity \\ ASR | 100% | 90-99% | <90% | 0% (Failed) |")
    lines.append("|---------------|------|--------|------|------------|")

    severity_order = ["critical", "high", "medium", "low"]
    for sev in severity_order:
        if not sev_findings:

            col_100 = [f.owasp_id for f in sev_findings if f.asr == 100]
        col_90 = [f.owasp_id for f in sev_findings if 90 <= f.asr < 100]
        col_lt90 = [f.owasp_id for f in sev_findings if 0 < f.asr < 90]
        col_0 = [f.owasp_id for f in sev_findings if f.asr == 0]

        lines.append(
            f"| {sev.title()} | {', '.join(col_100) or '-'} | "
            f"{', '.join(col_90) or '-'} | "
            f"{', '.join(col_lt90) or '-'} | "
            f"{', '.join(col_0) or '-'} |"
        )
    lines.append("")

# ================================================================
# E: Pipeline
# ================================================================

def _append_pipeline_flowchart(lines: list[str], evidence: EvidenceCollection) -> None:
    v60  (R-01):  REPORT ,  6
    v59 :  ARM->STRIKE Data flow (seeds/techniques/converter_map)
    """
    lines.append("## Pipeline Flowchart")
    lines.append("")
 lines.append("'''")
    lines.append("===========         ============         =============     ============     ============     ============")
    lines.append("=  RECON   ===fp====->=  ARM     ===seeds==->=  STRIKE   =====->= ESCALATE =====->=  ASSESS  =====->=  REPORT  =")

 # orchestration log ( phase )
    orch_log = getattr(evidence, "orchestration_log", [])
    recon_out: dict = {}
    arm_out: dict = {}
    strike_out: dict = {}
    escalate_out: dict = {}
    assess_out: dict = {}
    report_out: dict = {}
    for entry in orch_log:
        _out = entry.get("output", {}) or {}
        if phase == "recon":
            elif phase == "arm":
                elif phase == "strike":
                    elif phase == "escalate":
                        elif phase == "assess":
                            elif phase == "report":

                                recon_detail = recon_out.get("probe_count", "?") if isinstance(recon_out, dict) else "?"
    arm_seeds = arm_out.get("seed_count", "?") if isinstance(arm_out, dict) else "?"
    arm_techs = arm_out.get("techniques", None) if isinstance(arm_out, dict) else None
    strike_results = strike_out.get("total_results", evidence.total_attacks) if isinstance(strike_out, dict) else evidence.total_attacks
    esc_results = escalate_out.get("total_results", evidence.total_attacks) if isinstance(escalate_out, dict) else evidence.total_attacks
    assess_success = assess_out.get("overall_asr", "?") if isinstance(assess_out, dict) else "?"
 # R-01: - report_out output (), 
    _report_keys = ["report_index", "report_executive", "report_findings", "report_technical", "report_success", "native_output"]
    report_files = sum(1 for k in _report_keys if report_out.get(k)) if isinstance(report_out, dict) else 6

 # ARM : seeds + techs + converters
    _arm_tech_str = f"{len(arm_techs)} techs" if isinstance(arm_techs, list) else "? techs"
    lines.append(f"= {recon_detail} probes=         = {arm_seeds} seeds =+conv    = {strike_results} attacks=     = +{esc_results - strike_results if esc_results > strike_results else 0} attacks =     = ASR {assess_success}%=     = {report_files} files=")
    lines.append(f"=           =         = {_arm_tech_str}=+techs   =           =     =           =     =          =     =          =")
    lines.append("===========         ============         =============     ============     ============     ============")
    lines.append("")
 # R-02: Data flow ASSESS->REPORT
    lines.append("Data flow: RECON->ARM (target_fingerprint, capabilities) | ARM->STRIKE (ctx.seeds, ctx.techniques, ctx.converter_map) | STRIKE->ESCALATE (failed_objectives, attack_results) | ESCALATE->ASSESS (full attack_results) | ASSESS->REPORT (evidence, asr, orchestration_log)")
 lines.append("'''")
    lines.append("")

def _append_orchestration_flowchart(lines: list[str], orch_log: list) -> None:
    v60  (R-01):  REPORT ,  6 
    v59 : Data flow
    """
 lines.append("'''")
    lines.append("===========         ============         =============     ============     ============     ============")
    lines.append("=  RECON   ===fp====->=  ARM     ===seeds==->=  STRIKE   =====->= ESCALATE =====->=  ASSESS  =====->=  REPORT  =")

 # ( phase , Not overridden)
    phases_data: dict[str, dict] = {}
    for entry in orch_log:
        _out = entry.get("output", {}) or {}
        if phase not in phases_data:
            phases_data[phase].update(_out)

    recon_data = phases_data.get("recon", {})
    arm_data = phases_data.get("arm", {})
    strike_data = phases_data.get("strike", {})
    escalate_data = phases_data.get("escalate", {})
    assess_data = phases_data.get("assess", {})
    report_data = phases_data.get("report", {})

 # 
    recon_probe = recon_data.get("probe_count", "?") if isinstance(recon_data, dict) else "?"
    arm_seeds = arm_data.get("seed_count", "?") if isinstance(arm_data, dict) else "?"
    arm_techs = arm_data.get("techniques", None) if isinstance(arm_data, dict) else None
    strike_results = strike_data.get("total_results", "?") if isinstance(strike_data, dict) else "?"
    esc_techs = escalate_data.get("escalated_techniques", "-") if isinstance(escalate_data, dict) else "-"
    assess_asr = assess_data.get("overall_asr", "?") if isinstance(assess_data, dict) else "?"

    _arm_tech_str = f"{len(arm_techs)} techs" if isinstance(arm_techs, list) else "? techs"
 # R-01: report_data output (), 
    _report_keys = ["report_index", "report_executive", "report_findings", "report_technical", "report_success", "native_output"]
    _report_file_count = sum(1 for k in _report_keys if report_data.get(k)) if isinstance(report_data, dict) else 6

    lines.append(f"= {recon_probe} probes =         = {arm_seeds} seeds =+conv    = {strike_results} results =   = {esc_techs} =    = ASR {assess_asr}%=     = {_report_file_count} files=")
    lines.append(f"=           =         = {_arm_tech_str}=+techs   =           =   =           =    =          =     =          =")
    lines.append("===========         ============         =============     ============     ============     ============")
    lines.append("")
 # R-02: Data flow ASSESS->REPORT
    lines.append("Data flow: RECON->ARM (target_fingerprint, capabilities) | ARM->STRIKE (ctx.seeds, ctx.techniques, ctx.converter_map) | STRIKE->ESCALATE (failed_objectives, attack_results) | ESCALATE->ASSESS (full attack_results) | ASSESS->REPORT (evidence, asr, orchestration_log)")
 lines.append("'''")
    lines.append("")

# ================================================================
# Weapon Loadout (ARM Phase) - v59 
# ARM 1 , 
# ================================================================

def _append_weapon_loadout(lines: list[str], evidence: EvidenceCollection) -> None:
    imports orchestration_log  ARM //Converter ,
    imports evidence.evidence converter(s) seed/converter_chain/technique ,
    

    :
        - orchestration_log: ARM  seed_selection / technique_selection / converter_selection
        - evidence.evidence: converter(s) VulnerabilityEvidence  seed / converter_chain / technique_name

    R-07:  "Converter Selection Rationale"  -  converter
    """
    orch_log = getattr(evidence, "orchestration_log", [])

 # ARM 
    arm_data: dict[str, Any] = {}
    arm_input: dict[str, Any] = {}
    for entry in orch_log:
            _out = entry.get("output", {}) or {}
            _inp = entry.get("input", {}) or {}
            _decision = entry.get("decision", "")
            if _decision not in arm_data:
                arm_input[_decision] = {}
            arm_data[_decision].update(_out)
            arm_input[_decision].update(_inp)

    seed_info = arm_data.get("seed_selection", {})
    seed_input = arm_input.get("seed_selection", {})
    tech_info = arm_data.get("technique_selection", {})
    conv_info = arm_data.get("converter_selection", {})

    seed_count = seed_info.get("seed_count", "?")
    seed_files = seed_input.get("seed_files", "")
    techniques = tech_info.get("techniques", [])
    converter_count = conv_info.get("converter_count", "?")
    per_technique = conv_info.get("per_technique", {})

    lines.append("## Weapon Loadout (ARM Phase)")
    lines.append("")
    lines.append("> ARM stage weapon configuration - seeds, techniques, and converter paths selected for this assessment.")
    lines.append("")

 # == ==
    lines.append("### Summary")
    lines.append("")
    lines.append("| Attribute | Value |")
    lines.append("|-----------|-------|")
    lines.append(f"| Seeds | {seed_count} |")
    if seed_files:
        lines.append(f"| Techniques | {len(techniques) if isinstance(techniques, list) else '?'} |")
    lines.append(f"| Converter Paths | {converter_count} |")
    lines.append("")

 # == R-07: Converter Selection Rationale ==
    lines.append("### Converter Selection Rationale")
    lines.append("")
    lines.append("| Technique | Converter Count | Rationale |")
    lines.append("|-----------|----------------|-----------|")

 # converter 
    CONVERTER_RATIONALE: dict[str, str] = {
        "prompt_sending": "Baseline testing - no converter applied, used as ASR reference",
        "crescendo": "Multi-turn escalation - conversation-based, no encoding converters needed",
        "tap": "Tree-of-attacks - relies on adversarial LLM, minimal converter usage",
        "pair": "Black-box iterative refinement - adversarial LLM generates jailbreaks directly",
        "gcg": "Gradient-based suffix optimization - no prompt converters applicable",
        "best_of_n": "Sampling-based - multiple attempts increase success probability",
        "many_shot": "Multi-shot prompting - context-based, no encoding transformation",
        "chunked": "Payload splitting - uses chunking strategy instead of encoding",
        "red_teaming": "Native attack strategy - relies on technique-specific converters",
        "native": "PyRIT native attack - direct API interaction preferred",
    }

    if isinstance(techniques, list) and techniques:
            _conv_count = per_technique.get(tech, "?") if isinstance(per_technique, dict) else "?"
            rationale = CONVERTER_RATIONALE.get(tech, "Auto-selected based on target capabilities and ASR prior")
            lines.append(f"| {tech} | {_conv_count} | {rationale} |")
        lines.append("")

 # evidence converter
        lines.append("### Converters Used (from evidence)")
        lines.append("")
        lines.append("| # | Technique | Converter Chain | Effectiveness |")
        lines.append("|---|-----------|-----------------|---------------|")
        seen_convs: set[str] = set()
        idx = 0
        for ev in evidence.evidence:
            _key = f"{ev.technique_name}|{_conv}"
            if _key in seen_convs:
                seen_convs.add(_key)
            idx += 1
            effectiveness = "High" if ev.is_success else "Low"
            lines.append(f"| {idx} | {ev.technique_name} | {_conv} | {effectiveness} |")
        lines.append("")
    else:
        lines.append("")

 # == Techniques ==
    if isinstance(techniques, list) and techniques:
        lines.append("")
        lines.append("| # | Technique | Converter Paths |")
        lines.append("|---|-----------|----------------|")
        for i, tech in enumerate(techniques, 1):
            lines.append(f"| {i} | {tech} | {_conv_count} |")
        lines.append("")

 # == Seeds (from evidence - per-evidence seed/converter/technique) ==
    if evidence.evidence:
        lines.append("")
        lines.append("| # | Seed (truncated) | Technique | Converter Chain | Success |")
        lines.append("|---|------------------|-----------|------------------|---------|")
        seen_seeds: set[str] = set()
        idx = 0
        for ev in evidence.evidence:
            _seed_key = _seed[:30]  # 
            if _seed_key in seen_seeds:
                seen_seeds.add(_seed_key)
            idx += 1
            _tech = ev.technique_name or ""
            _conv = ev.converter_chain or "none (baseline)"
            _success = "[OK]" if ev.is_success else "[FAIL]"
            _seed_display = _seed + ("..." if len(ev.objective or "") > 60 else "")
            lines.append(f"| {idx} | {_seed_display} | {_tech} | {_conv} | {_success} |")
        lines.append("")

 # == Role Separation ==
    fp = evidence.target_fingerprint or {}
    lines.append("### Role Separation")
    lines.append("")
    lines.append("| Role | Value |")
    lines.append("|------|-------|")
    lines.append(f"| Target Type | {fp.get('target_type', 'unknown')} |")
    lines.append(f"| Model Family | {fp.get('model_family', 'unknown')} |")
    lines.append(f"| Capabilities | {fp.get('capabilities', 'none')} |")
    lines.append(f"| Auth Type | {fp.get('auth_type', 'unknown')} |")
    lines.append("")
