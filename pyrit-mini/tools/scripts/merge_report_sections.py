"""Merge _report_markdown_sections.py into report_markdown.py (P1-2) with bug fixes"""
import re
import os

sections_path = "report/_report_markdown_sections.py"
main_path = "report/report_markdown.py"

# Read both files
with open(sections_path, "r", encoding="utf-8") as f:
    sections_content = f.read()

with open(main_path, "r", encoding="utf-8") as f:
    main_content = f.read()

# Remove the import statement from main
import_block = """# ================================================================
# C-E: Evidence Card, Heatmap, Flowchart, Weapon Loadout
#   (delegated to _report_markdown_sections)
# ================================================================
from report._report_markdown_sections import (
    _append_evidence_card,
    _append_risk_heatmap,
    _append_pipeline_flowchart,
    _append_orchestration_flowchart,
    _append_weapon_loadout,
)
"""

main_content = main_content.replace(import_block, "")

# Extract and fix each function before merging
# Fix 1: _append_evidence_card - add missing _TRUNCATE_LEN and fix broken lines
fixed_evidence_card = '''def _append_evidence_card(lines: list[str], ev: VulnerabilityEvidence) -> None:
    """Append evidence card markdown section with Attack Chain visualization."""
    _TRUNCATE_LEN = 200
    lines.append(f"### {ev.evidence_id} - {ev.owasp_id}: {ev.owasp_category}")
    lines.append("")

    # Attack Chain: Seed -> Converter -> Technique -> Outcome
    lines.append("**Attack Chain:**")
    attack_chain_parts = []
    attack_chain_parts.append(f"Seed({(ev.objective or 'unknown')[:30]})")
    if ev.converter_chain and ev.converter_chain != "none (baseline)":
        conv_short = ev.converter_chain.split(" -> ")[0] if " -> " in ev.converter_chain else ev.converter_chain
        attack_chain_parts.append(f"Converter({conv_short})")
    attack_chain_parts.append(f"Tech({ev.technique_name or 'baseline'})")
    outcome_icon = "PASS" if ev.is_success else "BLOCKED"
    attack_chain_parts.append(f"Outcome({outcome_icon})")
    lines.append(" -> ".join(attack_chain_parts))
    lines.append("")

    # Attribute table
    lines.append("| Attribute | Value |")
    lines.append("|-----------|-------|")
    lines.append(f"| Technique | {ev.technique_display_name} |")
    lines.append(f"| Severity | {ev.owasp_severity} |")
    lines.append(f"| Risk Score | {ev.owasp_risk_score}/10 |")
    lines.append(f"| Converter | {ev.converter_chain or 'none (baseline)'} |")
    outcome = "Success" if ev.is_success else "Failed"
    lines.append(f"| Outcome | {outcome} |")
    lines.append(f"| Confidence | {ev.confidence} |")
    lines.append(f"| MITRE | {ev.mitre_technique_id or 'N/A'} ({ev.mitre_tactic or 'N/A'}) |")
    lines.append("")

    # Objective
    obj_truncated = ev.objective[:_TRUNCATE_LEN] + ("..." if len(ev.objective) > _TRUNCATE_LEN else "")
    lines.append(f"**Objective:** {obj_truncated}")
    lines.append("")

    # Jailbreak Prompt
    if ev.jailbreak_prompt and ev.jailbreak_prompt != ev.objective:
        jbp_truncated = ev.jailbreak_prompt[:_TRUNCATE_LEN] + ("..." if len(ev.jailbreak_prompt) > _TRUNCATE_LEN else "")
        lines.append(f"**Jailbreak Prompt (modified):** {jbp_truncated}")
        lines.append("")

    # Harmful Output
    if ev.harmful_output:
        harmful_lines = ev.harmful_output.split("\\n")
        harmful_preview = harmful_lines[0][:100] + "..." if harmful_lines else ""
        lines.append(f"**Model Response Preview:** {harmful_preview}")
        lines.append("")
        lines.append("<details>")
        lines.append(f"<summary>Full Model Response ({len(ev.harmful_output)} chars, click to expand)</summary>")
        lines.append("")
        lines.append(ev.harmful_output)
        lines.append("")
        lines.append("</details>")
        lines.append("")

    # Remediation
    lines.append("**Remediation:**")
    if ev.owasp_mitigations:
        for mitigation in ev.owasp_mitigations:
            lines.append(f"- {mitigation}")
    else:
        lines.append("- Follow OWASP guidelines for this category")
    lines.append("")
'''

# Fix 2: _append_risk_heatmap
fixed_heatmap = '''def _append_risk_heatmap(lines: list[str], evidence: EvidenceCollection) -> None:
    """Append Risk Heatmap (Severity x ASR) section."""
    if not evidence.findings:
        lines.append("## Risk Heatmap (Severity x ASR)")
        lines.append("")
        lines.append("*No findings available for heatmap generation*")
        lines.append("")
        return

    lines.append("## Risk Heatmap (Severity x ASR)")
    lines.append("")
    lines.append("| Severity \\ ASR | 100% | 90-99% | <90% | 0% (Failed) |")
    lines.append("|---------------|------|--------|------|------------|")

    severity_order = ["critical", "high", "medium", "low"]
    for sev in severity_order:
        sev_findings = [f for f in evidence.findings if f.owasp_severity == sev]
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
'''

# Fix 3: _append_pipeline_flowchart
fixed_pipeline = '''def _append_pipeline_flowchart(lines: list[str], evidence: EvidenceCollection) -> None:
    """Append Pipeline Flowchart section."""
    lines.append("## Pipeline Flowchart")
    lines.append("")
    lines.append("```")
    lines.append("===========         ============         =============     ============     ============     ============")
    lines.append("=  RECON   =====fp===>  ARM     ===seeds===>  STRIKE   ======> ESCALATE ======>  ASSESS  ======>  REPORT  =")

    orch_log = getattr(evidence, "orchestration_log", [])
    phases_data: dict[str, dict] = {}
    for entry in orch_log:
        phase = entry.get("phase", "unknown")
        if phase not in phases_data:
            phases_data[phase] = {}
        phases_data[phase].update(entry.get("output", {}) or {})

    recon_detail = phases_data.get("recon", {}).get("probe_count", "?")
    arm_seeds = phases_data.get("arm", {}).get("seed_count", "?")
    arm_techs = phases_data.get("arm", {}).get("techniques", [])
    strike_results = phases_data.get("strike", {}).get("total_results", evidence.total_attacks)
    esc_results = phases_data.get("escalate", {}).get("total_results", 0)
    assess_asr = phases_data.get("assess", {}).get("overall_asr", "?")
    report_data = phases_data.get("report", {})
    _report_keys = ["report_index", "report_executive", "report_findings", "report_technical", "report_success", "native_output"]
    report_files = sum(1 for k in _report_keys if report_data.get(k)) if isinstance(report_data, dict) else 6
    _arm_tech_str = f"{len(arm_techs)} techs" if isinstance(arm_techs, list) else "? techs"

    lines.append(f"= {recon_detail} probes       = {arm_seeds} seeds       = {strike_results} attacks     = +{max(0, esc_results - strike_results)} attacks    = ASR {assess_asr}%    = {report_files} files=")
    lines.append(f"=           =         = {_arm_tech_str}            =           =     =           =     =          =     =          =")
    lines.append("===========         ============         =============     ============     ============     ============")
    lines.append("```")
    lines.append("")
    lines.append("Data flow: RECON->ARM (target_fingerprint, capabilities) | ARM->STRIKE (ctx.seeds, ctx.techniques, ctx.converter_map) | STRIKE->ESCALATE (failed_objectives, attack_results) | ESCALATE->ASSESS (full attack_results) | ASSESS->REPORT (evidence, asr, orchestration_log)")
    lines.append("")
'''

# Fix 4: _append_orchestration_flowchart
fixed_orch = '''def _append_orchestration_flowchart(lines: list[str], orch_log: list) -> None:
    """Append Orchestration Flowchart section."""
    lines.append("## Orchestration Flowchart")
    lines.append("")
    lines.append("```")
    lines.append("===========         ============         =============     ============     ============     ============")
    lines.append("=  RECON   =====fp===>  ARM     ===seeds===>  STRIKE   ======> ESCALATE ======>  ASSESS  ======>  REPORT  =")

    phases_data: dict[str, dict] = {}
    for entry in orch_log:
        phase = entry.get("phase", "unknown")
        if phase not in phases_data:
            phases_data[phase] = {}
        phases_data[phase].update(entry.get("output", {}) or {})

    recon_probe = phases_data.get("recon", {}).get("probe_count", "?")
    arm_seeds = phases_data.get("arm", {}).get("seed_count", "?")
    arm_techs = phases_data.get("arm", {}).get("techniques", [])
    strike_results = phases_data.get("strike", {}).get("total_results", "?")
    esc_techs = phases_data.get("escalate", {}).get("escalated_techniques", "-")
    assess_asr = phases_data.get("assess", {}).get("overall_asr", "?")
    report_data = phases_data.get("report", {})
    _report_keys = ["report_index", "report_executive", "report_findings", "report_technical", "report_success", "native_output"]
    _report_file_count = sum(1 for k in _report_keys if report_data.get(k)) if isinstance(report_data, dict) else 6
    _arm_tech_str = f"{len(arm_techs)} techs" if isinstance(arm_techs, list) else "? techs"

    lines.append(f"= {recon_probe} probes       = {arm_seeds} seeds       = {strike_results} results     = {esc_techs}         = ASR {assess_asr}%    = {_report_file_count} files=")
    lines.append(f"=           =         = {_arm_tech_str}            =           =     =           =     =          =     =          =")
    lines.append("===========         ============         =============     ============     ============     ============")
    lines.append("```")
    lines.append("")
'''

# Fix 5: _append_weapon_loadout
fixed_weapon = '''def _append_weapon_loadout(lines: list[str], evidence: EvidenceCollection) -> None:
    """Append Weapon Loadout (ARM Phase) section."""
    orch_log = getattr(evidence, "orchestration_log", [])

    arm_data: dict[str, Any] = {}
    arm_input: dict[str, Any] = {}
    for entry in orch_log:
        if entry.get("phase") != "arm":
            continue
        _out = entry.get("output", {}) or {}
        _inp = entry.get("input", {}) or {}
        _decision = entry.get("decision", "unknown")
        if _decision not in arm_data:
            arm_data[_decision] = {}
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

    lines.append("### Summary")
    lines.append("")
    lines.append("| Attribute | Value |")
    lines.append("|-----------|-------|")
    lines.append(f"| Seeds | {seed_count} |")
    if seed_files:
        lines.append(f"| Seed Files | {seed_files} |")
    lines.append(f"| Techniques | {len(techniques) if isinstance(techniques, list) else '?'} |")
    lines.append(f"| Converter Paths | {converter_count} |")
    lines.append("")

    # Converter Selection Rationale
    lines.append("### Converter Selection Rationale")
    lines.append("")
    lines.append("| Technique | Converter Count | Rationale |")
    lines.append("|-----------|----------------|-----------|")

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
        for tech in techniques:
            _conv_count = per_technique.get(tech, "?") if isinstance(per_technique, dict) else "?"
            rationale = CONVERTER_RATIONALE.get(tech, "Auto-selected based on target capabilities and ASR prior")
            lines.append(f"| {tech} | {_conv_count} | {rationale} |")
        lines.append("")

    # Converters Used from evidence
    if evidence.evidence:
        lines.append("### Converters Used (from evidence)")
        lines.append("")
        lines.append("| # | Technique | Converter Chain | Effectiveness |")
        lines.append("|---|-----------|-----------------|---------------|")
        seen_convs: set[str] = set()
        idx = 0
        for ev in evidence.evidence:
            _conv = ev.converter_chain or "none (baseline)"
            _key = f"{ev.technique_name}|{_conv}"
            if _key in seen_convs:
                continue
            seen_convs.add(_key)
            idx += 1
            effectiveness = "High" if ev.is_success else "Low"
            lines.append(f"| {idx} | {ev.technique_name} | {_conv} | {effectiveness} |")
        lines.append("")

    # Role Separation
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
'''

# Combine fixed code
fixed_code = "\n\n".join([
    "# " + "=" * 63,
    "# C-E: Evidence Card, Heatmap, Flowchart, Weapon Loadout (merged from _report_markdown_sections)",
    "# " + "=" * 63,
    "",
    fixed_evidence_card,
    fixed_heatmap,
    fixed_pipeline,
    fixed_orch,
    fixed_weapon,
])

# Write merged file
with open(main_path, "w", encoding="utf-8") as f:
    f.write(main_content.rstrip() + "\n\n\n" + fixed_code + "\n")

# Delete sections file
os.remove(sections_path)

print(f"Merged _report_markdown_sections.py into report_markdown.py with bug fixes")
print(f"Deleted _report_markdown_sections.py")
