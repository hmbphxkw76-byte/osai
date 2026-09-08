"""Fix P0-3: Undefined variables and f-string syntax in report_markdown.py"""
path = "report/report_markdown.py"

with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Fix 1: max_risk undefined - add max() calculation before use
old_max_risk = """    if evidence.findings:
        lines.append(f"| Highest Risk Score | {max_risk.owasp_risk_score}/10 ({max_risk.owasp_id}) |")
    lines.append("")"""

new_max_risk = """    if evidence.findings:
        max_risk = max(evidence.findings, key=lambda f: f.owasp_risk_score)
        lines.append(f"| Highest Risk Score | {max_risk.owasp_risk_score}/10 ({max_risk.owasp_id}) |")
    lines.append("")"""

content = content.replace(old_max_risk, new_max_risk)

# Fix 2: sorted_findings undefined - add sort before use
old_sorted = """    if evidence.findings:
        for i, finding in enumerate(sorted_findings[:3], 1):"""

new_sorted = """    if evidence.findings:
        sorted_findings = sorted(evidence.findings, key=lambda f: f.asr, reverse=True)
        for i, finding in enumerate(sorted_findings[:3], 1):"""

content = content.replace(old_sorted, new_sorted)

# Fix 3: sorted_by_risk undefined
old_by_risk = """    if evidence.findings:
        for i, finding in enumerate(sorted_by_risk, 1):
            lines.append(
    f"| {priority} | {
        finding.owasp_id} | {
            finding.owasp_category} | {
                finding.owasp_risk_score} | {
                    finding.asr}% |")"""

new_by_risk = """    if evidence.findings:
        sorted_by_risk = sorted(evidence.findings, key=lambda f: f.owasp_risk_score, reverse=True)
        for i, finding in enumerate(sorted_by_risk, 1):
            priority = "P0" if finding.owasp_risk_score >= 9 else "P1" if finding.owasp_risk_score >= 7 else "P2"
            lines.append(
                f"| {priority} | {finding.owasp_id} | {finding.owasp_category} "
                f"| {finding.owasp_risk_score} | {finding.asr}% |")"""

content = content.replace(old_by_risk, new_by_risk)

# Fix 4: expected_asr undefined + f-string syntax error
old_expected = """    if evidence.findings:
        for finding in sorted_findings[:5]:
            lines.append(
                f"| Implement {finding.owasp_id} mitigations "
                f"| {finding.owasp_id} "
                f"| {finding.asr}% "
                f"| <={expected_asr:.0f}% |"
            )"""

new_expected = """    if evidence.findings:
        for finding in sorted_findings[:5]:
            expected_asr = finding.asr * 0.1  # Expected 90% reduction after remediation
            lines.append(
                f"| Implement {finding.owasp_id} mitigations "
                f"| {finding.owasp_id} "
                f"| {finding.asr}% "
                f"| <={expected_asr:.0f}% |"
            )"""

content = content.replace(old_expected, new_expected)

# Fix 5: Attack Path Summary section - sorted_findings reference
old_attack = """    if evidence.findings:
        top_paths = [f for f in sorted_findings if f.asr > 0][:3]
        if top_paths:
                techs = ", ".join(sorted({r.get('technique', '') for r in path.results if r.get('technique')}))
                lines.append(
                    f"{i}. **[{path.owasp_id}] {path.owasp_category}** - ASR {path.asr}% via techniques: {techs}")
        else:
    else:"""

new_attack = """    if evidence.findings:
        sorted_for_attack = sorted(evidence.findings, key=lambda f: f.asr, reverse=True)
        top_paths = [f for f in sorted_for_attack if f.asr > 0][:3]
        if top_paths:
            for i, path in enumerate(top_paths, 1):
                techs = ", ".join(sorted({r.get('technique', '') for r in path.results if r.get('technique')})) if path.results else "N/A"
                lines.append(
                    f"{i}. **[{path.owasp_id}] {path.owasp_category}** - ASR {path.asr}% via techniques: {techs}")
        else:
            lines.append("- No successful attack paths identified")
    else:
        lines.append("- No findings available")"""

content = content.replace(old_attack, new_attack)

# Now fix syntax errors in _generate_findings_markdown and _generate_technical_markdown
# These have orphaned code fragments from the audit corruption. Let's fix them.

# Fix _generate_findings_markdown - has broken indentation/fragments
old_findings_broken = """ # == Evidence (C) ==
    lines.append("## Evidence Cards")
    lines.append("")
    for ev in evidence_list:

 # == OWASP LLM Top 10 ==
    lines.append("## OWASP LLM Top 10")"""

new_findings_broken = """    # == Evidence Cards (C: per-evidence detail) ==
    lines.append("## Evidence Cards")
    lines.append("")
    for ev in evidence_list:
        lines.append(f"### {ev.evidence_id} - {ev.owasp_id}: {ev.owasp_category}")
        lines.append("")
        lines.append(f"| Attribute | Value |")
        lines.append(f"|-----------|-------|")
        lines.append(f"| Technique | {ev.technique_display_name} |")
        lines.append(f"| OWASP | {ev.owasp_id} |")
        lines.append(f"| Severity | {ev.owasp_severity} |")
        lines.append(f"| Risk Score | {ev.owasp_risk_score}/10 |")
        lines.append(f"| Success | {'YES' if ev.is_success else 'NO'} |")
        lines.append(f"| ASR | {ev.asr}% |")
        lines.append(f"| Converter | {ev.converter_chain or 'none'} |")
        lines.append(f"| Confidence | {ev.confidence} |")
        lines.append("")
        lines.append(f"**Objective:** {ev.objective[:200]}")
        lines.append("")
        if ev.jailbreak_prompt:
            lines.append(f"**Jailbreak Prompt:** {ev.jailbreak_prompt[:300]}")
            lines.append("")
        if ev.harmful_output:
            lines.append(f"**Model Response:** {ev.harmful_output[:500]}")
            lines.append("")
        lines.append("---")
        lines.append("")

    # == OWASP LLM Top 10 ==
    lines.append("## OWASP LLM Top 10")"""

content = content.replace(old_findings_broken, new_findings_broken)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("Fixed P0-3: report_markdown.py undefined variables and syntax errors")
