"""Fix remaining issues in report_markdown.py - tech failure categories"""
path = "report/report_markdown.py"

with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Fix orphaned if/elif/else after tech_failures counting
old_orphan = """ #
                if ev.converter_chain and "baseline" not in (ev.converter_chain or ""):
                    elif "jailbreak" in (ev.objective or "").lower():
                        else:
                tech_failures[tech]["categories"][cat] = tech_failures[tech]["categories"].get(cat, 0) + 1

        if tech_failures:
                primary_cat = max(data["categories"].items(), key=lambda x: x[1])[0] if data["categories"] else "N/A"
                lines.append(f"| {tech} | {data['count']} | {primary_cat} |")
        else:
        lines.append("")"""

new_orphan = """        # Generate failure table from counted data
        if tech_failures:
            for tech, count in sorted(tech_failures.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"| {tech} | {count} | See failure classification above |")
        else:
            lines.append("| No failures | 0 | N/A |")

        lines.append("")"""

content = content.replace(old_orphan, new_orphan)

# Fix three-tier evidence chain - broken loop
old_tier = """    if hasattr(evidence, "findings") and evidence.findings:
            lines.append(f"### {finding.finding_id}: {finding.owasp_id}")
            lines.append(f"**Severity:** {finding.owasp_severity} | **ASR:** {finding.asr}%")"""

new_tier = """    if hasattr(evidence, "findings") and evidence.findings:
        for finding in evidence.findings[:5]:
            lines.append(f"### {finding.finding_id}: {finding.owasp_id}")
            lines.append(f"**Severity:** {finding.owasp_severity} | **ASR:** {finding.asr}%")"""

content = content.replace(old_tier, new_tier)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("Fixed P0-3e: orphaned if/else and broken evidence chain loop")
