"""Fix remaining broken sections in report_markdown.py"""
path = "report/report_markdown.py"

with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Fix OWASP LLM Top 10 section - broken indentation
old_owasp_llm = """    for owasp_id, info in sorted(evidence.owasp_llm_compliance.items()):
            f"| {owasp_id} | {info.get('category', '')} | {info.get('tested', 0)} "
            f"| {info.get('success', 0)} | {info.get('failed', 0)} | {info.get('asr', 0)}% |",
        )
    lines.append("")"""

new_owasp_llm = """    for owasp_id, info in sorted(evidence.owasp_llm_compliance.items()):
        lines.append(
            f"| {owasp_id} | {info.get('category', '')} | {info.get('tested', 0)} "
            f"| {info.get('success', 0)} | {info.get('failed', 0)} | {info.get('asr', 0)}% |"
        )
    lines.append("")"""

content = content.replace(old_owasp_llm, new_owasp_llm)

# Fix OWASP ASI Top 10 section - broken indentation
old_owasp_asi = """    for owasp_id, info in sorted(evidence.owasp_asi_compliance.items()):
            f"| {owasp_id} | {info.get('category', '')} | {info.get('tested', 0)} "
            f"| {info.get('success', 0)} | {info.get('failed', 0)} | {info.get('asr', 0)}% |",
        )
    lines.append("")"""

new_owasp_asi = """    for owasp_id, info in sorted(evidence.owasp_asi_compliance.items()):
        lines.append(
            f"| {owasp_id} | {info.get('category', '')} | {info.get('tested', 0)} "
            f"| {info.get('success', 0)} | {info.get('failed', 0)} | {info.get('asr', 0)}% |"
        )
    lines.append("")"""

content = content.replace(old_owasp_asi, new_owasp_asi)

# Fix Technique Performance section - broken loop body
old_tech_perf = """    tech_map: dict[str, list[VulnerabilityEvidence]] = {}
    for ev in evidence_list:
        lines.append("| Technique | Tested | Success | Failed | ASR |")
    lines.append("|-----------|--------|---------|--------|-----|")
    for tech, evs in sorted(tech_map.items()):
        success = sum(1 for ev in evs if ev.is_success)
        failed = tested - success"""

new_tech_perf = """    tech_map: dict[str, list[VulnerabilityEvidence]] = {}
    for ev in evidence_list:
        tech = ev.technique_name or "unknown"
        if tech not in tech_map:
            tech_map[tech] = []
        tech_map[tech].append(ev)
    lines.append("| Technique | Tested | Success | Failed | ASR |")
    lines.append("|-----------|--------|---------|--------|-----|")
    for tech, evs in sorted(tech_map.items()):
        tested = len(evs)
        success = sum(1 for ev in evs if ev.is_success)
        failed = tested - success"""

# Only replace if the broken pattern exists
if "for ev in evidence_list:\n        lines.append" in content:
    content = content.replace(old_tech_perf, new_tech_perf)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("Fixed P0-3b: remaining broken sections in _generate_findings_markdown")
