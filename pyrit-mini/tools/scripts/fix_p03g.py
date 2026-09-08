"""Fix _generate_technical_markdown broken sections"""
path = "report/report_markdown.py"

with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Fix target fingerprint section - completely broken
old_fp = """        if fp:
                "app_type", "target_type", "auth_type", "framework", "content_type",
                "capabilities", "model_family", "language",
                "session_type", "secret_format", "tenant_id",
                "api_category", "burp_model_name",
            ):
                val = fp.get(key, "")
                if val:
                    if fp.get("ai_framework"):
                        if fp.get("system_prompt_leaked"):
                            f"| system_prompt_leaked | **LEAKED** via {
        fp.get(
            'system_prompt_extraction_method',
            '')} (len={
                fp.get(
                    'system_prompt_length',
                     0)}) |")
        if attack_surface:"""

new_fp = """        if fp:
            fp_keys = [
                "app_type", "target_type", "auth_type", "framework", "content_type",
                "capabilities", "model_family", "language",
                "session_type", "secret_format", "tenant_id",
                "api_category", "burp_model_name",
            ]
            for key in fp_keys:
                val = fp.get(key, "")
                if val:
                    lines.append(f"| {key} | {val} |")
            if fp.get("system_prompt_leaked"):
                lines.append(
                    f"| system_prompt_leaked | **LEAKED** via "
                    f"{fp.get('system_prompt_extraction_method', '')} "
                    f"(len={fp.get('system_prompt_length', 0)}) |"
                )
        if attack_surface:"""

content = content.replace(old_fp, new_fp)

# Fix MITRE mapping - broken seen_mitre logic
old_mitre = """    seen_mitre: set[str] = set()
    mitre_count = 0
    for ev in evidence.evidence:
        if key in seen_mitre:
            seen_mitre.add(key)
        lines.append(
            f"| {ev.owasp_id} | {ev.mitre_tactic} | {ev.mitre_technique_id} "
            f"| {ev.mitre_technique_name} |",
        )
        mitre_count += 1"""  

new_mitre = """    seen_mitre: set[str] = set()
    mitre_count = 0
    for ev in evidence.evidence:
        key = f"{ev.mitre_technique_id}|{ev.mitre_tactic}"
        if key in seen_mitre:
            continue
        seen_mitre.add(key)
        lines.append(
            f"| {ev.owasp_id} | {ev.mitre_tactic} | {ev.mitre_technique_id} "
            f"| {ev.mitre_technique_name} |"
        )
        mitre_count += 1"""

content = content.replace(old_mitre, new_mitre)

# Fix MITRE reference section - broken seen_refs logic
old_refs = """    seen_refs: set[str] = set()
    ref_count = 0
    for ev in evidence.evidence:
            ref_key = f"{ev.mitre_technique_id}|{ev.mitre_url}"
            if ref_key in seen_refs:
                seen_refs.add(ref_key)
            lines.append(f"- [{ev.mitre_technique_id}]({ev.mitre_url}): {ev.mitre_technique_name}")
            ref_count += 1"""  

new_refs = """    seen_refs: set[str] = set()
    ref_count = 0
    for ev in evidence.evidence:
        ref_key = f"{ev.mitre_technique_id}|{ev.mitre_url}"
        if ref_key in seen_refs:
            continue
        seen_refs.add(ref_key)
        lines.append(f"- [{ev.mitre_technique_id}]({ev.mitre_url}): {ev.mitre_technique_name}")
        ref_count += 1"""

content = content.replace(old_refs, new_refs)

# Fix score consistency section - broken if/else
old_score = """    if score_lines:
        else:
        lines.append("")
        lines.append("*No score consistency data available for this assessment.*")
        lines.append("")"""

new_score = """    if score_lines:
        lines.extend(score_lines)
    else:
        lines.append("")
        lines.append("*No score consistency data available for this assessment.*")
    lines.append("")"""

content = content.replace(old_score, new_score)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("Fixed P0-3g: _generate_technical_markdown broken sections")
