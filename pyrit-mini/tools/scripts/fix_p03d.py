"""Fix remaining issues in report_markdown.py - failure categories and tech failures"""
path = "report/report_markdown.py"

with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Fix failure categories section - broken dict definition
old_failure_dict = """        if failure_categories:
                "encoding_blocked": "Converter encoding was detected and blocked",
                "jailbreak_blocked": "Jailbreak prompt was refused by the model",
                "request_refused": "Request was refused due to policy violation",
            }
            for cat, count in sorted(failure_categories.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"| {cat} | {count} | {desc} |")
        else:

        lines.append("")"""

new_failure_dict = """        if failure_categories:
            desc_map = {
                "converter_blocked": "Converter encoding was detected and blocked",
                "jailbreak_refused": "Jailbreak prompt was refused by the model",
                "other": "Request was refused due to policy violation",
            }
            for cat, count in sorted(failure_categories.items(), key=lambda x: x[1], reverse=True):
                desc = desc_map.get(cat, "Unknown failure category")
                lines.append(f"| {cat.replace('_', ' ').title()} | {count} | {desc} |")
        else:
            lines.append("| No failures | 0 | All attacks succeeded |")

        lines.append("")"""

content = content.replace(old_failure_dict, new_failure_dict)

# Fix tech failures section - broken dict init
old_tech_fail = """        tech_failures: dict[str, dict] = {}
        for ev in evidence.evidence:
                tech = ev.technique_name or "unknown"
                if tech not in tech_failures:
                    tech_failures[tech]["count"] += 1"""

new_tech_fail = """        tech_failures: dict[str, int] = {}
        for ev in evidence.evidence:
            if not ev.is_success:
                tech = ev.technique_name or "unknown"
                if tech not in tech_failures:
                    tech_failures[tech] = 0
                tech_failures[tech] += 1"""

content = content.replace(old_tech_fail, new_tech_fail)

# Fix duplicated line
content = content.replace(
    '                failure_categories[cat] = failure_categories.get(cat, 0) + 1\n                failure_categories[cat] = failure_categories.get(cat, 0) + 1',
    '                failure_categories[cat] = failure_categories.get(cat, 0) + 1'
)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("Fixed P0-3d: failure categories and tech failures sections")
