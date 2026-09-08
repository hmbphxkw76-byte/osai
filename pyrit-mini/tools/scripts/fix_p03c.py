"""Fix remaining indentation/syntax errors in report_markdown.py"""
path = "report/report_markdown.py"

with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Fix Technique Ranking section - broken indentation
old_tech_rank = """        for rank in fa.get("technique_ranking", []):
                f"- {rank.get('technique', '')}: "
                f"{rank.get('success_rate', 0)}% ({rank.get('total', 0)} attacks)",
            )"""

new_tech_rank = """        for rank in fa.get("technique_ranking", []):
            lines.append(
                f"- {rank.get('technique', '')}: "
                f"{rank.get('success_rate', 0)}% ({rank.get('total', 0)} attacks)"
            )"""

content = content.replace(old_tech_rank, new_tech_rank)

# Fix Failure Classification section - broken if/elif/else
old_failure = """ #
        failure_categories: dict[str, int] = {}
        for ev in evidence.evidence:
 #
                if ev.converter_chain and "baseline" not in (ev.converter_chain or ""):
                    elif ev.objective and "jailbreak" in (ev.objective or "").lower():
                        else:"""

new_failure = """    # Failure Classification
        failure_categories: dict[str, int] = {}
        for ev in evidence.evidence:
            if not ev.is_success:
                if ev.converter_chain and "baseline" not in (ev.converter_chain or ""):
                    cat = "converter_blocked"
                elif ev.objective and "jailbreak" in (ev.objective or "").lower():
                    cat = "jailbreak_refused"
                else:
                    cat = "other"
                failure_categories[cat] = failure_categories.get(cat, 0) + 1"""

content = content.replace(old_failure, new_failure)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("Fixed P0-3c: remaining indentation errors")
