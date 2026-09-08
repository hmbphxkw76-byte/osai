"""Fix remaining indentation issues in report_markdown.py"""
path = "report/report_markdown.py"

with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Fix evidence chain result loop
old_result_loop = """            for result in finding.results:
                    f"  - **Result:** {result.get('evidence_id', '')} "
                    f"({result.get('technique', '')}) - "
                    f"{'Success' if result.get('is_success') else 'Failed'}",
                )"""

new_result_loop = """            for result in finding.results:
                lines.append(
                    f"  - **Result:** {result.get('evidence_id', '')} "
                    f"({result.get('technique', '')}) - "
                    f"{'Success' if result.get('is_success') else 'Failed'}"
                )"""

content = content.replace(old_result_loop, new_result_loop)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("Fixed P0-3f: evidence chain result loop indentation")
