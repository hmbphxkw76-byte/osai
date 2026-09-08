path = "report/evidence.py"
with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

# Find and fix the buggy block
new_lines = []
i = 0
while i < len(lines):
    line = lines[i]
    # Look for the start of the buggy block
    if " # OWASP ASR" in line:
        # Skip the comment line
        i += 1
        # Skip the for loop and its body
        while i < len(lines) and "collection.owasp_llm_compliance" not in lines[i]:
            i += 1
        # Now i points to collection.owasp_llm_compliance
        # We want to keep these three lines but without the loop
        new_lines.append("        # OWASP compliance stats (P0-2 fix: removed buggy loop)\n")
        new_lines.append("        collection.owasp_web_compliance = owasp_web_stats\n")
        # Skip the old web_compliance line (was inside loop)
        i += 1  # now at owasp_llm line
        new_lines.append(lines[i])  # owasp_llm_compliance
        i += 1
        new_lines.append(lines[i])  # owasp_asi_compliance
        i += 1
    else:
        new_lines.append(line)
        i += 1

with open(path, "w", encoding="utf-8") as f:
    f.writelines(new_lines)

print("Fixed P0-2")
