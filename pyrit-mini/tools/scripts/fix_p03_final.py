"""Final comprehensive fix for report_markdown.py indentation and syntax issues"""
path = "report/report_markdown.py"

with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

new_lines = []
i = 0
while i < len(lines):
    line = lines[i]
    stripped = line.lstrip()
    
    # Fix 1: lines that have only an if condition with no colon (orphaned if)
    if stripped.startswith('"') and not stripped.startswith('"""') and '(' not in stripped and ')' not in stripped:
        # Likely a broken for loop body - skip
        i += 1
        continue
    
    # Fix 2: lines.append lines that are not indented properly (missing lines.append)
    if stripped.startswith('f"|') and not stripped.startswith('f"| {') and 'lines.append' not in line:
        # Wrap in lines.append
        indent = len(line) - len(stripped)
        new_lines.append(' ' * indent + 'lines.append("' + stripped.rstrip() + '")\n')
        i += 1
        continue
    
    # Fix 3: Broken escalation dashboard loop
    if "for stage in dashboard:" in stripped:
        new_lines.append(line)
        i += 1
        # Skip broken line
        if i < len(lines) and 'f"| {stage[' in lines[i]:
            indent = len(lines[i]) - len(lines[i].lstrip())
            new_lines.append(' ' * indent + 'lines.append(\n')
            new_lines.append(' ' * (indent + 4) + 'f"| {stage[\'stage\']} | {stage[\'technique\']} | {stage[\'asr\']} | {stage[\'escalated\']} |"\n')
            new_lines.append(' ' * indent + ')\n')
            i += 1
        continue
    
    # Fix 4: else: with next line not indented
    if stripped == "else:" and i + 1 < len(lines):
        new_lines.append(line)
        i += 1
        next_line = lines[i]
        next_stripped = next_line.lstrip()
        if next_line.strip() and not next_line.startswith(' ' * (len(line) - len(stripped) + 4)):
            # Add proper indentation
            indent = len(line) - len(stripped) + 4
            new_lines.append(' ' * indent + next_stripped)
            i += 1
            continue
    
    new_lines.append(line)
    i += 1

with open(path, "w", encoding="utf-8") as f:
    f.writelines(new_lines)

print("Fixed P0-3 final pass")
