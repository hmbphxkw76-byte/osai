"""临时脚本：修复 orchestrator.py 的缩进问题"""
with open('core/orchestrator.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

fixed = []
for i, line in enumerate(lines):
    # 从第 205 行（索引 204）开始，修复缩进 >= 24 的行
    if i >= 204 and line.strip():
        indent = len(line) - len(line.lstrip())
        if indent >= 24:
            # 减少 16 空格
            new_indent = indent - 16
            fixed.append(' ' * new_indent + line.lstrip())
            if i < 260:
                print(f"Line {i + 1}: {indent} -> {new_indent} | {line.strip()[:50]}")
        else:
            fixed.append(line)
    else:
        fixed.append(line)

# 写回文件
with open('core/orchestrator.py', 'w', encoding='utf-8') as f:
    f.writelines(fixed)

print(f"\n修复完成，共处理 {len(fixed)} 行")
