"""临时脚本：修复 orchestrator.py 第73行后的缩进问题"""
with open('core/orchestrator.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

fixed = []
for i, line in enumerate(lines):
    # 从第 73 行（索引 72）开始，修复缩进 >= 8 的行
    if i >= 72 and line.strip():
        indent = len(line) - len(line.lstrip())
        if indent >= 8:
            # 减少 4 空格
            new_indent = indent - 4
            fixed.append(' ' * new_indent + line.lstrip())
        else:
            fixed.append(line)
    else:
        fixed.append(line)

# 写回文件
with open('core/orchestrator.py', 'w', encoding='utf-8') as f:
    f.writelines(fixed)

print(f"修复完成，共处理 {len(fixed)} 行")
