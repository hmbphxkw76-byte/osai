#!/usr/bin/env python3
"""
批量语法修复脚本 - 专门修复 docstring 位置问题
问题模式: def foo():\\n    \\\"\\\"\\\"docstring\\\"\\\"\\\"  (docstring 在函数体外)
修复为: def foo():\\n        \\\"\\\"\\\"docstring\\\"\\\"\\\"  (docstring 在函数体内)
"""
import ast
import os
import sys


def check_syntax(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            ast.parse(f.read())
        return True, None
    except SyntaxError as e:
        return False, str(e)


def fix_docstring_placement(filepath):
    """修复 docstring 位置问题"""
    with open(filepath, 'r', encoding='utf-8') as f:
        original_lines = f.readlines()
    
    new_lines = []
    i = 0
    fixes = 0
    
    while i < len(original_lines):
        line = original_lines[i]
        stripped = line.lstrip()
        
        # 检查是否是函数定义行
        if stripped.startswith(('def ', 'async def ')) and ':' in stripped:
            new_lines.append(line)
            i += 1
            
            # 计算基础缩进
            base_indent = len(line) - len(stripped)
            expected_body_indent = base_indent + 4
            
            # 检查下一行
            if i < len(original_lines):
                next_line = original_lines[i]
                next_stripped = next_line.lstrip()
                
                # 检查是否是 docstring 且在错误的缩进位置
                if (next_stripped.startswith('"""') and 
                    (len(next_line) - len(next_stripped)) <= base_indent and
                    next_stripped != ''):
                    
                    # 计算需要添加的缩进
                    indent_needed = expected_body_indent - (len(next_line) - len(next_stripped))
                    
                    # 修复 docstring
                    if next_stripped.count('"""') >= 2:
                        # 单行 docstring
                        new_lines.append(' ' * expected_body_indent + next_stripped + '\n')
                        fixes += 1
                        i += 1
                    else:
                        # 多行 docstring
                        new_lines.append(' ' * expected_body_indent + next_stripped + '\n')
                        fixes += 1
                        i += 1
                        
                        # 继续处理剩余 docstring 行
                        while i < original_lines:
                            doc_line = original_lines[i]
                            doc_stripped = doc_line.lstrip()
                            if '"""' in doc_stripped and doc_stripped != next_stripped:
                                # docstring 结束行
                                new_lines.append(' ' * expected_body_indent + doc_stripped + '\n')
                                fixes += 1
                                i += 1
                                break
                            else:
                                doc_indent = len(doc_line) - len(doc_stripped)
                                if doc_indent <= base_indent:
                                    new_lines.append(' ' * expected_body_indent + doc_stripped + '\n')
                                    fixes += 1
                                else:
                                    new_lines.append(doc_line)
                                i += 1
                    continue
        
        new_lines.append(line)
        i += 1
    
    # 写回文件
    if fixes > 0:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
    
    return fixes


def fix_duplicate_functions(filepath):
    """修复重复的函数定义"""
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    new_lines = []
    i = 0
    fixes = 0
    
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()
        
        # 检查是否是函数定义
        if stripped.startswith(('def ', 'async def ')) and stripped.endswith(':'):
            # 检查下一行是否是相同的函数定义
            if i + 1 < len(lines):
                next_stripped = lines[i + 1].lstrip()
                if next_stripped.startswith(stripped):
                    # 跳过当前重复的函数定义
                    fixes += 1
                    i += 1
                    continue
        
        new_lines.append(line)
        i += 1
    
    if fixes > 0:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
    
    return fixes


def process_file(filepath):
    """处理单个文件，返回 (是否成功, 修复次数)"""
    total_fixes = 0
    
    # 修复重复定义
    fixes = fix_duplicate_functions(filepath)
    total_fixes += fixes
    
    # 修复 docstring 位置
    fixes = fix_docstring_placement(filepath)
    total_fixes += fixes
    
    # 验证
    ok, err = check_syntax(filepath)
    return ok, total_fixes


def main():
    project_root = Path('.')
    exclude_dirs = {'.venv', '__pycache__', '.ruff_cache', '.git', '.idea', '.vscode', 'outputs', '.assistant_pyrit'}
    
    # 收集所有 Python 文件
    py_files = []
    for path in project_root.rglob('*.py'):
        if any(part in exclude_dirs for part in path.parts):
            continue
        py_files.append(path)
    
    print(f"Found {len(py_files)} Python files")
    
    # 找出有语法错误的文件
    broken_files = []
    for path in py_files:
        ok, err = check_syntax(str(path))
        if not ok:
            broken_files.append((path, err))
    
    print(f"Found {len(broken_files)} files with syntax errors\n")
    
    if not broken_files:
        print("All files have valid syntax!")
        return True
    
    # 修复文件
    fixed = 0
    still_broken = []
    
    for path, err in broken_files:
        ok, num_fixes = process_file(str(path))
        if ok:
            fixed += 1
            print(f"  [OK] {path} ({num_fixes} fixes)")
        else:
            still_broken.append((path, err))
            print(f"  [FAIL] {path} - {err[:60]}")
    
    print(f"\nResults: {fixed}/{len(broken_files)} files fixed")
    
    if still_broken:
        print(f"\n{len(still_broken)} files still have syntax errors")
    
    return len(still_broken) == 0


if __name__ == '__main__':
    from pathlib import Path
    success = main()
    sys.exit(0 if success else 1)
