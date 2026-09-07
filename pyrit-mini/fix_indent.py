#!/usr/bin/env python3
"""Fix indentation in orchestrator.py"""

import re

filepath = 'core/orchestrator.py'

with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

lines = content.split('\n')
fixed_lines = []
in_function = False
function_indent = 0

for i, line in enumerate(lines):
    stripped = line.lstrip()
    if not stripped:
        fixed_lines.append('')
        continue
    
    current_indent = len(line) - len(stripped)
    
    # Detect function definition
    if stripped.startswith('def ') or stripped.startswith('async def '):
        in_function = True
        function_indent = current_indent
        fixed_lines.append(line)  # Keep function def as-is
        continue
    
    # If we're in a function and line has extra indentation
    if in_function and current_indent > function_indent:
        expected_indent = function_indent + 4
        # Fix various indentation issues
        if current_indent >= expected_indent + 4:
            # Too much indentation - reduce to expected
            fixed_lines.append(' ' * expected_indent + stripped)
        elif current_indent == function_indent + 1:
            # 1 space indent - should be 4
            fixed_lines.append(' ' * expected_indent + stripped)
        elif current_indent == function_indent + 2:
            # 2 space indent - should be 4
            fixed_lines.append(' ' * expected_indent + stripped)
        elif current_indent == function_indent + 3:
            # 3 space indent - should be 4
            fixed_lines.append(' ' * expected_indent + stripped)
        else:
            fixed_lines.append(line)
    else:
        fixed_lines.append(line)
        
        # Reset function state if we hit a non-indented line at function level or above
        if stripped and not stripped.startswith('#') and current_indent <= function_indent and current_indent > 0:
            in_function = False

with open(filepath, 'w', encoding='utf-8') as f:
    f.write('\n'.join(fixed_lines))

print('Indentation fix complete')
