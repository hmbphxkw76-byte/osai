#!/usr/bin/env python3
"""Check which regex patterns in judge_manager.py are broken."""
import re
import sys
import io

# Force UTF-8 output
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Read file
with open('assess/judge_manager.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Find _REFUSAL_PATTERNS
start_marker = '_REFUSAL_PATTERNS = ['
start_idx = content.find(start_marker)
if start_idx == -1:
    print("_REFUSAL_PATTERNS not found!")
    exit(1)

# Find matching closing bracket
bracket_count = 0
end_idx = start_idx
for i, c in enumerate(content[start_idx:], start_idx):
    if c == '[':
        bracket_count += 1
    elif c == ']':
        bracket_count -= 1
        if bracket_count == 0:
            end_idx = i + 1
            break

patterns_text = content[start_idx:end_idx]

# Try to find each raw string pattern
pattern_count = 0
error_count = 0
error_lines = []
lines = patterns_text.split('\n')

for i, line in enumerate(lines, 1):
    stripped = line.strip()
    # Skip empty lines, comments, and non-pattern lines
    if not stripped or stripped.startswith('#') or stripped == ']' or stripped == '[':
        continue
    if not (stripped.startswith('r"') or stripped.startswith("r'")):
        continue
    
    pattern_count += 1
    # Remove trailing comma
    if stripped.endswith(','):
        stripped = stripped[:-1]
    
    try:
        pattern = eval(stripped)
        re.compile(pattern)
    except Exception as e:
        error_count += 1
        error_lines.append((i, pattern_count, str(e), ))
        print(f"Line {i} (pattern #{pattern_count}): ERROR - {e}")

print(f"\n=== Summary ===")
print(f"Total patterns: {pattern_count}")
print(f"Broken patterns: {error_count}")
print(f"\nBroken pattern line numbers: {[x[0] for x in error_lines]}")
