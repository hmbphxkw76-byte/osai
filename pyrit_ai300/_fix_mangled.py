#!/usr/bin/env python3
"""Fix all mangled docstrings in upgrade_strategy.py - no printing"""

import re

filepath = "src/executor/workflow/upgrade_strategy.py"
content = open(filepath, "r", encoding="utf-8").read()

# Replace all U+FFFD and non-ASCII chars in docstrings
# Strategy: Remove all non-ASCII characters from the file entirely
# This will clean up mangled Chinese comments/docstrings

# First, fix triple-quoted docstrings by removing non-ASCII chars inside them
def clean_docstring(match):
    full = match.group(0)
    prefix = full[:3]
    suffix = full[-3:]
    inner = full[3:-3]
    # Remove non-ASCII characters
    cleaned = "".join(c for c in inner if ord(c) < 128)
    if not cleaned.strip():
        cleaned = ""
    return prefix + cleaned + suffix

content = re.sub(
    r'"""[\s\S]*?"""',
    clean_docstring,
    content,
)

# Fix single-line comments with non-ASCII chars
lines = content.split("\n")
fixed_lines = []
for line in lines:
    has_non_ascii = any(ord(c) >= 128 for c in line)
    if has_non_ascii:
        stripped = line.lstrip()
        if stripped.startswith("#"):
            indent = line[:len(line) - len(stripped)]
            fixed_lines.append(f"{indent}# (comment)")
        else:
            # Keep only ASCII chars
            cleaned = "".join(c for c in line if ord(c) < 128)
            fixed_lines.append(cleaned)
    else:
        fixed_lines.append(line)

content = "\n".join(fixed_lines)

# Verify
remaining = sum(1 for c in content if ord(c) >= 128)
with open(filepath, "w", encoding="utf-8") as f:
    f.write(content)
print(f"File saved. Remaining non-ASCII chars: {remaining}")
