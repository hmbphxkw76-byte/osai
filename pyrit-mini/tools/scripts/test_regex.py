#!/usr/bin/env python3
"""Test regex patterns for converter chain detection - with improved preprocessing."""
import importlib
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import core.architecture_guard as ag
importlib.reload(ag)

chains_file = Path("arm/converter_chains.py")
content = chains_file.read_text(encoding="utf-8")

print("=" * 60)
print("Line-by-line converter chain detection (improved)")
print("=" * 60)

# Step 1: Find function boundaries
func_pattern = re.compile(r"^def\s+(\w+)\s*\(|^(?=\s)", re.MULTILINE)

# Step 2: For each function, check return statements
lines = content.split("\n")
current_func = None
in_function = False
results = []

i = 0
while i < len(lines):
    line = lines[i]
    stripped = line.strip()

    # Detect function start
    if stripped.startswith("def "):
        match = re.match(r"def\s+(\w+)\s*\(", stripped)
        if match:
            current_func = match.group(1)
            func_start_line = i + 1
            in_function = True
            i += 1
            continue

    # Detect function end (dedented line that's not blank or comment)
    if in_function and stripped and not stripped.startswith("#"):
        indent = len(line) - len(line.lstrip())
        if indent == 0 and not stripped.startswith("def ") and not stripped.startswith("return") and not stripped.startswith("]"):
            # End of function at module level
            in_function = False
            current_func = None

    # Detect return [ block
    if in_function and current_func and "return [" in stripped:
        # Find the complete return block
        j = i + 1
        conv_count = 0
        block_lines = [stripped]
        while j < len(lines):
            block_line = lines[j]
            block_stripped = block_line.strip()
            if block_stripped == "]" or block_stripped.startswith("]"):
                break
            if "_conv(" in block_stripped and not block_stripped.startswith("#"):
                conv_count += 1
            block_lines.append(block_stripped)
            j += 1

        if conv_count > 1:
            results.append({
                "func": current_func,
                "line": func_start_line,
                "conv_count": conv_count,
                "body_preview": " | ".join(block_lines[1:3])[:80] if len(block_lines) > 1 else ""
            })

    i += 1

print(f"Found {len(results)} multi-converter returns:\n")
for r in results:
    severity = "OK"
    if r["conv_count"] > 3:
        severity = "BLOCKING"
    elif r["conv_count"] > 2:
        severity = "WARNING"
    print(f"  [{severity}] {r['func']} (line {r['line']}): {r['conv_count']} converters")
    print(f"          Body: {r['body_preview']}")
    print()
