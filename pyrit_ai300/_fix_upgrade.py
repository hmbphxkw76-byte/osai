#!/usr/bin/env python3
"""Fix upgrade_strategy.py constants - handles multiple encodings"""
import os

filepath = os.path.join(os.path.dirname(__file__), "src", "executor", "workflow", "upgrade_strategy.py")

# Read as binary and try multiple encodings
raw = open(filepath, "rb").read()

# Try to detect encoding
content = None
for enc in ["utf-8", "gbk", "gb2312", "latin-1", "cp1252"]:
    try:
        content = raw.decode(enc)
        print(f"Encoding detected: {enc}")
        break
    except (UnicodeDecodeError, UnicodeError):
        continue

if content is None:
    print("ERROR: Could not decode file with any known encoding")
    exit(1)

# Find the line with MAX_UPGRADE_DEPTH = 2
lines = content.split("\n")
found = False
for i, line in enumerate(lines):
    if "MAX_UPGRADE_DEPTH = 2" in line:
        # Replace this line and add new constants
        lines[i] = line.replace("MAX_UPGRADE_DEPTH = 2", "MAX_UPGRADE_DEPTH = 1")
        # Insert new constants after this line
        lines.insert(i + 1, "")
        lines.insert(i + 2, "# Maximum upgrade candidates per depth level (prevent upgrade chain bloat)")
        lines.insert(i + 3, "MAX_UPGRADE_CANDIDATES = 3")
        lines.insert(i + 4, "")
        lines.insert(i + 5, "# Per-plan total upgrade time budget (seconds)")
        lines.insert(i + 6, "# If cumulative upgrade time exceeds this, stop upgrading")
        lines.insert(i + 7, "MAX_UPGRADE_TOTAL_TIME = 600  # 10 minutes")
        found = True
        print(f"OK: Replaced at line {i}")
        break

if not found:
    print("NOT FOUND: MAX_UPGRADE_DEPTH = 2")
    for i, line in enumerate(lines):
        if "MAX_UPGRADE" in line:
            print(f"  Line {i}: {repr(line)}")
    exit(1)

# Write back with UTF-8 encoding
new_content = "\n".join(lines)
with open(filepath, "w", encoding="utf-8") as f:
    f.write(new_content)
print("File written successfully in UTF-8")
