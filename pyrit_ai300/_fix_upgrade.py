#!/usr/bin/env python3
"""Fix upgrade_strategy.py constants"""
import os

filepath = os.path.join(os.path.dirname(__file__), "src", "executor", "workflow", "upgrade_strategy.py")
content = open(filepath, "r", encoding="utf-8").read()

old = "MAX_UPGRADE_DEPTH = 2"
new = """MAX_UPGRADE_DEPTH = 1

# Maximum upgrade candidates per depth level (prevent upgrade chain bloat)
MAX_UPGRADE_CANDIDATES = 3

# Per-plan total upgrade time budget (seconds)
# If cumulative upgrade time exceeds this, stop upgrading
MAX_UPGRADE_TOTAL_TIME = 600  # 10 minutes"""

if old in content:
    content = content.replace(old, new, 1)
    open(filepath, "w", encoding="utf-8").write(content)
    print("OK: replaced MAX_UPGRADE_DEPTH=2 with =1 + new constants")
else:
    print("NOT FOUND: MAX_UPGRADE_DEPTH = 2 not found in file")
    # Let's find what's actually there
    for i, line in enumerate(content.split("\n")):
        if "MAX_UPGRADE_DEPTH" in line:
            print(f"Line {i}: {repr(line)}")
