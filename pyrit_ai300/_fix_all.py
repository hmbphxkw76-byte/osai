#!/usr/bin/env python3
"""Fix upgrade_strategy.py with error-tolerant encoding"""

filepath = "src/executor/workflow/upgrade_strategy.py"
raw = open(filepath, "rb").read()

# Try UTF-8 with error replacement, then convert
content = raw.decode("utf-8", errors="replace")

# Apply changes
# 1. MAX_UPGRADE_DEPTH = 2 → 1
old = "MAX_UPGRADE_DEPTH = 2"
new = """MAX_UPGRADE_DEPTH = 1

# Maximum upgrade candidates per depth level (prevent upgrade chain bloat)
MAX_UPGRADE_CANDIDATES = 3

# Per-plan total upgrade time budget (seconds)
# If cumulative upgrade time exceeds this, stop upgrading
MAX_UPGRADE_TOTAL_TIME = 600  # 10 minutes"""

if old in content:
    content = content.replace(old, new, 1)
    print("OK: Set MAX_UPGRADE_DEPTH = 1 + new constants")
else:
    print("WARN: MAX_UPGRADE_DEPTH = 2 not found")

# 2. Add candidate cap before first 'return final_candidates'
old_return = "        return final_candidates"
cap_code = """        # Cap the number of candidates to prevent upgrade chain bloat
        if len(final_candidates) > MAX_UPGRADE_CANDIDATES:
            logger.info(
                f"Upgrade strategy: capping from {len(final_candidates)} to "
                f"{MAX_UPGRADE_CANDIDATES} candidates"
            )
            final_candidates = final_candidates[:MAX_UPGRADE_CANDIDATES]

        return final_candidates"""

if "MAX_UPGRADE_CANDIDATES" not in content:
    content = content.replace(old_return, cap_code, 1)
    print("OK: Added MAX_UPGRADE_CANDIDATES cap")
else:
    print("WARN: MAX_UPGRADE_CANDIDATES already present")

# Write as UTF-8 (replacing mangled bytes with U+FFFD)
with open(filepath, "w", encoding="utf-8") as f:
    f.write(content)
print("File written as UTF-8 (with replacement chars for mangled comments)")
