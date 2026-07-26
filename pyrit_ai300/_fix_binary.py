#!/usr/bin/env python3
"""Apply only ASCII-safe changes to upgrade_strategy.py using binary editing"""

filepath = "src/executor/workflow/upgrade_strategy.py"
raw = open(filepath, "rb").read()

# 1. Replace MAX_UPGRADE_DEPTH = 2 with = 1 + new constants
old_depth = b"MAX_UPGRADE_DEPTH = 2"
new_depth = b"""MAX_UPGRADE_DEPTH = 1

# Maximum upgrade candidates per depth level (prevent upgrade chain bloat)
MAX_UPGRADE_CANDIDATES = 3

# Per-plan total upgrade time budget (seconds)
# If cumulative upgrade time exceeds this, stop upgrading
MAX_UPGRADE_TOTAL_TIME = 600  # 10 minutes"""

if old_depth in raw:
    raw = raw.replace(old_depth, new_depth, 1)
    print("OK: Set MAX_UPGRADE_DEPTH = 1 + new constants")
else:
    print("WARN: MAX_UPGRADE_DEPTH = 2 not found")

# 2. Add candidate cap before first 'return final_candidates'
old_return = b"        return final_candidates"
cap_code = b"""        # Cap the number of candidates to prevent upgrade chain bloat
        if len(final_candidates) > MAX_UPGRADE_CANDIDATES:
            logger.info(
                f"Upgrade strategy: capping from {len(final_candidates)} to "
                f"{MAX_UPGRADE_CANDIDATES} candidates"
            )
            final_candidates = final_candidates[:MAX_UPGRADE_CANDIDATES]

        return final_candidates"""

if old_return in raw:
    raw = raw.replace(old_return, cap_code, 1)
    print("OK: Added MAX_UPGRADE_CANDIDATES cap")
else:
    print("WARN: return final_candidates not found")

# Write back as binary (preserving original encoding)
with open(filepath, "wb") as f:
    f.write(raw)
print("File saved (binary, preserving original encoding)")
