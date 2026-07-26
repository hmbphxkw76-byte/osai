#!/usr/bin/env python3
"""Add MAX_UPGRADE_CANDIDATES cap to generate_upgrade_plans return value"""

filepath = "src/executor/workflow/upgrade_strategy.py"
content = open(filepath, "r", encoding="utf-8").read()

# Find the exact return statement and insert cap before it
old = "        return final_candidates\n\n\n\n    # -----------------------------------------------"
new = """        # Cap the number of candidates to prevent upgrade chain bloat
        if len(final_candidates) > MAX_UPGRADE_CANDIDATES:
            logger.info(
                f"Upgrade strategy: capping from {len(final_candidates)} to "
                f"{MAX_UPGRADE_CANDIDATES} candidates"
            )
            final_candidates = final_candidates[:MAX_UPGRADE_CANDIDATES]

        return final_candidates

    # -----------------------------------------------"""

if old in content:
    content = content.replace(old, new, 1)
    open(filepath, "w", encoding="utf-8").write(content)
    print("OK: Added MAX_UPGRADE_CANDIDATES cap")
else:
    print("NOT FOUND, trying alternative...")
    # Alternative: just insert before return
    old2 = "        return final_candidates"
    if old2 in content:
        cap_code = """        # Cap the number of candidates to prevent upgrade chain bloat
        if len(final_candidates) > MAX_UPGRADE_CANDIDATES:
            logger.info(
                f"Upgrade strategy: capping from {len(final_candidates)} to "
                f"{MAX_UPGRADE_CANDIDATES} candidates"
            )
            final_candidates = final_candidates[:MAX_UPGRADE_CANDIDATES]

        return final_candidates"""
        # Only replace the first occurrence (in generate_upgrade_plans)
        content = content.replace(old2, cap_code, 1)
        open(filepath, "w", encoding="utf-8").write(content)
        print("OK: Added cap (alternative method)")
    else:
        print("STILL NOT FOUND")
