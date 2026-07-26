#!/usr/bin/env python3
"""Fix the encoding of upgrade_strategy.py
The file was originally GBK, but was read as latin-1 and written as UTF-8.
We need to reverse this: read as UTF-8, encode to latin-1, decode as GBK.
"""

filepath = "src/executor/workflow/upgrade_strategy.py"

# Read the current (mangled) UTF-8 content
mangled = open(filepath, "r", encoding="utf-8").read()

# Reverse: encode as latin-1 to get original bytes, then decode as GBK
try:
    original_bytes = mangled.encode("latin-1")
    proper = original_bytes.decode("gbk")
    print("OK: Successfully recovered original GBK text")
    
    # Now apply our changes to the properly decoded text
    # 1. MAX_UPGRADE_DEPTH = 2 → 1 + new constants (already done, verify)
    if "MAX_UPGRADE_DEPTH = 1" in proper:
        print("MAX_UPGRADE_DEPTH already = 1")
    elif "MAX_UPGRADE_DEPTH = 2" in proper:
        proper = proper.replace(
            "MAX_UPGRADE_DEPTH = 2",
            "MAX_UPGRADE_DEPTH = 1\n\n# Maximum upgrade candidates per depth level (prevent upgrade chain bloat)\nMAX_UPGRADE_CANDIDATES = 3\n\n# Per-plan total upgrade time budget (seconds)\n# If cumulative upgrade time exceeds this, stop upgrading\nMAX_UPGRADE_TOTAL_TIME = 600  # 10 minutes",
            1
        )
        print("Set MAX_UPGRADE_DEPTH = 1")
    
    # 2. Add MAX_UPGRADE_CANDIDATES cap (already done, verify)
    if "MAX_UPGRADE_CANDIDATES" not in proper.split("return final_candidates")[0]:
        # Find the first return final_candidates and add cap before it
        old_return = "        return final_candidates"
        cap_code = """        # Cap the number of candidates to prevent upgrade chain bloat
        if len(final_candidates) > MAX_UPGRADE_CANDIDATES:
            logger.info(
                f"Upgrade strategy: capping from {len(final_candidates)} to "
                f"{MAX_UPGRADE_CANDIDATES} candidates"
            )
            final_candidates = final_candidates[:MAX_UPGRADE_CANDIDATES]

        return final_candidates"""
        proper = proper.replace(old_return, cap_code, 1)
        print("Added MAX_UPGRADE_CANDIDATES cap")
    else:
        print("MAX_UPGRADE_CANDIDATES cap already present")
    
    # Write back as UTF-8
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(proper)
    print("File written as proper UTF-8")
    
except Exception as e:
    print(f"ERROR: {e}")
    # If the reverse doesn't work, try a different approach
    print("Trying alternative: just fix the syntax errors in comments...")
