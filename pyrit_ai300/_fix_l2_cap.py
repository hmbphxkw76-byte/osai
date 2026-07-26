#!/usr/bin/env python3
"""Fix L2 threshold to cap required successes for large plan counts"""

filepath = "src/executor/workflow/scenario_orchestrator.py"
content = open(filepath, "r", encoding="utf-8").read()

# Fix the L2 required calculation to cap at a maximum
old = """                                required = math.ceil(total_for_owasp * owasp_success_threshold)"""

new = """                                # Cap required successes to prevent excessive attempts for large plan counts
                                # e.g., 37 plans * 0.5 = 19 (too many) → capped to 5
                                _raw_required = math.ceil(total_for_owasp * owasp_success_threshold)
                                required = min(_raw_required, 5)"""

if old in content:
    content = content.replace(old, new, 1)
    print("OK: Added L2 threshold cap")
else:
    print("NOT FOUND: L2 required calculation")

open(filepath, "w", encoding="utf-8").write(content)
print("File saved")
