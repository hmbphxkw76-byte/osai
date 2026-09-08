#!/usr/bin/env python3
"""Fix P0-2: OWASP stats loop bug in evidence.py"""
import re

path = "report/evidence.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Fix the buggy loop - replace the entire problematic block
old_block = re.compile(
    r" # OWASP ASR\n"
    r"        for stats_dict in \[owasp_web_stats, owasp_llm_stats, owasp_asi_stats\]:\n"
    r"                decided = stats\[\"success\"\] \+ stats\[\"failed\"\]\n"
    r"                if decided > 0:\n"
    r"\n"
    r"                    collection\.owasp_web_compliance = owasp_web_stats\n"
    r"        collection\.owasp_llm_compliance = owasp_llm_stats\n"
    r"        collection\.owasp_asi_compliance = owasp_ansi_stats"
)

new_block = (
    "        # OWASP compliance stats (P0-2 fix: direct assignments, no loop bug)\n"
    "        collection.owasp_web_compliance = owasp_web_stats\n"
    "        collection.owasp_llm_compliance = owasp_llm_stats\n"
    "        collection.owasp_asi_compliance = owasp_asi_stats"
)

new_content, count = old_block.subn(new_block, content)

if count == 0:
    print("ERROR: Pattern not found!")
    exit(1)
elif count > 1:
    print(f"WARNING: Found {count} matches, using first")
    new_content = old_block.sub(new_block, content, count=1)

with open(path, "w", encoding="utf-8") as f:
    f.write(new_content)

print(f"Fixed P0-2: {count} replacement(s) made")
