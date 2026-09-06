#!/usr/bin/env python3
"""Extract full file content from the clean write call region."""
import re

TRANSCRIPT = r'C:\Users\liude\.catpaw\projects\ided--文档-GitHub-osai-pyrit-mini\9791aca6-72e6-40bb-a2e2-ac799312f5fa\agent-transcripts\transcript.txt'

with open(TRANSCRIPT, encoding='utf-8') as f:
    t = f.read()

out = open(r'd:\文档\GitHub\osai\pyrit-mini/_full_extract.txt', 'w', encoding='utf-8')

# The clean dual_judge.py content starts at pos=1042735
# Let's extract a large chunk from there
start = 1042735

# Find the end - look for the end of write call pattern
# Usually followed by [Tool result] or similar
chunk = t[start:start+30000]
out.write(f"From pos {start}, first 30000 chars:\n")
out.write(chunk)

out.write("\n\n")
out.write("="*60)
out.write("\n\n")

# Also extract escalation.py clean content
# Found at pos=159369 in _recover_out.txt
esc_start = 159369
chunk2 = t[esc_start:esc_start+50000]
out.write(f"From pos {esc_start} (escalation.py), first 50000 chars:\n")
out.write(chunk2)

out.close()
print("Done")
