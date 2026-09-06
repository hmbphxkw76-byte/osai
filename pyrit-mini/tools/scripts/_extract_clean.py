#!/usr/bin/env python3
"""Extract clean file content from write call in transcript."""
import re

TRANSCRIPT = r'C:\Users\liude\.catpaw\projects\ided--文档-GitHub-osai-pyrit-mini\9791aca6-72e6-40bb-a2e2-ac799312f5fa\agent-transcripts\transcript.txt'

with open(TRANSCRIPT, encoding='utf-8') as f:
    t = f.read()

# For dual_judge.py: clean content starts at pos=1042735 (the line "Prefers ConversationScorer wrapper")
# But this is in the MIDDLE of the file. We need to find the actual START of the write call.
# The write call would have started with """dual_judge 从 asr_tracker.py 拆分而来.

# Let's search backward from 1042735 to find the actual start
start_search = t.rfind('"""dual_judge', 0, 1042735)
print(f"dual_judge docstring start: {start_search}")

# Also search for the start using other unique patterns
start_search2 = t.rfind('dual_judge ', 900000, 1042735)
print(f"dual_judge space (searching backward): {start_search2}")

# Get 500 chars before 1042735 to see context
context = t[1042735-500:1042735+100]
print(f"\nContext before clean content:")
print(context)

# Find where this write call starts by looking for file_path marker
# Search backward for "assess/dual_judge.py" reference
fp_pos = t.rfind('assess/dual_judge.py', 900000, 1042735)
print(f"\n'assess/dual_judge.py' last pos before clean content: {fp_pos}")

# Show context around that file_path mention
if fp_pos > 0:
    print(f"\nContext around file_path mention:")
    print(t[fp_pos-100:fp_pos+200])
