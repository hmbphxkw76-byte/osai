#!/usr/bin/env python3
"""Extract file content from write tool calls by finding the first line."""
import re

TRANSCRIPT = r'C:\Users\liude\.catpaw\projects\ided--文档-GitHub-osai-pyrit-mini\9791aca6-72e6-40bb-a2e2-ac799312f5fa\agent-transcripts\transcript.txt'

with open(TRANSCRIPT, encoding='utf-8') as f:
    t = f.read()

out = open(r'd:\文档\GitHub\osai\pyrit-mini/_extract_out.txt', 'w', encoding='utf-8')

# The first line of dual_judge.py is: """dual_judge 从 asr_tracker.py 拆分而来.
# The first line of precompute.py is: # arXiv:2308.07920 - Zhang et al., Dual Judge cross-validation
# The first line of escalation.py is: """单轮失败 多轮升级逻辑。

# Search for write tool calls that contain the first line content
# Format in transcript: [Tool call] write ... <content> ... [Tool result]

# Find all positions where the first line content appears in write calls
# The content after a write call would have the raw file content

# Let's look for the FIRST occurrence of dual_judge 从 in the transcript
# This would be when the file was originally written

# The file content would appear after a tool call marker
# Search for  (the first part of dual_judge.py)
markers = [
    ('dual_judge.py', 'dual_judge'),
    ('precompute.py', 'arXiv:2308.07920'),
    ('escalation.py', '单轮失败'),
]

for fname, marker in markers:
    # Find all occurrences
    pos = 0
    occurrences = []
    while True:
        idx = t.find(marker, pos)
        if idx == -1:
            break
        occurrences.append(idx)
        pos = idx + 1
    
    out.write(f"\n{'='*60}\n")
    out.write(f"{fname}: {len(occurrences)} occurrences of '{marker}'\n")
    
    # For each occurrence, check what comes before and after
    for idx in occurrences[:10]:
        # Get context: 200 chars before, 600 after
        before = t[max(0, idx-200):idx]
        after = t[idx:idx+600]
        
        # Check if this looks like write tool call content
        # Write calls have the content after the file_path line
        is_in_write = False
        if 'write' in before[-100:] or 'contents' in before[-100:]:
            is_in_write = True
        
        out.write(f"\n  pos={idx} (in_write_ctx={is_in_write}):\n")
        out.write(f"  BEFORE: ...{before[-80:]}\n")
        out.write(f"  AFTER:  {after[:200]}\n")

out.close()
print("Done")
