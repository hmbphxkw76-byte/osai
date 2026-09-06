#!/usr/bin/env python3
import os
import re

TRANSCRIPT = r'C:\Users\liude\.catpaw\projects\ided--文档-GitHub-osai-pyrit-mini\9791aca6-72e6-40bb-a2e2-ac799312f5fa\agent-transcripts\transcript.txt'

with open(TRANSCRIPT, encoding='utf-8') as f:
    t = f.read()

# Find write tool calls - look for the pattern in transcript
# The tool call format is not standard JSON - let's look for file_path markers
# and then find the content that follows

# Search for "file_path:" followed by one of our target files
targets = {
    'dual_judge.py': None,
    'precompute.py': None,
    'escalation.py': None,
}

for fname in targets:
    pattern = r'file_path:[^"' + r']*' + re.escape(fname)
    for m in re.finditer(pattern, t):
        pos = m.end()
        # Look for contents marker nearby
        chunk = t[pos:pos+200]
        if 'contents' in chunk:
            print(f"\n{fname} at pos {pos}: {chunk[:100]}")
            targets[fname] = pos
            break

print("\nSummary:", targets)
