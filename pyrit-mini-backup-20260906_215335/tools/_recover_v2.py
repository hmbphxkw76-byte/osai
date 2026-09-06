#!/usr/bin/env python3
"""Recover by searching transcript for file content via unique markers."""
import os
import re

TRANSCRIPT = r'C:\Users\liude\.catpaw\projects\ided--文档-GitHub-osai-pyrit-mini\9791aca6-72e6-40bb-a2e2-ac799312f5fa\agent-transcripts\transcript.txt'

# Read transcript once
with open(TRANSCRIPT, encoding='utf-8') as f:
    t = f.read()

print(f"Transcript length: {len(t)} chars")

# Strategy: find large blocks of text that look like file content
# In the transcript, file contents appear in tool call payloads
# They are usually preceded by "file_path" and "contents" keys

# Find all occurrences where file_path appears with a known filename
target_filenames = [
    'dual_judge.py',
    'precompute.py', 
    'escalation.py',
]

for fname in target_filenames:
    positions = [m.start() for m in re.finditer(re.escape(fname), t)]
    print(f"\n{fname}: found at {len(positions)} positions")
    
    # For each position, look at surrounding context
    for pos in positions[:5]:  # Show first 5 occurrences
        start = max(0, pos - 100)
        end = min(len(t), pos + 300)
        context = t[start:end]
        # Show what's around it
        snippet = context.replace('\n', '\\n')[:200]
        print(f"  pos={pos}: ...{snippet}...")
