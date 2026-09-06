#!/usr/bin/env python3
import os
import re

TRANSCRIPT = r'C:\Users\liude\.catpaw\projects\ided--文档-GitHub-osai-pyrit-mini\9791aca6-72e6-40bb-a2e2-ac799312f5fa\agent-transcripts\transcript.txt'

with open(TRANSCRIPT, encoding='utf-8') as f:
    t = f.read()

print(f"Transcript: {len(t)} chars")

# Find write tool calls and associated files
write_calls = [m.start() for m in re.finditer(r"\[Tool call\] write", t)]
print(f"Found {len(write_calls)} write calls")

file_targets = ['dual_judge.py', 'precompute.py', 'escalation.py']

for fname in file_targets:
    for pos in write_calls:
        end = min(len(t), pos + 100000)
        chunk = t[pos:end]
        if fname in chunk:
            fp_idx = chunk.find(fname)
            # Show context
            ctx_start = max(0, fp_idx - 200)
            ctx_end = min(len(chunk), fp_idx + 500)
            context = chunk[ctx_start:ctx_end]
            print(f"\n=== {fname} found at write_pos={pos} ===")
            print(context[:600])
            print("...(truncated)")
            break
