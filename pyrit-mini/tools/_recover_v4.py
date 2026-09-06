#!/usr/bin/env python3
"""Extract file content from write tool calls in transcript."""
import os
import re

TRANSCRIPT = r'C:\Users\liude\.catpaw\projects\ided--文档-GitHub-osai-pyrit-mini\9791aca6-72e6-40bb-a2e2-ac799312f5fa\agent-transcripts\transcript.txt'

with open(TRANSCRIPT, encoding='utf-8') as f:
    t = f.read()

# Search for the first line of each file in the transcript
first_lines = {
    'dual_judge.py': 'dual_judge',
    'precompute.py': 'arXiv:2308.07920',
    'escalation.py': '单轮失败',
}

for fname, marker in first_lines.items():
    positions = [m.start() for m in re.finditer(re.escape(marker), t)]
    print(f"\n{fname} ({marker}): found {len(positions)} times")
    for p in positions[:3]:
        ctx = t[max(0,p-50):p+200].replace('\n', '\\n')
        print(f"  pos={p}: ...{ctx}...")
