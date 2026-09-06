#!/usr/bin/env python3
import os
import re

TRANSCRIPT = r'C:\Users\liude\.catpaw\projects\ided--文档-GitHub-osai-pyrit-mini\9791aca6-72e6-40bb-a2e2-ac799312f5fa\agent-transcripts\transcript.txt'

with open(TRANSCRIPT, encoding='utf-8') as f:
    t = f.read()

# Unique markers
unique_markers = {
    'dual_judge.py': '_get_judge_scorer(primary_name',
    'precompute.py': 'precompute_outcomes_async(',
    'escalation.py': 'check_and_escalate(',
}

for fname, marker in unique_markers.items():
    positions = [m.start() for m in re.finditer(re.escape(marker), t)]
    print(f"\n{fname} ({marker}): {len(positions)} occurrences")
    for p in positions:
        ctx = t[max(0,p-200):p+500].replace('\n', '\\n')
        print(f"  pos={p}: ...{ctx}...")
