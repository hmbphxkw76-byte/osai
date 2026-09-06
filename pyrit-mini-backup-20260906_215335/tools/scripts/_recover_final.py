#!/usr/bin/env python3
import re

TRANSCRIPT = r'C:\Users\liude\.catpaw\projects\ided--文档-GitHub-osai-pyrit-mini\9791aca6-72e6-40bb-a2e2-ac799312f5fa\agent-transcripts\transcript.txt'

with open(TRANSCRIPT, encoding='utf-8') as f:
    t = f.read()

out = open(r'd:\文档\GitHub\osai\pyrit-mini/_recover_out.txt', 'w', encoding='utf-8')

file_markers = {
    'dual_judge.py': 'Prefers ConversationScorer wrapper',
    'precompute.py': 'precompute_outcomes_async(',
    'escalation.py': 'check_and_escalate(',
}

for fname, marker in file_markers.items():
    positions = [m.start() for m in re.finditer(re.escape(marker), t)]
    out.write(f"\n{fname}: found {len(positions)} times\n")
    for p in positions[:5]:
        out.write(f"  pos={p}:\n")
        ctx = t[max(0,p-200):p+400]
        out.write(f"  ...{ctx}...\n\n")

out.close()
print("Done")
