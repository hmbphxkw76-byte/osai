#!/usr/bin/env python3
"""Search transcript for T0-10 definition."""
import re

TRANSCRIPT = r'C:\Users\liude\.catpaw\projects\ided--文档-GitHub-osai-pyrit-mini\9791aca6-72e6-40bb-a2e2-ac799312f5fa\agent-transcripts\transcript.txt'

with open(TRANSCRIPT, encoding='utf-8') as f:
    t = f.read()

out = open(r'd:\文档\GitHub\osai\pyrit-mini/_t0_10_context.txt', 'w', encoding='utf-8')

markers = [
    'T0-10',
    'display.py',
    '硬编码',
]

for marker in markers:
    positions = [m.start() for m in re.finditer(re.escape(marker), t)]
    out.write(f"\n'{marker}': {len(positions)} occurrences\n")
    for p in positions[:10]:
        ctx = t[max(0,p-100):p+300].replace('\n', '\\n')
        out.write(f"  pos={p}: ...{ctx}...\n")

out.close()
print("Done")
