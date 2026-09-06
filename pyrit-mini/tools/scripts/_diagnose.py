#!/usr/bin/env python3
"""Diagnose the exact encoding issue."""
import os

fp = r'd:\文档\GitHub\osai\pyrit-mini\assess\dual_judge.py'

# Read raw bytes
with open(fp, 'rb') as f:
    raw = f.read()

# Show first 500 bytes as hex
hex_dump = ' '.join(f'{b:02x}' for b in raw[:500])
with open(r'd:\文档\GitHub\osai\pyrit-mini/_hex500.txt', 'w') as f:
    f.write(hex_dump)

# Try to find where the corruption starts
# Pattern: valid UTF-8 char followed by invalid sequence
corruptions = []
i = 0
while i < min(len(raw), 1000):
    b = raw[i]
    if b < 0x80:
        i += 1
    elif 0xC0 <= b <= 0xDF:
        if i+1 < len(raw) and 0x80 <= raw[i+1] <= 0xBF:
            i += 2
        else:
            corruptions.append((i, b, '2-byte invalid'))
            i += 1
    elif 0xE0 <= b <= 0xEF:
        if i+2 < len(raw) and 0x80 <= raw[i+1] <= 0xBF and 0x80 <= raw[i+2] <= 0xBF:
            i += 3
        else:
            corruptions.append((i, b, f'3-byte invalid: {raw[i]:02x} {raw[i+1]:02x} {raw[i+2]:02x}' if i+2 < len(raw) else f'3-byte truncated'))
            i += 1
    else:
        i += 1

print(f"Corruptions in first 1000 bytes: {len(corruptions)}")
for pos, byte, desc in corruptions[:10]:
    print(f"  pos={pos}: byte={byte:02x} ({desc})")

# Try reading the file the same way the read_file tool might
# The read_file tool uses UTF-8 with surrogateescape or replace
text = raw.decode('utf-8', errors='replace')
print(f"\nFirst 200 chars (with replace): {text[:200]}")
