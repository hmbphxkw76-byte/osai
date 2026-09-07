#!/usr/bin/env python3
"""Verify no Chinese characters remain in Python files."""
import os
import re

files = []
for r, d, fs in os.walk('.'):
    for f in fs:
        if f.endswith('.py') and '_remove_chinese' not in f and '_verify_clean' not in f:
            files.append(os.path.join(r, f))

bad = []
for f in files:
    try:
        content = open(f, encoding='utf-8').read()
        if re.search(r'[\u4e00-\u9fff]', content):
            bad.append(f)
    except Exception as e:
        print(f"ERROR reading {f}: {e}")

print(f"Checked {len(files)} files")
print(f"Files with Chinese: {len(bad)}")
for f in bad:
    print(f"  - {f}")
