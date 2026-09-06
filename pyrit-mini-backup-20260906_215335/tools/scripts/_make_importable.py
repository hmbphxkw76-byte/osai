#!/usr/bin/env python3
"""Make the corrupted files importable Python by fixing invalid UTF-8 sequences.
The corruption pattern: 3rd byte of 3-byte UTF-8 sequences was replaced with 0x3f.
Strategy: for each invalid sequence eX YY 3f, replace with eX YY 80 (lowest valid continuation).
Then the file becomes valid UTF-8 with some wrong Chinese characters.
A second pass uses read_file output (with replacement chars) to infer correct Chinese.
"""
import re

def fix_file(filepath):
    with open(filepath, 'rb') as f:
        raw = f.read()
    
    # Count corruption before fix
    fixed = bytearray()
    i = 0
    fixes = 0
    while i < len(raw):
        b = raw[i]
        # Check for 3-byte UTF-8 start: 1110xxxx
        if 0xE0 <= b <= 0xEF and i + 2 < len(raw):
            b2 = raw[i+1]
            b3 = raw[i+2]
            # Check if b2 is a valid continuation byte
            if 0x80 <= b2 <= 0xBF:
                # Check if b3 is invalid (not a continuation byte)
                if not (0x80 <= b3 <= 0xBF):
                    # Try to fix: replace b3 with a valid continuation byte
                    # The most common 3rd bytes for Chinese: 0x80, 0x81, 0x82, 0x8e, 0x8b, 0x9c, 0x9d, etc.
                    # Default: replace with 0x80 and handle error later
                    fixed.append(b)
                    fixed.append(b2)
                    fixed.append(0x80)  # Will decode to wrong char, but valid UTF-8
                    fixes += 1
                    i += 3
                    continue
            else:
                # b2 is not a continuation byte, so b is just a lone start byte
                pass
        fixed.append(b)
        i += 1
    
    # Make sure it decodes
    try:
        text = bytes(fixed).decode('utf-8')
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(text)
        print(f"Fixed {filepath}: {fixes} sequences repaired, file is valid UTF-8")
        return text
    except Exception as e:
        print(f"Failed {filepath}: {e}")
        # Fallback: decode with replace
        text = bytes(fixed).decode('utf-8', errors='replace')
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(text)
        print(f"  Fallback: replaced remaining invalid bytes")

files = [
    r'd:\文档\GitHub\osai\pyrit-mini\assess\dual_judge.py',
    r'd:\文档\GitHub\osai\pyrit-mini\assess\precompute.py',
    r'd:\文档\GitHub\osai\pyrit-mini\strike\escalation.py',
]

for fp in files:
    fix_file(fp)

# Verify each file can be parsed
for fp in files:
    import ast
    try:
        with open(fp, encoding='utf-8') as f:
            ast.parse(f.read())
        print(f"  {fp}: PARSE OK")
    except SyntaxError as e:
        print(f"  {fp}: PARSE ERROR - {e}")
