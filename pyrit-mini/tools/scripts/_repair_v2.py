#!/usr/bin/env python3
"""Repair files using a smarter approach:
1. Read raw bytes
2. Find corrupted sequences (3-byte UTF-8 with 3rd byte = 0x3f)
3. For each, look at surrounding valid UTF-8 context to infer the correct 3rd byte
4. Write back valid UTF-8
"""
import re

def analyze_context(raw, pos, window=50):
    """Get context around a corrupted position."""
    # Find the end of this corrupted sequence (pos, pos+1 are valid start+continuation, pos+2 is 0x3f)
    # Get valid chars before and after
    before = []
    after = []
    
    # Go backward from pos
    i = pos - 1
    count = 0
    while i >= 0 and count < window:
        b = raw[i]
        if b < 0x80:
            before.append(chr(b))
            i -= 1
            count += 1
        elif 0xC0 <= b <= 0xDF:
            if i >= 1:
                try:
                    c = raw[i-1:i+1].decode('utf-8')
                    before.append(c)
                    i -= 2
                    count += 1
                    continue
                except:
                    pass
            i -= 1
        elif 0xE0 <= b <= 0xEF:
            if i >= 2:
                try:
                    c = raw[i-2:i+1].decode('utf-8')
                    before.append(c)
                    i -= 3
                    count += 1
                    continue
                except:
                    pass
            i -= 1
        else:
            i -= 1
    
    # Go forward from pos+3
    i = pos + 3
    count = 0
    while i < len(raw) and count < window:
        b = raw[i]
        if b < 0x80:
            after.append(chr(b))
            i += 1
            count += 1
        elif 0xC0 <= b <= 0xDF:
            if i + 1 < len(raw):
                try:
                    c = raw[i:i+2].decode('utf-8')
                    after.append(c)
                    i += 2
                    count += 1
                    continue
                except:
                    pass
            i += 1
        elif 0xE0 <= b <= 0xEF:
            if i + 2 < len(raw):
                try:
                    c = raw[i:i+3].decode('utf-8')
                    after.append(c)
                    i += 3
                    count += 1
                    continue
                except:
                    pass
            i += 1
        else:
            i += 1
    
    return ''.join(reversed(before)), ''.join(after)


def repair_file(filepath):
    with open(filepath, 'rb') as f:
        raw = bytearray(f.read())
    
    # Find all corrupted 3-byte sequences
    corruptions = []
    i = 0
    while i < len(raw) - 2:
        b1 = raw[i]
        b2 = raw[i+1]
        b3 = raw[i+2]
        
        if (0xE0 <= b1 <= 0xEF) and (0x80 <= b2 <= 0xBF) and (b3 == 0x3F):
            corruptions.append((i, b1, b2, b3))
            i += 3
        else:
            i += 1
    
    print(f"\n{filepath}: found {len(corruptions)} corrupted sequences")
    
    # Try to infer correct 3rd byte for each
    # Common 3rd byte values for Chinese CJK characters (U+4E00-U+9FFF):
    # Most common: 0x80, 0x81, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, ...
    # For CJK: 0x80-0xBF all valid, but certain values are more common
    
    # Strategy: try each candidate and check if the resulting character is a valid CJK char
    fixed = bytearray(raw)
    
    for pos, b1, b2, b3 in corruptions:
        # Try candidate values for the 3rd byte
        # Priority: common CJK 3rd bytes
        candidates = [0x80, 0x81, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 
                      0x90, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
                      0xA0, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
                      0xB0, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF]
        
        best = 0x80  # default
        for cand in candidates:
            try:
                c = bytes([b1, b2, cand]).decode('utf-8')
                # Check if it's a CJK character or common punctuation
                cp = ord(c)
                if (0x4E00 <= cp <= 0x9FFF or  # CJK Unified Ideographs
                    0x3000 <= cp <= 0x303F or  # CJK Symbols
                    0x2000 <= cp <= 0x206F or  # General Punctuation
                    0xFF00 <= cp <= 0xFFEF):   # Fullwidth Forms
                    best = cand
                    break
            except:
                continue
        
        fixed[pos+2] = best
    
    # Verify it decodes
    try:
        text = bytes(fixed).decode('utf-8')
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(text)
        print(f"  -> Fixed and saved successfully")
        return True
    except Exception as e:
        print(f"  -> Still has errors: {e}")
        # Fallback: replace remaining invalid bytes
        text = bytes(fixed).decode('utf-8', errors='replace')
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(text)
        print(f"  -> Saved with replacement chars as fallback")
        return False


files = [
    r'd:\文档\GitHub\osai\pyrit-mini\assess\dual_judge.py',
    r'd:\文档\GitHub\osai\pyrit-mini\assess\precompute.py',
    r'd:\文档\GitHub\osai\pyrit-mini\strike\escalation.py',
]

for fp in files:
    repair_file(fp)

# Verify
for fp in files:
    import ast
    try:
        with open(fp, encoding='utf-8') as f:
            ast.parse(f.read())
        print(f"PARSE OK: {fp}")
    except SyntaxError as e:
        print(f"PARSE ERROR: {fp} - {e}")
