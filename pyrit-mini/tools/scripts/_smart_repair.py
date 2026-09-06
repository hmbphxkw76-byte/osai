#!/usr/bin/env python3
"""Smart repair: Use read_file output (which has replacement chars) + context to fix."""
import re

# The file with corruption marker
fp = r'd:\文档\GitHub\osai\pyrit-mini\assess\dual_judge.py'

with open(fp, 'rb') as f:
    raw = f.read()

# Decode with replacement to see what read_file shows
text_replace = raw.decode('utf-8', errors='replace')

# Count replacement chars
replacement_count = text_replace.count('\ufffd')
print(f"Total replacement chars: {replacement_count}")

# Find all positions of replacement chars
positions = [i for i, c in enumerate(text_replace) if c == '\ufffd']
print(f"First 20 positions: {positions[:20]}")

# For each replacement char, show surrounding context
for pos in positions[:30]:
    start = max(0, pos - 10)
    end = min(len(text_replace), pos + 10)
    ctx = text_replace[start:end]
    # Show the raw bytes at this position
    raw_pos = text_replace[:pos].encode('utf-8').index(b'\xef\xbf\xbd') if pos > 0 else 0
    print(f"  pos={pos}: context='{ctx}'")

# Now let's understand the corruption pattern
# The pattern is: original 3-byte UTF-8 has 3rd byte = 0x3f
# So e2 80 3f should be e2 80 xx (where xx is the proper continuation byte)
# Most likely xx values for common Chinese:
# e2 80 9c = " (U+201C LEFT DOUBLE QUOTATION MARK)
# e2 80 9d = " (U+201D RIGHT DOUBLE QUOTATION MARK)
# e2 80 98 = ' (U+2018 LEFT SINGLE QUOTATION MARK)
# e2 80 99 = ' (U+2019 RIGHT SINGLE QUOTATION MARK)
# e2 80 93 = – (U+2013 EN DASH)
# e2 80 94 = — (U+2014 EM DASH)
# e2 80 8b = zero-width space

# For e4 bb xx (CJK range U+4E80-U+4EBF):
# e4 bb 8e = 从 (U+4ECE) - very common
# e4 bb a3 = 令 (U+4EE3) etc.

# Strategy: for each corrupted 3-byte sequence, try common replacements
print("\n\n=== Repair Attempt ===")

# Read raw bytes
repaired = bytearray(raw)

# Find all positions where we have pattern: valid_utf8_startXX 3f (where XX is continuation byte 80-BF)
# This means a 3-byte sequence was truncated to lead byte + continuation + 0x3f
i = 0
fixes = 0
while i < len(repaired) - 2:
    b1 = repaired[i]
    b2 = repaired[i+1]
    b3 = repaired[i+2]
    
    # Pattern: 3-byte UTF-8 start (1110xxxx) + continuation (10xxxxxx) + 0x3f
    if (0xE0 <= b1 <= 0xEF) and (0x80 <= b2 <= 0xBF) and (b3 == 0x3F):
        # This is a corrupted 3-byte sequence
        # Check if what follows makes sense
        # For e2 80 3f: most likely e2 80 9c, 9d, 98, 99, 93, 94
        # For e4 bb 3f: most likely e4 bb 8e (从)
        
        # Determine most likely original byte
        replacement = None
        
        if b1 == 0xE2 and b2 == 0x80:
            # General Punctuation block
            # Context-dependent; most common:  " " ' ' – —
            replacement = 0x9C  # Default to left double quote
        elif b1 == 0xE4 and b2 == 0xBB:
            replacement = 0x8E  # 从
        elif b1 == 0xE5 and b2 == 0x8F:
            replacement = 0x91  # 发/类/equivalent in CJK
        elif b1 == 0xE5 and b2 == 0x8C:
            replacement = 0x85  # 包 etc
        elif b1 == 0xE7 and b2 == 0x94:
            replacement = 0xA8  # 用 etc
        elif b1 == 0xE4 and b2 == 0xB8:
            replacement = 0x8A  # 下/equivalent
        
        if replacement:
            repaired[i+2] = replacement
            fixes += 1
            i += 3
            continue
    
    i += 1

print(f"Applied {fixes} fixes")

# Try to decode repaired bytes
try:
    result = repaired.decode('utf-8')
    print("SUCCESS: Decoded as UTF-8!")
    with open(r'd:\文档\GitHub\osai\pyrit-mini/_repaired_dual_judge.py', 'w', encoding='utf-8') as f:
        f.write(result)
    print("Saved to _repaired_dual_judge.py")
except Exception as e:
    print(f"FAILED: {e}")
    # Show first error position
    try:
        repaired.decode('utf-8')
    except UnicodeDecodeError as e2:
        print(f"Error at position {e2.start}: {e2.reason}")
