#!/usr/bin/env python3
"""Fix encoding corruption from PowerShell Get-Content | Set-Content round-trip.

The corruption pattern:
- Original file was UTF-8
- PowerShell Get-Content (default ANSI/ASCII) read it and replaced non-decodable bytes with '?'
- Set-Content wrote back as UTF-8 (or system default)

Strategy:
1. Find the original content from git or transcript
2. Re-write the file as proper UTF-8

Since git is unavailable, we try to reconstruct from the transcript.
"""
import os
import re
import sys

def find_file_content_in_transcript(transcript_path, filepath, marker=None):
    """Search transcript for the file's original content (from write tool call)."""
    with open(transcript_path, encoding='utf-8') as f:
        content = f.read()
    
    # Look for write tool calls that contain this filepath
    # Pattern: write followed by the path
    escaped_path = re.escape(filepath)
    # Find all occurrences of the path in transcript
    positions = []
    start = 0
    while True:
        idx = content.find(filepath, start)
        if idx == -1:
            break
        positions.append(idx)
        start = idx + 1
    
    return positions

def try_recover_by_reconstruction(filepath):
    """Try to reconstruct by reading as bytes and fixing common corruption patterns."""
    with open(filepath, 'rb') as f:
        raw = f.read()
    
    # The corruption pattern we see: bytes like e2 80 3f indicate
    # the original UTF-8 byte (3rd byte of a 3-byte sequence) was replaced with 0x3f ('?')
    # This happens when Get-Content reads in ASCII/ANSI mode and replaces undecodable bytes with '?'
    
    # Strategy: for each invalid UTF-8 byte sequence, try to figure out what the original byte was
    # This is heuristic and may not be perfect
    
    result = bytearray()
    i = 0
    fixes = 0
    
    while i < len(raw):
        b = raw[i]
        
        # ASCII - pass through
        if b < 0x80:
            result.append(b)
            i += 1
            continue
        
        # 2-byte sequence (110xxxxx 10xxxxxx)
        if 0xC0 <= b <= 0xDF:
            if i + 1 < len(raw) and 0x80 <= raw[i+1] <= 0xBF:
                result.append(b)
                result.append(raw[i+1])
                i += 2
            else:
                # Invalid continuation, skip
                result.append(b)
                i += 1
            continue
        
        # 3-byte sequence (1110xxxx 10xxxxxx 10xxxxxx)
        if 0xE0 <= b <= 0xEF:
            if i + 2 < len(raw):
                b2 = raw[i+1]
                b3 = raw[i+2]
                
                if 0x80 <= b2 <= 0xBF:
                    if 0x80 <= b3 <= 0xBF:
                        # Valid 3-byte
                        result.append(b)
                        result.append(b2)
                        result.append(b3)
                        i += 3
                    elif b3 == 0x3F:  # '?' - likely corruption
                        # The original byte was replaced with '?'
                        # We can't know what it was without the original text
                        # Mark for now
                        result.append(b)
                        result.append(b2)
                        result.append(b3)  # keep as-is, will need human fix
                        i += 3
                    else:
                        result.append(b)
                        i += 1
                else:
                    result.append(b)
                    i += 1
            else:
                result.append(b)
                i += 1
            continue
        
        # 4-byte sequence
        if 0xF0 <= b <= 0xF7:
            if i + 3 < len(raw):
                b2 = raw[i+1]
                b3 = raw[i+2]
                b4 = raw[i+3]
                if (0x80 <= b2 <= 0xBF and 
                    0x80 <= b3 <= 0xBF and 
                    0x80 <= b4 <= 0xBF):
                    result.extend([b, b2, b3, b4])
                    i += 4
                    continue
            result.append(b)
            i += 1
            continue
        
        result.append(b)
        i += 1
    
    return bytes(result)

def recover_from_transcript(filepath, transcript_path):
    """Try to find the original file content from transcript write calls."""
    filename = os.path.basename(filepath)
    
    with open(transcript_path, encoding='utf-8') as f:
        transcript = f.read()
    
    # The transcript contains write tool calls with file_path and contents
    # Pattern: {"file_path": "...", "contents": "...{actual content}..."}
    
    # Search for write calls mentioning this file
    # Look for the filepath in a write tool call context
    escaped = re.escape(filename)
    
    # Find all positions where filename appears
    for match in re.finditer(escaped, transcript):
        pos = match.start()
        # Look backwards for file_path marker
        context_start = max(0, pos - 500)
        context = transcript[context_start:pos]
        
        if 'file_path' in context:
            # Look forward for contents
            forward_end = min(len(transcript), pos + 50)
            forward = transcript[pos:forward_end]
            print(f"Found reference at pos {pos}: ...{forward[:60]}...")
    
    return None

def brute_force_fix(filepath):
    """Brute force: replace every '?' (0x3F) that appears as 3rd byte of 
    a 3-byte UTF-8 sequence with the most likely original byte.
    
    Common Chinese punctuation in UTF-8 3-byte sequences:
    - EOF/period: E3 80 82 (。)
    - Comma: E3 80 8C, E3 80 8D
    - Colon: E3 80 81 (、)
    - Brackets: E3 80 90, E3 80 91, E3 80 94, E3 80 95
    - CJK chars mostly have 3rd byte >= 0x80
    
    But the corruption pattern shows: e2 80 3f, e4 bb 3f, e5 8f 3f, etc.
    The 3rd byte 0x3F is clearly ASCII '?' which is the replacement character.
    """
    with open(filepath, 'rb') as f:
        raw = f.read()
    
    # Just try to decode with error handling to see what we have
    text = raw.decode('utf-8', errors='replace')
    
    # Count replacement characters
    replacement_count = text.count('\ufffd')
    
    return replacement_count, text

if __name__ == '__main__':
    files = [
        r'd:\文档\GitHub\osai\pyrit-mini\assess\dual_judge.py',
        r'd:\文档\GitHub\osai\pyrit-mini\assess\precompute.py',
        r'd:\文档\GitHub\osai\pyrit-mini\strike\escalation.py',
    ]
    
    for fp in files:
        count, text = brute_force_fix(fp)
        print(f"{os.path.basename(fp)}: {count} replacement chars, {len(text)} total chars")
