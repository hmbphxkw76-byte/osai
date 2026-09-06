#!/usr/bin/env python3
"""Find actual file write operations with full content."""
import os
import re

TRANSCRIPT = r'C:\Users\liude\.catpaw\projects\ided--文档-GitHub-osai-pyrit-mini\9791aca6-72e6-40bb-a2e2-ac799312f5fa\agent-transcripts\transcript.txt'

with open(TRANSCRIPT, encoding='utf-8') as f:
    t = f.read()

print(f"Transcript length: {len(t)} chars")

# Look for string_replace tool calls that edited these files
# The tool call format seems to include the full old_string
# Let's search for tool calls targeting our files

target_files = [
    'assess/dual_judge.py',
    'assess/precompute.py',
    'strike/escalation.py',
]

# Also look for MultiEdit calls
for fname in target_files:
    # Find all tool calls for this file
    for match in re.finditer(re.escape(fname), t):
        pos = match.start()
        # Look backward for tool call context
        start = max(0, pos - 2000)
        chunk = t[start:pos]
        # Check if this is part of a write/edit operation
        if 'file_path' in chunk[-200:].replace(fname, ''):
            # Extract the tool name
            tool_ctx = t[max(0,pos-3000):pos]
            if 'string_replace' in tool_ctx or 'MultiEdit' in tool_ctx or 'write' in tool_ctx:
                print(f"\n--- {fname} at {pos} ---")
                # Print surrounding 500 chars
                print(t[pos:pos+500].replace('\n', '\\n')[:500])
                break
