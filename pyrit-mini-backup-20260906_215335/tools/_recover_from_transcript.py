#!/usr/bin/env python3
"""Recover original file content from transcript write tool calls."""
import os
import re
import json

TRANSCRIPT = r'C:\Users\liude\.catpaw\projects\ided--文档-GitHub-osai-pyrit-mini\9791aca6-72e6-40bb-a2e2-ac799312f5fa\agent-transcripts\transcript.txt'

def find_write_calls(transcript_path):
    """Find all write tool calls and extract file_path + contents."""
    with open(transcript_path, encoding='utf-8') as f:
        content = f.read()
    
    # The transcript has tool calls. write tool calls contain file_path and contents.
    # Pattern: the tool call contains "file_path" and "contents" JSON-like keys
    
    # Look for patterns like: {"file_path": "path", "contents": "...multi-line..."}
    # We need to find file_path occurrences and then extract the contents
    
    results = {}
    
    # Find all file_path occurrences
    for match in re.finditer(r'"file_path":\s*"([^"]+)"', content):
        path = match.group(1)
        pos = match.end()
        
        # Look for contents key after file_path
        contents_match = re.search(r'"contents":\s*"', content[pos:pos+10000])
        if contents_match:
            start = pos + contents_match.end()
            # Extract the content - it's a quoted string with escapes
            # We need to handle escape sequences
            i = start
            file_content = []
            while i < len(content):
                c = content[i]
                if c == '\\':
                    if i + 1 < len(content):
                        next_c = content[i+1]
                        if next_c == 'n':
                            file_content.append('\n')
                        elif next_c == 't':
                            file_content.append('\t')
                        elif next_c == '"':
                            file_content.append('"')
                        elif next_c == '\\':
                            file_content.append('\\')
                        else:
                            file_content.append(next_c)
                        i += 2
                        continue
                elif c == '"':
                    # End of string
                    break
                else:
                    file_content.append(c)
                i += 1
            
            results[path] = ''.join(file_content)
    
    return results

if __name__ == '__main__':
    results = find_write_calls(TRANSCRIPT)
    print(f"Found {len(results)} write calls")
    
    target_files = ['dual_judge.py', 'precompute.py', 'escalation.py']
    
    for path, content in results.items():
        basename = os.path.basename(path)
        if basename in target_files:
            print(f"\n=== {path} ({len(content)} chars) ===")
            print(content[:200])
            print("...")
