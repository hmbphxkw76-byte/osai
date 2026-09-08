#!/usr/bin/env python3
"""Remove corrupted Chinese regex patterns from judge_manager.py.
    
These patterns were damaged during the refactoring process and cause
re.PatternError: missing ), unterminated subpattern at position 0.
"""
import re

FILE_PATH = 'assess/judge_manager.py'

def main():
    with open(FILE_PATH, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # Find the start of corrupted Chinese patterns section
    # These are between "# == 涓枃鎷掔粷妯″紡" and the closing "]"
    start_marker = None
    end_marker = None
    
    for i, line in enumerate(lines):
        # Look for the comment line that starts the Chinese patterns section
        if '涓枃鎷掔粷妯″紡' in line or 'Chinese Refusal Patterns' in line:
            start_marker = i
        # Find the closing bracket after the start marker
        elif start_marker is not None and line.strip() == ']':
            end_marker = i
            break
    
    if start_marker is None:
        print("Could not find Chinese patterns section start marker")
        return
    
    if end_marker is None:
        print("Could not find Chinese patterns section end marker")
        return
    
    print(f"Found corrupted section: lines {start_marker + 1} to {end_marker + 1}")
    
    # Create new content: keep lines before start, add replacement, keep lines after end
    replacement = """    # == Chinese Refusal Patterns (Removed: encoding corrupted in refactor) ==
    # NOTE: Complex Chinese regex patterns were removed during Phase B refactoring.
    # Chinese refusal detection now relies on core English patterns + LLM judge.
"""
    
    new_lines = lines[:start_marker] + [replacement] + lines[end_marker + 1:]
    
    with open(FILE_PATH, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)
    
    print(f"Removed {end_marker - start_marker + 1} lines of corrupted patterns")
    print("File updated successfully")

if __name__ == '__main__':
    main()
