#!/usr/bin/env python3
"""Remove all Chinese characters from Python files - aggressive v3."""
import re
from pathlib import Path


def remove_chinese_aggressive(filepath: Path) -> bool:
    """Remove all Chinese/CJK characters from a file."""
    # Read with explicit UTF-8 encoding
    with open(filepath, 'r', encoding='utf-8') as f:
        original = f.read()
    
    # Pattern to match CJK characters:
    # \u4e00-\u9fff: CJK Unified Ideographs (most common Chinese chars)
    # \u3400-\u4dbf: CJK Unified Ideographs Extension A
    # \uf900-\ufaff: CJK Compatibility Ideographs
    # \u3000-\u303f: CJK Symbols and Punctuation
    # \uff00-\uffef: Fullwidth Forms
    # \u2e80-\u2eff: CJK Radicals Supplement
    # \u31c0-\u31ef: CJK Strokes
    # \u3200-\u32ff: Enclosed CJK Letters and Months
    # \u3300-\u33ff: CJK Compatibility
    # \u2f00-\u2fdf: Kangxi Radicals
    
    cjk_pattern = re.compile(
        r'[\u4e00-\u9fff\u3400-\u4dbf\uf900-\ufaff\u3000-\u303f\uff00-\uffef'
        r'\u2e80-\u2eff\u31c0-\u31ef\u3200-\u32ff\u3300-\u33ff\u2f00-\u2fdf]+'
    )
    
    # Replace all CJK characters with empty string
    cleaned = cjk_pattern.sub('', original)
    
    if cleaned != original:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(cleaned)
        return True
    return False


def main():
    project_root = Path(__file__).parent
    py_files = list(project_root.rglob("*.py"))
    
    # Exclude utility scripts
    exclude = {'_remove_chinese.py', '_remove_chinese_v2.py', '_remove_chinese_v3.py'}
    py_files = [f for f in py_files if f.name not in exclude]
    
    modified = 0
    for f in py_files:
        try:
            if remove_chinese_aggressive(f):
                modified += 1
                print(f"Cleaned: {f.relative_to(project_root)}")
        except Exception as e:
            print(f"ERROR: {f.relative_to(project_root)} - {e}")
    
    print(f"\nTotal: {modified}/{len(py_files)} files cleaned")


if __name__ == "__main__":
    main()
