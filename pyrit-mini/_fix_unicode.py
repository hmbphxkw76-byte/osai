#!/usr/bin/env python3
"""Replace special Unicode characters with ASCII equivalents."""
import os
import glob

# Unicode to ASCII replacements
REPLACEMENTS = {
    '\u2014': '-',    # em dash
    '\u2013': '-',    # en dash
    '\u2192': '->',   # right arrow
    '\u2190': '<-',   # left arrow
    '\u2191': '^',    # up arrow
    '\u2193': 'v',    # down arrow
    '\u2460': '(1)',  # circled 1
    '\u2461': '(2)',  # circled 2
    '\u2462': '(3)',  # circled 3
    '\u2463': '(4)',  # circled 4
    '\u2464': '(5)',  # circled 5
    '\u2465': '(6)',  # circled 6
    '\u2466': '(7)',  # circled 7
    '\u2467': '(8)',  # circled 8
    '\u2468': '(9)',  # circled 9
    '\u2022': '*',    # bullet
    '\u2026': '...',  # ellipsis
    '\u00b0': 'deg',  # degree
    '\u2019': "'",    # right single quote
    '\u2018': "'",    # left single quote
    '\u201c': '"',    # left double quote
    '\u201d': '"',    # right double quote
    '\u00a7': 'Sec',  # section sign
    '\u00b4': "'",    # acute accent
    '\u0060': "'",    # grave accent
    '\u00b7': '*',    # middle dot
    '\u2023': '>',    # triangular bullet
    '\u25b6': '>',    # play button
    '\u25c0': '<',    # reverse button
    '\u203a': '>',    # single right-pointing angle quotation mark
    '\u2039': '<',    # single left-pointing angle quotation mark
    '\u00ab': '<<',   # left-pointing double angle quotation mark
    '\u00bb': '>>',   # right-pointing double angle quotation mark
    '\u2020': '+',    # dagger
    '\u2021': '++',   # double dagger
    '\u00a9': '(c)',  # copyright
    '\u00ae': '(r)',  # registered
    '\u2122': '(tm)', # trademark
}

def fix_file(filepath):
    """Fix Unicode characters in a file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original = content
        for char, replacement in REPLACEMENTS.items():
            content = content.replace(char, replacement)
        
        if content != original:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        return False
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False

def main():
    """Fix all Python files in the project."""
    fixed = []
    for root, dirs, files in os.walk('.'):
        # Skip hidden directories and __pycache__
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__']
        
        for filename in files:
            if filename.endswith('.py') and not filename.startswith('_'):
                filepath = os.path.join(root, filename)
                if fix_file(filepath):
                    fixed.append(filepath)
    
    print(f"Fixed {len(fixed)} files:")
    for f in fixed:
        print(f"  {f}")

if __name__ == '__main__':
    main()
