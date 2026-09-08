"""Fix strike Python files - remove duplicates and repair indentation."""

import os
from pathlib import Path


def remove_duplicate_lines(content: str) -> str:
    """Remove consecutive duplicate lines."""
    lines = content.split('\n')
    if not lines:
        return content
    
    result = [lines[0]]
    for line in lines[1:]:
        if line != result[-1]:
            result.append(line)
    return '\n'.join(result)


def fix_missing_docstrings(content: str) -> str:
    """Fix function definitions where docstring body is missing."""
    lines = content.split('\n')
    fixed = []
    i = 0
    
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        
        # Check if this is a function definition
        if stripped.startswith('def ') and stripped.endswith(':'):
            fixed.append(line)
            i += 1
            
            # Skip empty lines after def
            while i < len(lines) and not lines[i].strip():
                i += 1
            
            # Check if next line is indented (function body)
            if i < len(lines):
                next_line = lines[i]
                next_stripped = next_line.strip()
                indent = len(next_line) - len(next_line.lstrip())
                
                # If next line has proper indentation (>= 4 spaces), it's the body
                if next_stripped and indent >= 4:
                    # Check if it starts with docstring or code
                    if next_stripped.startswith('"""') or next_stripped.startswith("'''"):
                        # Has docstring - keep it
                        pass
                    elif next_stripped.startswith('#'):
                        # Has comment - keep it
                        pass
                    elif next_stripped.startswith(('return ', 'pass', 'try:', 'if ', 'for ', 'while ', 'import ', 'from ')):
                        # Has code - keep it
                        pass
                    else:
                        # Missing docstring - add a pass
                        func_indent = len(line) - len(line.lstrip())
                        fixed.append(' ' * (func_indent + 4) + '"""TODO: Add docstring."""')
            
            continue
        
        fixed.append(line)
        i += 1
    
    return '\n'.join(fixed)


def process_file(filepath: str) -> bool:
    """Process a single Python file."""
    try:
        with open(filepath, encoding='utf-8') as f:
            content = f.read()
        
        original_lines = len(content.split('\n'))
        
        # Step 1: Remove duplicates
        content = remove_duplicate_lines(content)
        
        # Step 2: Fix missing docstrings
        content = fix_missing_docstrings(content)
        
        # Write back
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        new_lines = len(content.split('\n'))
        print(f"  {filepath}: {original_lines} -> {new_lines} lines")
        return True
    except Exception as e:
        print(f"  ERROR {filepath}: {e}")
        return False


def main():
    """Fix all strike Python files."""
    project_root = Path(__file__).resolve().parent.parent
    strike_dir = project_root / 'strike'
    
    files_to_fix = []
    for filepath in strike_dir.rglob('*.py'):
        if '_fixed' not in filepath.name and '_dedup' not in filepath.name and filepath.name != '__init__.py':
            files_to_fix.append(str(filepath))
    
    print(f"Processing {len(files_to_fix)} files...")
    for filepath in files_to_fix:
        process_file(filepath)
    
    print("Done.")


if __name__ == '__main__':
    main()
