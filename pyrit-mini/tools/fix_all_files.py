"""Fix all Python files - remove duplicates and fix basic indentation."""

import os
import re
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


def fix_basic_indentation(content: str) -> str:
    """Fix basic indentation issues after if/elif/else/try/except/finally."""
    lines = content.split('\n')
    fixed = []
    i = 0
    
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        
        # Check if this is a control flow statement
        if stripped and not stripped.startswith('#') and stripped.endswith(':'):
            # Check if next line has proper indentation
            if i + 1 < len(lines):
                next_line = lines[i + 1]
                next_stripped = next_line.strip()
                next_indent = len(next_line) - len(next_line.lstrip()) if next_stripped else 0
                
                if (next_stripped 
                    and next_indent <= indent 
                    and not next_stripped.startswith('#')
                    and not next_stripped.startswith('"""')
                    and not next_stripped.startswith("'''")
                    and not next_stripped.startswith('def ')
                    and not next_stripped.startswith('@')):
                    # Fix indentation of next line
                    fixed_line = ' ' * (indent + 4) + next_stripped
                    fixed.append(line)
                    fixed.append(fixed_line)
                    i += 2
                    continue
        
        fixed.append(line)
        i += 1
    
    return '\n'.join(fixed)


def fix_python_keywords_spacing(content: str) -> str:
    """Fix spacing around Python keywords like if/elif/else/try/except."""
    # Fix patterns like "if cap_str:" followed by correct indentation
    return content


def process_file(filepath: str, output_suffix: str = '_fixed') -> bool:
    """Process a single Python file."""
    try:
        with open(filepath, encoding='utf-8') as f:
            content = f.read()
        
        # Step 1: Remove duplicates
        content = remove_duplicate_lines(content)
        
        # Step 2: Fix indentation (iterate until stable)
        prev_content = None
        iterations = 0
        while prev_content != content and iterations < 5:
            prev_content = content
            content = fix_basic_indentation(content)
            iterations += 1
        
        # Write output
        path = Path(filepath)
        output_path = path.parent / f"{path.stem}{output_suffix}.py"
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"  {filepath} -> {output_path.name}")
        return True
    except Exception as e:
        print(f"  ERROR {filepath}: {e}")
        return False


def main():
    """Fix all Python files in the project."""
    project_root = Path(__file__).resolve().parent.parent
    
    # List of files to fix (known to be corrupted)
    corrupted_files = [
        'arm/converter_presets.py',
    ]
    
    files_to_fix = []
    for rel_path in corrupted_files:
        full_path = project_root / rel_path
        if full_path.exists():
            files_to_fix.append(str(full_path))
    
    print(f"Processing {len(files_to_fix)} files...")
    for filepath in files_to_fix:
        process_file(filepath)
    
    print("Done.")


if __name__ == '__main__':
    main()
