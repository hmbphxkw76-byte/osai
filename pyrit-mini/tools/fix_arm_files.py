"""Fix arm Python files - remove duplicates and repair indentation."""

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


def fix_indentation_after_control(content: str) -> str:
    """Fix indentation after control flow statements (if/elif/else/try/except/finally)."""
    lines = content.split('\n')
    fixed = []
    i = 0
    
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        
        # Check if this is a control flow statement ending with :
        # But not a function/class definition or comment
        if (stripped 
            and not stripped.startswith('#')
            and stripped.endswith(':')
            and not stripped.startswith('def ')
            and not stripped.startswith('class ')
            and not stripped.startswith('@')):
            
            # Get the next non-empty line
            next_idx = i + 1
            while next_idx < len(lines) and not lines[next_idx].strip():
                next_idx += 1
            
            if next_idx < len(lines):
                next_line = lines[next_idx]
                next_stripped = next_line.strip()
                next_indent = len(next_line) - len(next_line.lstrip())
                
                # If next line is not properly indented, fix it
                if (next_stripped 
                    and next_indent <= indent
                    and not next_stripped.startswith('#')
                    and not next_stripped.startswith('"""')
                    and not next_stripped.startswith("'''")):
                    
                    # Fix the indentation
                    fixed_line = ' ' * (indent + 4) + next_stripped
                    fixed.append(line)
                    fixed.append(fixed_line)
                    i = next_idx + 1
                    continue
        
        fixed.append(line)
        i += 1
    
    return '\n'.join(fixed)


def fix_empty_if_block(content: str) -> str:
    """Fix empty if blocks by adding pass statement."""
    lines = content.split('\n')
    fixed = []
    i = 0
    
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        
        # Check for empty if block
        if (stripped 
            and not stripped.startswith('#')
            and stripped.endswith(':')
            and not stripped.startswith('def ')
            and not stripped.startswith('class ')):
            
            # Check if next non-empty line is at same or lower indent
            next_idx = i + 1
            while next_idx < len(lines) and not lines[next_idx].strip():
                next_idx += 1
            
            if next_idx < len(lines):
                next_line = lines[next_idx]
                next_stripped = next_line.strip()
                next_indent = len(next_line) - len(next_line.lstrip())
                
                if (next_stripped 
                    and next_indent <= indent 
                    and not next_stripped.startswith('#')
                    and not next_stripped.startswith('def ')
                    and not next_stripped.startswith('@')):
                    # Empty block - add pass
                    fixed.append(line)
                    fixed.append(' ' * (indent + 4) + 'pass')
                    i += 1
                    continue
        
        fixed.append(line)
        i += 1
    
    return '\n'.join(fixed)


def process_file(filepath: str) -> bool:
    """Process a single Python file."""
    try:
        with open(filepath, encoding='utf-8') as f:
            content = f.read()
        
        original_len = len(content)
        
        # Step 1: Remove duplicates
        content = remove_duplicate_lines(content)
        
        # Step 2: Fix indentation (iterate until stable)
        prev_content = None
        iterations = 0
        while prev_content != content and iterations < 10:
            prev_content = content
            content = fix_indentation_after_control(content)
            content = fix_empty_if_block(content)
            iterations += 1
        
        # Write back
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"  {filepath}: {original_len} -> {len(content)} chars")
        return True
    except Exception as e:
        print(f"  ERROR {filepath}: {e}")
        return False


def main():
    """Fix all arm Python files."""
    project_root = Path(__file__).resolve().parent.parent
    arm_dir = project_root / 'arm'
    
    files_to_fix = []
    for filepath in arm_dir.rglob('*.py'):
        if '_fixed' not in filepath.name:
            files_to_fix.append(str(filepath))
    
    print(f"Processing {len(files_to_fix)} files...")
    for filepath in files_to_fix:
        process_file(filepath)
    
    print("Done.")


if __name__ == '__main__':
    main()
