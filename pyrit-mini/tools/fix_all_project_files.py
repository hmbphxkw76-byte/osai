"""Fix all project Python files - remove duplicates and repair indentation."""

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
    """Fix function definitions where function body is completely missing."""
    lines = content.split('\n')
    fixed = []
    i = 0
    
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        
        # Check if this is a function definition with nothing after it
        if stripped.startswith('def ') and stripped.endswith(':'):
            fixed.append(line)
            i += 1
            
            # Skip empty lines
            while i < len(lines) and not lines[i].strip():
                i += 1
            
            # Check if next non-empty line is at same or lower indentation
            # (meaning function body is missing)
            if i < len(lines):
                next_line = lines[i]
                next_stripped = next_line.strip()
                current_indent = len(line) - len(line.lstrip())
                next_indent = len(next_line) - len(next_line.lstrip()) if next_stripped else 0
                
                if (next_stripped 
                    and next_indent <= current_indent 
                    and not next_stripped.startswith('def ')
                    and not next_stripped.startswith('@')):
                    # Function body is missing - add pass
                    fixed.append(' ' * (current_indent + 4) + '"""TODO: Reconstruct function."""')
                    fixed.append(' ' * (current_indent + 4) + 'pass')
            
            continue
        
        fixed.append(line)
        i += 1
    
    return '\n'.join(fixed)


def fix_broken_if_blocks(content: str) -> str:
    """Fix if blocks where indentation is wrong."""
    lines = content.split('\n')
    fixed = []
    i = 0
    
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        
        # Check for if/elif/else/try/except/finally with bad indentation
        if (stripped 
            and not stripped.startswith('#')
            and stripped.endswith(':')
            and not stripped.startswith('def ')
            and not stripped.startswith('class ')
            and not stripped.startswith('@')
            and stripped.split()[0] in ('if', 'elif', 'else', 'try', 'except', 'finally', 'for', 'while', 'with')
        ):
            fixed.append(line)
            i += 1
            
            # Skip empty lines
            while i < len(lines) and not lines[i].strip():
                fixed.append(lines[i])
                i += 1
            
            if i < len(lines):
                next_line = lines[i]
                next_stripped = next_line.strip()
                next_indent = len(next_line) - len(next_line.lstrip()) if next_stripped else 0
                
                # If next line is not properly indented, fix it
                if (next_stripped 
                    and next_indent <= indent
                    and not next_stripped.startswith('#')
                    and not next_stripped.startswith('def ')
                    and not next_stripped.startswith('@')):
                    # Fix indentation
                    fixed_line = ' ' * (indent + 4) + next_stripped
                    fixed.append(fixed_line)
                    i += 1
                    continue
            
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
        
        # Step 2: Fix issues (iterate until stable)
        prev_content = None
        iterations = 0
        while prev_content != content and iterations < 10:
            prev_content = content
            content = fix_missing_docstrings(content)
            content = fix_broken_if_blocks(content)
            iterations += 1
        
        # Write back
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        new_lines = len(content.split('\n'))
        if original_lines != new_lines:
            print(f"  {filepath}: {original_lines} -> {new_lines} lines")
        return True
    except Exception as e:
        print(f"  ERROR {filepath}: {e}")
        return False


def main():
    """Fix all project Python files (excluding tests and tools)."""
    project_root = Path(__file__).resolve().parent.parent
    
    # Directories to fix
    dirs_to_fix = ['assess', 'core', 'recon', 'report', 'utils', 'glue']
    
    files_to_fix = []
    for dir_name in dirs_to_fix:
        dir_path = project_root / dir_name
        if dir_path.exists():
            for filepath in dir_path.rglob('*.py'):
                if '_fixed' not in filepath.name and '_dedup' not in filepath.name:
                    files_to_fix.append(str(filepath))
    
    print(f"Processing {len(files_to_fix)} files...")
    for filepath in files_to_fix:
        process_file(filepath)
    
    print("Done.")


if __name__ == '__main__':
    main()
