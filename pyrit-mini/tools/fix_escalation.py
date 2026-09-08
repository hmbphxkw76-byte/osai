"""Fix escalation.py - repair docstrings and indentation."""


def fix_escalation_file(input_path: str, output_path: str) -> None:
    """Fix the corrupted escalation.py file."""
    with open(input_path, encoding='utf-8') as f:
        content = f.read()

    # Pattern 1: Fix broken docstrings - lines like:
    # def foo():
    #
    #     Some text here.
    #     """
    # Should become:
    # def foo():
    #     """Some text here.
    #     """

    lines = content.split('\n')
    fixed_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Check if this is a function definition
        if stripped.startswith('def ') and stripped.endswith(':'):
            fixed_lines.append(line)
            i += 1

            # Skip if next line is empty
            if i < len(lines) and not lines[i].strip():
                fixed_lines.append(lines[i])  # keep the empty line
                i += 1

            # Check if next line has broken docstring (text without """)
            if i < len(lines):
                next_stripped = lines[i].strip()
                if (next_stripped
                    and not next_stripped.startswith('"""')
                    and not next_stripped.startswith("'''")
                    and not next_stripped.startswith('#')
                    and not next_stripped.startswith('def ')
                    and not next_stripped.startswith('@')
                    and not next_stripped.startswith('try:')
                    and not next_stripped.startswith('except')
                    and not next_stripped.startswith('return')
                    and not next_stripped.startswith('import')
                    and not next_stripped.startswith('from')):

                    # This is a broken docstring - wrap it in """
                    indent = len(lines[i]) - len(lines[i].lstrip())
                    indent_str = ' ' * indent

                    # Collect all broken docstring lines until we find """
                    docstring_content = []
                    while i < len(lines) and lines[i].strip() != '"""':
                        docstring_content.append(lines[i].strip())
                        i += 1

                    # Skip the closing """
                    if i < len(lines) and lines[i].strip() == '"""':
                        i += 1

                    # Emit proper docstring
                    if docstring_content:
                        fixed_lines.append(f'{indent_str}"""{" ".join(docstring_content)}')
                        fixed_lines.append(f'{indent_str}"""')
                    continue

            continue

        fixed_lines.append(line)
        i += 1

    # Write fixed content
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(fixed_lines))

    print(f"Fixed {len(lines)} -> {len(fixed_lines)} lines")


if __name__ == '__main__':
    fix_escalation_file(
        'strike/escalation_dedup.py',
        'strike/escalation_fixed.py'
    )
