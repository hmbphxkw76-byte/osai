"""Fix missing docstring opening triple-quotes in report_markdown.py and _report_markdown_sections.py."""
import pathlib
import re

for fname in ["report/report_markdown.py", "report/_report_markdown_sections.py"]:
    path = pathlib.Path(__file__).parent / fname
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)

    # Find function defs followed by a line that starts with "    :" or "    -"
    # but not by a proper docstring
    fixed = []
    i = 0
    while i < len(lines):
        fixed.append(lines[i])
        # Check if this line is a function def
        if re.match(r"^def \w+\(", lines[i]):
            # Look ahead: next non-empty line
            if i + 1 < len(lines):
                next_line = lines[i + 1]
                stripped = next_line.strip()
                # If next line starts with ":" or "-" and is not a docstring
                if (stripped.startswith(":") or stripped.startswith("-")) and '"""' not in next_line:
                    # Insert opening """
                    indent = next_line[:len(next_line) - len(next_line.lstrip())]
                    fixed.append(indent + '"""Docstring.\n')
                    print(f"  Fixed docstring at line {i + 2} in {fname}")
        i += 1

    path.write_text("".join(fixed), encoding="utf-8")
    print(f"Processed {fname}")
