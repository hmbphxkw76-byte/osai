"""Remove unused template functions from generator.py (P1-4 cleanup)"""
import re

path = "report/generator.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Remove _html_template_cache global and _load_html_template function
content = re.sub(
    r'\n\n_html_template_cache: str \| None = None\n\n'
    r'def _load_html_template\(\) -> str:.*?'
    r'return _html_template_cache\n\n',
    '\n\n',
    content,
    flags=re.DOTALL
)

# Remove clear_template_cache function
content = re.sub(
    r'\ndef clear_template_cache\(\) -> None:.*?'
    r'logger\.debug\("HTML template cache cleared"\)',
    '',
    content,
    flags=re.DOTALL
)

# Update docstring
content = content.replace(
    "    - _load_html_template: imports report/templates/report.html Load HTML\n",
    ""
)
content = content.replace(
    "                              -> report_sections.py ()\n",
    ""
)
content = content.replace(
    "                              -> templates/report.html (HTML )\n",
    ""
)
content = content.replace(
    "    HTML imports,  _load_html_template() .\n",
    "    P1-4: Jinja2 removed - HTML uses pure Python string formatting.\n"
)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("Cleaned generator.py: removed Jinja2 template functions")
