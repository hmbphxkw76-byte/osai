"""Merge _poc_generator_helpers.py back into poc_generator.py (P1-1)"""
import os

helpers_path = "report/_poc_generator_helpers.py"
main_path = "report/poc_generator.py"

# Read helpers file
with open(helpers_path, "r", encoding="utf-8") as f:
    helpers_content = f.read()

# Read main file
with open(main_path, "r", encoding="utf-8") as f:
    main_content = f.read()

# Remove the import line from main
import_line = "from report._poc_generator_helpers import (\n    _generate_multi_turn_poc,\n    _generate_single_turn_poc,\n)\n"
main_content = main_content.replace(import_line, "")

# Extract function definitions from helpers (skip the docstring and TYPE_CHECKING)
# Find where the actual code starts
helpers_lines = helpers_content.split("\n")
code_start = 0
for i, line in enumerate(helpers_lines):
    if line.startswith("def ") or line.startswith("class "):
        code_start = i
        break

# Get the code portion (functions only)
helpers_code = "\n".join(helpers_lines[code_start:])

# Append to main file (before the final newline)
merged_content = main_content.rstrip() + "\n\n\n" + helpers_code + "\n"

# Write merged file
with open(main_path, "w", encoding="utf-8") as f:
    f.write(merged_content)

# Delete helpers file
os.remove(helpers_path)

print(f"Merged _poc_generator_helpers.py into poc_generator.py")
print(f"Deleted _poc_generator_helpers.py")
