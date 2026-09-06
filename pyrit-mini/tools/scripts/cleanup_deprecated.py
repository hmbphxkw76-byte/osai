#!/usr/bin/env python3
"""Remove deprecated stacking functions from converter_chains.py."""
import re
from pathlib import Path

chains_file = Path(__file__).resolve().parent.parent.parent / "arm" / "converter_chains.py"

with open(chains_file, "r", encoding="utf-8") as f:
    lines = f.readlines()

result = []
skip = False
skip_indent = None

for i, line in enumerate(lines):
    stripped = line.strip()
    
    # Start skipping at deprecated function definitions
    if stripped.startswith("def _encoding_bypass_deprecated(") or stripped.startswith("def _multi_encoding_deprecated("):
        skip = True
        skip_indent = len(line) - len(line.lstrip())
        # Insert deprecation note comment
        result.append("\n")
        result.append("# NOTE (L5 v42): encoding_bypass and multi_encoding removed from _build_chain_builders.\n")
        result.append("# Reasons: 3-4 layer stack violates Wei et al. (arXiv:2307.15043) decay law (ASR <4%).\n")
        result.append("# Replacements: selective_encoding (single conv, ASR 25-35%) or chained_selective (2-layer, ASR 30-40%).\n")
        continue
    
    # Continue skipping until next function definition at same or lower indentation
    if skip:
        if stripped.startswith("def ") and not stripped.startswith("def _"):
            # Check if this def is at same or lower indent (new top-level function)
            current_indent = len(line) - len(line.lstrip())
            if current_indent <= skip_indent:
                skip = False
            else:
                continue
        elif stripped and not stripped.startswith("#") and not stripped.startswith('"""') and not stripped.startswith("'''"):
            current_indent = len(line) - len(line.lstrip())
            if current_indent <= skip_indent and not stripped.startswith(")") and not stripped.startswith("return") and not stripped.startswith("]") and not stripped.startswith("pass"):
                skip = False
    
    if not skip:
        result.append(line)

with open(chains_file, "w", encoding="utf-8") as f:
    f.writelines(result)

print(f"[OK] Cleaned up deprecated functions")
print(f"   Original: {len(lines)} lines")
print(f"   New:      {len(result)} lines")
print(f"   Removed:  {len(lines) - len(result)} lines")
