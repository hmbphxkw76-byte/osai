#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fix remaining missing metadata in core seed files."""

import re
import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent

# Files that still need fixing with their attack vectors
FILES_CONFIG = {
    "data/seeds/_core/T2_LLM01_many_shot_cot_injection.prompt": "many_shot_cot",
    "data/seeds/_core/T2_LLM01_targeted_jailbreaks.prompt": "targeted_jailbreak",
    "data/seeds/_core/T2_LLM02_info_disclosure_specific.prompt": "info_extraction",
    "data/seeds/_core/T2_multiturn_targets.prompt": "multi_turn",
    "data/seeds/_core/T2_web_vulns.prompt": "web_injection",
    "data/seeds/_core/T2_structured_injection.prompt": "structured_injection",
}


def fix_file(filepath: Path, default_attack_vector: str) -> int:
    """Fix missing metadata in a file."""
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    fixes = 0
    new_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]
        new_lines.append(line)

        # Check if this is a source line
        if re.search(r"source:\s*['\"]?\w+['\"]?", line):
            # Look ahead for tier
            has_tier = False
            for j in range(i + 1, min(i + 3, len(lines))):
                if "tier:" in lines[j]:
                    has_tier = True
                    break
                elif lines[j].strip() and not lines[j].strip().startswith("#"):
                    break

            if not has_tier:
                # Check if this is a T2 file (tier 2)
                tier = 2 if "T2_" in str(filepath) else 1
                new_lines.append(f"    tier: {tier}\n")
                new_lines.append(f"    attack_vector: {default_attack_vector}\n")
                fixes += 1

        i += 1

    if fixes > 0:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

    return fixes


def main():
    total_fixes = 0

    for filepath_str, attack_vector in FILES_CONFIG.items():
        filepath = BASE_DIR / filepath_str
        if filepath.exists():
            fixes = fix_file(filepath, attack_vector)
            if fixes > 0:
                rel_path = filepath.relative_to(BASE_DIR)
                print(f"  Fixed {fixes} seeds in {rel_path}")
                total_fixes += fixes
        else:
            print(f"  File not found: {filepath_str}")

    print(f"\nTotal: Fixed {total_fixes} seeds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
