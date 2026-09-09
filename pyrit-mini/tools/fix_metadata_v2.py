#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fix remaining missing tier and attack_vector metadata."""

import re
import sys
from pathlib import Path

SEEDS_DIR = Path(__file__).parent.parent / "data/seeds"

# Files that still need fixing
FILES_TO_FIX = [
    "data/seeds/_core/T1_LLM01_advanced_injection.prompt",
    "data/seeds/_core/T1_LLM07_system_prompt_leakage.prompt",
    "data/seeds/_core/T1_multi_targeted_extraction.prompt",
]

# Category to attack vector mapping
CATEGORY_MAP = {
    "prompt_injection": "direct_injection",
    "sensitive_info": "info_extraction",
    "system_prompt_leakage": "prompt_leakage",
    "targeted_extraction": "info_extraction",
}


def fix_file(filepath: Path) -> int:
    """Fix missing metadata in a file."""
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    fixes = 0
    new_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]
        new_lines.append(line)

        # Check if this is a source line without tier following
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
                # Determine tier and attack_vector from context
                tier = 1
                attack_vector = "direct_injection"

                # Look back for category context
                context = "".join(lines[max(0, i - 10):i])
                for cat, av in CATEGORY_MAP.items():
                    if cat in context:
                        attack_vector = av
                        break

                new_lines.append("    tier: 1\n")
                new_lines.append(f"    attack_vector: {attack_vector}\n")
                fixes += 1

        i += 1

    if fixes > 0:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

    return fixes


def main():
    total_fixes = 0

    for filepath_str in FILES_TO_FIX:
        filepath = Path(__file__).parent.parent / filepath_str
        if filepath.exists():
            fixes = fix_file(filepath)
            if fixes > 0:
                rel_path = filepath.relative_to(SEEDS_DIR.parent)
                print(f"  Fixed {fixes} seeds in {rel_path}")
                total_fixes += fixes

    print(f"\nTotal: Fixed {total_fixes} seeds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
