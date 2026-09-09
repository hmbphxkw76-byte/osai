#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Batch fix missing tier and attack_vector metadata in seed files."""

import re
import sys
from pathlib import Path

SEEDS_DIR = Path(__file__).parent.parent / "data/seeds"

# Attack vector mapping based on category
CATEGORY_TO_ATTACK_VECTOR = {
    "prompt_injection": "direct_injection",
    "sensitive_info": "info_extraction",
    "supply_chain": "dependency_enumeration",
    "data_poisoning": "training_data_extraction",
    "improper_output": "injection",
    "excessive_agency": "tool_abuse",
    "rag_kb_leak": "knowledge_base_extraction",
    "rag_vector_leak": "vector_db_enumeration",
    "rag_retrieval_hijack": "retrieval_manipulation",
    "rag_embedding_probe": "embedding_inversion",
    "rag_embedding_search": "embedding_search",
    "rag_kb_poisoning": "knowledge_base_poisoning",
    "rag_chunked_extract": "chunking_boundary",
    "rag_metadata_leak": "metadata_extraction",
    "rag_topk_manipulation": "ranking_manipulation",
    "rag_chunk_boundary": "chunking_boundary",
    "rag_indirect_injection": "indirect_injection",
}


def fix_seed_file(filepath: Path) -> int:
    """Fix missing tier and attack_vector in a seed file. Returns count of fixes."""
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    fixes = 0
    new_lines = []
    current_category = None

    i = 0
    while i < len(lines):
        line = lines[i]
        new_lines.append(line)

        # Track current category from comments
        if "# ──" in line and "──" in line:
            # Extract category from comment like "# ── LLM02: Sensitive Information ──"
            match = re.search(r"# ── ([^:]+):", line)
            if match:
                current_category_raw = match.group(1).strip()

        # Check if this is a metadata source line
        if re.search(r"source:\s*['\"]?curated['\"]?", line):
            # Look ahead to see if tier already exists
            has_tier = False
            for j in range(i + 1, min(i + 3, len(lines))):
                if "tier:" in lines[j]:
                    has_tier = True
                    break
                elif lines[j].strip() and not lines[j].strip().startswith("#"):
                    break

            if not has_tier:
                # Determine attack vector from category context
                attack_vector = "direct_injection"  # default
                if current_category:
                    attack_vector = CATEGORY_TO_ATTACK_VECTOR.get(
                        current_category, "direct_injection"
                    )

                # Add tier and attack_vector
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
    files_fixed = 0

    # Find all seed files
    seed_files = list(SEEDS_DIR.rglob("*.prompt"))

    for filepath in sorted(seed_files):
        fixes = fix_seed_file(filepath)
        if fixes > 0:
            rel_path = filepath.relative_to(SEEDS_DIR.parent)
            print(f"  Fixed {fixes} seeds in {rel_path}")
            total_fixes += fixes
            files_fixed += 1

    print(f"\nTotal: Fixed {total_fixes} seeds in {files_fixed} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
