"""One-time cleanup script to remove dead code from rag_metadata_parser.py."""

import re


def main():
    filepath = "recon/rag_metadata_parser.py"

    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # Find the start of dead code section (KnowledgeBaseMapper)
    start_marker = "\n\n# ====================================================================\n# Section 4:"
    start_idx = content.find(start_marker)
    if start_idx == -1:
        print("ERROR: Could not find Section 4 marker")
        return

    # Find where production code resumes (run_rag_metadata_collection)
    end_marker = "\n\n# ====================================================================\n# Section 6:"
    end_idx = content.find(end_marker)
    if end_idx == -1:
        # Try alternative: find "async def run_rag_metadata_collection"
        end_marker2 = "\nasync def run_rag_metadata_collection"
        end_idx = content.find(end_marker2)
        if end_idx == -1:
            print("ERROR: Could not find Section 6 marker or run_rag_metadata_collection")
            return
        # Move to start of line
        end_idx = content.rfind("\n", 0, end_idx) + 1

    # Extract parts to keep
    before = content[:start_idx]
    after = content[end_idx:]

    # Create new section header
    new_section = """
# ====================================================================
# Section 4: High-Level Orchestrator — RAG Metadata Collection
# ====================================================================
"""

    # Reconstruct file
    new_content = before + new_section + after

    # Clean up any placeholder comments from failed edit
    new_content = new_content.replace(
        "\n\n\n# Placeholder removed: KnowledgeBaseMapper class was dead code (only used in tests)\n"
        "# The production pipeline uses run_rag_metadata_collection() directly\n\n"
        "def _placeholder_removed_kb_mapper():\n",
        "\n"
    )

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(new_content)

    # Count lines
    lines = new_content.split("\n")
    print(f"Cleanup complete. File reduced from ~1332 to {len(lines)} lines.")

    # Verify critical functions exist
    critical = [
        "class RetrievedChunk",
        "class RetrievalTiming",
        "class RAGResponseMetadata",
        "class KnowledgeBaseMap",
        "def parse_rag_response",
        "async def run_rag_metadata_collection",
        "def _compute_score_range",
    ]
    for name in critical:
        if name in new_content:
            print(f"  ✓ {name}")
        else:
            print(f"  ✗ MISSING: {name}")

    # Verify dead code removed
    dead = [
        "class KnowledgeBaseMapper",
        "def get_kb_mapping_queries",
        "def generate_targeted_queries",
        "_KB_MAPPING_QUERIES",
        "def _compute_score_stats",
        "def _pearson_correlation",
    ]
    print("\nDead code removal verification:")
    for name in dead:
        if name in new_content:
            print(f"  ✗ STILL PRESENT: {name}")
        else:
            print(f"  ✓ Removed: {name}")


if __name__ == "__main__":
    main()
