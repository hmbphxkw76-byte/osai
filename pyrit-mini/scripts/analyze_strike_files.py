#!/usr/bin/env python3
"""Analyze strike/ root .py files to identify entry points vs full implementations."""

import ast
from pathlib import Path

STRIKE_DIR = Path(__file__).resolve().parent.parent / "strike"


def is_entry_file(filepath: Path) -> bool:
    """Check if a file is just a re-export entry point."""
    try:
        content = filepath.read_text(encoding="utf-8")
    except Exception:
        return False

    lines = [
        line
        for line in content.split("\n")
        if line.strip()
        and not line.strip().startswith("#")
        and not line.strip().startswith('"""')
        and not line.strip().startswith("'''")
    ]

    has_from_import = any("from " in line and " import " in line for line in lines)
    has_all = "__all__" in content
    is_short = len(content) < 2000  # Less than 2KB

    return has_from_import and has_all and is_short


def classify_file(filepath: Path) -> str:
    """Classify a strike/ root .py file."""
    if filepath.name == "__init__.py":
        return "INIT"

    content = filepath.read_text(encoding="utf-8")
    _ = len(content)  # content length for future use

    # Check for backward compatibility markers
    has_compat_marker = (
        "向后兼容" in content
        or "backward compatibility" in content.lower()
        or "Re-exports from" in content
        or "本模块已迁移到" in content
    )

    # Check for re-export pattern
    has_from_import = any(
        "from " in line and " import " in line for line in content.split("\n") if not line.strip().startswith("#")
    )

    has_all = "__all__" in content

    # Check if it has real implementation (functions, classes defined locally)
    has_local_impl = False
    try:
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # If it's not just a re-export, it has real implementation
                if node.col_offset > 0:  # Indented = nested
                    continue
                has_local_impl = True
                break
    except SyntaxError:
        pass

    if has_compat_marker and has_from_import and has_all:
        return "ENTRY_COMPAT"
    elif is_entry_file(filepath):
        return "ENTRY_REEXPORT"
    elif has_local_impl:
        return "FULL_IMPL"
    else:
        return "UNKNOWN"


def main():
    print("=" * 80)
    print("Strike/ Root Directory File Analysis")
    print("=" * 80)
    print()

    categories = {
        "INIT": [],
        "ENTRY_COMPAT": [],
        "ENTRY_REEXPORT": [],
        "FULL_IMPL": [],
        "UNKNOWN": [],
    }

    for filepath in sorted(STRIKE_DIR.glob("*.py")):
        category = classify_file(filepath)
        size = filepath.stat().st_size
        categories[category].append((filepath.name, size))

    # Print summary
    print("FILE CLASSIFICATION SUMMARY:")
    print("-" * 80)

    for cat_name, files in categories.items():
        if not files:
            continue
        print(f"\n[{cat_name}] ({len(files)} files):")
        for name, size in sorted(files, key=lambda x: x[0]):
            print(f"  {name:45s} {size:7d} bytes")

    # Print detailed recommendations
    print()
    print("=" * 80)
    print("OPTIMIZATION RECOMMENDATIONS:")
    print("=" * 80)

    # Entry files that can be moved or deleted
    entry_files = categories.get("ENTRY_COMPAT", []) + categories.get("ENTRY_REEXPORT", [])

    if entry_files:
        print()
        print(f"ENTRY FILES ({len(entry_files)} files):")
        print("  These are backward-compatibility entry points.")
        print("  Options:")
        print("  1. Move to strike/common/entry_points/ if still needed")
        print("  2. Delete and update imports to use new paths")
        print("  3. Keep in root for backward compatibility (current state)")
        print()

    # Common/ duplicates
    print("DUPLICATE FILES (also exist in strike/common/):")
    common_files = {
        "adaptive_executor.py",
        "asr_forensics.py",
        "asr_trend_tracker.py",
        "attack_knowledge_base.py",
        "decision_safety.py",
        "dispatcher.py",
        "escalation_runtime.py",
        "executor.py",
        "progressive_strike.py",
        "_executor_attack_paths.py",
        "_executor_doc_poison.py",
        "_executor_feedback.py",
        "_executor_helpers.py",
        "_executor_vuln_inject.py",
    }

    root_files = {f for f, _ in categories.get("ENTRY_COMPAT", [])}
    root_files |= {f for f, _ in categories.get("ENTRY_REEXPORT", [])}
    root_files |= {f for f, _ in categories.get("FULL_IMPL", [])}
    root_files |= {f for f, _ in categories.get("UNKNOWN", [])}

    duplicates = root_files & common_files
    if duplicates:
        for name in sorted(duplicates):
            print(f"  {name}")

    # Proposed directory structure
    print()
    print("=" * 80)
    print("PROPOSED DIRECTORY STRUCTURE:")
    print("=" * 80)
    print("""
strike/
├── __init__.py                 # Main entry point (lazy imports)
├── common/                     # Shared infrastructure
│   ├── dispatcher.py           # Attack dispatcher
│   ├── executor.py             # Attack executor
│   ├── progressive_strike.py   # Progressive strike
│   └── ...                     # Other shared modules
├── a2a/                        # A2A / Multi-Agent attacks
├── mcp/                        # MCP protocol attacks
├── rag/                        # RAG attacks
├── model/                      # Model direct attacks
├── web/                        # Web attacks
├── memory/                     # Memory attacks
├── session/                    # Session/auth attacks
├── evasion/                    # Evasion techniques
└── injection/                  # Injection attacks

REMOVE from root:
  - All backward-compatibility entry files (*.py that just re-export from subdirs)
  - Duplicates of common/ modules (dispatcher.py, executor.py, etc.)

CLEANUP:
  - Update strike/__init__.py to use lazy imports from subdirectories
  - Update any external imports to use new module paths
    """)


if __name__ == "__main__":
    main()
