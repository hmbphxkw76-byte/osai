#!/usr/bin/env python3
"""Quick check for a single file — validates architecture rules on-the-fly.

Usage:
    py -m tools.quick_check path/to/file.py
    py -m tools.quick_check --all        # check all modified files
"""

import argparse
import re
import sys
from pathlib import Path

# === Quick Architecture Checks ===
MAX_LINE_LIMIT = 300  # R-DELIVERY-1
MODULE_DOCSTRING_REQUIRED = True  # R-DELIVERY-5

# Forbidden cross-layer imports (R-DELIVERY-3)
FORBIDDEN_CROSS_LAYER = {
    "report": ["strike"],
    "utils": ["strike", "recon", "arm", "assess", "report"],
}


def check_file_size(filepath: Path) -> list[str]:
    """R-DELIVERY-1: Check module line count."""
    violations = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
        lines = len(content.splitlines())
        if lines > MAX_LINE_LIMIT:
            violations.append(
                f"  R-DELIVERY-1 [WARNING] {filepath.name}: {lines} lines (limit: {MAX_LINE_LIMIT})"
            )
    except OSError:
        pass
    return violations


def check_docstring(filepath: Path) -> list[str]:
    """R-DELIVERY-5: Check module docstring."""
    violations = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()
        has_docstring = False
        for line in lines[:10]:
            stripped = line.strip()
            if stripped.startswith(('"""', "'''")):
                has_docstring = True
                break
            elif stripped and not stripped.startswith("#"):
                break
        if not has_docstring and len(lines) > 5:
            violations.append(
                f"  R-DELIVERY-5 [INFO] {filepath.name}: missing module docstring"
            )
    except OSError:
        pass
    return violations


def check_cross_layer_imports(filepath: Path) -> list[str]:
    """R-DELIVERY-3: Check forbidden cross-layer imports."""
    violations = []
    rel_path = str(filepath).replace("\\", "/")

    # Determine which layer this file belongs to
    src_layer = None
    for layer in FORBIDDEN_CROSS_LAYER:
        if f"/{layer}/" in rel_path or rel_path.startswith(f"{layer}/"):
            src_layer = layer
            break

    if not src_layer:
        return violations

    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return violations

    for dst_layer in FORBIDDEN_CROSS_LAYER.get(src_layer, []):
        # Check for import from forbidden layer
        pattern = rf"from\s+{dst_layer}\.|import\s+{dst_layer}\."
        if re.search(pattern, content):
            violations.append(
                f"  R-DELIVERY-3 [BLOCKING] {filepath.name}: cross-layer import from '{dst_layer}'"
            )

    return violations


def check_single_file(filepath: Path) -> list[str]:
    """Run all quick checks on a single file."""
    if not filepath.exists():
        print(f"Error: {filepath} not found")
        return []

    if not filepath.suffix == ".py":
        print(f"Error: {filepath} is not a Python file")
        return []

    all_violations = []
    all_violations.extend(check_file_size(filepath))
    all_violations.extend(check_docstring(filepath))
    all_violations.extend(check_cross_layer_imports(filepath))
    return all_violations


def find_modified_files(project_root: Path) -> list[Path]:
    """Find all Python files in core packages."""
    modified = []
    dirs = ["strike", "recon", "arm", "assess", "core", "report", "utils"]
    for d in dirs:
        d_path = project_root / d
        if d_path.exists():
            for f in d_path.rglob("*.py"):
                if f.name != "__init__.py":
                    modified.append(f)
    return modified


def main():
    parser = argparse.ArgumentParser(description="Quick architecture check for files")
    parser.add_argument("file", nargs="?", help="Python file to check")
    parser.add_argument("--all", action="store_true", help="Check all files in core packages")
    parser.add_argument("--root", type=Path, default=None, help="Project root")

    args = parser.parse_args()

    # Find project root
    if args.root:
        project_root = args.root
    else:
        cwd = Path.cwd()
        if (cwd / "tools" / "guard.py").exists():
            project_root = cwd
        elif (cwd.parent / "tools" / "guard.py").exists():
            project_root = cwd.parent
        else:
            project_root = cwd

    if args.file:
        filepath = Path(args.file)
        if not filepath.is_absolute():
            filepath = project_root / filepath

        violations = check_single_file(filepath)
        if violations:
            print(f"Quick check: {filepath.name}")
            for v in violations:
                print(v)
            print()
            sys.exit(1)
        else:
            print(f"  [PASS] {filepath.name}: All R-DELIVERY rules passed")
            sys.exit(0)

    elif args.all:
        files = find_modified_files(project_root)
        all_violations = []
        for f in files:
            all_violations.extend(check_single_file(f))

        if all_violations:
            print(f"Quick check: {len(all_violations)} violation(s) found")
            for v in all_violations[:20]:  # Show first 20
                print(v)
            if len(all_violations) > 20:
                print(f"  ... and {len(all_violations) - 20} more")
            sys.exit(1)
        else:
            print("  [PASS] All files pass R-DELIVERY rules")
            sys.exit(0)

    else:
        parser.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
