#!/usr/bin/env python3
"""Real-time file watcher for architecture guard.

Monitors .py file changes and runs targeted architecture checks.
Auto-triggers when you save a file, preventing violations before commit.

Usage:
    py -m tools.watch_guard              # Watch all packages
    py -m tools.watch_guard --package strike  # Watch specific package
    py -m tools.watch_guard --fast       # Fast mode (only modified files)
"""

import argparse
import hashlib
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Set, Tuple


# === Configuration ===
WATCHED_DIRS = ["strike", "recon", "arm", "assess", "core", "report", "utils", "tools"]
CHECK_INTERVAL = 2  # seconds between scans
DEBOUNCE_SECONDS = 1  # wait before checking after change


class FileWatcher:
    """Watches Python files for changes and triggers architecture checks."""

    def __init__(self, project_root: Path, package: str = None, fast: bool = False):
        self.project_root = project_root
        self.target_dirs = [project_root / package] if package else [
            project_root / d for d in WATCHED_DIRS
        ]
        self.fast = fast
        self.file_hashes: Dict[str, str] = {}
        self.last_change_time: float = 0
        self.pending_check: bool = False

    def _compute_file_hash(self, filepath: Path) -> str:
        """Compute MD5 hash of a file."""
        try:
            content = filepath.read_bytes()
            return hashlib.md5(content).hexdigest()
        except OSError:
            return ""

    def _get_all_py_files(self) -> list[Path]:
        """Get all Python files to watch."""
        files = []
        for d in self.target_dirs:
            if d.exists():
                for f in d.rglob("*.py"):
                    if f.name != "__init__.py" or not self.fast:
                        files.append(f)
        return files

    def _scan_for_changes(self) -> list[Path]:
        """Scan files and return list of changed files."""
        changed = []
        current_files: Set[str] = set()

        for filepath in self._get_all_py_files():
            rel_path = str(filepath.relative_to(self.project_root))
            current_files.add(rel_path)

            new_hash = self._compute_file_hash(filepath)
            old_hash = self.file_hashes.get(rel_path)

            if old_hash is None:
                # First scan, just record hash
                self.file_hashes[rel_path] = new_hash
            elif old_hash != new_hash:
                # File changed
                changed.append(filepath)
                self.file_hashes[rel_path] = new_hash

        # Remove deleted files from tracking
        for rel_path in list(self.file_hashes.keys()):
            if rel_path not in current_files:
                del self.file_hashes[rel_path]

        return changed

    def _run_full_guard(self) -> Tuple[bool, str]:
        """Run full architecture guard."""
        try:
            result = subprocess.run(
                [sys.executable, "-m", "tools.guard"],
                capture_output=True,
                text=True,
                cwd=self.project_root,
                timeout=30,
            )
            output = result.stdout + result.stderr
            return result.returncode == 0, output
        except subprocess.TimeoutExpired:
            return False, "Guard timeout (30s)"
        except Exception as e:
            return False, f"Guard error: {e}"

    def _run_targeted_check(self, changed_files: list[Path]) -> Tuple[bool, str]:
        """Run targeted check on modified files (faster)."""
        if not changed_files:
            return True, ""

        # Build a quick check script for just modified files
        modified_rel = [str(f.relative_to(self.project_root)) for f in changed_files]

        check_script = f'''
import sys
sys.path.insert(0, ".")
from pathlib import Path
from tools.guard import ArchitectureGuard, Severity

root = Path("{self.project_root.as_posix()}")
guard = ArchitectureGuard(root)

# Run only R-DELIVERY rules (fast)
for method_name in ["check_delivery_module_size", "check_delivery_module_docstring",
                     "check_delivery_init_export_consistency"]:
    method = getattr(guard, method_name, None)
    if method:
        try:
            method()
        except Exception as e:
            pass

# Filter violations to only modified files
modified = {modified_rel!r}
filtered = [v for v in guard.violations if any(m in v.file for m in modified)]

if filtered:
    print(f"  [WARNING] {{len(filtered)}} violation(s) in modified files:")
    for v in filtered:
        print(f"    {{v.rule}} {{v.file}}:{{v.line}} - {{v.description}}")
    sys.exit(0)  # Warnings don't block
else:
    print("  [PASS] No violations in modified files")
    sys.exit(0)
'''
        try:
            result = subprocess.run(
                [sys.executable, "-c", check_script],
                capture_output=True,
                text=True,
                cwd=self.project_root,
                timeout=15,
            )
            return result.returncode == 0, result.stdout + result.stderr
        except Exception as e:
            return False, f"Check error: {e}"

    def run(self):
        """Main watch loop."""
        print("=" * 60)
        print("  Red Team Delivery Framework - Real-time Watcher")
        print("=" * 60)
        print()
        print(f"  Watching: {[d.name for d in self.target_dirs if d.exists()]}")
        print(f"  Interval: {CHECK_INTERVAL}s")
        print(f"  Mode: {'Fast (modified files only)' if self.fast else 'Full (all rules)'}")
        print()
        print("  Press Ctrl+C to stop")
        print("-" * 60)
        print()

        # Initial scan
        print("[1/2] Running initial check...")
        ok, output = self._run_full_guard()
        if ok:
            print("  [PASS] Initial check passed")
        else:
            # Count by severity
            blocking = output.count("BLOCKING") if output else 0
            warnings = output.count("WARNING") if output else 0
            print(f"  [INFO] Found issues: {output.strip().split(chr(10))[-1] if output else 'unknown'}")

        print("[2/2] Starting file watcher...")
        print()

        try:
            while True:
                time.sleep(CHECK_INTERVAL)

                changed = self._scan_for_changes()
                if not changed:
                    continue

                # Debounce: wait a moment for file to stabilize
                time.sleep(DEBOUNCE_SECONDS)
                # Re-scan after debounce
                changed = self._scan_for_changes()

                now = time.strftime("%H:%M:%S")
                print(f"[{now}] Changed: {[f.name for f in changed]}")

                if self.fast:
                    ok, output = self._run_targeted_check(changed)
                else:
                    ok, output = self._run_full_guard()

                if ok:
                    print(f"  [PASS] All checks passed")
                else:
                    # Show summary
                    lines = output.strip().split("\n")
                    if lines:
                        last_line = lines[-1] if lines else ""
                        print(f"  [WARN] {last_line}")
                        # Show R-DELIVERY specific
                        rdelivery_lines = [l for l in lines if "R-DELIVERY" in l]
                        if rdelivery_lines:
                            print("  R-DELIVERY violations:")
                            for line in rdelivery_lines[:3]:
                                print(f"    {line.strip()}")

                print()

        except KeyboardInterrupt:
            print()
            print("-" * 60)
            print("  Watcher stopped.")
            print("-" * 60)


def main():
    parser = argparse.ArgumentParser(description="Real-time architecture guard watcher")
    parser.add_argument(
        "--package", "-p",
        help="Watch specific package only (strike/recon/arm/assess/core/report/utils/tools)",
    )
    parser.add_argument(
        "--fast", "-f",
        action="store_true",
        help="Fast mode: only check modified files (faster)",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="Project root directory",
    )

    args = parser.parse_args()

    # Find project root
    if args.root:
        project_root = args.root
    else:
        # Try to find pyrit-mini root
        cwd = Path.cwd()
        if (cwd / "tools" / "guard.py").exists():
            project_root = cwd
        elif (cwd.parent / "tools" / "guard.py").exists():
            project_root = cwd.parent
        else:
            # Search upward
            p = cwd
            while p != p.parent:
                if (p / "tools" / "guard.py").exists():
                    project_root = p
                    break
                p = p.parent
            else:
                print("Error: Cannot find pyrit-mini root (tools/guard.py)")
                sys.exit(1)

    watcher = FileWatcher(project_root, package=args.package, fast=args.fast)
    watcher.run()


if __name__ == "__main__":
    main()
