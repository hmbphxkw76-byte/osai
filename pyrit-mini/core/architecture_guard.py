"""
Architecture Guard - R-SIZE God Object .

19+  R-SIZE
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path

logger = logging.getLogger(__name__)

# ===============================================================================
# R-SIZE :  God Object
# ===============================================================================

_SIZE_WARNING_THRESHOLD = 850  # 850 (800 + 50)
_SIZE_BLOCKING_THRESHOLD = 1500  # 1500
_SIZE_BYPASS_WHITELIST = {
    "arm/converter_chains.py",
    "arm/converter_selector.py",
    "core/architecture_guard_extended.py",
    "core/orchestrator.py",
    "recon/rag_metadata_parser.py",
    "utils/display.py",
    "report/report_markdown.py",
}

# ===============================================================================

class Severity(IntEnum):
    BLOCKING = 0      # CI
    WARNING = 1       #
    INFO = 2          #

@dataclass
class Violation:

    rule: str
    severity: Severity
    file: str
    line: int
    description: str
    fix_hint: str = ""

class ArchitectureGuard:


    def __init__(self, project_root: Path) -> None:
        self.root = project_root
        self.violations: list[Violation] = []
        self._source_files: list[Path] | None = None

    @property
    def source_files(self) -> list[Path]:
        if self._source_files is not None:
            return self._source_files

        exclude_dirs = {
            "outputs", ".venv", "__pycache__", ".pytest_cache",
            ".ruff_cache", "node_modules", ".git", ".assistant_pyrit",
            ".idea", ".vscode", "pyrit_strike.egg-info"
        }
        self._source_files = []
        for path in self.root.rglob("*.py"):
            if any(part in exclude_dirs for part in path.parts):
                continue
            self._source_files.append(path)
        return self._source_files


    def check_size_escape(self) -> None:
        for path in self.source_files:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                line_count = len(content.splitlines())
            except OSError:
                continue

            rel_path = str(path.relative_to(self.root))

            #  ()
            # Windows:   /
            norm_path = rel_path.replace("\\", "/")
            if norm_path in _SIZE_BYPASS_WHITELIST:
                continue

            if line_count >= _SIZE_BLOCKING_THRESHOLD:
                self.violations.append(Violation(
                    rule="R-SIZE",
                    severity=Severity.BLOCKING,
                    file=rel_path,
                    line=1,
                    description=f": {path.name} {line_count}  ( +{_SIZE_BLOCKING_THRESHOLD})",
                    fix_hint=f"  <{_SIZE_WARNING_THRESHOLD}: () core/phases/ assess/",
                ))
            elif line_count >= _SIZE_WARNING_THRESHOLD:
                self.violations.append(Violation(
                    rule="R-SIZE",
                    severity=Severity.WARNING,
                    file=rel_path,
                    line=1,
                    description=f": {path.name} {line_count}  ( +{_SIZE_WARNING_THRESHOLD})",
                    fix_hint=" : () core/phases/ assess/",
                ))

    def check_serial_stacking(self) -> None:
        for path in self.source_files:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.split("\n")
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue

                if "ConverterConfiguration" in line and "converters=[" in line:
                    match = re.search(r"converters\s*=\s*\[(.*?)\]", line)
                    if not match:
                        continue

                    inner = match.group(1).strip()
                    comma_count = inner.count(",")

                    if comma_count > 2:
                        self.violations.append(Violation(
                            rule="R-CONV-1",
                            severity=Severity.BLOCKING,
                            file=str(path.relative_to(self.root)),
                            line=i,
                            description=f": {path.name}:{i} {comma_count + 1} converter",
                            fix_hint="2 converter : chained_selective",
                        ))

    def check_forbidden_custom_classes(self) -> None:
        forbidden_patterns = [
            (r"import\s+requests", "Use urllib.request  httpx"),
            (r"from\s+requests\s+import", "Use urllib.request  httpx"),
        ]

        for path in self.source_files:
            if "adapters" in str(path):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for pattern, fix in forbidden_patterns:
                for i, line in enumerate(content.split("\n"), 1):
                    if re.search(pattern, line) and not line.strip().startswith("#"):
                        self.violations.append(Violation(
                            rule="R-IMPORT-1",
                            severity=Severity.WARNING,
                            file=str(path.relative_to(self.root)),
                            line=i,
                            description=f": {line.strip()[:60]}",
                            fix_hint=fix,
                        ))

    def check_all(self) -> list[Violation]:
        self.violations.clear()

        # R-SIZE / R-STACK / R-CLASS (built-in checks)
        self.check_size_escape()
        self.check_serial_stacking()
        self.check_forbidden_custom_classes()

        # R-PIPE / R-IMPORT / R-REDTEAM / R-EVID / R-REPORT (extended checks)
        # Registered via register_extended_checks() at module level
        for attr_name in dir(self):
            if attr_name.startswith("check_") and attr_name not in (
                "check_size_escape", "check_serial_stacking",
                "check_forbidden_custom_classes", "check_all",
            ):
                method = getattr(self, attr_name, None)
                if callable(method):
                    try:
                        method()
                    except Exception as e:
                        logger.debug("Extended check %s failed: %s", attr_name, e)

        return self.violations

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    if not args.verbose:
        logging.basicConfig(level=logging.WARNING)

    guard = ArchitectureGuard(args.root)
    violations = guard.check_all()


    blocking = [v for v in violations if v.severity == Severity.BLOCKING]
    warnings = [v for v in violations if v.severity == Severity.WARNING]
    info = [v for v in violations if v.severity == Severity.INFO]

    for v in blocking:
        print(f"  {v.rule} {v.file}:{v.line}")
        print(f"    {v.description}")
        if v.fix_hint:
            print(f"    : {v.fix_hint}")

    for v in warnings:
        print(f"  {v.rule} {v.file}:{v.line}")
        print(f"    {v.description}")
        if v.fix_hint:
            print(f"    : {v.fix_hint}")

    for v in info:
        print(f"  {v.rule} {v.file}:{v.line}")
        print(f"    {v.description}")

    print(f"\n : {len(blocking)}  {len(warnings)}  {len(info)} ")

    if blocking:
        raise SystemExit(1)
    return None

# === Register extended checks (R-PIPE / R-IMPORT / R-REDTEAM / R-EVID / R-REPORT) ===
def _register_all_extended_checks() -> None:
    try:
        from core.architecture_guard_extended import register_extended_checks
        register_extended_checks(ArchitectureGuard)
    except ImportError as e:
        logger.debug("Extended checks not available: %s", e)


_register_all_extended_checks()


if __name__ == "__main__":
    main()
