# -*- coding: utf-8 -*-
"""tools/component_purity_core.py - Component Purity 核心验证逻辑

包含:
    - _PurityAnalyzer AST 分析器
    - ComponentPurityValidator 验证器类
    - 主验证流程函数
"""

from __future__ import annotations

import ast
import logging
import re
from pathlib import Path

from tools.component_purity_config import (
    _RECON_COMPONENT_BASELINES,
    _STRIKE_COMPONENT_BASELINES,
    ComponentPurityReport,
    PurityFinding,
)

logger = logging.getLogger(__name__)


# ====================================================================
# AST-Based Purity Analyzer
# ====================================================================


class _PurityAnalyzer(ast.NodeVisitor):
    """AST visitor to detect non-component-specific code patterns."""

    def __init__(self, source: str, forbidden_patterns: list[str], component: str):
        self.source = source
        self.lines = source.split("\n")
        self.forbidden_patterns = [re.compile(p) for p in forbidden_patterns]
        self.component = component
        self.violations: list[tuple[int, str, str]] = []  # (line_no, pattern, line_text)

    def analyze(self) -> list[tuple[int, str, str]]:
        """Run analysis and return violations."""
        try:
            tree = ast.parse(self.source)
            self.visit(tree)
        except SyntaxError:
            pass  # Skip unparseable files

        # Also do regex-based scan for string literals and comments
        self._regex_scan()
        return self.violations

    def _regex_scan(self) -> None:
        """Scan source text for forbidden patterns."""
        for i, line in enumerate(self.lines, 1):
            for pattern in self.forbidden_patterns:
                if pattern.search(line):
                    self.violations.append((i, pattern.pattern, line.strip()))

    def visit_Import(self, node: ast.Import) -> None:
        """Check imports for cross-component pollution."""
        for alias in node.names:
            if self._is_cross_component_import(alias.name):
                self.violations.append(
                    (
                        node.lineno,
                        f"cross_component_import:{alias.name}",
                        f"import {alias.name}",
                    )
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Check from-imports for cross-component pollution."""
        if node.module and self._is_cross_component_import(node.module):
            self.violations.append(
                (
                    node.lineno,
                    f"cross_component_import:{node.module}",
                    f"from {node.module} import ...",
                )
            )
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Check function names for forbidden patterns."""
        for pattern in self.forbidden_patterns:
            if pattern.search(node.name):
                self.violations.append(
                    (
                        node.lineno,
                        f"forbidden_function:{pattern.pattern}",
                        f"def {node.name}(...)",
                    )
                )
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Check class names for forbidden patterns."""
        for pattern in self.forbidden_patterns:
            if pattern.search(node.name):
                self.violations.append(
                    (
                        node.lineno,
                        f"forbidden_class:{pattern.pattern}",
                        f"class {node.name}",
                    )
                )
        self.generic_visit(node)

    def _is_cross_component_import(self, module_name: str) -> bool:
        """Detect imports from other strike/recon components."""
        # Extract component name from import path
        parts = module_name.split(".")
        if len(parts) >= 2:
            # Check for strike.<other_component> or recon.<other_component>
            if parts[0] in ("strike", "recon") and len(parts) >= 2:
                source_module = parts[1] if len(parts) > 1 else ""
                # A module importing from another component is cross-contamination
                if source_module != self.component and source_module in (
                    "a2a",
                    "mcp",
                    "rag",
                    "model",
                    "web",
                    "session",
                    "memory",
                ):
                    return True
        return False


# ====================================================================
# Component Purity Validator
# ====================================================================


class ComponentPurityValidator:
    """Validates that component directories contain only component-specific code.

    Usage:
        validator = ComponentPurityValidator("d:/文档/Gosai/pyrit-mini")
        report = validator.validate_strike_component("a2a")
        print(f"Purity: {report.purity_score}, Coverage: {report.coverage_score}")
    """

    def __init__(self, project_root: str | Path):
        self.project_root = Path(project_root)
        self.strike_root = self.project_root / "strike"
        self.recon_root = self.project_root / "recon"

    def validate_strike_component(self, component: str) -> ComponentPurityReport:
        """Validate a strike component directory for purity.

        Args:
            component: Component name (e.g., "a2a", "mcp")

        Returns:
            ComponentPurityReport with findings and scores
        """
        component_path = self.strike_root / component
        baseline = _STRIKE_COMPONENT_BASELINES.get(component, {})

        if not component_path.exists():
            return ComponentPurityReport(
                component=component,
                component_path=str(component_path),
                findings=[
                    PurityFinding(
                        severity="error",
                        component=component,
                        module="__init__",
                        finding_type="missing_directory",
                        message=f"Component directory not found: {component_path}",
                    )
                ],
                purity_score=0.0,
                coverage_score=0.0,
            )

        report = ComponentPurityReport(
            component=component,
            component_path=str(component_path),
        )

        # 1. AST-based purity analysis
        py_files = list(component_path.glob("*.py"))

        for py_file in py_files:
            if py_file.name == "__init__.py":
                continue  # Skip __init__.py for purity (it's just exports)
            source = py_file.read_text(encoding="utf-8")
            file_analyzer = _PurityAnalyzer(
                source=source,
                forbidden_patterns=baseline.get("forbidden_patterns", []),
                component=component,
            )
            violations = file_analyzer.analyze()
            for line_no, pattern, line_text in violations:
                report.findings.append(
                    PurityFinding(
                        severity="error",
                        component=component,
                        module=py_file.name,
                        finding_type="forbidden_technique",
                        message=f"Forbidden pattern in {component}: {pattern}",
                        line_number=line_no,
                        suggestion=f"Remove or relocate non-{component} technique",
                    )
                )

        # 2. Technique coverage analysis
        all_source = "\n".join(f.read_text(encoding="utf-8") for f in py_files if f.name != "__init__.py")

        required_techniques = baseline.get("required_techniques", [])
        found_techniques: list[str] = []

        for technique in required_techniques:
            # Convert snake_case to search pattern
            search_terms = technique.replace("_", "[_ ]?")
            pattern = re.compile(rf"(?i){search_terms}")
            if pattern.search(all_source):
                found_techniques.append(technique)

        report.missing_techniques = [t for t in required_techniques if t not in found_techniques]
        report.technique_count = len(found_techniques)

        # 3. High-ASR technique coverage
        high_asr_techniques = baseline.get("high_asr_techniques", [])
        report.high_asr_technique_count = sum(1 for tech, _ in high_asr_techniques if tech in found_techniques)

        # 4. Calculate scores
        if required_techniques:
            report.coverage_score = len(found_techniques) / len(required_techniques)

        # Purity score: 1.0 - (violations / total_lines)
        violation_count = len([f for f in report.findings if f.severity == "error"])
        if py_files:
            total_lines = sum(len(f.read_text(encoding="utf-8").split("\n")) for f in py_files)
            report.purity_score = max(0.0, 1.0 - (violation_count / max(total_lines, 1)))
        else:
            report.purity_score = 0.0

        # 5. Add missing technique findings
        for missing in report.missing_techniques:
            report.findings.append(
                PurityFinding(
                    severity="warning",
                    component=component,
                    module="__init__",
                    finding_type="missing_technique",
                    message=f"Missing required technique: {missing}",
                    suggestion=f"Implement {missing} to achieve complete attack coverage",
                )
            )

        return report

    def validate_recon_component(self, component: str) -> ComponentPurityReport:
        """Validate a recon component directory for strategy completeness.

        Args:
            component: Component name (e.g., "a2a", "mcp")

        Returns:
            ComponentPurityReport with findings and scores
        """
        component_path = self.recon_root / component
        baseline = _RECON_COMPONENT_BASELINES.get(component, {})

        if not component_path.exists():
            return ComponentPurityReport(
                component=component,
                component_path=str(component_path),
                findings=[
                    PurityFinding(
                        severity="error",
                        component=component,
                        module="__init__",
                        finding_type="missing_directory",
                        message=f"Recon component directory not found: {component_path}",
                    )
                ],
                purity_score=0.0,
                coverage_score=0.0,
            )

        report = ComponentPurityReport(
            component=component,
            component_path=str(component_path),
        )

        # 1. Cross-contamination analysis
        py_files = list(component_path.glob("*.py"))

        for py_file in py_files:
            if py_file.name == "__init__.py":
                continue
            source = py_file.read_text(encoding="utf-8")
            file_analyzer = _PurityAnalyzer(
                source=source,
                forbidden_patterns=baseline.get("forbidden_patterns", []),
                component=component,
            )
            violations = file_analyzer.analyze()
            for line_no, pattern, line_text in violations:
                report.findings.append(
                    PurityFinding(
                        severity="error",
                        component=component,
                        module=py_file.name,
                        finding_type="cross_contamination",
                        message=f"Non-{component} pattern found: {pattern}",
                        line_number=line_no,
                        suggestion="Remove or relocate to appropriate component module",
                    )
                )

        # 2. Strategy completeness analysis
        all_source = "\n".join(f.read_text(encoding="utf-8") for f in py_files if f.name != "__init__.py")

        required_strategies = baseline.get("required_strategies", [])
        found_strategies: list[str] = []

        for strategy in required_strategies:
            search_terms = strategy.replace("_", "[_ ]?")
            pattern = re.compile(rf"(?i){search_terms}")
            if pattern.search(all_source):
                found_strategies.append(strategy)

        report.missing_techniques = [s for s in required_strategies if s not in found_strategies]
        report.technique_count = len(found_strategies)

        # 3. Calculate scores
        if required_strategies:
            report.coverage_score = len(found_strategies) / len(required_strategies)

        violation_count = len([f for f in report.findings if f.severity == "error"])
        if py_files:
            total_lines = sum(len(f.read_text(encoding="utf-8").split("\n")) for f in py_files)
            report.purity_score = max(0.0, 1.0 - (violation_count / max(total_lines, 1)))
        else:
            report.purity_score = 0.0

        # Add missing strategy findings
        for missing in report.missing_techniques:
            report.findings.append(
                PurityFinding(
                    severity="warning",
                    component=component,
                    module="__init__",
                    finding_type="missing_strategy",
                    message=f"Missing required recon strategy: {missing}",
                    suggestion=f"Implement {missing} to achieve 100% recon accuracy",
                )
            )

        return report

    def validate_all_strike_components(self) -> dict[str, ComponentPurityReport]:
        """Validate all strike components.

        Returns:
            Dict mapping component name to its purity report
        """
        reports: dict[str, ComponentPurityReport] = {}
        for component in _STRIKE_COMPONENT_BASELINES:
            component_path = self.strike_root / component
            if component_path.exists():
                reports[component] = self.validate_strike_component(component)
        return reports

    def validate_all_recon_components(self) -> dict[str, ComponentPurityReport]:
        """Validate all recon components.

        Returns:
            Dict mapping component name to its purity report
        """
        reports: dict[str, ComponentPurityReport] = {}
        for component in _RECON_COMPONENT_BASELINES:
            component_path = self.recon_root / component
            if component_path.exists():
                reports[component] = self.validate_recon_component(component)
        return reports

    def validate_all(self) -> dict[str, dict[str, ComponentPurityReport]]:
        """Validate all components (strike + recon).

        Returns:
            Dict with "strike" and "recon" keys containing component reports
        """
        return {
            "strike": self.validate_all_strike_components(),
            "recon": self.validate_all_recon_components(),
        }


# ====================================================================
# CLI Entry Point
# ====================================================================


def format_purity_report(report: ComponentPurityReport) -> str:
    """Format a purity report for console output."""
    lines: list[str] = []

    # Header with score emoji
    purity_emoji = "PASS" if report.is_pure else "FAIL"
    lines.append(f"[{purity_emoji}] {report.component} - Purity Score: {report.purity_score:.2%}")
    lines.append(f"       Coverage: {report.coverage_score:.2%} ({report.technique_count} techniques)")
    lines.append(f"       Pure: {report.is_pure}, Complete: {report.is_complete}")

    # Findings
    if report.findings:
        lines.append("       Findings:")
        for finding in report.findings:
            prefix = "[ERR]" if finding.severity == "error" else "[WRN]"
            line_info = f":{finding.line_number}" if finding.line_number else ""
            lines.append(f"         {prefix} {finding.message} ({finding.module}{line_info})")

    # Missing techniques
    if report.missing_techniques:
        lines.append("       Missing techniques:")
        for missing in report.missing_techniques:
            lines.append(f"         - {missing}")

    return "\n".join(lines)


def run_component_purity_check(
    project_root: str | Path | None = None,
    verbose: bool = True,
) -> dict[str, dict[str, ComponentPurityReport]]:
    """Run complete component purity validation.

    Args:
        project_root: Root path of the project (auto-detected if None)
        verbose: Print detailed findings

    Returns:
        Nested dict of validation results
    """
    if project_root is None:
        project_root = Path(__file__).resolve().parent.parent

    validator = ComponentPurityValidator(project_root)
    results = validator.validate_all()

    if verbose:
        print("\n" + "=" * 70)
        print("COMPONENT PURITY & COVERAGE VALIDATION REPORT")
        print("=" * 70)

        for category, components in results.items():
            print(f"\n--- {category.upper()} COMPONENTS ---")
            for name, report in sorted(components.items()):
                print(format_purity_report(report))

        # Summary
        print("\n" + "-" * 70)
        all_reports = [r for cat in results.values() for r in cat.values()]
        avg_purity = sum(r.purity_score for r in all_reports) / max(len(all_reports), 1)
        avg_coverage = sum(r.coverage_score for r in all_reports) / max(len(all_reports), 1)
        total_missing = sum(len(r.missing_techniques) for r in all_reports)

        print(f"SUMMARY: Purity {avg_purity:.2%} | Coverage {avg_coverage:.2%} | Missing: {total_missing}")
        print("=" * 70 + "\n")

    return results
