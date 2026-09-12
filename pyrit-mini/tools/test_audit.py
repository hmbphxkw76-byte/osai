# -*- coding: utf-8 -*-
"""tools/test_audit.py — 测试审计（开发全审 Phase J）。

对 tests/ 目录做静态分析，覆盖：
    1. 覆盖率   — 统计测试函数/文件总数（精确覆盖率建议用 pytest --cov）
    2. 测试质量 — 空测试 / 无意义 assert True
    3. 边界条件 — 引用边界/空值/极值断言的测试文件比例
    4. 测试隔离 — 测试中使用 global 关键字的隔离风险
    5. 变异测试 — 变异测试工具可用性（静态提示，不实际运行）

严重级别：
    WARNING — 空测试 / assert True / global 隔离风险（建议修复）
    INFO    — 覆盖率统计 / 边界覆盖 / 变异工具可用性（知会即可）

退出码：仅 BLOCKING 阻断；本审计默认不产生 BLOCKING（测试质量属 WARNING），故常态退出 0。

Academic basis:
    - Google Testing Blog: "Test Pitfalls" / 边界值分析 (Boundary Value Analysis)
    - mutation testing: mutmut / cosmic-ray
"""

from __future__ import annotations

import ast
import re

from tools._audit_base import Finding, Severity, project_root, run_audit


def _is_true_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _collect() -> list[Finding]:
    findings: list[Finding] = []
    root = project_root()
    test_files = sorted(root.rglob("tests/**/*.py"))

    n_tests = 0
    trivial = 0
    global_use = 0

    for tf in test_files:
        try:
            tree = ast.parse(tf.read_text(encoding="utf-8", errors="replace"))
        except (OSError, SyntaxError):
            continue
        rel = str(tf.relative_to(root))

        for node in ast.walk(tree):
            if isinstance(node, ast.Global):
                global_use += 1
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
                n_tests += 1
                body = node.body
                if len(body) == 1 and isinstance(body[0], ast.Pass):
                    trivial += 1
                    findings.append(Finding("TRIVIAL_TEST", Severity.WARNING, f"空测试函数: {node.name}", rel))
                elif len(body) == 1 and isinstance(body[0], ast.Assert) and _is_true_literal(body[0].test):
                    trivial += 1
                    findings.append(Finding("ASSERT_TRUE", Severity.WARNING, f"无意义的 assert True: {node.name}", rel))

    if global_use:
        findings.append(
            Finding("GLOBAL_STATE", Severity.WARNING, f"测试中使用 global 关键字 {global_use} 处（隔离风险）", "tests/")
        )

    # 边界条件覆盖（INFO）
    boundary_hits = 0
    for tf in test_files:
        try:
            text = tf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if re.search(r"\b(boundary|edge|empty|none|max_|min_|-1|zero|0)\b", text, re.I):
            boundary_hits += 1

    findings.append(
        Finding("TEST_COUNT", Severity.INFO, f"测试函数总数: {n_tests}；测试文件: {len(test_files)}", "tests/")
    )
    findings.append(
        Finding(
            "BOUNDARY_COVERAGE",
            Severity.INFO,
            f"含边界/空值断言的测试文件: {boundary_hits}/{len(test_files)}",
            "tests/",
        )
    )

    # 变异测试工具可用性（INFO）
    try:
        import importlib.util

        have_mutmut = importlib.util.find_spec("mutmut") is not None
        have_cosmic = importlib.util.find_spec("cosmic_ray") is not None
        findings.append(
            Finding(
                "MUTATION_TOOLING",
                Severity.INFO,
                f"变异测试工具: mutmut={have_mutmut}, cosmic-ray={have_cosmic}",
                "tests/",
            )
        )
    except Exception:
        pass

    if trivial == 0 and n_tests:
        findings.append(Finding("TEST_QUALITY", Severity.INFO, "未发现空测试 / 无意义断言", "tests/"))

    return findings


def main() -> int:
    """CLI 入口：python -m tools.test_audit"""
    return run_audit("Test Audit (J)", _collect)


if __name__ == "__main__":
    raise SystemExit(main())
