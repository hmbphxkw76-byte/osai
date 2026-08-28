"""代码量守卫 — 防止项目膨胀覆辙。

检查项:
    1. 单文件行数: 任何 .py 文件超过 MAX_LINES_PER_FILE 行 → CRITICAL
    2. pipeline/ 总行数: 超过 MAX_TOTAL_LINES → CRITICAL
    3. pipeline/ 文件数: 超过 MAX_FILES → WARNING
    4. defaults.yaml 行数: 超过 MAX_CONFIG_LINES → CRITICAL
    5. strike/ 文件数: 超过 MAX_STRIKE_FILES → WARNING
    6. 死代码检测: escalation.py 中未被调用的 _run_* 函数 → WARNING

使用:
    python guard_complexity.py          # 检查
    python guard_complexity.py --fix    # 检查 + 输出修复建议

V2 规范目标:
    - pipeline/ 总行数: ~5,000 行 (当前: ~19,700, 已超 4x)
    - 单文件最大: ~200 行 (当前: escalation.py 2,648 行)
    - pipeline/ 文件数: ~35 (当前: 61)
    - defaults.yaml: <50 行 (当前: 42 行, 已优化)
    - escalation.py: 无死 _run_* 函数 (当前: 0, 已清理)
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_PIPELINE_DIR = _PROJECT_ROOT / "pipeline"
_STRIKE_DIR = _PIPELINE_DIR / "strike"
_ESCALATION_PATH = _STRIKE_DIR / "escalation.py"
_CONFIG_FILE = _PROJECT_ROOT / "config" / "defaults.yaml"

# ── 阈值 (基于 V2 规范, 放宽 2x 作为过渡期) ──
MAX_LINES_PER_FILE = 600       # V2 目标: 200, 过渡: 600
MAX_TOTAL_LINES = 12000        # V2 目标: 5000, 过渡: 12000
MAX_FILES = 50                 # V2 目标: 35, 过渡: 50
MAX_CONFIG_LINES = 60          # V2 目标: 50, 过渡: 60 (含 L5 必需参数)
MAX_STRIKE_FILES = 10          # V2 目标: 3, 过渡: 10


def count_lines(path: Path) -> int:
    """统计文件行数."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return len(lines)
    except Exception:
        return 0


def check_single_file_bloat() -> list[tuple[Path, int, str]]:
    """检查单文件膨胀."""
    violations: list[tuple[Path, int, str]] = []
    for py_file in _PIPELINE_DIR.rglob("*.py"):
        lines = count_lines(py_file)
        if lines > MAX_LINES_PER_FILE:
            rel = py_file.relative_to(_PROJECT_ROOT)
            severity = "CRITICAL" if lines > 1000 else "WARNING"
            violations.append((rel, lines, severity))
    return violations


def check_total_lines() -> tuple[int, str]:
    """检查 pipeline/ 总行数."""
    total = sum(count_lines(f) for f in _PIPELINE_DIR.rglob("*.py"))
    severity = "CRITICAL" if total > MAX_TOTAL_LINES else "OK"
    return total, severity


def check_file_count() -> tuple[int, str]:
    """检查 pipeline/ 文件数."""
    count = sum(1 for f in _PIPELINE_DIR.rglob("*.py") if f.stat().st_size > 0)
    severity = "WARNING" if count > MAX_FILES else "OK"
    return count, severity


def check_config_bloat() -> tuple[int, str]:
    """检查 defaults.yaml 行数."""
    lines = count_lines(_CONFIG_FILE)
    severity = "CRITICAL" if lines > MAX_CONFIG_LINES else "OK"
    return lines, severity


def check_strike_bloat() -> tuple[int, str]:
    """检查 strike/ 文件数."""
    if not _STRIKE_DIR.exists():
        return 0, "OK"
    count = sum(1 for f in _STRIKE_DIR.rglob("*.py") if f.stat().st_size > 0)
    severity = "WARNING" if count > MAX_STRIKE_FILES else "OK"
    return count, severity


def check_dead_code() -> list[tuple[str, int, str]]:
    """检查 escalation.py 中的死 _run_* 函数。

    死代码 = 定义了但从未在 check_and_escalate 函数中被调用的 _run_* 函数。
    这些函数通常是旧版本升级链的遗留包装函数。
    """
    if not _ESCALATION_PATH.exists():
        return []

    source = _ESCALATION_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)

    # 提取所有顶级 _run_* 函数定义
    all_runners: dict[str, tuple[int, int]] = {}  # name -> (start_line, end_line)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if (
                node.name.startswith("_run_")
                and node.end_lineno is not None
                and node.col_offset == 0  # 顶级函数
            ):
                all_runners[node.name] = (node.lineno, node.end_lineno)

    # 提取 check_and_escalate 函数体中调用的 _run_* 函数
    called_runners: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == "check_and_escalate":
                # 遍历函数体中的所有函数调用
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        if isinstance(child.func, ast.Name):
                            called_runners.add(child.func.id)
                        elif isinstance(child.func, ast.Attribute):
                            called_runners.add(child.func.attr)

    # 也要检查间接调用: _run_multi_model_escalation 中调用 _run_single_model
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if (
                node.name in called_runners  # 是被 check_and_escalate 调用的函数
                and node.name.startswith("_run_")
            ):
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        if isinstance(child.func, ast.Name):
                            called_runners.add(child.func.id)

    # 死函数 = 定义了但从未被调用的
    dead_funcs = []
    for name, (start, end) in sorted(all_runners.items(), key=lambda x: x[1][0]):
        if name not in called_runners:
            line_count = end - start + 1
            dead_funcs.append((name, line_count, f"lines {start}-{end}"))

    return dead_funcs


def main() -> int:
    """主检查函数. Returns 0=pass, 1=warning, 2=critical."""
    print("=" * 70)
    print("Code Guard -- prevent code bloat")
    print("=" * 70)
    print()

    exit_code = 0

    # 1. 单文件检查
    file_violations = check_single_file_bloat()
    if file_violations:
        has_critical = any(s == "CRITICAL" for _, _, s in file_violations)
        print(f"[{'CRITICAL' if has_critical else 'WARNING'}] "
              f"files over {MAX_LINES_PER_FILE} lines ({len(file_violations)} files):")
        for rel, lines, sev in sorted(file_violations, key=lambda x: -x[1]):
            print(f"  [{sev}] {lines:5d} lines  {rel}")
        if has_critical:
            exit_code = max(exit_code, 2)
        else:
            exit_code = max(exit_code, 1)
    else:
        print(f"[OK] all files <= {MAX_LINES_PER_FILE} lines")

    # 2. 总行数
    total, total_sev = check_total_lines()
    print(f"\n[{total_sev}] pipeline/ total: {total} / {MAX_TOTAL_LINES}")
    if total_sev == "CRITICAL":
        exit_code = max(exit_code, 2)

    # 3. 文件数
    count, count_sev = check_file_count()
    print(f"[{count_sev}] pipeline/ files: {count} / {MAX_FILES}")

    # 4. 配置行数
    cfg_lines, cfg_sev = check_config_bloat()
    print(f"[{cfg_sev}] config/defaults.yaml: {cfg_lines} / {MAX_CONFIG_LINES} lines")
    if cfg_sev == "CRITICAL":
        exit_code = max(exit_code, 2)

    # 5. strike/ 文件数
    strike_count, strike_sev = check_strike_bloat()
    print(f"[{strike_sev}] pipeline/strike/ files: {strike_count} / {MAX_STRIKE_FILES}")

    # 6. 死代码检测
    dead_funcs = check_dead_code()
    if dead_funcs:
        total_dead_lines = sum(lc for _, lc, _ in dead_funcs)
        print(f"\n[WARNING] dead _run_* functions in escalation.py ({len(dead_funcs)} funcs, {total_dead_lines} lines):")
        for name, lc, loc in dead_funcs:
            print(f"  [DEAD] {name} ({lc} lines, {loc})")
        exit_code = max(exit_code, 1)
    else:
        print("\n[OK] no dead _run_* functions in escalation.py")

    print()
    if exit_code == 0:
        print("[PASS] all checks passed")
    elif exit_code == 1:
        print("[WARN] warnings found, optimize recommended")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
