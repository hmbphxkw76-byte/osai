#!/usr/bin/env python3
"""tools/hooks.py - Git Hooks 安装器 (pre-commit / pre-push)

 在 git commit / push 时自动运行 architecture_guard.py 检查 BLOCKING 违规

调用方式:
    py -m tools.hooks              # 安装 hooks
    py -m tools.hooks --remove     # 移除 hooks
    py -m tools.hooks --local      # 本地模式 (.git 在上级目录)

 架构原则:
    - 本文件是 CLI 工具，不属于运行时流水线
    - 路径引用: tools/guard.py (原 core/architecture_guard.py)

迁移自: core/setup_hooks.py (2026-09-08 目录职责优化)
更新: 2026-09-09 增强 MSYS2/Git Bash 兼容性 (修复 GitHub Desktop 提交报错)
合并自: tools/install_hooks_local.py (2026-09-10 功能合并)
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# UTF-8 强制 (兼容 Windows GBK 终端)
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def find_git_root() -> str | None:
    """定位 .git 根目录"""
    # Method 1: Try using git command
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            capture_output=True,
            text=False,
            cwd=str(_PROJECT_ROOT),
        )
        if result.returncode == 0:
            git_dir_str = result.stdout.decode("utf-8", errors="replace").strip()
            git_dir = os.path.abspath(git_dir_str)
            if not os.path.isabs(git_dir):
                git_dir = os.path.abspath(os.path.join(str(_PROJECT_ROOT), git_dir_str))
            return os.path.dirname(git_dir)
    except Exception:
        pass

    # Method 2: Fallback - search for .git directory by walking up
    current = _PROJECT_ROOT
    while current != current.parent:
        git_dir = current / ".git"
        if git_dir.exists():
            return str(current)
        current = current.parent

    return None


def _find_python_exe() -> str:
    """定位 Python 可执行文件路径"""
    try:
        result = subprocess.run(
            [sys.executable, "-c", "import sys; print(sys.executable)"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            exe = result.stdout.strip()
            return exe.replace("/", "\\")
    except Exception:
        pass
    return sys.executable.replace("/", "\\")


_GIT_ROOT = find_git_root()
_HOOKS_DIR = None
if _GIT_ROOT:
    candidate = os.path.join(_GIT_ROOT, ".git", "hooks")
    if os.path.exists(candidate):
        _HOOKS_DIR = candidate
    else:
        candidate2 = os.path.join(_GIT_ROOT, "hooks")
        if os.path.exists(candidate2):
            _HOOKS_DIR = candidate2


def _get_local_paths() -> tuple[Path, Path, Path]:
    """本地模式: .git 在上级目录 (合并自 install_hooks_local.py)

    返回: (project_root, git_root, hooks_dir)
    """
    project_root = Path(__file__).resolve().parent.parent  # pyrit-mini/
    git_root = project_root.parent  # osai/
    hooks_dir = git_root / ".git" / "hooks"
    return project_root, git_root, hooks_dir


_PROJECT_NAME = _PROJECT_ROOT.name
_PYTHON_EXE = _find_python_exe()

# Hook 模板 - 使用 {python_exe} 占位符
# 注意: {{ 和 }} 是 Python format 转义，输出为单个 { 和 }
_PRE_COMMIT_HOOK = """#!/bin/sh
# Combined pre-commit hook for {repo_name} + architecture_guard + data_flow_validator
# Auto-installed by: py -m tools.install_hooks
# Compatible: Windows Git Bash (MSYS2) / WSL / Linux / macOS
# Strategy: fail-open on env issues, block only on guard violations

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT_DIR="$REPO_ROOT/{project_name}"

# --- 0. Locate Python ---
PYTHON=""

_find_python() {{
    for _cmd in py py.exe python python3; do
        if command -v "$_cmd" >/dev/null 2>&1; then
            if "$_cmd" -c "import sys" >/dev/null 2>&1; then
                PYTHON="$_cmd"
                return
            fi
        fi
    done
    _WIN_PY='{python_exe}'
    [ -x "$_WIN_PY" ] && PYTHON="$_WIN_PY" && return
    _MSYS_PY="$(echo "$_WIN_PY" | sed 's|^\\([A-Za-z]\\):|/\\L\\1|; s|\\\\|/|g')"
    [ -x "$_MSYS_PY" ] && PYTHON="$_MSYS_PY" && return
}}

_find_python

if [ -z "$PYTHON" ] || ! $PYTHON -c "import sys" >/dev/null 2>&1; then
    echo '  [SKIP] pre-commit: Python not available (commit allowed)'
    exit 0
fi

cd "$PROJECT_DIR" || exit 0

# --- 1. data_flow_validator ---
echo "  [1/2] Running data flow integrity tests..."
DF_OUTPUT=$($PYTHON -m pytest tests/test_data_flow_integrity.py -q --tb=line -p no:cacheprovider --no-header 2>&1)
DF_EXIT=$?
if [ $DF_EXIT -ne 0 ]; then
    echo "  [WARN] data flow tests failed (non-blocking)"
    echo "$DF_OUTPUT" | tail -3
else
    echo "  [PASS] data_flow_validator"
fi

# --- 2. architecture_guard (BLOCKING) ---
echo "  [2/2] Running architecture_guard..."
GUARD_OUTPUT=$($PYTHON -m tools.guard 2>&1)
GUARD_EXIT=$?
if [ $GUARD_EXIT -ne 0 ]; then
    echo ""
    echo "$GUARD_OUTPUT" | tail -10
    echo ""
    echo "  COMMIT BLOCKED - Fix BLOCKING violations listed above"
    echo "  Verify with: py -m tools.guard"
    exit 1
fi
echo "  [PASS] architecture_guard"

echo ""
echo "  All checks passed. Commit allowed."
exit 0
"""

_PRE_PUSH_HOOK = """#!/bin/sh
# Combined pre-push hook for {project_name}
# Runs: data_flow_validator + architecture_guard + drift_detector
# Strategy: push blocked only on actual test/guard failures

REPOROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT_DIR="$REPO_ROOT/{project_name}"

# --- 0. Locate Python ---
PYTHON=""

_find_python() {{
    for _cmd in py py.exe python python3; do
        if command -v "$_cmd" >/dev/null 2>&1; then
            if "$_cmd" -c "import sys" >/dev/null 2>&1; then
                PYTHON="$_cmd"
                return
            fi
        fi
    done
    _WIN_PY='{python_exe}'
    [ -x "$_WIN_PY" ] && PYTHON="$_WIN_PY" && return
    _MSYS_PY="$(echo "$_WIN_PY" | sed 's|^\\([A-Za-z]\\):|/\\L\\1|; s|\\\\|/|g')"
    [ -x "$_MSYS_PY" ] && PYTHON="$_MSYS_PY" && return
}}

_find_python

if [ -z "$PYTHON" ] || ! $PYTHON -c "import sys" >/dev/null 2>&1; then
    echo '  [SKIP] pre-push: Python not available (push allowed)'
    exit 0
fi

cd "$PROJECT_DIR" || exit 0

# --- 1. data_flow_validator ---
echo "  [1/3] Running data flow integrity tests..."
if [ -f "$PROJECT_DIR/tools/data_flow_validator.py" ]; then
    DF_OUTPUT=$($PYTHON -m pytest tests/test_data_flow_integrity.py -q --tb=line -p no:cacheprovider --no-header 2>&1)
    DF_EXIT=$?
    if [ $DF_EXIT -ne 0 ]; then
        echo "  [FAIL] data flow tests failed"
        echo "$DF_OUTPUT" | tail -5
        echo "  PUSH BLOCKED"
        exit 1
    fi
    echo "  [PASS] data_flow_validator"
fi

# --- 2. architecture_guard ---
echo "  [2/3] Running architecture_guard..."
GUARD_OUTPUT=$($PYTHON -m tools.guard 2>&1)
GUARD_EXIT=$?
if [ $GUARD_EXIT -ne 0 ]; then
    echo "$GUARD_OUTPUT" | tail -10
    echo "  PUSH BLOCKED - BLOCKING violations found"
    exit 1
fi
echo "  [PASS] architecture_guard"

# --- 3. drift_detector ---
echo "  [3/3] Running drift_detector..."
if [ -f "$PROJECT_DIR/tools/drift_detector.py" ]; then
    DRIFT_OUTPUT=$($PYTHON -m tools.drift_detector --full 2>&1)
    DRIFT_EXIT=$?
    if [ $DRIFT_EXIT -ne 0 ]; then
        echo "  [FAIL] drift_detector: blocking drift detected"
        exit 1
    fi
    echo "  [PASS] drift_detector"
fi

echo "  All checks passed. Push allowed."
exit 0
"""

HOOKS = {
    "pre-commit": _PRE_COMMIT_HOOK,
    "pre-push": _PRE_PUSH_HOOK,
}


def install_hooks() -> int:
    """安装 Git hooks"""
    if not _HOOKS_DIR or not os.path.exists(_HOOKS_DIR):
        print("ERROR: .git/hooks/ directory not found")
        return 1

    for name, template in HOOKS.items():
        content = template.format(
            repo_name=os.path.basename(_GIT_ROOT) if _GIT_ROOT else "repo",
            project_name=_PROJECT_NAME,
            python_exe=_PYTHON_EXE,
        )
        hook_path = os.path.join(_HOOKS_DIR, name)
        with open(hook_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
        try:
            os.chmod(hook_path, 0o755)
        except OSError:
            pass
        print(f"Installed: {hook_path}")

    print()
    print("Git hooks installed successfully!")
    print("  pre-commit: blocks commits with BLOCKING violations")
    print("  pre-push:   blocks pushes with BLOCKING violations")
    print()
    print("Every git commit / push now auto-runs tools/guard.py")
    print("No manual execution needed.")
    print()
    print("[WARN]  R10 Reminder: After every code change, also run:")
    print("    python main.py --dry-run --max-seeds 1  (zero-token pipeline check)")
    print("    (Git hooks run static guard only - dry-run is runtime verification)")
    return 0


def remove_hooks() -> int:
    """移除 Git hooks"""
    for name in HOOKS:
        if not _HOOKS_DIR:
            continue
        hook_path = os.path.join(_HOOKS_DIR, name)
        if os.path.exists(hook_path):
            os.unlink(hook_path)
            print(f"Removed: {hook_path}")
        else:
            print(f"Not found: {hook_path}")

    print()
    print("Git hooks removed. Manual guard runs required again:")
    print("  py -m tools.guard")
    print("  python main.py --dry-run --max-seeds 1  (R10 runtime verification)")
    return 0


def install_hooks_local() -> int:
    """安装 Git hooks (本地模式 - .git 在上级目录)

    合并自 tools/install_hooks_local.py
    适用于 .git 目录在项目目录上一级的情况 (如 osai/pyrit-mini/)
    """
    project_root, git_root, hooks_dir = _get_local_paths()

    if not hooks_dir.exists():
        print(f"ERROR: .git/hooks not found at {hooks_dir}")
        return 1

    # 使用本地化的 hook 模板
    _PRE_COMMIT_LOCAL = """#!/bin/sh
# Pre-commit hook for pyrit-mini
# data_flow_validator + architecture_guard
# Installed: 2026-09-10 (merged from install_hooks_local.py)

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT_DIR="$REPO_ROOT/pyrit-mini"

# --- Find Python ---
PYTHON=""
if command -v py >/dev/null 2>&1; then
    py -3 --version >/dev/null 2>&1 && PYTHON="py -3"
elif command -v python >/dev/null 2>&1; then
    python --version >/dev/null 2>&1 && PYTHON=python
fi

if [ -z "$PYTHON" ]; then
    echo "WARN: Python not found, skipping"
    exit 0
fi

cd "$PROJECT_DIR"

# --- 1. Data Flow Validator ---
echo "  [1/2] Data flow validator..."
$PYTHON -m pytest tests/test_data_flow_integrity.py -q --tb=line -p no:cacheprovider --no-header 2>&1 | tail -2
DF_EXIT=${PIPESTATUS[0]}
if [ $DF_EXIT -ne 0 ]; then
    echo "  [WARN] Data flow tests failed (check: py -m pytest tests/test_data_flow_integrity.py -v)"
else
    echo "  [PASS] Data flow OK"
fi

# --- 2. Architecture Guard ---
echo "  [2/2] Architecture guard..."
$PYTHON -m tools.guard 2>&1 | tail -5
EXIT_CODE=${PIPESTATUS[0]}
if [ $EXIT_CODE -ne 0 ]; then
    echo "  [BLOCK] Architecture guard found BLOCKING violations"
    echo "  Fix: py -m tools.guard"
    exit 1
fi

echo "[PASS] All checks passed. Commit allowed."
exit 0
"""

    _PRE_PUSH_LOCAL = """#!/bin/sh
# Pre-push hook for pyrit-mini (full checks)
# data_flow_validator + architecture_guard

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT_DIR="$REPO_ROOT/pyrit-mini"

PYTHON=""
if command -v py >/dev/null 2>&1; then
    py -3 --version >/dev/null 2>&1 && PYTHON="py -3"
elif command -v python >/dev/null 2>&1; then
    python --version >/dev/null 2>&1 && PYTHON=python
fi

if [ -z "$PYTHON" ]; then
    echo "WARN: Python not found, skipping"
    exit 0
fi

cd "$PROJECT_DIR"

# --- Full Data Flow Validation ---
echo "  [1/2] Data flow validator (full)..."
$PYTHON -m pytest tests/test_data_flow_integrity.py -v --tb=short -p no:cacheprovider --no-header 2>&1 | tail -5
DF_EXIT=${PIPESTATUS[0]}
if [ $DF_EXIT -ne 0 ]; then
    echo "  [BLOCK] Data flow tests failed"
    echo "  Fix issues: py -m pytest tests/test_data_flow_integrity.py -v -s"
    exit 1
fi
echo "  [PASS] Data flow validation OK"

# --- Architecture Guard ---
echo "  [2/2] Architecture guard..."
$PYTHON -m tools.guard 2>&1 | tail -10
EXIT_CODE=${PIPESTATUS[0]}
if [ $EXIT_CODE -ne 0 ]; then
    echo "  [BLOCK] Architecture guard found violations"
    exit 1
fi

echo "[PASS] Push allowed."
exit 0
"""

    # 写入 hooks
    commit_path = hooks_dir / "pre-commit"
    commit_path.write_text(_PRE_COMMIT_LOCAL, encoding="utf-8", newline="\n")

    push_path = hooks_dir / "pre-push"
    push_path.write_text(_PRE_PUSH_LOCAL, encoding="utf-8", newline="\n")

    # 尝试设置可执行权限 (POSIX)
    try:
        os.chmod(commit_path, 0o755)
        os.chmod(push_path, 0o755)
    except OSError:
        pass

    print(f"[OK] Installed: {commit_path}")
    print(f"[OK] Installed: {push_path}")
    print()
    print("Hooks installed successfully! (local mode)")
    print("  pre-commit: runs data_flow_validator + architecture_guard")
    print("  pre-push:   runs full data_flow_validator + architecture_guard")
    print()
    print("Every git commit / push will now auto-verify data flow integrity.")
    return 0


def remove_hooks_local() -> int:
    """移除 Git hooks (本地模式)"""
    _, _, hooks_dir = _get_local_paths()

    for name in ["pre-commit", "pre-push"]:
        path = hooks_dir / name
        if path.exists():
            path.unlink()
            print(f"[OK] Removed: {path}")
        else:
            print(f"[SKIP] Not found: {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    # 本地模式: .git 在上级目录
    if argv and "--local" in argv:
        if argv and "--remove" in argv:
            return remove_hooks_local()
        return install_hooks_local()

    if not _GIT_ROOT:
        print("ERROR: Not a git repository (.git/ not found)")
        return 1

    if argv and "--remove" in argv:
        return remove_hooks()

    return install_hooks()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
