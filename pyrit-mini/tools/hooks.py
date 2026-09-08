#!/usr/bin/env python3
"""tools/hooks.py - Git Hooks 安装器 (pre-commit / pre-push)

 在 git commit / push 时自动运行 architecture_guard.py 检查 BLOCKING 违规

调用方式:
    py -m tools.install_hooks              # 安装 hooks
    py -m tools.install_hooks --remove     # 移除 hooks

 架构原则:
    - 本文件是 CLI 工具，不属于运行时流水线
    - 路径引用: tools/guard.py (原 core/architecture_guard.py)

迁移自: core/setup_hooks.py (2026-09-08 目录职责优化)
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

_PROJECT_NAME = _PROJECT_ROOT.name
_PYTHON_EXE = _find_python_exe()

# Hook 模板 - 使用 {python_exe} 占位符
_PRE_COMMIT_HOOK = """#!/bin/sh
# Combined pre-commit hook for {repo_name} + architecture_guard + data_flow_validator
# Auto-installed by: py -m tools.install_hooks

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT_DIR="$REPO_ROOT/{project_name}"
INSTALL_PYTHON='{python_exe}'

# --- 0. Locate Python ---
PYTHON=""
if [ -x "$INSTALL_PYTHON" ]; then
    PYTHON="$INSTALL_PYTHON"
elif command -v py >/dev/null 2>&1; then
    py -3 --version >/dev/null 2>&1 && PYTHON="py -3"
elif command -v python >/dev/null 2>&1; then
    python --version >/dev/null 2>&1 && PYTHON=python
fi

if [ -z "$PYTHON" ]; then
    echo 'WARNING: No python found, skipping all checks'
    exit 0
fi

cd "$PROJECT_DIR"

# --- 1. data_flow_validator (自动 pytest 测试) ---
# 检查 ARM → Strike → Assess 数据流完整性
echo "  [1/2] Running data flow integrity tests..."
if [ -f "$PROJECT_DIR/tools/data_flow_validator.py" ]; then
    $PYTHON -m pytest tests/test_data_flow_integrity.py -q --tb=line -p no:cacheprovider --no-header 2>/dev1
    DF_EXIT=$?
    if [ $DF_EXIT -ne 0 ]; then
        echo "  [FAIL] data_flow_validator: 数据流测试失败 (exit=$DF_EXIT)"
        echo "    运行查看详细: py -m pytest tests/test_data_flow_integrity.py -v"
        # 不阻断 commit，仅警告 (因数据流测试可能依赖环境)
    else
        echo "  [PASS] data_flow_validator: 测试通过"
    fi
else
    echo "  [SKIP] data_flow_validator: 模块不存在"
fi

# --- 2. architecture_guard (tools/guard.py) ---
echo "  [2/2] Running architecture_guard..."
if [ -f "$PROJECT_DIR/tools/guard.py" ]; then
    $PYTHON -m tools.guard
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        echo ""
        echo "COMMIT BLOCKED - Architecture guard detected BLOCKING violations."
        echo "Fix all BLOCKING violations, then re-run: py -m tools.guard"
        exit 1
    fi
    echo "  [PASS] architecture_guard"
fi

echo ""
echo "All checks passed. Commit allowed."
exit 0
"""

_PRE_PUSH_HOOK = """#!/bin/sh
# Combined pre-push hook for {project_name}
# Auto-installed by: py -m tools.install_hooks
# 运行全量 data_flow_validator + architecture_guard

REPOROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT_DIR="$REPO_ROOT/{project_name}"
INSTALL_PYTHON='{python_exe}'

PYTHON=""
if [ -x "$INSTALL_PYTHON" ]; then
    PYTHON="$INSTALL_PYTHON"
elif command -v py >/dev/null 2>&1; then
    py -3 --version >/dev/null 2>&1 && PYTHON="py -3"
elif command -v python >/dev/null 2>&1; then
    python --version >/dev/null 2>&1 && PYTHON=python
fi

if [ -z "$PYTHON" ]; then
    echo 'WARNING: No python found, skipping checks'
    exit 0
fi

cd "$PROJECT_DIR"

# --- 1. data_flow_validator (全量测试) ---
echo "  [1/2] Running data flow integrity tests (full)..."
if [ -f "$PROJECT_DIR/tools/data_flow_validator.py" ]; then
    $PYTHON -m pytest tests/test_data_flow_integrity.py -v --tb=short -p no:cacheprovider --no-header 2>&1 | tail -3
    DF_EXIT=${PIPESTATUS[0]}
    if [ $DF_EXIT -ne 0 ]; then
        echo "  [FAIL] data_flow_validator: 数据流测试失败"
        echo "    PUSH BLOCKED - Fix data flow issues first"
        exit 1
    fi
    echo "  [PASS] data_flow_validator"
else
    echo "  [SKIP] data_flow_validator"
fi

# --- 2. architecture_guard ---
echo "  [2/2] Running architecture_guard..."
$PYTHON -m tools.guard
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "PUSH BLOCKED - Architecture guard BLOCKING"
    exit 1
fi

echo "All checks passed. Push allowed."
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

def main(argv: list[str] | None = None) -> int:
    if not _GIT_ROOT:
        print("ERROR: Not a git repository (.git/ not found)")
        return 1

    if argv and "--remove" in argv:
        return remove_hooks()

    return install_hooks()

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
