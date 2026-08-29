#!/usr/bin/env python3
"""Git Hooks 安装脚本 — 一键配置 pre-commit / pre-push 自动检查。

安装后，每次 git commit 和 git push 都会自动运行 architecture_guard.py，
任何 BLOCKING 违规都会阻止提交，无需开发者手动运行。

用法:
    python core/setup_hooks.py          # 安装 hooks
    python core/setup_hooks.py --remove # 卸载 hooks

学术依据: 无 (工程门禁工具, R3 工程门禁自动化)
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# UTF-8 enforcement (Windows GBK terminal compatibility)
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def find_git_root() -> str | None:
    """查找真实的 git 仓库根目录（处理子目录场景）。返回仓库根路径字符串。"""
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
    """查找 Python 可执行文件完整路径，用于 hook 中硬编码。"""
    try:
        result = subprocess.run(
            [sys.executable, "-c", "import sys; print(sys.executable)"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            exe = result.stdout.strip()
            # 转换为 Windows 路径格式
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

# Hook 模板 — 使用 {python_exe} 硬编码完整路径避免 PATH 问题
_PRE_COMMIT_HOOK = """#!/bin/sh
# Combined pre-commit hook for {repo_name} + architecture_guard
# Auto-installed by: python {project_name}/core/setup_hooks.py

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT_DIR="$REPO_ROOT/{project_name}"
INSTALL_PYTHON='{python_exe}'

# --- 1. architecture_guard ({project_name}) ---
# Run FIRST - fast static check, no test execution
if [ -f "$PROJECT_DIR/core/architecture_guard.py" ]; then
    PYTHON=""
    if [ -x "$INSTALL_PYTHON" ]; then
        PYTHON="$INSTALL_PYTHON"
    elif command -v py >/dev/null 2>&1; then
        py -3 --version >/dev/null 2>&1 && PYTHON="py -3"
    elif command -v python >/dev/null 2>&1; then
        python --version >/dev/null 2>&1 && PYTHON=python
    fi
    if [ -z "$PYTHON" ]; then
        echo 'WARNING: No python found, skipping architecture_guard'
    else
        echo "Running architecture_guard.py (pre-commit, {project_name})..."
        cd "$PROJECT_DIR"
        $PYTHON core/architecture_guard.py --fix-hints
        EXIT_CODE=$?
        if [ $EXIT_CODE -ne 0 ]; then
            echo ""
            echo "COMMIT BLOCKED - Architecture guard detected BLOCKING violations."
            echo "Fix all BLOCKING violations, then re-run: python core/architecture_guard.py --fix-hints"
            exit 1
        fi
        echo "Architecture guard passed."
    fi
fi

# --- 2. Existing pre-commit framework (if any sibling project) ---
# This section runs any existing pre-commit-config.yaml from sibling projects
# Uncomment and adjust if needed:
# ARGS=(hook-impl '--config=sibling-project/.pre-commit-config.yaml' --hook-type=pre-commit)
# HERE="$(cd "$(dirname "$0")" && pwd)"
# ARGS+=(--hook-dir "$HERE" -- "$@")
# if [ -x "$INSTALL_PYTHON" ]; then
#     "$INSTALL_PYTHON" -mpre_commit "${{ARGS[@]}}" || exit 1
# fi

exit 0
"""

_PRE_PUSH_HOOK = """#!/bin/sh
# Combined pre-push hook for {project_name}
# Auto-installed by: python {project_name}/core/setup_hooks.py

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT_DIR="$REPO_ROOT/{project_name}"
INSTALL_PYTHON='{python_exe}'

if [ -f "$PROJECT_DIR/core/architecture_guard.py" ]; then
    PYTHON=""
    if [ -x "$INSTALL_PYTHON" ]; then
        PYTHON="$INSTALL_PYTHON"
    elif command -v py >/dev/null 2>&1; then
        py -3 --version >/dev/null 2>&1 && PYTHON="py -3"
    elif command -v python >/dev/null 2>&1; then
        python --version >/dev/null 2>&1 && PYTHON=python
    fi
    if [ -z "$PYTHON" ]; then
        echo 'WARNING: No python found, skipping architecture_guard'
        exit 0
    fi

    echo "Running architecture_guard.py (pre-push, {project_name})..."

    cd "$PROJECT_DIR"
    $PYTHON core/architecture_guard.py --fix-hints
    EXIT_CODE=$?

    if [ $EXIT_CODE -ne 0 ]; then
        echo ""
        echo "PUSH BLOCKED - Architecture guard detected BLOCKING violations."
        echo "Fix all BLOCKING violations, then re-run: python core/architecture_guard.py --fix-hints"
        exit 1
    fi

    echo "Architecture guard passed - push allowed."
fi

exit 0
"""

HOOKS = {
    "pre-commit": _PRE_COMMIT_HOOK,
    "pre-push": _PRE_PUSH_HOOK,
}


def install_hooks() -> int:
    """安装 Git hooks。"""
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
    print("Every git commit / push now auto-runs architecture_guard.py")
    print("No manual execution needed.")
    return 0


def remove_hooks() -> int:
    """卸载 Git hooks。"""
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
    print("  python core/architecture_guard.py --fix-hints")
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
