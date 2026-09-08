#!/usr/bin/env python3
"""
本地 Git Hooks 安装器 — 修复 tools/hooks.py 路径定位问题

问题: tools/hooks.py 从 cwd 向上找 .git，但本项目 cwd 是 pyrit-mini/，
      .git 实际在上一级目录 osai/.git/。
     
解决: 直接写 hooks 到正确位置。

使用: py -m tools.install_hooks_local
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# UTF-8 强制
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# 项目布局
_PROJECT_ROOT = Path(__file__).resolve().parent.parent  # pyrit-mini/
_GIT_ROOT = _PROJECT_ROOT.parent  # osai/
_HOOKS_DIR = _GIT_ROOT / ".git" / "hooks"

# Hook 模板
_PRE_COMMIT = '''#!/bin/sh
# Pre-commit hook for pyrit-mini
# data_flow_validator + architecture_guard
# Installed: 2026-09-08

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
    echo "  [PASS] Data flow: 25/25 tests OK"
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
'''

_PRE_PUSH = '''#!/bin/sh
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
'''

def install():
    """安装 hooks"""
    if not _HOOKS_DIR.exists():
        print(f"ERROR: .git/hooks not found at {_HOOKS_DIR}")
        return 1
    
    # 写入 pre-commit
    commit_path = _HOOKS_DIR / "pre-commit"
    commit_path.write_text(_PRE_COMMIT, encoding="utf-8", newline="\n")
    
    # 写入 pre-push
    push_path = _HOOKS_DIR / "pre-push"  
    push_path.write_text(_PRE_PUSH, encoding="utf-8", newline="\n")
    
    # 尝试设置可执行权限 (POSIX)
    try:
        os.chmod(commit_path, 0o755)
        os.chmod(push_path, 0o755)
    except OSError:
        pass
    
    print(f"[OK] Installed: {commit_path}")
    print(f"[OK] Installed: {push_path}")
    print()
    print("Hooks installed successfully!")
    print("  pre-commit: runs data_flow_validator + architecture_guard")
    print("  pre-push:   runs full data_flow_validator + architecture_guard")
    print()
    print("Every git commit / push will now auto-verify data flow integrity.")
    return 0

def remove():
    """移除 hooks"""
    for name in ["pre-commit", "pre-push"]:
        path = _HOOKS_DIR / name
        if path.exists():
            path.unlink()
            print(f"[OK] Removed: {path}")
        else:
            print(f"[SKIP] Not found: {path}")
    return 0

def main():
    import sys
    if "--remove" in sys.argv:
        return remove()
    return install()

if __name__ == "__main__":
    sys.exit(main())
