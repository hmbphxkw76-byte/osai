#!/usr/bin/env python3
"""Install git hooks from hooks/ into .git/hooks/.

幂等：把 hooks/ 下每个文件复制到 <root>/.git/hooks/，同名覆盖，并赋予可执行位。
对应 INSTALL_HOOKS_CMD。详见 docs/ai-dev-guides.md §5.2。

Usage:
    python tools/install_hooks.py [--hooks-dir hooks] [--git-dir .git]
"""
from __future__ import annotations

import argparse
import shutil
import stat
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    ap = argparse.ArgumentParser(description="Install git hooks from hooks/")
    ap.add_argument("--hooks-dir", default="hooks")
    ap.add_argument("--git-dir", default=".git")
    args = ap.parse_args()

    src = ROOT / args.hooks_dir
    dst = ROOT / args.git_dir / "hooks"
    if not src.is_dir():
        print(f"[ERR] hooks 源目录不存在: {src}")
        return 1

    dst.mkdir(parents=True, exist_ok=True)
    count = 0
    for hook in sorted(src.iterdir()):
        if hook.is_file():
            target = dst / hook.name
            shutil.copy2(hook, target)
            try:
                target.chmod(target.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
            except OSError:
                pass  # Windows 忽略可执行位
            print(f"[OK] {hook.name} -> {target}")
            count += 1

    print(f"\n[SUMMARY] 已安装 {count} 个 hook 到 {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
