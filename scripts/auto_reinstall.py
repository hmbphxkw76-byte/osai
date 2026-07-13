"""自动检测代码变更并重新安装包。

使用方法：
    python scripts/auto_reinstall.py
    或
    make watch

特性：
    - 监控 redteam/ 目录下的 .py 文件变更
    - 检测到变更后自动重新安装包（pip install -e .）
    - 支持 Windows 和 Linux/macOS
"""
import os
import subprocess
import sys
import time
from pathlib import Path

WATCH_DIR = Path(__file__).parent.parent / "redteam"
LAST_CHECK_TIME = 0
LAST_MODIFIED = {}


def get_latest_modified_time():
    latest = 0
    for root, dirs, files in os.walk(WATCH_DIR):
        dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git")]
        for f in files:
            if f.endswith(".py"):
                fp = Path(root) / f
                try:
                    mtime = fp.stat().st_mtime
                    latest = max(latest, mtime)
                except Exception:
                    pass
    return latest


def reinstall_package():
    print("\n" + "="*60)
    print("🔄 检测到代码变更，正在重新安装包...")
    print("="*60)
    
    python = sys.executable
    result = subprocess.run(
        [python, "-m", "pip", "install", "-e", ".", "--no-deps"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    
    if result.returncode == 0:
        print("✓ 重新安装成功！")
    else:
        print("✗ 重新安装失败:")
        print(result.stderr)
    
    print("="*60 + "\n")


def main():
    global LAST_CHECK_TIME
    
    print(f"🔍 正在监控目录: {WATCH_DIR}")
    print("   检测到 .py 文件变更时将自动重新安装包")
    print("   按 Ctrl+C 退出\n")
    
    LAST_CHECK_TIME = get_latest_modified_time()
    
    try:
        while True:
            time.sleep(2)
            current_time = get_latest_modified_time()
            if current_time > LAST_CHECK_TIME:
                LAST_CHECK_TIME = current_time
                reinstall_package()
    except KeyboardInterrupt:
        print("\n👋 退出监控")


if __name__ == "__main__":
    main()
