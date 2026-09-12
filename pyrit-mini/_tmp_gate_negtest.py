"""临时负面测试：验证 R-GATE-2 能拦截静默降级（用完即删）。"""
from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys

GATE = pathlib.Path("tools/gate.py")
BAK = pathlib.Path("tools/gate.py.bak")

shutil.copy(GATE, BAK)
try:
    original = GATE.read_text(encoding="utf-8")
    GATE.write_text(original.replace("禁止降级为跳过", "视为非阻塞"), encoding="utf-8")
    print("--- patched gate.py (simulated old silent-skip) ---")
    proc = subprocess.run([sys.executable, "-m", "tools.guard"], capture_output=True, text=True, encoding="utf-8")
    tail = [ln for ln in proc.stdout.splitlines() if "R-GATE" in ln or "扫描结果" in ln]
    print("\n".join(tail) or proc.stdout[-800:])
    print("exit code:", proc.returncode)
finally:
    shutil.copy(BAK, GATE)
    BAK.unlink()
    print("--- restored gate.py ---")
