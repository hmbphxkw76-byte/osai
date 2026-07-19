# -*- coding: utf-8 -*-
import os

base = "pyrit_ai300/reconnaissance/adapters/"
print("=== adapters/ 目录结构 ===")
for r, ds, fs in os.walk(base):
    for f in sorted(fs):
        if f.endswith(".py"):
            path = os.path.join(r, f)
            rel = os.path.relpath(path, base)
            n = sum(1 for _ in open(path, encoding="utf-8"))
            print(f"  {rel:40s} {n:6d}")
