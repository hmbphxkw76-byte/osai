#!/usr/bin/env python3
"""宪法守卫一键入口 — 统一执行 specs + 架构 + 红线护栏验证。

用法:
    py guard              # 文本报告 (默认)
    py guard --fix-hints  # 含修复建议
    py guard --json       # JSON 输出 (CI 集成)
    py guard --rule R-H1  # 单规则验证
"""
from core.architecture_guard import main

if __name__ == "__main__":
    raise SystemExit(main())
