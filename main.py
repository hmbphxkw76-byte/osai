#!/usr/bin/env python3
"""
===============================================================================
RedTeam_AI 完整 AI 红队流水线 — 主入口
===============================================================================

使用方式:
  python main.py --target https://target.com --mode auto
  python main.py --target https://target.com --stage recon

代码已拆分至 pipeline/ 子包:
  pipeline/models.py    — 数据模型 & 常量
  pipeline/guidance.py  — 阶段专家指导
  pipeline/engine.py    — 全流程编排引擎
  pipeline/cli.py       — CLI 入口
===============================================================================
"""
from __future__ import annotations

from pipeline.cli import main

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
