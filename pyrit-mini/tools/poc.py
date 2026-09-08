#!/usr/bin/env python3
"""
tools/poc.py - PoC 生成器 CLI

 独立运行 PoC (Proof of Concept) 证据生成和验证流程

调用方式:
    py -m tools.poc                   # 运行 PoC 生成
    python main.py --stage report     # 从主入口调用 (report 阶段生成 PoC)

 架构原则:
    - 本文件是 CLI 工具入口，不属于运行时流水线
    - 实际 PoC 生成逻辑仍在 report/poc_generator.py
    - 此入口允许单独调试/测试 PoC 生成流程

迁移自: report/poc_generator.py 的 __main__ 块 (2026-09-08 目录职责优化)
"""

from __future__ import annotations

import asyncio
import sys


def main() -> None:
    """CLI entry point for PoC generation."""
    from report.poc_generator import run_poc
    success = asyncio.run(run_poc())
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
