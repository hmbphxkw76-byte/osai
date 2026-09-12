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

import sys


def main() -> None:
    """CLI entry point for PoC generation.

    W0 fix: `from report.poc_generator import run_poc` could never succeed - both definitions
    of `run_poc` in that module are nested inside the generator, so the symbol is not
    importable and the console script died with ImportError. Report the real state instead
    of shipping a broken entry point.
    """
    sys.stderr.write(
        "pyrit-poc is unavailable: report.poc_generator has no module-level run_poc().\n"
        "PoC scripts are emitted by the report phase via generate_poc_script(evidence)\n"
        "or generate_component_poc(evidence).\n"
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
