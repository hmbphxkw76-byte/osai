#!/usr/bin/env python3
"""
tools/scenarios.py - 场景路由列表 CLI

 列出所有可用的攻击场景 (--list-scenarios 参数调用)

调用方式:
    py -m tools.list_scenarios            # 列出所有场景
    python main.py --list-scenarios       # 或从主入口调用

 架构原则:
    - 本文件是 CLI 工具，不属于运行时流水线
    - 提供场景的独立查看入口 (不启动攻击)

迁移自: core/scenario_router.py 的 main() 函数 (2026-09-08 目录职责优化)
"""

from __future__ import annotations

import logging

from core.scenario_router import get_router


def main() -> None:
    """CLI entry point for --list-scenarios."""
    router = get_router()
    print(router.format_scenarios_display())


if __name__ == "__main__":
    # 示例: py -m tools.list_scenarios
    logging.basicConfig(level=logging.INFO)
    main()
