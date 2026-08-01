#!/usr/bin/env python3
# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Web Red Team Framework — 薄入口。.

仅串联 pipeline/ 下五个独立阶段, 自身不含任何业务逻辑。
对齐 main.py 的设计模式。

五阶段流程:
  1. pipeline.stages.stage_init    — PyRIT 原生初始化
  2. pipeline.stage_auth    — 认证 (人工辅助 + 自动检测)
  3. pipeline.stage_target  — 目标创建 (PlaywrightTarget)
  4. pipeline.stage_attack  — 攻击执行 (PromptSending/RedTeaming/Crescendo/TAP)
  5. pipeline.stages.stage_output  — 结果输出 (Markdown 报告)

Usage:
  python -m web_redteam.run --target-profile <yaml> --attack-type <type> --objective <text>
"""

import asyncio
import logging
import sys

from web_redteam.config import parse_args
from web_redteam.pipeline.context import WebRedteamContext
from web_redteam.pipeline.stage_attack import run as stage_attack
from web_redteam.pipeline.stage_auth import run as stage_auth
from web_redteam.pipeline.stages.stage_init import run as stage_init
from web_redteam.pipeline.stages.stage_output import run as stage_output
from web_redteam.pipeline.stage_target import run as stage_target

# Windows 事件循环策略 (对齐 doc/code/targets/10_2_playwright_target_copilot.py)
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

logger = logging.getLogger(__name__)


async def main_async() -> None:
    """串联五个阶段。."""
    ctx = WebRedteamContext(args=parse_args())

    try:
        await stage_init(ctx)
        await stage_auth(ctx)
        await stage_target(ctx)
        await stage_attack(ctx)
        await stage_output(ctx)
    finally:
        # 清理浏览器会话
        if ctx.browser_session:
            await ctx.browser_session.close()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n用户中断")
        sys.exit(0)
