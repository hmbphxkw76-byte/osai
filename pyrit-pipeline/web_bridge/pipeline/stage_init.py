# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Stage 1: PyRIT 原生初始化。.

职责:
  - 调用 initialize_pyrit_async() 初始化 CentralMemory + 全部 Registry

产出 (写入 WebBridgeContext):
  - ctx.config = 初始化完成标志

依赖的原生 API:
  - pyrit.setup.initialize_pyrit_async
"""

import logging

from web_bridge.pipeline.context import WebBridgeContext

logger = logging.getLogger(__name__)


async def run(ctx: WebBridgeContext) -> None:
    """执行 Stage 1: PyRIT 原生初始化。."""
    print("=" * 70)
    print("[Stage 1] PyRIT 原生初始化")
    print("=" * 70)

    from pyrit.setup import IN_MEMORY, initialize_pyrit_async

    await initialize_pyrit_async(memory_db_type=IN_MEMORY)
    ctx.config = True

    print("  CentralMemory + 全部 Registry 就绪")
    logger.info("Stage 1: PyRIT initialized (IN_MEMORY)")
