# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Stage 3: 目标创建。.

职责:
  - 从 profile.interaction 配置生成 interaction_func
  - 创建 PlaywrightTarget(interaction_func, page)

产出 (写入 WebBridgeContext):
  - ctx.target = PlaywrightTarget 实例

依赖的原生 API:
  - pyrit.prompt_target.PlaywrightTarget
"""

import logging

from web_bridge.pipeline.context import WebBridgeContext

logger = logging.getLogger(__name__)


async def run(ctx: WebBridgeContext) -> None:
    """执行 Stage 3: 目标创建。."""
    print("\n" + "=" * 70)
    print("[Stage 3] 目标创建 (PlaywrightTarget)")
    print("=" * 70)

    from pyrit.prompt_target import PlaywrightTarget

    from web_bridge.interaction.interaction_factory import InteractionFactory

    # 从 profile 生成 interaction_func
    interaction_func = InteractionFactory.create(ctx.profile.interaction)

    # 创建 PlaywrightTarget (原生 API)
    ctx.target = PlaywrightTarget(
        interaction_func=interaction_func,
        page=ctx.page,
        max_requests_per_minute=getattr(ctx.args, "max_rpm", None),
    )

    print("  PlaywrightTarget 已创建")
    print(f"    输入选择器: {ctx.profile.interaction.input.selector}")
    print(f"    发送选择器: {ctx.profile.interaction.send.selector}")
    print(f"    响应选择器: {ctx.profile.interaction.response.selector}")
    print(f"    等待策略: {ctx.profile.interaction.response.wait_strategy}")

    logger.info("Stage 3: PlaywrightTarget created")
