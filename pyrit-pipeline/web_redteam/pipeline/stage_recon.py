# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Stage 1: 侦察数据加载 (Recon Data Loader).

在 API 模式下，侦察不再依赖 recon-pipeline (core 模块)，
而是从外部 JSON 文件加载 recon-pipeline 已经产出的侦察结果。

数据流:
  --recon-data <json_file>  →  ctx.recon_result (dict)
  无 --recon-data            →  跳过侦察 (ctx.recon_result = None)

侦察数据 JSON 格式 (由 recon-pipeline 产出)::

    {
      "target_url": "https://example.com/chat",
      "auth_type": "none",
      "endpoints": [
        {"method": "POST", "url": "/api/chat", "endpoint_type": "llm_inference"}
      ],
      "injection_surfaces": [
        {"surface_type": "chat_input", "selector": "textarea"}
      ],
      "recommendations": [
        {"owasp_id": "LLM01", "attack_strategy": "prompt_sending", "priority": 1}
      ]
    }

> **日期**: 2026-8-3
> **变更**: 完全移除 core (recon-pipeline) 依赖，改为外部 JSON 传入。
"""

import json
import logging
import time
from pathlib import Path
from typing import Any

from web_redteam.pipeline.context import WebRedTeamContext

logger = logging.getLogger(__name__)


async def run(ctx: WebRedTeamContext) -> None:
    """执行 Stage 1: 侦察数据加载.

    前置条件: 无 (API 模式下不需要浏览器页面)。

    流程:
      1. 检查 --recon-data 参数
      2. 如果提供，加载 JSON 文件到 ctx.recon_result
      3. 如果未提供，跳过侦察阶段

    Args:
        ctx: WebRedTeamContext。
    """
    logger.info("=" * 70)
    logger.info("[Stage 1] 侦察数据加载 (Recon Data Loader)")
    logger.info("=" * 70)

    recon_data_path = getattr(ctx.args, "recon_data", None)

    if not recon_data_path:
        logger.info("  [跳过] 未提供 --recon-data, 侦察阶段跳过")
        logger.info("  [提示] 如需侦察数据驱动攻击, 请使用 --recon-data <json_file>")
        logger.info("Stage 1: skipped (no --recon-data)")
        return

    recon_file = Path(recon_data_path)
    if not recon_file.exists():
        logger.warning(f"  [警告] 侦察数据文件不存在: {recon_data_path}")
        logger.warning(f"Stage 1: recon data file not found: {recon_data_path}")
        return

    start_time = time.time()

    logger.info(f"  加载侦察数据: {recon_data_path}")

    try:
        with open(recon_file, encoding="utf-8") as f:
            recon_data: dict[str, Any] = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"  [错误] 加载侦察数据失败: {e}")
        logger.error(f"Stage 1: failed to load recon data: {e}")
        return

    # 解析并打印摘要
    target_url = recon_data.get("target_url", "unknown")
    auth_type = recon_data.get("auth_type", "unknown")
    endpoints = recon_data.get("endpoints", [])
    surfaces = recon_data.get("injection_surfaces", [])
    recommendations = recon_data.get("recommendations", [])

    logger.info(f"  目标 URL: {target_url}")
    logger.info(f"  认证类型: {auth_type}")
    logger.info(f"  API 端点: {len(endpoints)} 个")
    for ep in endpoints[:10]:
        method = ep.get("method", "?")
        url = ep.get("url", "?")
        ep_type = ep.get("endpoint_type", "?")
        logger.info(f"    [{ep_type}] {method} {url}")
    if len(endpoints) > 10:
        logger.info(f"    ... 还有 {len(endpoints) - 10} 个端点")

    logger.info(f"  注入面: {len(surfaces)} 个")
    for s in surfaces[:10]:
        s_type = s.get("surface_type", "?")
        selector = s.get("selector", "?")
        logger.info(f"    [{s_type}] {selector}")

    logger.info(f"  攻击推荐: {len(recommendations)} 条")
    for rec in recommendations[:10]:
        owasp_id = rec.get("owasp_id", "?")
        strategy = rec.get("attack_strategy", "?")
        priority = rec.get("priority", "?")
        logger.info(f"    [P{priority}] {owasp_id} → {strategy}")

    # 写入 ctx (作为 dict, 不依赖 ReconReport 类)
    ctx.recon_result = recon_data

    elapsed = round(time.time() - start_time, 2)
    logger.info(f"  侦察数据加载完成 ({elapsed}s)")
    logger.info(
        f"Stage 1: recon data loaded ({elapsed}s, "
        f"{len(endpoints)} endpoints, {len(surfaces)} surfaces, "
        f"{len(recommendations)} recommendations)"
    )
