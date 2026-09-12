"""裸 URL 关联端点发现（REQ-160 ④ / BL-032）。

给定一个基础 URL（裸 URL 或无 HAR 的单端点），按策划词表探测常见 API 文档与路由前缀，
将发现的关联端点收敛进 `ParsedBurpRequest.target_fingerprint.extra["related_endpoints"]`
（recon 唯一输出总线，I12）。

设计约束：
- 有界：默认词表 + 短超时 + 并发上限，绝不枚举整个字典/端口空间（R-H3 反过度工程）。
- 非致命：任何单次探测失败不影响主链路；整体失败仅 debug 日志。
- 纯 httpx（与 `recon.target_builder` 一致，R-IMPORT-1 无 httpx/aiohttp 冲突）。
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

# 默认探测词表：OpenAPI/Swagger 文档、GraphQL 入口、常见 API 路由前缀与管理端点。
# 仅覆盖"高信息价值 + 低噪声"的路径，不做全字典爆破（避免触发防御/产生海量误报）。
DEFAULT_PATHS: tuple[str, ...] = (
    "/openapi.json",
    "/openapi/v1.json",
    "/openapi/v3/api-docs",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/api/openapi.json",
    "/.well-known/openapi.json",
    "/api/docs",
    "/docs",
    "/redoc",
    "/graphql",
    "/graphiql",
    "/api",
    "/api/v1",
    "/api/v2",
    "/v1",
    "/v2",
    "/health",
    "/healthz",
    "/actuator",
    "/robots.txt",
    "/sitemap.xml",
)


async def discover_related_endpoints(
    base_url: str,
    *,
    headers: dict[str, str] | None = None,
    verify: bool | str = True,
    timeout: float = 5.0,
    concurrency: int = 8,
    paths: tuple[str, ...] | None = None,
    client: httpx.AsyncClient | None = None,
) -> list[dict[str, Any]]:
    """探测 `base_url` 下的关联端点。

    Args:
        base_url: 目标基础 URL（含 scheme/host，可带路径前缀）。
        headers: 透传的请求头（默认剔除 content-length/host）。
        verify: TLS 校验（对齐 `_TLS_VERIFY`）。
        timeout: 单请求超时（秒）。
        concurrency: 并发上限。
        paths: 覆盖默认探测词表（测试用）。
        client: 注入 httpx 客户端（测试用；非空则不由本函数关闭）。

    Returns:
        发现列表，每项为 `{"path", "status", "method", "source"}`；仅收录响应码 < 400 的端点。
    """
    paths = paths or DEFAULT_PATHS
    own_client = client is None
    client = client or httpx.AsyncClient(verify=verify, follow_redirects=True, timeout=timeout)
    sem = asyncio.Semaphore(concurrency)
    found: list[dict[str, Any]] = []

    async def _probe(path: str) -> None:
        async with sem:
            try:
                resp = await client.get(urljoin(base_url, path), headers=headers, timeout=timeout)
            except Exception as e:  # 单次失败不阻断其余探测
                logger.debug("related-endpoint probe %s failed: %s", path, e)
                return
            if resp.status_code < 400:
                found.append(
                    {"path": path, "status": resp.status_code, "method": "GET", "source": "path_probe"}
                )

    try:
        await asyncio.gather(*(_probe(p) for p in paths))
    finally:
        if own_client:
            await client.aclose()
    logger.debug("Related endpoint discovery on %s: %d found", base_url, len(found))
    return found
