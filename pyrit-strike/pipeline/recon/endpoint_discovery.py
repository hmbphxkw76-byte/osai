"""端点自动发现 — 基于学术方法论的高效 API 路径枚举。

学术依据:
    - OWASP WSTG-INFO-03 (Fingerprint Web Application Framework)
      https://owasp.org/www-project-web-security-testing-guide/
      → 框架指纹识别 → 针对性路径探测
    - PTES (Penetration Testing Execution Standard) Section 2: Intelligence Gathering
      → 分层发现: 先探测规范文档, 再基于响应引导扩展
    - Arbis et al. (arXiv:2306.01943) "Automated API Endpoint Discovery"
      → 自适应路径树: 根据 200/301/403 响应引导后续探测方向
    - OWASP API Security Top 10 (2025) + OWASP Top 10 (2025)
      → 端点关键词按 OWASP 漏洞分类分级

设计原则 — 分层优先发现 (Priority-Based Discovery):
    Layer 0: API 规范文档发现 (OpenAPI/Swagger/graphql) — 1 次请求可能揭示全部端点
    Layer 1: 框架/技术指纹 (actuator, debug, env) — 高价值信息泄露端点
    Layer 2: 同前缀路径推断 (从原始 Burp 请求路径推断 API 前缀, 探测同级端点)
    Layer 3: 版本化探测 (v1/v2/api 级别回退)
    Layer 4: 响应引导扩展 (根据 Layer 1-3 的响应内容动态发现新路径)
    Layer 5: 通用基线探测 (常见 API 路径, 仅在前面层未发现足够端点时执行)

效率优化:
    - 优先级分层: 高价值端点先探测, 早期命中率高
    - 早期终止: Layer 0 发现 OpenAPI 规范 → 跳过 Layer 5 通用探测
    - 响应引导: 从 200 响应中提取链接/路径 → 动态扩展
    - 去重: 全局去重, 同一路径不重复探测
    - 并发控制: 分层并发, 每层内部最大并发
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from pipeline.recon.burp_parser import ParsedBurpRequest
from pipeline.recon.endpoint_constants import (  # noqa: F401
    _ALL_KEYWORDS,
    _API_SPEC_PATHS,
    _API_VERSION_PREFIXES,
    _BASELINE_PATHS,
    _HIGH_VALUE_PATHS,
    _TIER_A_KEYWORDS,
    _TIER_B_KEYWORDS,
    _TIER_C_KEYWORDS,
    _VALID_STATUS_CODES,
    DiscoveredEndpoint,
)
from pipeline.recon.endpoint_path_tools import (  # noqa: F401
    _build_layer0_paths,
    _build_layer1_paths,
    _build_layer2_paths,
    _build_layer3_paths,
    _build_layer5_paths,
    _build_probe_paths,
    _infer_api_prefix,
    _infer_numbered_siblings,
    _infer_parent_prefix,
    _infer_version_segments,
)
from pipeline.recon.endpoint_response import (  # noqa: F401
    _detect_vuln_hints,
    _extract_paths_from_response,
    _normalize_vuln_type,
    _parse_openapi_paths,
)

# Re-export for backward compatibility
__all__ = [
    "DiscoveredEndpoint",
    "discover_endpoints",
    "match_seeds_to_endpoints",
    "_API_SPEC_PATHS",
    "_HIGH_VALUE_PATHS",
    "_TIER_A_KEYWORDS",
    "_TIER_B_KEYWORDS",
    "_TIER_C_KEYWORDS",
    "_ALL_KEYWORDS",
    "_API_VERSION_PREFIXES",
    "_BASELINE_PATHS",
    "_VALID_STATUS_CODES",
    "_infer_api_prefix",
    "_infer_parent_prefix",
    "_infer_version_segments",
    "_infer_numbered_siblings",
    "_build_layer0_paths",
    "_build_layer1_paths",
    "_build_layer2_paths",
    "_build_layer3_paths",
    "_build_layer5_paths",
    "_build_probe_paths",
    "_extract_paths_from_response",
    "_parse_openapi_paths",
    "_detect_vuln_hints",
    "_normalize_vuln_type",
]

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════
# 主发现引擎
# ══════════════════════════════════════════════════════════════

async def discover_endpoints(
    parsed: ParsedBurpRequest,
    *,
    timeout: float = 5.0,
    max_concurrent: int = 10,
) -> list[DiscoveredEndpoint]:
    """自动发现目标 API 端点 — 分层优先发现。

    分层策略 (学术依据: PTES §2 + arXiv:2306.01943):
        Layer 0: API 规范文档 (OpenAPI/Swagger) — 1 次请求可能揭示全部端点
        Layer 1: 高价值端点 (actuator/debug/env) — 信息泄露
        Layer 2: 同前缀推断 (从 Burp 请求路径推断 API 前缀)
        Layer 3: 版本化探测 (v1 → v2/v3)
        Layer 4: 响应引导扩展 (从 Layer 0-3 响应中提取新路径)
        Layer 5: 通用基线 (仅在前面层发现 <3 端点时执行)

    早期终止:
        - Layer 0 发现 OpenAPI 规范 → 跳过 Layer 5
        - Layer 0-3 累计发现 ≥10 端点 → 跳过 Layer 5

    Args:
        parsed: 解析后的 Burp 请求。
        timeout: 单个探针超时秒数。
        max_concurrent: 最大并发探测数。

    Returns:
        可用端点列表。
    """
    import httpx

    scheme = "https" if parsed.use_tls else "http"
    base_url = f"{scheme}://{parsed.host}"

    # 构建 headers
    probe_headers: dict[str, str] = {}
    for key, value in parsed.raw_headers:
        if key.lower() not in ("content-length", "host"):
            probe_headers[key] = value

    # 全局去重集合
    global_seen: set[str] = set()
    discovered: list[DiscoveredEndpoint] = []
    has_openapi_spec = False

    # ── 创建共享的 HTTP client (连接池复用) ──
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
    ) as client:
        semaphore = asyncio.Semaphore(max_concurrent)

        async def _probe(path: str, layer: int) -> DiscoveredEndpoint | None:
            """探测单个路径, 返回 DiscoveredEndpoint 或 None."""
            if path in global_seen:
                return None
            global_seen.add(path)

            async with semaphore:
                url = f"{base_url}{path}"
                ep = DiscoveredEndpoint(path=path, method="GET", discovery_layer=layer)
                try:
                    response = await client.get(url, headers=probe_headers)
                    ep.status_code = response.status_code
                    ep.content_type = response.headers.get("content-type", "")
                    ep.response_length = len(response.content)
                    ep.response_preview = response.text[:500] if response.text else ""
                    ep.available = response.status_code in _VALID_STATUS_CODES

                    ep.vuln_hints = _detect_vuln_hints(
                        path, response.status_code, ep.response_preview, ep.content_type
                    )

                    if ep.available:
                        logger.info(
                            "Endpoint [L%d] %s → %d (%s) hints=%s",
                            layer, ep.path, ep.status_code, ep.content_type, ep.vuln_hints,
                        )
                    return ep
                except (httpx.ConnectError, httpx.TimeoutException):
                    return None
                except Exception as e:
                    logger.debug("Probe %s failed: %s", path, e)
                    return None

        async def _probe_batch(paths: list[str], layer: int) -> list[DiscoveredEndpoint]:
            """批量探测路径列表."""
            tasks = [_probe(p, layer) for p in paths]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            found: list[DiscoveredEndpoint] = []
            for result in results:
                if isinstance(result, DiscoveredEndpoint) and result.available:
                    found.append(result)
            return found

        # ═══ Layer 0: API 规范文档发现 ═══
        logger.info("[Layer 0] Probing API spec documents...")
        layer0_paths = _build_layer0_paths()
        layer0_results = await _probe_batch(layer0_paths, 0)
        discovered.extend(layer0_results)

        # 检查是否发现 OpenAPI 规范
        for ep in layer0_results:
            if "json" in ep.content_type or "yaml" in ep.content_type:
                spec_paths = _parse_openapi_paths(ep.response_preview)
                if spec_paths:
                    logger.info(
                        "[Layer 0] OpenAPI spec found at %s: %d paths extracted",
                        ep.path, len(spec_paths),
                    )
                    has_openapi_spec = True
                    # 探测 OpenAPI 规范中的路径
                    spec_results = await _probe_batch(spec_paths[:50], 0)  # 限制 50 个
                    for r in spec_results:
                        r.from_spec = True
                    discovered.extend(spec_results)

        # ═══ Layer 1: 高价值端点探测 ═══
        logger.info("[Layer 1] Probing high-value endpoints...")
        layer1_paths = _build_layer1_paths()
        layer1_results = await _probe_batch(layer1_paths, 1)
        discovered.extend(layer1_results)

        # ═══ Layer 2: 同前缀路径推断 ═══
        logger.info("[Layer 2] Probing same-prefix endpoints...")
        layer2_paths = _build_layer2_paths(parsed.path)
        layer2_results = await _probe_batch(layer2_paths, 2)
        discovered.extend(layer2_results)

        # ═══ Layer 3: 版本化探测 ═══
        logger.info("[Layer 3] Probing versioned API endpoints...")
        layer3_paths = _build_layer3_paths(parsed.path)
        layer3_results = await _probe_batch(layer3_paths, 3)
        discovered.extend(layer3_results)

        # ═══ Layer 4: 响应引导扩展 ═══
        logger.info("[Layer 4] Extracting paths from responses...")
        guided_paths: list[str] = []
        for ep in discovered:
            extracted = _extract_paths_from_response(
                ep.response_preview
            )
            guided_paths.extend(extracted)

        # 去重 (Layer 4 提取的路径可能与已探测的重叠)
        guided_paths = [p for p in guided_paths if p not in global_seen]
        if guided_paths:
            logger.info("[Layer 4] %d new paths from responses", len(guided_paths))
            layer4_results = await _probe_batch(guided_paths[:30], 4)  # 限制 30 个
            discovered.extend(layer4_results)

        # ═══ Layer 5: 通用基线探测 (条件执行) ═══
        # 早期终止: 发现 OpenAPI 规范 或 累计 ≥10 端点 → 跳过
        if not has_openapi_spec and len(discovered) < 10:
            logger.info("[Layer 5] Probing baseline endpoints (insufficient discovery)...")
            layer5_paths = _build_layer5_paths()
            layer5_results = await _probe_batch(layer5_paths, 5)
            discovered.extend(layer5_results)
        else:
            logger.info(
                "[Layer 5] Skipped (early termination: spec=%s, found=%d)",
                has_openapi_spec, len(discovered),
            )

    logger.info(
        "Endpoint discovery complete: %d endpoints found (%d total probes, %d unique paths)",
        len(discovered), len(global_seen), len(global_seen),
    )
    return discovered


# ══════════════════════════════════════════════════════════════
# 种子-端点匹配
# ══════════════════════════════════════════════════════════════

def match_seeds_to_endpoints(
    seeds: list[dict[str, Any]],
    endpoints: list[DiscoveredEndpoint],
) -> dict[str, list[dict[str, Any]]]:
    """将种子匹配到端点。

    根据 vulnerability_type 和 vuln_hints 匹配。

    Args:
        seeds: 种子列表 (原始 dict 格式)。
        endpoints: 发现的端点列表。

    Returns:
        {endpoint_path: [matched_seeds]}
    """
    # 构建端点 hint → endpoint 映射
    hint_to_endpoints: dict[str, list[DiscoveredEndpoint]] = {}
    for ep in endpoints:
        for hint in ep.vuln_hints:
            hint_to_endpoints.setdefault(hint, []).append(ep)

    # 构建种子 vuln_type → seeds 映射
    type_to_seeds: dict[str, list[dict[str, Any]]] = {}
    for seed in seeds:
        meta = seed.get("metadata", {})
        vuln_type = meta.get("vulnerability_type", "")
        if vuln_type:
            type_key = _normalize_vuln_type(vuln_type)
            type_to_seeds.setdefault(type_key, []).append(seed)

    # 匹配
    matches: dict[str, list[dict[str, Any]]] = {}
    for hint, eps in hint_to_endpoints.items():
        matched_seeds = type_to_seeds.get(hint, [])
        if not matched_seeds:
            for seed_type, seeds_list in type_to_seeds.items():
                if hint in seed_type or seed_type in hint:
                    matched_seeds.extend(seeds_list)
        for ep in eps:
            existing = matches.get(ep.path, [])
            for s in matched_seeds:
                if s not in existing:
                    existing.append(s)
            matches[ep.path] = existing

    # 无 hint 的端点分配所有种子 (通用端点)
    for ep in endpoints:
        if ep.path not in matches or not matches[ep.path]:
            if not ep.vuln_hints:
                matches[ep.path] = seeds

    # 统计
    total_matches = sum(len(v) for v in matches.values())
    logger.info(
        "Seed-endpoint matching: %d seeds → %d endpoints (%d total matches)",
        len(seeds), len(endpoints), total_matches,
    )

    return matches
