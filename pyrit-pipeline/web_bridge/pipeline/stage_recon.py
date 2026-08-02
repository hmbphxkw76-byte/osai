# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Stage 0: 目标侦察 (Target Recon)。.

在认证和攻击之前执行, 发现目标系统的攻击面:
  1. AuthProbe: 探测认证拓扑 (现有模块)
  2. NetworkInterceptor: 拦截网络响应, 发现 API 端点
  3. DOMAnalyzer: 扫描 DOM 注入面
  4. AttackRecommender: 生成攻击推荐

产出 (写入 WebBridgeContext):
  - ctx.recon_result = ReconResult

数据流:
  Stage 0 (Recon) → Stage 2 (Auth) → Stage 3 (Target) → Stage 4 (Attack)
       ↓
  Bridge → 主 Pipeline Stage 1.5 (WebAuth) → Stage 2 (Scenario)

> **日期**: 2026-8-2
"""

import logging
import time
from typing import TYPE_CHECKING

from web_bridge.pipeline.context import WebBridgeContext

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# 侦察默认持续时间 (秒)
_DEFAULT_RECON_DURATION = 10


async def run(ctx: WebBridgeContext) -> None:
    """执行 Stage 0: 目标侦察。.

    流程:
      1. 启动浏览器 (如果尚未启动)
      2. AuthProbe 探测认证拓扑
      3. NetworkInterceptor 拦截网络响应
      4. DOMAnalyzer 扫描注入面
      5. AttackRecommender 生成推荐
      6. 写入 ctx.recon_result

    Args:
        ctx: WebBridgeContext (需要 args.target_url 或 args.target_profile)
    """
    print("\n" + "=" * 70)
    print("[Stage 0] 目标侦察 (Recon)")
    print("=" * 70)

    start_time = time.time()

    from web_bridge.auth.auth_probe import AuthProbe
    from web_bridge.auth.browser_session import BrowserSession
    from core.probes import (
        AttackRecommender,
        DOMAnalyzer,
        NetworkInterceptor,
        ReconResult,
    )
    from web_bridge.targets.target_profile import TargetProfile

    args = ctx.args
    target_url = getattr(args, "target_url", None) or ""

    # 如果有 target_profile, 从中提取 target_url
    if not target_url and getattr(args, "target_profile", None):
        profile = TargetProfile.from_yaml_file(args.target_profile)
        target_url = profile.auth.target_url

    if not target_url:
        print("  [跳过] 未指定目标 URL, 侦察阶段跳过")
        logger.info("Stage 0: skipped (no target URL)")
        ctx.recon_result = ReconResult()
        return

    print(f"  目标 URL: {target_url}")

    # 1. 启动浏览器 (侦察专用, 之后会被 Stage 2 复用或关闭)
    session = BrowserSession()
    headless = getattr(args, "headless", True)  # 侦察默认无头
    cdp_port = getattr(args, "cdp_port", 9222)

    page = await session.launch_with_debug_port(
        port=cdp_port,
        headless=headless,
    )
    ctx.browser_session = session

    # 2. AuthProbe 探测认证拓扑
    print("  [1/4] 探测认证拓扑...")
    probe = AuthProbe()
    probe_result = await probe.probe(page, target_url)
    auth_type = probe_result.auth_type
    print(f"    认证类型: {auth_type}")
    print(f"    {probe_result.detection_reason}")

    # 3. NetworkInterceptor 拦截网络响应
    print("  [2/4] 拦截网络响应, 发现 API 端点...")
    recon_duration = getattr(args, "recon_duration", _DEFAULT_RECON_DURATION)
    interceptor = NetworkInterceptor()
    endpoints = await interceptor.probe_endpoints(
        page,
        target_url,
        duration=recon_duration,
    )
    print(f"    发现 {len(endpoints)} 个 API 端点")
    for ep in endpoints[:10]:
        print(f"      [{ep.endpoint_type.value}] {ep.method} {ep.url} ({ep.status_code})")

    # 4. DOMAnalyzer 扫描注入面
    print("  [3/4] 扫描 DOM 注入面...")
    analyzer = DOMAnalyzer()
    surfaces = await analyzer.scan(page)
    print(f"    发现 {len(surfaces)} 个注入面")
    for s in surfaces[:10]:
        print(f"      [{s.surface_type.value}] {s.selector} → {s.description}")

    # 5. AttackRecommender 生成推荐
    print("  [4/4] 生成攻击推荐...")
    recon_result = ReconResult(
        target_url=target_url,
        auth_type=auth_type,
        endpoints=endpoints,
        injection_surfaces=surfaces,
        domain_transitions=probe_result.domain_transitions,
        recon_duration_seconds=round(time.time() - start_time, 2),
    )

    recommender = AttackRecommender()
    recommendations = recommender.recommend(recon_result)
    recon_result.recommendations = recommendations

    print(f"    生成 {len(recommendations)} 条攻击推荐:")
    for rec in recommendations[:10]:
        print(f"      [P{rec.priority}] {rec.owasp_id} → {rec.attack_strategy} ({rec.target_type})")

    ctx.recon_result = recon_result

    # 侦察摘要
    print("\n  ── 侦察摘要 ──")
    print(recon_result.summary())

    # 关闭侦察浏览器 (Stage 2 会启动新的浏览器会话)
    await session.close()
    ctx.browser_session = None

    logger.info(
        f"Stage 0: recon completed ({recon_result.recon_duration_seconds}s, "
        f"{len(endpoints)} endpoints, {len(surfaces)} surfaces, "
        f"{len(recommendations)} recommendations)"
    )
