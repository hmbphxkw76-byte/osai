"""AI 红队攻击流水线 — 显示工具函数。

从 runner.py 中拆分，包含速率限制建议展示和 RPM 覆盖交互。
保持单一模块 ≤500 行。
"""

from __future__ import annotations

from typing import Any

from redteam.core.models import AIService
from redteam.core.rate_limiter import RateLimitGovernor


def print_rate_limit_advisory(
    governor: RateLimitGovernor,
    services: list[AIService],
) -> list[dict[str, Any]]:
    """攻击前展示调速策略建议（AI 红队专家风格）。

    基于 Phase 1 速率限制探测结果，为攻击执行器推荐安全的请求速率
    和执行模式（batch/sequential）。

    Args:
        governor: 自适应调速器实例
        services: AI 服务列表

    Returns:
        具有高 RPM 潜力的端点摘要列表（供后续交互覆写使用）
    """
    summaries = governor.get_all_summaries()
    if not summaries:
        return []

    has_limit = governor.has_any_rate_limit()
    global_delay = governor.get_global_min_delay_ms()
    high_potential_targets: list[dict[str, Any]] = []

    print(f"\n  ╔{' Rate Limit Advisory '.center(64, '═')}╗")
    if has_limit:
        print(f"  ║ {'  Detected Rate Limiting  —   攻击将自动调速'.ljust(64)}║")
    else:
        print(f"  ║ {'No rate limiting detected — conservative 15 RPM default'.ljust(64)}║")
    print(f"  ╠{'─' * 64}╣")

    for s in summaries[:5]:
        safe_rpm = s["safe_rpm"]
        threshold = s["known_threshold_rpm"]
        url_short = s["url"]
        if len(url_short) > 48:
            from urllib.parse import urlparse
            parsed = urlparse(url_short)
            url_short = f"{parsed.path}" if parsed.path else url_short[:48]

        if s["rate_limit_detected"] and threshold > 0:
            safe_delay = int((60.0 / safe_rpm) * 1000) if safe_rpm > 0 else 0
            print(f"  ║  {url_short.ljust(48)} ║")
            print(f"  ║    Threshold: {threshold:.0f} RPM → Safe: {safe_rpm:.0f} RPM ({safe_delay}ms) ║")
        elif threshold >= 20:
            print(f"  ║  {url_short.ljust(48)} ║")
            print(f"  ║    Tested: {threshold:.0f} RPM (no limit) → Safe: {safe_rpm:.0f} RPM        ║")
            high_potential_targets.append({
                "url": s["url"],
                "url_short": url_short,
                "tested_rpm": threshold,
                "safe_rpm": safe_rpm,
            })
        else:
            print(f"  ║  {url_short.ljust(48)} → No limit    ║")

    print(f"  ╠{'─' * 64}╣")
    if has_limit:
        if global_delay > 1000:
            mode = "sequential"
            batch_size = 1
            est_min = (len(services) * 10 * global_delay / 1000 / 60)
            print(f"  ║  Attack Mode:       {mode.ljust(14)} batch_size={batch_size}           ║")
            if est_min > 0:
                print(f"  ║  Est. Duration:    ~{est_min:.1f} min (10 payloads/endpoint)          ║")
        elif global_delay > 500:
            mode = "sequential"
            batch_size = 3
            print(f"  ║  Attack Mode:       {mode.ljust(14)} batch_size={batch_size}           ║")
        else:
            mode = "sequential"
            batch_size = 5
            print(f"  ║  Attack Mode:       {mode.ljust(14)} batch_size={batch_size}           ║")
    else:
        avg_safe = sum(s["safe_rpm"] for s in summaries) / max(len(summaries), 1)
        if avg_safe < 20:
            print(f"  ║  Attack Mode:       sequential     batch_size=3           ║")
        else:
            print(f"  ║  Attack Mode:       batch          batch_size=5           ║")

    if high_potential_targets:
        print(f"  ╠{'─' * 64}╣")
        print(f"  ║  {'30 RPM Capability Hint'.ljust(62)} ║")
        for t in high_potential_targets:
            short = t["url_short"]
            tested = t["tested_rpm"]
            print(f"  ║    {short[:48].ljust(44)} tested {tested:.0f} RPM OK  ║")
        print(f"  ║  {' '.ljust(62)} ║")
        print(f"  ║  {'Probe Stopped at 15 RPM (OffSec safe default).'.ljust(62)} ║")
        print(f"  ║  {'Target may support 30+ RPM — override via prompt below.'.ljust(62)} ║")

    print(f"  ╚{'═' * 64}╝\n")
    return high_potential_targets


def interactive_rpm_override(
    governor: RateLimitGovernor,
    high_rpm_targets: list[dict[str, Any]],
    default_rpm: int = 15,
    max_rpm: int = 30,
) -> None:
    """Phase 2 预攻击交互：允许用户覆写目标端点的安全 RPM。

    当探测结果显示目标支持 20+ RPM 且未触发限速时，提供交互界面
    让用户选择使用更高速率（最大 30 RPM）或保持保守默认值 15 RPM。

    若侦察阶段已通过高阶探测确认更高安全速率，支持覆写至 300 RPM。
    >30 RPM 时会显示风险提示。

    Args:
        governor: 自适应调速器实例
        high_rpm_targets: print_rate_limit_advisory 返回的高 RPM 潜力端点
        default_rpm: 保守默认 RPM（OffSec 考试推荐 15）
        max_rpm: 允许手动调整的最大 RPM（默认 30，高阶探测后可达 300）
    """
    if not high_rpm_targets:
        return

    existing_safe, _ = governor.get_safe_rate(high_rpm_targets[0]["url"])
    effective_max = max(max_rpm, int(existing_safe) if existing_safe > 0 else max_rpm)
    if effective_max < 300 and existing_safe >= 30:
        effective_max = 300

    try:
        override = input(
            f"  Override RPM? [{default_rpm}-{effective_max}, Enter=default {default_rpm}]: "
        ).strip()
    except (EOFError, KeyboardInterrupt):
        print(f"\n  Using default {default_rpm} RPM (conservative)\n")
        return

    if not override:
        print(f"  Using default {default_rpm} RPM (conservative)\n")
        return

    try:
        rpm = int(override)
    except ValueError:
        print(f"  Invalid input — using default {default_rpm} RPM\n")
        return

    if rpm < default_rpm or rpm > effective_max:
        print(f"  Value {rpm} out of range [{default_rpm}-{effective_max}] — using default {default_rpm} RPM\n")
        return

    if rpm > 30:
        print(f"\n   Risk: {rpm} RPM exceeds normal safe range [10-30].")
        print(f"     High frequency may cause WAF blocking or target performance degradation.")
        print(f"     Rate limiter will auto-fallback if rate limit triggers.\n")

    for t in high_rpm_targets:
        governor.override_safe_rpm(t["url"], float(rpm))

    print()
    for t in high_rpm_targets:
        new_safe, _ = governor.get_safe_rate(t["url"])
        print(f"  [{t['url_short']}] safe rate: {new_safe:.0f} RPM")

    est_phase2_min = 40 / rpm
    print(f"  Est. Phase 2 duration: ~{est_phase2_min:.1f} min\n")


__all__ = [
    "print_rate_limit_advisory",
    "interactive_rpm_override",
]
