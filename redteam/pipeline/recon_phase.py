"""AI 攻击面侦察阶段 (AI-300 Ch2)。

执行 AI 攻击面侦察：
  - 被动侦察：分析响应头、CSP、端点线索
  - 主动服务发现：探测 AI 协议端点
  - MCP/A2A 深入枚举：基于发现结果做定向枚举
  - 护栏画像：指纹识别、分类、绕过评估
  - 规避分析：速率限制、确定性、检测签名、JS客户端分析

对齐 OWASP ASI Top 10: ASI07 (Sensitive Information)
"""
from __future__ import annotations

import uuid
from typing import Any

from redteam.core.models import AIService, AIProtocol, AuthContext, ReconResult
from redteam.core.store import save_json, make_run_id
from redteam.core.tools import ToolResolver
from redteam.core.terminal_output import print_section_header, print_target_list
from redteam.recon.auth_parse import parse_headers, parse_headers_file, describe_auth
from redteam.recon.discover import discover_ai_services, passive_recon, enum_protected_endpoints
from redteam.recon.guardrail import profile_guardrails
from redteam.recon.mcp_recon import probe_mcp_server, enumerate_mcp_tools
from redteam.recon.a2a_recon import probe_a2a_endpoint, enumerate_agent_capabilities
from redteam.recon.evasion import (
    probe_rate_limit,
    probe_determinism,
    analyze_detection_signatures,
    analyze_js_client,
)


def _format_time(seconds: float) -> str:
    """格式化时间显示。"""
    if seconds < 60:
        return f"{seconds:.1f} 秒"
    minutes = seconds / 60
    if minutes < 60:
        return f"{seconds:.0f} 秒 ({minutes:.1f} 分钟)"
    hours = minutes / 60
    return f"{seconds:.0f} 秒 ({minutes:.1f} 分钟, {hours:.2f} 小时)"


def recon_phase(
    target: str,
    header_text: str | None = None,
    header_file: str | None = None,
    run_id: str | None = None,
    resolver: ToolResolver | None = None,
) -> tuple[str, ReconResult, list[AIService]]:
    """AI 攻击面侦察。

    Args:
        target: 目标 URL
        header_text: F12 请求头文本
        header_file: F12 请求头文件路径
        run_id: 运行 ID
        resolver: 工具解析器

    Returns:
        (run_id, recon_result, ai_services)
    """
    resolver = resolver or ToolResolver()
    run_id = run_id or make_run_id(target, uuid.uuid4().hex[:8])
    print_section_header("[Phase 1] AI 攻击面侦察", f"Target: {target}")

    auth: AuthContext | None = None
    if header_file:
        auth = parse_headers_file(header_file)
    elif header_text:
        auth = parse_headers(header_text)
    if auth:
        print(f"\n[Auth] {describe_auth(auth)}")

    recon = ReconResult(target=target)
    all_services: list[AIService] = []

    recon_cfg = resolver.settings.get("recon", {}) or {}
    rate_limit_ms = int(recon_cfg.get("rate_limit_ms", 0))
    if rate_limit_ms:
        print(f"[Recon] 限速模式: {rate_limit_ms}ms/请求")

    print("\n[1/5] 被动侦察...")
    passive = passive_recon(target)
    print(f"  发现 AI 端点线索: {len(passive['ai_endpoints_hint'])}")
    print(f"  技术响应头: {passive['tech_headers']}")
    print(f"  CSP AI 域名: {passive['csp_ai_hints']}")

    print("\n[2/5] 主动 AI 服务发现...")
    est_time = 30.0 + (len(passive.get("ai_endpoints_hint", [])) * 15.0) + (rate_limit_ms / 1000.0 * 20)
    if est_time >= 60:
        print(f"[info] 预估侦察时间: {_format_time(est_time)}")
    services = discover_ai_services(target, auth, rate_limit_ms=rate_limit_ms)
    all_services.extend(services)

    print_target_list(
        [s.model_dump() for s in services],
        "AI Services Discovered"
    )

    recon.ai_services = services
    recon.components = sorted(set(s.protocol for s in services))
    recon.models = sorted(set(m for s in services for m in s.models))

    print("\n[3/5] MCP/A2A 协议深入枚举...")
    mcp_services = [s for s in services if s.protocol == AIProtocol.MCP.value]
    a2a_services = [s for s in services if s.protocol == AIProtocol.A2A.value]
    
    est_time = 15.0 + (len(mcp_services) * 10.0) + (len(a2a_services) * 10.0) + (rate_limit_ms / 1000.0 * 15)
    if est_time >= 60:
        print(f"[info] 预估侦察时间: {_format_time(est_time)}")

    if mcp_services:
        print(f"\n  MCP 服务 ({len(mcp_services)} 个):")
        for svc in mcp_services:
            mcp_info = probe_mcp_server(svc.url, auth)
            recon.mcp_info[svc.url] = mcp_info
            if mcp_info.get("mcp_detected"):
                print(f"    URL: {svc.url}")
                print(f"    版本: {mcp_info.get('mcp_version', 'unknown')}")
                tools = enumerate_mcp_tools(svc.url, auth)
                if tools:
                    tool_names = [t.get("name", "") for t in tools[:10]]
                    print(f"    工具列表: {tool_names}")
                    svc.tools = tool_names
    elif passive.get("ai_endpoints_hint") and any("mcp" in h.lower() for h in passive["ai_endpoints_hint"]):
        mcp_info = probe_mcp_server(target, auth)
        recon.mcp_info[target] = mcp_info
        if mcp_info.get("mcp_detected"):
            print(f"  MCP 服务器检测到: {mcp_info.get('mcp_version', 'unknown')}")

    if a2a_services:
        print(f"\n  A2A 服务 ({len(a2a_services)} 个):")
        for svc in a2a_services:
            a2a_info = probe_a2a_endpoint(svc.url, auth)
            recon.a2a_info[svc.url] = a2a_info
            if a2a_info.get("a2a_detected"):
                print(f"    URL: {svc.url}")
                print(f"    Agent 能力: {a2a_info.get('capabilities', [])}")
                cap_detail = enumerate_agent_capabilities(svc.url, auth)
                if cap_detail.get("excessive_permissions_detected"):
                    print(f"    ⚠️  检测到过度授权: {cap_detail.get('permission_level')}")
    elif passive.get("ai_endpoints_hint") and any("agent-card" in h.lower() for h in passive["ai_endpoints_hint"]):
        a2a_info = probe_a2a_endpoint(target, auth)
        recon.a2a_info[target] = a2a_info
        if a2a_info.get("a2a_detected"):
            print(f"  A2A 端点检测到")

    print("\n[4/5] 护栏画像...")
    est_time = len(all_services) * 30.0 + (rate_limit_ms / 1000.0 * len(all_services) * 5)
    if est_time >= 60:
        print(f"[info] 预估侦察时间: {_format_time(est_time)}")
    for svc in all_services:
        if svc.protocol in ("openai_compatible", "ollama", "mcp", "generic_ai", "agent_to_agent"):
            print(f"\n  目标: {svc.url}")
            guard = profile_guardrails(svc, auth=auth, rate_limit_ms=rate_limit_ms)
            svc.guardrail_profile = guard
            print(f"    护栏类型: {guard.guardrail_type.value} (置信度 {guard.guardrail_confidence})")
            print(f"    阻断类别: {[c.value for c in guard.blocked_categories]}")
            print(f"    绕过难度: {guard.bypass_difficulty}")
            if guard.recommended_techniques:
                from redteam.recon.guardrail import _OWASP_RISK_MAPPING, _PYRIT_EFFECTIVENESS
                print(f"    推荐攻击策略:")
                for i, tech in enumerate(guard.recommended_techniques, 1):
                    owasp = _OWASP_RISK_MAPPING.get(tech, [])
                    eff = _PYRIT_EFFECTIVENESS.get(tech, {})
                    rate = eff.get("base_rate", 0)
                    print(f"      [{i}] {tech} (成功率: {rate:.0%}, OWASP: {', '.join(owasp)})")

    print("\n[5/5] 规避分析...")
    est_time = 60.0 + (len(all_services) * 20.0) + (rate_limit_ms / 1000.0 * 30)
    if est_time >= 60:
        print(f"[info] 预估侦察时间: {_format_time(est_time)}")
    
    print("  检测签名分析...")
    detection_info = analyze_detection_signatures(target, auth)
    recon.detection_signatures = detection_info
    if detection_info.get("keyword_rules_detected"):
        print(f"    检测到关键词规则: {detection_info['keyword_rules_detected']}")

    print("  JS 客户端分析...")
    js_info = analyze_js_client(target, auth)
    recon.js_client_analysis = js_info
    if js_info.get("endpoints"):
        print(f"    发现端点: {len(js_info['endpoints'])}")
    if js_info.get("api_keys_found"):
        print(f"    ⚠️  发现 API Key: {len(js_info['api_keys_found'])}")

    for svc in all_services:
        if not svc.auth_required and not svc.model_fingerprint:
            print(f"\n  速率限制探测 ({svc.url})...")
            rate_info = probe_rate_limit(svc.url, auth, max_requests=10)
            recon.rate_limit_info[svc.url] = rate_info
            if rate_info.get("rate_limit_detected"):
                print(f"    速率限制阈值: {rate_info.get('threshold_rpm', 0):.0f} RPM")
                print(f"    状态码: {rate_info.get('status_code')}")

            print(f"  确定性探测 ({svc.url})...")
            det_info = probe_determinism(svc.url, auth, num_requests=3)
            recon.determinism_info[svc.url] = det_info
            print(f"    确定性: {'是' if det_info.get('is_deterministic') else '否'}")
            print(f"    唯一响应数: {det_info.get('unique_response_count')}/{det_info.get('total_response_count')}")

    save_json(run_id, "recon", recon.model_dump())
    save_json(run_id, "services", [s.model_dump() for s in all_services])

    return run_id, recon, all_services


__all__ = [
    "recon_phase",
]
