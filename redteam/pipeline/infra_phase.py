"""MCP+基础设施攻击阶段 (AI-300 Ch7+Ch9)。

执行基础设施攻击：
  - MCP 端点安全扫描
  - 云 AI 服务配置错误检测

对齐 OWASP ASI Top 10: ASI04 (Supply Chain), ASI07 (Sensitive Information)
"""
from __future__ import annotations

from typing import Any

from redteam.core.models import AIService, Finding, ReconResult
from redteam.core.store import load_json, save_json
from redteam.core.terminal_output import print_section_header
from redteam.attack.infra import scan_cloud_misconfigs, generate_infra_findings


def infra_attack_phase(
    run_id: str,
    recon: ReconResult,
    services: list[AIService],
) -> list[Finding]:
    """MCP 工具面 + AI 基础设施攻击 (Ch7+Ch9)。

    供应链部分已独立为 Phase 6 (supply_chain_phase)。
    本阶段聚焦：
      - MCP 端点安全扫描 (Ch7)
      - 云 AI 服务配置错误检测 (Ch9)
    """
    print_section_header("[Phase 7] MCP + AI 基础设施攻击", "MCP Security + Cloud Misconfigs")

    all_findings: list[Finding] = []

    mcp_urls = [e["url"] for e in recon.endpoints if "mcp" in e.get("url", "").lower()]
    mcp_results: list[dict] = []
    if mcp_urls:
        print(f"\n[MCP] 检测到 {len(mcp_urls)} 个 MCP 端点（待手动分析）")
        for mcp_url in mcp_urls[:5]:
            print(f"  - {mcp_url}")

    print("\n[Cloud] AI 云端配置检查...")
    cloud_findings = scan_cloud_misconfigs(recon.target)
    if cloud_findings:
        print(f"  发现 {len(cloud_findings)} 个配置问题")
    else:
        print("  未发现明显问题")

    supply_risks: list[dict] = []

    findings = generate_infra_findings(mcp_results, supply_risks, cloud_findings)
    all_findings.extend(findings)

    prior = load_json(run_id, "findings") or []
    all_findings = prior + [f.model_dump() for f in all_findings]
    save_json(run_id, "findings", all_findings)
    return [Finding(**f) if isinstance(f, dict) else f for f in all_findings]


__all__ = [
    "infra_attack_phase",
]