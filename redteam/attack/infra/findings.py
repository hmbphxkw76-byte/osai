"""基础设施攻击 Findings 生成（AI-300 Ch9: Infrastructure Attacks on AI Systems）。

将基础设施攻击结果转化为 AI-300 报告格式的 Finding，
对齐 OWASP LLM Top 10 和 MITRE ATLAS 战术。
"""
from __future__ import annotations

from redteam.core.models import (
    Finding, OWASPLlm, MITREATLASTactic,
)


def generate_infra_findings(
    mcp_results: list[dict],
    supply_chain_risks: list[dict],
    cloud_findings: list[dict],
) -> list[Finding]:
    """合并基础设施/供应链攻击发现（AI-300 Ch9.2）。"""
    findings: list[Finding] = []

    # MCP 扫描发现
    for mr in mcp_results:
        if mr.get("vulnerabilities"):
            for v in mr["vulnerabilities"]:
                findings.append(Finding(
                    source="mcp_attack",
                    category="mcp_vulnerability",
                    severity="high",
                    title=f"MCP 漏洞: {v}",
                    description=f"在 {mr['url']} 发现 MCP 安全漏洞",
                    evidence=mr.get("output", "")[:500],
                    remediation="修复 MCP 服务器配置，实施输入验证和工具权限控制",
                    endpoint=mr["url"],
                    owasp_llm=OWASPLlm.LLM06_EXCESSIVE_AGENCY,
                    mitre_atlas_tactic=MITREATLASTactic.EXECUTION,
                ))
        if mr.get("tools_found"):
            findings.append(Finding(
                source="mcp_attack",
                category="mcp_tools_exposed",
                severity="medium",
                title=f"MCP 工具暴露: {len(mr['tools_found'])} 个",
                description=f"发现暴露的 MCP 工具: {', '.join(mr['tools_found'])}",
                evidence=mr.get("output", "")[:300],
                remediation="审查 MCP 工具权限，移除高风险工具或限制调用",
                endpoint=mr["url"],
                mitre_atlas_tactic=MITREATLASTactic.RECON,
            ))

    # 供应链风险
    for risk in supply_chain_risks:
        findings.append(Finding(
            source="supply_chain",
            category="supply_chain_risk",
            severity="medium",
            title=f"供应链风险: {risk['risk']}",
            description=risk.get("description", ""),
            evidence=f"模型: {risk.get('model', '')}, 来源: {risk.get('source', '')}",
            remediation="验证模型来源可信性，实施模型签名验证",
            owasp_llm=OWASPLlm.LLM03_SUPPLY_CHAIN,
            mitre_atlas_tactic=MITREATLASTactic.RESOURCE_DEV,
        ))

    # 云配置错误
    for cf in cloud_findings:
        findings.append(Finding(
            source="infra_attack",
            category="cloud_misconfiguration",
            severity=cf.get("severity", "medium"),
            title=f"云配置错误: {cf['risk']}",
            description=f"在 {cf['url']} 发现配置错误",
            evidence=cf.get("evidence", ""),
            remediation="修复 IAM 策略、启用认证、关闭匿名访问",
            endpoint=cf["url"],
            mitre_atlas_tactic=MITREATLASTactic.INITIAL_ACCESS,
        ))

    return findings


__all__ = [
    "generate_infra_findings",
]