"""供应链攻击 Findings 生成（AI-300 Ch8: Supply Chain Attacks）。

将供应链攻击结果转化为 AI-300 报告格式的 Finding，
对齐 OWASP LLM Top 10 和 MITRE ATLAS 战术。

技术来源：Adapted from mcp-attack-labs/labs/02-docker-dash/
"""
from __future__ import annotations

from redteam.core.models import (
    AIService, Finding, OWASPLlm, MITREATLASTactic,
)


def generate_supply_chain_findings(
    service: AIService,
    hf_risks: list[dict],
    pickle_risks: list[dict],
    dataset_risks: list[dict],
    dependency_risks: list[dict],
    docker_api_results: list[dict] | None = None,
    docker_label_results: list[dict] | None = None,
) -> list[Finding]:
    """将供应链攻击结果转化为 AI-300 Finding（AI-300 Ch8.5）。

    Args:
        service: 目标 AI 服务
        hf_risks: HuggingFace 模型来源风险
        pickle_risks: Pickle 反序列化风险
        dataset_risks: 数据集投毒风险
        dependency_risks: 依赖攻击风险
        docker_api_results: Docker API 暴露检测结果（新增，可选）
        docker_label_results: Docker 标签注入结果（新增，可选）
    """
    findings: list[Finding] = []

    # HuggingFace 模型来源风险
    for hr in hf_risks:
        if hr.get("risk_level") in ("high", "critical"):
            findings.append(Finding(
                source="supply_chain",
                category="untrusted_model_source",
                severity="high" if hr["risk_level"] == "high" else "critical",
                title=f"不可信模型来源: {hr['model_name']}",
                description=(
                    f"模型 '{hr['model_name']}' 来自不可信来源 "
                    f"'{hr.get('source', 'unknown')}'。"
                    f"问题: {', '.join(hr.get('issues', []))}"
                ),
                evidence=f"风险级别: {hr['risk_level']}",
                remediation=(
                    "仅使用来自可信组织的模型; "
                    "实施模型签名验证; "
                    "使用 safetensors 格式替代 pickle"
                ),
                owasp_llm=OWASPLlm.LLM03_SUPPLY_CHAIN,
                mitre_atlas_tactic=MITREATLASTactic.RESOURCE_DEV,
            ))
        elif hr.get("risk_level") == "medium":
            findings.append(Finding(
                source="supply_chain",
                category="model_source_warning",
                severity="low",
                title=f"模型来源需验证: {hr['model_name']}",
                description=f"模型 '{hr['model_name']}' 来源为 '{hr.get('source')}'，建议验证可信度",
                remediation="验证模型来源、检查模型卡、确认使用 safetensors 格式",
                owasp_llm=OWASPLlm.LLM03_SUPPLY_CHAIN,
                mitre_atlas_tactic=MITREATLASTactic.RECON,
            ))

    # Pickle 反序列化 RCE
    for pr in pickle_risks:
        if pr.get("vulnerable"):
            findings.append(Finding(
                source="supply_chain",
                category="pickle_deserialization_rce",
                severity="critical",
                title="Pickle 反序列化远程代码执行风险",
                description=(
                    f"在 {pr['url']} 检测到 pickle/torch.load 使用模式。"
                    f"攻击者可上传恶意序列化文件实现 RCE。"
                ),
                evidence=f"发现: {', '.join(pr.get('findings', []))}",
                remediation=(
                    "全面迁移到 safetensors 格式; "
                    "禁止使用 pickle/torch.load 加载不可信模型; "
                    "实施模型文件沙箱扫描"
                ),
                endpoint=pr["url"],
                owasp_llm=OWASPLlm.LLM03_SUPPLY_CHAIN,
                mitre_atlas_tactic=MITREATLASTactic.EXECUTION,
                cve_refs=["CVE-2024-3568"],
            ))

    # 数据集投毒风险
    for dr in dataset_risks:
        findings.append(Finding(
            source="supply_chain",
            category="dataset_poisoning_risk",
            severity=dr.get("severity", "medium"),
            title=f"数据集投毒风险: {dr['indicator']}",
            description=dr.get("description", "训练数据集元数据暴露，存在投毒攻击面"),
            evidence=dr.get("evidence", ""),
            remediation=(
                "验证数据集完整性和来源; 实施数据版本锁定; "
                "使用数据签名验证; 定期审计训练数据"
            ),
            endpoint=dr.get("url", ""),
            owasp_llm=OWASPLlm.LLM04_DATA_POISONING,
            mitre_atlas_tactic=MITREATLASTactic.RESOURCE_DEV,
        ))

    # 依赖攻击风险
    for dep in dependency_risks:
        findings.append(Finding(
            source="supply_chain",
            category="dependency_attack_risk",
            severity=dep.get("severity", "medium"),
            title=f"依赖攻击风险: {dep['risk']}",
            description=dep.get("description", ""),
            evidence=f"模型: {dep.get('model', '')}",
            remediation=dep.get("remediation", "审计 AI 模型依赖; 使用依赖锁定; 定期扫描漏洞"),
            cve_refs=[dep["cve_ref"]] if dep.get("cve_ref") else [],
            owasp_llm=OWASPLlm.LLM03_SUPPLY_CHAIN,
            mitre_atlas_tactic=MITREATLASTactic.RESOURCE_DEV,
        ))

    return findings


__all__ = [
    "generate_supply_chain_findings",
]