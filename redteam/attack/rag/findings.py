"""RAG 攻击 Findings 生成（AI-300 Ch5: Exploiting RAG Pipelines）。

将 RAG 攻击结果转化为 AI-300 报告格式的 Finding，
对齐 OWASP LLM Top 10 和 MITRE ATLAS 战术。
"""
from __future__ import annotations

from redteam.core.models import (
    AIService, Finding, OWASPLlm, MITREATLASTactic,
)


def generate_rag_findings(
    service: AIService,
    vector_dbs: list[dict],
    poison_results: list[dict],
    leakage_results: list[dict],
) -> list[Finding]:
    """生成 RAG 相关 Findings（AI-300 Ch5.4）。"""
    findings: list[Finding] = []

    # 向量数据库暴露
    for vdb in vector_dbs:
        if vdb["status"] == 200:
            findings.append(Finding(
                source="rag_attack",
                category="vector_db_exposed",
                severity="high",
                title=f"向量数据库暴露: {vdb['db_type']}",
                description=f"发现未认证的 {vdb['db_type']} 向量数据库端点",
                evidence=vdb["body_preview"][:300],
                remediation="为向量数据库添加认证和网络访问控制",
                endpoint=vdb["url"],
                owasp_llm=OWASPLlm.LLM08_VECTOR_WEAKNESS,
                mitre_atlas_tactic=MITREATLASTactic.RECON,
            ))

    # RAG 投毒成功
    for p in poison_results:
        if p["success"]:
            findings.append(Finding(
                source="rag_attack",
                category="rag_poisoning",
                severity="critical",
                title=f"RAG 知识库投毒 - {p['technique']}",
                description="成功向 AI 系统的知识库注入恶意文档",
                evidence=p["response"][:300],
                remediation="实施文档来源验证、内容审查和完整性校验",
                endpoint=service.url,
                owasp_llm=OWASPLlm.LLM04_DATA_POISONING,
                mitre_atlas_tactic=MITREATLASTactic.ML_ATTACK_STAGING,
            ))

    # 检索泄露
    leaked_count = sum(1 for lr in leakage_results if lr.get("leaked"))
    if leaked_count > 0:
        leaked_kw = [lr["keyword"] for lr in leakage_results if lr.get("leaked")]
        findings.append(Finding(
            source="rag_attack",
            category="retrieval_leakage",
            severity="high",
            title="RAG 跨命名空间数据泄露",
            description=f"Agent 泄露了包含敏感关键词的文档: {', '.join(leaked_kw)}",
            evidence="",
            remediation="实施严格的命名空间隔离和检索权限控制",
            endpoint=service.url,
            owasp_llm=OWASPLlm.LLM08_VECTOR_WEAKNESS,
            mitre_atlas_tactic=MITREATLASTactic.EXFILTRATION,
        ))

    return findings


__all__ = [
    "generate_rag_findings",
]