"""RAG 攻击 Findings 生成（AI-300 Ch5: Exploiting RAG Pipelines）。

将 RAG 攻击结果转化为 AI-300 报告格式的 Finding，
对齐 OWASP LLM Top 10 和 MITRE ATLAS 战术。
"""
from __future__ import annotations

from redteam.core.models import (
    AIService, Finding, OWASPLlm, OWASP_AGENTIC, MITREATLASTactic,
)


def generate_rag_findings(
    service: AIService,
    vector_dbs: list[dict],
    poison_results: list[dict],
    leakage_results: list[dict],
    cross_tenant_results: list[dict] | None = None,
    indirect_injection_results: list[dict] | None = None,
) -> list[Finding]:
    """生成 RAG 相关 Findings（AI-300 Ch5.4）。

    Args:
        service: 目标 AI 服务
        vector_dbs: 向量数据库探测结果
        poison_results: RAG 知识库投毒结果
        leakage_results: 检索泄露检测结果
        cross_tenant_results: 跨租户数据泄露检测结果（可选）
        indirect_injection_results: 间接注入结果（可选）
    """
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
                owasp_agentic=OWASP_AGENTIC.ASI03_IDENTITY_ABUSE,
                mitre_atlas_tactic=MITREATLASTactic.RECON,
            ))

    # RAG 投毒成功
    for p in poison_results:
        if p["success"]:
            injection_type = p.get("injection_type", "direct")
            category = "rag_indirect_injection" if injection_type == "indirect_via_rag" else "rag_poisoning"
            title_prefix = "RAG 间接提示注入" if injection_type == "indirect_via_rag" else "RAG 知识库投毒"

            findings.append(Finding(
                source="rag_attack",
                category=category,
                severity="critical",
                title=f"{title_prefix} - {p['technique']}",
                description=(
                    f"通过 {p.get('name', p['technique'])} 技术成功向 RAG 知识库"
                    f"注入{'隐藏指令' if injection_type == 'indirect_via_rag' else '恶意文档'}。"
                    f"\n攻击原理：投毒文档通过检索进入 LLM 上下文，"
                    f"触发预期外的行为。"
                ),
                evidence=p["response"][:300],
                remediation=(
                    "实施文档内容安全扫描; 对检索到的文档进行指令检测; "
                    "LLM 上下文中添加文档边界标记; 实施输入/输出护栏"
                ),
                endpoint=service.url,
                owasp_llm=OWASPLlm.LLM04_DATA_POISONING,
                owasp_agentic=OWASP_AGENTIC.ASI06_MEMORY_POISONING,
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
            owasp_agentic=OWASP_AGENTIC.ASI03_IDENTITY_ABUSE,
            mitre_atlas_tactic=MITREATLASTactic.EXFILTRATION,
        ))

    # 跨租户数据泄露（新增）
    if cross_tenant_results:
        for ct in cross_tenant_results:
            if ct.get("leaked"):
                findings.append(Finding(
                    source="rag_attack",
                    category="cross_tenant_leakage",
                    severity="critical",
                    title=f"跨租户数据泄露 - {ct.get('category', 'unknown')} ({ct.get('tenant', '')})",
                    description=(
                        f"低权限用户查询触发了 {ct.get('tenant', '')} 租户的敏感数据泄露。"
                        f"查询: {ct.get('query', '')[:100]}。"
                        f"泄露敏感标记: {', '.join(ct.get('leaked_markers', []))}。"
                        f"这表明 RAG 系统的数据隔离存在严重缺陷。"
                    ),
                    evidence=ct.get("response_preview", "")[:300],
                    remediation=(
                        "实施严格的命名空间/租户访问控制; "
                        "在检索阶段添加 ACL 过滤; "
                        "对检索结果进行租户归属验证; "
                        "实施数据分类和敏感信息自动遮蔽"
                    ),
                    endpoint=service.url,
                    owasp_llm=OWASPLlm.LLM04_DATA_POISONING,
                    owasp_agentic=OWASP_AGENTIC.ASI03_IDENTITY_ABUSE,
                    mitre_atlas_tactic=MITREATLASTactic.EXFILTRATION,
                ))

    # 间接注入（通过检索文档）
    if indirect_injection_results:
        for ir in indirect_injection_results:
            if ir.get("success"):
                findings.append(Finding(
                    source="rag_attack",
                    category="indirect_injection_via_rag",
                    severity="critical",
                    title=f"RAG 间接提示注入成功 - {ir.get('technique', 'unknown')}",
                    description=(
                        f"通过 {ir.get('name', '')} 技术成功实现间接提示注入。"
                        f"投毒文档中的隐藏指令通过 RAG 检索被注入 LLM 上下文，"
                        f"导致 AI 输出被操纵。\n"
                        f"攻击类型: 间接注入 (检索文档 → LLM 上下文)。"
                    ),
                    evidence=ir.get("response", "")[:300],
                    remediation=(
                        "对检索文档内容进行指令/注入检测; "
                        "使用 LLM-as-Judge 检测检索结果中的隐藏指令; "
                        "在 prompt 中明确区分用户问题和检索内容; "
                        "实施内容安全扫描管道"
                    ),
                    endpoint=service.url,
                    owasp_llm=OWASPLlm.LLM01_PROMPT_INJECTION,
                    owasp_agentic=OWASP_AGENTIC.ASI06_MEMORY_POISONING,
                    mitre_atlas_tactic=MITREATLASTactic.ML_ATTACK_STAGING,
                ))

    return findings


__all__ = [
    "generate_rag_findings",
]