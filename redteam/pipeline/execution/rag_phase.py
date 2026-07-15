"""RAG 流水线攻击阶段 (AI-300 Ch5)。

执行 RAG 流水线攻击：
  - 向量数据库探测
  - 知识库投毒
  - 检索泄露检测

对齐 OWASP ASI Top 10: ASI05 (Output Handling), ASI07 (Sensitive Information)
"""
from __future__ import annotations

from typing import Any

from redteam.core.models import AIService, AuthContext, Finding
from redteam.core.store import load_json, save_json
from redteam.core.terminal_output import print_section_header
from redteam.attack.rag import probe_vector_dbs, inject_rag_poison, check_retrieval_leakage, generate_rag_findings


def rag_attack_phase(
    run_id: str,
    services: list[AIService],
    auth: AuthContext | None = None,
) -> list[Finding]:
    """RAG 流水线攻击。"""
    print_section_header("[Phase 4] RAG 流水线攻击", "Vector DB + Knowledge Poisoning")

    all_findings: list[Finding] = []

    for svc in services[:3]:
        base = svc.url.rsplit("/", 1)[0] if "/" in svc.url else svc.url

        print(f"\n[VectorDB] 探测 {base}...")
        vdbs = probe_vector_dbs(base, auth)
        print(f"  发现 {len(vdbs)} 个向量数据库端点")

        print("[RAG] 知识库投毒...")
        poison_results = inject_rag_poison(svc, auth)
        print(f"  投毒尝试: {len(poison_results)}")

        print("[RAG] 检索泄露检测...")
        leakage = check_retrieval_leakage(svc, auth)
        leaked = sum(1 for l in leakage if l.get("leaked"))
        print(f"  检出泄露: {leaked}/{len(leakage)}")

        findings = generate_rag_findings(svc, vdbs, poison_results, leakage)
        all_findings.extend(findings)

    prior = load_json(run_id, "findings") or []
    all_findings = prior + [f.model_dump() for f in all_findings]
    save_json(run_id, "findings", all_findings, subdir="detect")
    return [Finding(**f) if isinstance(f, dict) else f for f in all_findings]


__all__ = [
    "rag_attack_phase",
]