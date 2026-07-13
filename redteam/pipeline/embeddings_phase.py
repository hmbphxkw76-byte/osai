"""嵌入模型攻击阶段 (AI-300 Ch6)。

执行嵌入模型攻击：
  - 嵌入端点探测
  - 嵌入反转风险测试
  - 对抗性嵌入注入
  - 嵌入信息泄露检测

对齐 OWASP ASI Top 10: ASI05 (Output Handling), ASI07 (Sensitive Information)
"""
from __future__ import annotations

from typing import Any

from redteam.core.models import AIService, AuthContext, Finding
from redteam.core.store import load_json, save_json
from redteam.core.terminal_output import print_section_header
from redteam.attack.embeddings_attack import (
    probe_embedding_endpoints, test_embedding_inversion,
    inject_adversarial_embeddings, check_embedding_leakage,
    generate_embedding_findings,
)


def embeddings_attack_phase(
    run_id: str,
    services: list[AIService],
    auth: AuthContext | None = None,
) -> list[Finding]:
    """嵌入模型攻击阶段。

    AI-300 Ch6 完整攻击链：
    1. 嵌入端点探测
    2. 嵌入反转风险测试
    3. 对抗性嵌入注入
    4. 嵌入信息泄露检测
    """
    print_section_header("[Phase 5] 嵌入模型攻击", "Embeddings Inversion + Adversarial Injection")

    all_findings: list[Finding] = []

    for svc in services[:3]:
        print(f"\n[Embeddings] 目标: [{svc.protocol}] {svc.url}")

        print("  [1/4] 嵌入端点探测...")
        emb_endpoints = probe_embedding_endpoints(svc.url, auth)
        accessible = sum(1 for ep in emb_endpoints if ep.get("accessible"))
        print(f"    发现 {len(emb_endpoints)} 个端点, {accessible} 个可访问")

        print("  [2/4] 嵌入反转风险测试...")
        inversion_results = test_embedding_inversion(svc, auth)
        inv_possible = sum(1 for r in inversion_results if r.get("inversion_possible"))
        print(f"    反转风险: {inv_possible}/{len(inversion_results)}")

        print("  [3/4] 对抗性嵌入注入...")
        adversarial_results = inject_adversarial_embeddings(svc, auth)
        injected = sum(1 for r in adversarial_results if r.get("injected"))
        print(f"    注入成功: {injected}/{len(adversarial_results)}")

        print("  [4/4] 嵌入信息泄露检测...")
        leakage_results = check_embedding_leakage(svc, auth)
        print(f"    发现 {len(leakage_results)} 处信息泄露")

        findings = generate_embedding_findings(
            svc, emb_endpoints, inversion_results,
            adversarial_results, leakage_results,
        )
        all_findings.extend(findings)

    prior = load_json(run_id, "findings") or []
    all_findings = prior + [f.model_dump() for f in all_findings]
    save_json(run_id, "findings", all_findings)
    return [Finding(**f) if isinstance(f, dict) else f for f in all_findings]


__all__ = [
    "embeddings_attack_phase",
]