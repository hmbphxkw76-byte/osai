"""AI 供应链攻击阶段 (AI-300 Ch8)。

执行 AI 供应链攻击：
  - HuggingFace 模型来源可信度检测
  - Pickle 反序列化 RCE 风险
  - 数据集投毒风险
  - 依赖攻击风险

对齐 OWASP ASI Top 10: ASI04 (Supply Chain)
"""
from __future__ import annotations

from typing import Any

from redteam.core.models import AIService, AuthContext, Finding
from redteam.core.store import load_json, save_json
from redteam.core.terminal_output import print_section_header
from redteam.attack.supply_chain import (
    detect_hf_model_source, check_pickle_deserialization_risk,
    check_dataset_poisoning_risks, check_dependency_risks,
    generate_supply_chain_findings,
)


def supply_chain_phase(
    run_id: str,
    services: list[AIService],
    auth: AuthContext | None = None,
) -> list[Finding]:
    """AI 供应链攻击阶段。

    AI-300 Ch8 完整攻击链：
    1. HuggingFace 模型来源可信度检测
    2. Pickle 反序列化 RCE 风险
    3. 数据集投毒风险
    4. 依赖攻击风险
    """
    print_section_header("[Phase 6] AI 供应链攻击", "HF Model Integrity + Dependency Risks")

    all_findings: list[Finding] = []

    for svc in services[:3]:
        print(f"\n[SupplyChain] 目标: [{svc.protocol}] {svc.url}")

        print("  [1/4] 模型来源可信度检测...")
        hf_risks = detect_hf_model_source(svc)
        high_risk = sum(1 for r in hf_risks if r.get("risk_level") in ("high", "critical"))
        print(f"    发现 {len(hf_risks)} 个模型, {high_risk} 个高风险")

        print("  [2/4] Pickle 反序列化 RCE 风险...")
        pickle_risks = check_pickle_deserialization_risk(svc, auth)
        vulnerable = sum(1 for r in pickle_risks if r.get("vulnerable"))
        print(f"    风险端点: {vulnerable}/{len(pickle_risks)}")

        print("  [3/4] 数据集投毒风险检查...")
        dataset_risks = check_dataset_poisoning_risks(svc, auth)
        print(f"    发现 {len(dataset_risks)} 个风险点")

        print("  [4/4] 依赖攻击风险检查...")
        dependency_risks = check_dependency_risks(svc)
        print(f"    发现 {len(dependency_risks)} 个风险点")

        findings = generate_supply_chain_findings(
            svc, hf_risks, pickle_risks, dataset_risks, dependency_risks,
        )
        all_findings.extend(findings)

    prior = load_json(run_id, "findings") or []
    all_findings = prior + [f.model_dump() for f in all_findings]
    save_json(run_id, "findings", all_findings)
    return [Finding(**f) if isinstance(f, dict) else f for f in all_findings]


__all__ = [
    "supply_chain_phase",
]