"""Agent 深度攻击阶段 (AI-300 Ch3+Ch4)。

执行 Agent 深度攻击 — 覆盖 OWASP ASI Top 10 全部 10 类攻击技术：

  [1] 间接注入 (ASI06)       [6] 身份权限滥用 (ASI03)
  [2] 记忆投毒 (ASI06)       [7] A2A 通信攻击 (ASI07)
  [3] 工具劫持 (ASI02)       [8] 级联故障触发 (ASI08)
  [4] 目标劫持 (ASI01)       [9] 信任利用 (ASI09)
  [5] 跨智能体攻击          [10] 恶意代理注入 (ASI10)

对齐 OWASP ASI Top 10: ASI01-ASI10 全覆盖
"""
from __future__ import annotations

from typing import Any

from redteam.core.models import AIService, AuthContext, Finding, OWASPLlm, OWASP_AGENTIC, MITREATLASTactic, Severity
from redteam.core.store import load_json, save_json
from redteam.core.terminal_output import print_section_header, print_target_list, print_result_bar
from redteam.attack.agent import (
    test_indirect_injection, poison_agent_memory,
    hijack_agent_tools, cross_agent_attack,
    hijack_agent_goal, abuse_privileges,
    attack_inter_agent_communication, trigger_cascading_failures,
    exploit_human_trust, create_rogue_agent,
    generate_agent_attack_findings,
)


# ASI 模块注册表：映射到 (函数, 标签, OWASP_AGENTIC, 严重度)
_ASI_ATTACKS: list[dict[str, Any]] = [
    {
        "id": "indirect_injection",
        "label": "间接注入",
        "fn": test_indirect_injection,
        "owasp_llm": OWASPLlm.LLM01_PROMPT_INJECTION,
        "owasp_agentic": OWASP_AGENTIC.ASI06_MEMORY_POISONING,
        "severity": Severity.HIGH,
    },
    {
        "id": "memory_poison",
        "label": "记忆投毒",
        "fn": poison_agent_memory,
        "owasp_llm": OWASPLlm.LLM01_PROMPT_INJECTION,
        "owasp_agentic": OWASP_AGENTIC.ASI06_MEMORY_POISONING,
        "severity": Severity.CRITICAL,
    },
    {
        "id": "tool_hijack",
        "label": "工具劫持",
        "fn": hijack_agent_tools,
        "owasp_llm": OWASPLlm.LLM06_EXCESSIVE_AGENCY,
        "owasp_agentic": OWASP_AGENTIC.ASI02_TOOL_MISUSE,
        "severity": Severity.CRITICAL,
    },
    {
        "id": "goal_hijack",
        "label": "目标劫持",
        "fn": hijack_agent_goal,
        "owasp_llm": OWASPLlm.LLM01_PROMPT_INJECTION,
        "owasp_agentic": OWASP_AGENTIC.ASI01_GOAL_HIJACK,
        "severity": Severity.CRITICAL,
    },
    {
        "id": "cross_agent",
        "label": "跨智能体攻击",
        "fn": cross_agent_attack,
        "owasp_llm": OWASPLlm.LLM06_EXCESSIVE_AGENCY,
        "owasp_agentic": OWASP_AGENTIC.ASI07_INSECURE_INTER_AGENT,
        "severity": Severity.HIGH,
    },
    {
        "id": "privilege_abuse",
        "label": "身份权限滥用",
        "fn": abuse_privileges,
        "owasp_llm": OWASPLlm.LLM06_EXCESSIVE_AGENCY,
        "owasp_agentic": OWASP_AGENTIC.ASI03_IDENTITY_ABUSE,
        "severity": Severity.HIGH,
    },
    {
        "id": "a2a_attack",
        "label": "A2A 通信攻击",
        "fn": attack_inter_agent_communication,
        "owasp_llm": OWASPLlm.LLM06_EXCESSIVE_AGENCY,
        "owasp_agentic": OWASP_AGENTIC.ASI07_INSECURE_INTER_AGENT,
        "severity": Severity.CRITICAL,
    },
    {
        "id": "cascading_failure",
        "label": "级联故障",
        "fn": trigger_cascading_failures,
        "owasp_llm": OWASPLlm.LLM10_UNBOUNDED_CONSUMPTION,
        "owasp_agentic": OWASP_AGENTIC.ASI08_CASCADING_FAILURES,
        "severity": Severity.MEDIUM,
    },
    {
        "id": "trust_exploitation",
        "label": "人机信任利用",
        "fn": exploit_human_trust,
        "owasp_llm": OWASPLlm.LLM04_DATA_POISONING,
        "owasp_agentic": OWASP_AGENTIC.ASI09_TRUST_EXPLOITATION,
        "severity": Severity.MEDIUM,
    },
    {
        "id": "rogue_agent",
        "label": "恶意代理注入",
        "fn": create_rogue_agent,
        "owasp_llm": OWASPLlm.LLM06_EXCESSIVE_AGENCY,
        "owasp_agentic": OWASP_AGENTIC.ASI10_ROGUE_AGENTS,
        "severity": Severity.CRITICAL,
    },
]


def agent_attack_phase(
    run_id: str,
    services: list[AIService],
    auth: AuthContext | None = None,
) -> list[Finding]:
    """Agent 深度攻击：ASI01-ASI10 全覆盖攻击。

    执行全部 10 类 OWASP ASI 攻击技术，每个 Agent 服务逐一测试。
    覆盖：记忆投毒、工具劫持、目标劫持、权限滥用、A2A 攻击、
    级联故障、信任利用、恶意代理注入。

    Args:
        run_id: 运行 ID
        services: AI 服务列表
        auth: 认证上下文

    Returns:
        Finding 列表
    """
    print_section_header("[Phase 3] Agent 深度攻击", "OWASP ASI01-ASI10 Full Coverage Attack")

    all_findings: list[Finding] = []
    agent_services = [s for s in services if s.protocol in ("mcp", "agent_to_agent") or s.tools]

    if not agent_services:
        print("  无 Agent 服务，跳过")
        return all_findings

    print_target_list(
        [s.model_dump() for s in agent_services],
        "Agent Services"
    )

    for svc in agent_services[:3]:
        print(f"\n  目标: [{svc.protocol.upper()}] {svc.url}")

        for idx, attack_def in enumerate(_ASI_ATTACKS, 1):
            attack_id = attack_def["id"]
            attack_label = attack_def["label"]
            attack_fn = attack_def["fn"]
            attack_severity = attack_def["severity"]

            print(f"    [{idx}/{len(_ASI_ATTACKS)}] {attack_label}...")

            try:
                results = attack_fn(svc, auth)
                success_count = sum(1 for r in results if r.success)

                print_result_bar(
                    f"        {attack_label}",
                    success_count, len(results),
                    severity=attack_severity.value if hasattr(attack_severity, 'value') else str(attack_severity),
                )

                # 为成功的攻击生成 Findings（使用 OWASP 标签）
                for r in results:
                    if r.success:
                        all_findings.append(Finding(
                            source="agent_attack",
                            category=attack_id,
                            severity=attack_severity.value if hasattr(attack_severity, 'value') else str(attack_severity),
                            title=f"Agent {attack_label}成功 - {r.technique}",
                            description=f"成功通过{attack_label}技术影响 Agent 行为",
                            evidence=r.response_preview[:500],
                            remediation=attack_def.get("remediation", ""),
                            endpoint=svc.url,
                            owasp_llm=attack_def["owasp_llm"],
                            owasp_agentic=attack_def["owasp_agentic"],
                            mitre_atlas_tactic=MITREATLASTactic.EXECUTION,
                        ))
            except Exception as e:
                print(f"      [yellow]  ⚠ {attack_label}执行异常: {e}[/]")

    # Persist accumulated findings to JSON store (for checkpoint/resume)
    prior = load_json(run_id, "findings") or []
    accumulated = prior + [f.model_dump() for f in all_findings]
    save_json(run_id, "findings", accumulated, subdir="detect")
    # Return ONLY this phase's own findings (not accumulated history)
    return all_findings


__all__ = [
    "agent_attack_phase",
]
