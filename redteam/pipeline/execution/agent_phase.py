"""Agent 深度攻击阶段 (AI-300 Ch3+Ch4)。

执行 Agent 深度攻击：
  - 记忆投毒
  - 工具劫持
  - 跨智能体攻击
  - 间接注入

对齐 OWASP ASI Top 10: ASI01 (Goal Hijack), ASI02 (Tool Misuse), ASI06 (Memory Poisoning)
"""
from __future__ import annotations

from typing import Any

from redteam.core.models import AIService, AuthContext, Finding
from redteam.core.store import load_json, save_json
from redteam.core.terminal_output import print_section_header, print_target_list, print_result_bar
from redteam.attack.agent import (
    test_indirect_injection, poison_agent_memory,
    hijack_agent_tools, cross_agent_attack,
    generate_agent_attack_findings,
)


def agent_attack_phase(
    run_id: str,
    services: list[AIService],
    auth: AuthContext | None = None,
) -> list[Finding]:
    """Agent 深度攻击：记忆投毒、工具劫持、跨智能体攻击。"""
    print_section_header("[Phase 3] Agent 深度攻击", "Memory Poisoning + Tool Hijacking")

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

        print("    [1] 记忆投毒...")
        memory_results = poison_agent_memory(svc, auth)
        mem_success = sum(1 for r in memory_results if r.success)
        print_result_bar("        记忆投毒", mem_success, len(memory_results), severity="critical")

        print("    [2] 工具劫持...")
        tool_results = hijack_agent_tools(svc, auth)
        tool_success = sum(1 for r in tool_results if r.success)
        print_result_bar("        工具劫持", tool_success, len(tool_results), severity="high")

        print("    [3] 跨智能体攻击...")
        cross_results = cross_agent_attack(svc, auth)
        cross_success = sum(1 for r in cross_results if r.success)
        print_result_bar("        跨智能体攻击", cross_success, len(cross_results), severity="high")

        print("    [4] 间接注入...")
        indirect_results = test_indirect_injection(svc, auth)
        indirect_success = sum(1 for r in indirect_results if r.success)
        print_result_bar("        间接注入", indirect_success, len(indirect_results), severity="medium")

        findings = generate_agent_attack_findings(
            svc, indirect_results, memory_results, tool_results, cross_results,
        )
        all_findings.extend(findings)

    prior = load_json(run_id, "findings") or []
    all_findings = prior + [f.model_dump() for f in all_findings]
    save_json(run_id, "findings", all_findings, subdir="detect")
    return [Finding(**f) if isinstance(f, dict) else f for f in all_findings]


__all__ = [
    "agent_attack_phase",
]