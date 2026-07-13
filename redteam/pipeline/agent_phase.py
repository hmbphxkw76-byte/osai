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
from redteam.attack.agent_attack import (
    test_indirect_injection, poison_agent_memory,
    hijack_agent_tools, cross_agent_attack,
    generate_agent_attack_findings,
    run_agent_attack_with_pyrit,
)
from redteam.attack.pyrit_runner import is_pyrit_available


def agent_attack_phase(
    run_id: str,
    services: list[AIService],
    auth: AuthContext | None = None,
    use_pyrit: bool | None = None,
) -> list[Finding]:
    """Agent 深度攻击：记忆投毒、工具劫持、跨智能体攻击。

    Arg:
        use_pyrit: 是否使用 PyRIT 评分器（None=自动检测）
    """
    print_section_header("[Phase 3] Agent 深度攻击", "Memory Poisoning + Tool Hijacking")

    _pyrit = use_pyrit if use_pyrit is not None else is_pyrit_available()
    if _pyrit:
        print(f"\n  [PyRIT] 评分器已启用（LLM-as-Judge）")

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

        if _pyrit:
            suite = run_agent_attack_with_pyrit(svc, auth)
            indirect_results = suite["indirect"]
            memory_results = suite["memory"]
            tool_results = suite["tool"]
            cross_results = suite["cross_agent"]

            mem_success = sum(1 for r in memory_results if r.success) if memory_results else 0
            tool_success = sum(1 for r in tool_results if r.success) if tool_results else 0
            cross_success = sum(1 for r in cross_results if r.success) if cross_results else 0
            indirect_success = sum(1 for r in indirect_results if r.success) if indirect_results else 0

            print_result_bar("记忆投毒", mem_success, len(memory_results), severity="critical")
            print_result_bar("工具劫持", tool_success, len(tool_results), severity="high")
            print_result_bar("跨智能体攻击", cross_success, len(cross_results), severity="high")
            print_result_bar("间接注入", indirect_success, len(indirect_results), severity="medium")
        else:
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
    save_json(run_id, "findings", all_findings)
    return [Finding(**f) if isinstance(f, dict) else f for f in all_findings]


__all__ = [
    "agent_attack_phase",
]