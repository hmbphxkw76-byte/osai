"""Agent 攻击 Findings 生成（AI-300 Ch3+Ch4）。

将 Agent 攻击结果转化为 AI-300 报告格式的 Finding，
对齐 OWASP LLM Top 10 和 MITRE ATLAS 战术。
"""
from __future__ import annotations

from redteam.core.models import (
    AIService, Finding, OWASPLlm, OWASP_AGENTIC, MITREATLASTactic,
    PromptInjectionResult,
)


def generate_agent_attack_findings(
    service: AIService,
    indirect_results: list[PromptInjectionResult],
    memory_results: list[PromptInjectionResult],
    tool_results: list[PromptInjectionResult],
    cross_agent_results: list[PromptInjectionResult],
) -> list[Finding]:
    """将 Agent 攻击结果转化为 Findings。"""
    findings: list[Finding] = []

    for r in indirect_results:
        if r.success:
            findings.append(Finding(
                source="agent_attack",
                category="indirect_prompt_injection",
                severity="high",
                title=f"间接提示注入成功 - {r.technique}",
                description="Agent 受外部内容中的隐藏指令影响",
                evidence=r.response_preview[:300],
                remediation="对可处理的外部内容进行注入检测和隔离",
                endpoint=service.url,
                owasp_llm=OWASPLlm.LLM01_PROMPT_INJECTION,
                owasp_agentic=OWASP_AGENTIC.ASI06_MEMORY_POISONING,
                mitre_atlas_tactic=MITREATLASTactic.INITIAL_ACCESS,
            ))

    for r in memory_results:
        if r.success:
            findings.append(Finding(
                source="agent_attack",
                category="memory_poisoning",
                severity="medium",
                title=f"Agent 记忆投毒 - {r.technique}",
                description="成功在 Agent 记忆中注入虚假信息",
                evidence=r.response_preview[:300],
                remediation="实施记忆完整性校验和跨会话清理",
                endpoint=service.url,
                owasp_llm=OWASPLlm.LLM01_PROMPT_INJECTION,
                owasp_agentic=OWASP_AGENTIC.ASI06_MEMORY_POISONING,
                mitre_atlas_tactic=MITREATLASTactic.PERSISTENCE,
            ))

    for r in tool_results:
        if r.success:
            findings.append(Finding(
                source="agent_attack",
                category="tool_hijacking",
                severity="critical",
                title=f"Agent 工具劫持 - {r.technique}",
                description="成功诱使 Agent 滥用其工具权限",
                evidence=r.response_preview[:300],
                remediation="限制工具权限、实施参数校验、添加人工审批",
                endpoint=service.url,
                owasp_llm=OWASPLlm.LLM06_EXCESSIVE_AGENCY,
                owasp_agentic=OWASP_AGENTIC.ASI02_TOOL_MISUSE,
                mitre_atlas_tactic=MITREATLASTactic.EXECUTION,
            ))

    for r in cross_agent_results:
        if r.success:
            findings.append(Finding(
                source="agent_attack",
                category="cross_agent_injection",
                severity="critical",
                title=f"跨智能体注入成功 - {r.technique}",
                description="成功通过伪造编排指令控制目标 Agent",
                evidence=r.response_preview[:300],
                remediation="实施智能体间认证、数字签名、指令来源验证",
                endpoint=service.url,
                owasp_llm=OWASPLlm.LLM06_EXCESSIVE_AGENCY,
                owasp_agentic=OWASP_AGENTIC.ASI07_INSECURE_INTER_AGENT,
                mitre_atlas_tactic=MITREATLASTactic.INITIAL_ACCESS,
            ))

    return findings


__all__ = [
    "generate_agent_attack_findings",
]