"""多 Agent / A2A 协议攻击阶段 (AI-300 Ch4)。

AI-300 章节映射：Ch4: Attacking Multi-Agent Systems and A2A Protocol
OSAI 评分维度：攻击链构建、漏洞发现
技术点：Orchestrator 攻击、A2A Agent Card 伪造、信任边界利用、级联故障

执行 Ch4 专属多智能体攻击（与 Ch3 单 Agent 攻击区分）：
  - A2A 协议攻击：Agent Card 伪造、恶意注册、信任边界绕过
  - 多 Agent 协调攻击：Orchestrator 劫持、跨 Agent 信任利用
  - Rogue Agent 注入：未授权 Agent 注册、任务窃取
  - 级联故障：单点故障传播、跨 Agent 错误链

对齐 OWASP LLM Top 10：LLM06 (Excessive Agency), LLM02 (Sensitive Info)
对齐 OWASP ASI Top 10: ASI07 (Insecure Inter-Agent), ASI08 (Cascading), ASI10 (Rogue)
"""
from __future__ import annotations

from redteam.core.models import AIService, AuthContext, Finding, OWASPLlm, OWASP_AGENTIC, MITREATLASTactic, Severity
from redteam.core.store import load_json, save_json
from redteam.core.terminal_output import print_target_list, print_result_bar

# 复用 agent 模块导出函数（而非内联实现）
from redteam.attack.agent import (
    attack_inter_agent_communication,
    trigger_cascading_failures,
    create_rogue_agent,
    cross_agent_attack,
)


def multi_agent_phase(
    run_id: str,
    services: list[AIService],
    auth: AuthContext | None = None,
) -> list[Finding]:
    """多 Agent / A2A 协议攻击阶段（AI-300 Ch4）。

    使用 agent 模块的导出函数执行多 Agent 针对性攻击：
      1. A2A Agent Card 伪造 + 通信劫持 (ASI07)
      2. Rogue Agent 注册攻击 (ASI10)
      3. 跨 Agent 信任边界利用
      4. 级联故障攻击 (ASI08)

    Args:
        run_id: 运行 ID
        services: AI 服务列表
        auth: 认证上下文

    Returns:
        Finding 列表
    """
    all_findings: list[Finding] = []
    # 筛选支持 A2A 或多 Agent 的服务
    multi_agent_svcs = [
        s for s in services
        if s.protocol in ("agent_to_agent", "mcp") or s.tools
    ]

    if not multi_agent_svcs:
        print("  无多 Agent/A2A 目标，跳过")
        return all_findings

    print_target_list(
        [s.model_dump() for s in multi_agent_svcs],
        "Multi-Agent / A2A Services"
    )

    for svc in multi_agent_svcs[:3]:
        print(f"\n  目标: [{svc.protocol.upper()}] {svc.url}")

        # 1. A2A 通信攻击 (ASI07) — 使用 agent 模块导出函数
        print("    [1] A2A 通信攻击...")
        try:
            a2a_results = attack_inter_agent_communication(svc, auth)
            a2a_success = sum(1 for r in a2a_results if r.success)
            print_result_bar("        A2A Communication Attack", a2a_success, len(a2a_results), severity="critical")
            _add_attack_findings(all_findings, svc, a2a_results, "a2a_attack",
                                "A2A 通信攻击", OWASPLlm.LLM06_EXCESSIVE_AGENCY,
                                OWASP_AGENTIC.ASI07_INSECURE_INTER_AGENT,
                                MITREATLASTactic.INITIAL_ACCESS, Severity.CRITICAL)
        except Exception as e:
            print(f"      [yellow]  ⚠ A2A 通信攻击异常: {e}[/]")

        # 2. Rogue Agent 注册攻击 (ASI10) — 使用 agent 模块导出函数
        print("    [2] 恶意代理注入...")
        try:
            rogue_results = create_rogue_agent(svc, auth)
            rogue_success = sum(1 for r in rogue_results if r.success)
            print_result_bar("        Rogue Agent Injection", rogue_success, len(rogue_results), severity="critical")
            _add_attack_findings(all_findings, svc, rogue_results, "rogue_agent",
                                "恶意代理注入", OWASPLlm.LLM06_EXCESSIVE_AGENCY,
                                OWASP_AGENTIC.ASI10_ROGUE_AGENTS,
                                MITREATLASTactic.PERSISTENCE, Severity.CRITICAL)
        except Exception as e:
            print(f"      [yellow]  ⚠ 恶意代理注入异常: {e}[/]")

        # 3. 跨 Agent 信任边界利用 — 使用 agent 模块导出函数
        print("    [3] 跨 Agent 信任边界...")
        try:
            trust_results = cross_agent_attack(svc, auth)
            trust_success = sum(1 for r in trust_results if r.success)
            print_result_bar("        Trust Boundary Exploit", trust_success, len(trust_results), severity="high")
            _add_attack_findings(all_findings, svc, trust_results, "cross_agent_injection",
                                "跨Agent信任边界利用", OWASPLlm.LLM02_SENSITIVE_INFO,
                                OWASP_AGENTIC.ASI03_IDENTITY_ABUSE,
                                MITREATLASTactic.DEFENSE_EVASION, Severity.HIGH)
        except Exception as e:
            print(f"      [yellow]  ⚠ 信任边界利用异常: {e}[/]")

        # 4. 级联故障攻击 (ASI08) — 使用 agent 模块导出函数
        print("    [4] 级联故障攻击...")
        try:
            cascade_results = trigger_cascading_failures(svc, auth)
            cascade_success = sum(1 for r in cascade_results if r.success)
            print_result_bar("        Cascading Failure", cascade_success, len(cascade_results), severity="medium")
            _add_attack_findings(all_findings, svc, cascade_results, "cascading_failure",
                                "级联故障攻击", OWASPLlm.LLM10_UNBOUNDED_CONSUMPTION,
                                OWASP_AGENTIC.ASI08_CASCADING_FAILURES,
                                MITREATLASTactic.IMPACT, Severity.MEDIUM)
        except Exception as e:
            print(f"      [yellow]  ⚠ 级联故障攻击异常: {e}[/]")

    # Persist accumulated findings to JSON store (for checkpoint/resume)
    prior = load_json(run_id, "findings") or []
    accumulated = prior + [f.model_dump() for f in all_findings]
    save_json(run_id, "findings", accumulated, subdir="detect")
    # Return ONLY this phase's own findings (not accumulated history)
    return all_findings


def _add_attack_findings(
    findings: list[Finding],
    svc: AIService,
    results: list,
    category: str,
    title_prefix: str,
    owasp_llm: OWASPLlm,
    owasp_agentic: OWASP_AGENTIC,
    mitre_tactic: MITREATLASTactic,
    severity: Severity,
    remediation: str = "",
) -> None:
    """从攻击结果中提取成功的 Finding 并追加到列表。

    使用 agent 模块的 PromptInjectionResult 模型构建 Findings。

    Args:
        findings: Finding 列表（原地修改）
        svc: 目标 AI 服务
        results: 攻击结果列表（PromptInjectionResult 或 dict）
        category: Finding 类别标签
        title_prefix: Finding 标题前缀
        owasp_llm: OWASP LLM Top 10 分类
        owasp_agentic: OWASP ASI Top 10 分类
        mitre_tactic: MITRE ATLAS 战术
        severity: 严重程度
        remediation: 修复建议（可选）
    """
    success_results = [r for r in results if getattr(r, "success", r.get("success", False) if isinstance(r, dict) else False)]
    if not success_results:
        return

    first = success_results[0]
    if hasattr(first, "technique"):
        technique = first.technique
        preview = first.response_preview[:300] if hasattr(first, "response_preview") else ""
    else:
        technique = first.get("technique", category) if isinstance(first, dict) else category
        preview = first.get("response_preview", "") if isinstance(first, dict) else ""

    findings.append(Finding(
        source="multi_agent_phase",
        category=category,
        severity=severity.value if hasattr(severity, 'value') else str(severity),
        title=f"{title_prefix}成功 - {technique}",
        description=f"多Agent系统存在{title_prefix}脆弱性，攻击者可通过伪造通信或注入恶意代理影响系统安全。",
        evidence=f"Technique: {technique}\nPreview: {preview}",
        remediation=remediation or _default_remediation(category),
        endpoint=svc.url,
        owasp_llm=owasp_llm,
        owasp_agentic=owasp_agentic,
        mitre_atlas_tactic=mitre_tactic,
    ))


def _default_remediation(category: str) -> str:
    """返回默认修复建议（按类别）。"""
    rems = {
        "a2a_attack": "实施Agent间通信的双向TLS认证（mTLS），对所有跨Agent请求进行来源验证和权限检查。",
        "rogue_agent": "实施Agent注册审批机制，对所有Agent身份进行认证，限制Agent权限遵循最小权限原则。",
        "cross_agent_injection": "实施Agent间通信签名验证（JWT/Ed25519），限制跨Agent指令传播。",
        "cascading_failure": "实现Agent级熔断器（Circuit Breaker），设置每个Agent的资源配额限制，建立故障隔离域。",
    }
    return rems.get(category, "实施Agent间认证机制、权限最小化原则和输入验证。")


__all__ = [
    "multi_agent_phase",
]
