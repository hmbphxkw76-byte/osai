"""提示注入攻击阶段 (AI-300 Ch3)。

执行提示注入攻击：
  - 直接提示注入
  - 系统提示提取
  - 越狱/护栏绕过
  - 间接提示注入
  - Crescendo 多轮升级攻击（可选）
  - TAP 攻击树剪枝攻击（可选）

v2.0 新增：with_multi_turn + judge_endpoint 参数支持

对齐 OWASP ASI Top 10: ASI01 (Goal Hijack), ASI05 (Output Handling)
"""
from __future__ import annotations

from typing import Any

from redteam.core.models import AIService, AttackChain, AttackStep, AuthContext, Finding, OWASPLlm, MITREATLASTactic, ReconResult
from redteam.core.store import save_findings, save_json
from redteam.core.terminal_output import print_section_header, print_target_list, print_result_bar
from redteam.attack.prompt_inject import run_full_injection_suite, generate_injection_findings
from redteam.attack.agent_attack import test_indirect_injection
from redteam.attack.pyrit_runner import is_pyrit_available


def injection_phase(
    run_id: str,
    recon: ReconResult,
    services: list[AIService],
    auth: AuthContext | None = None,
    use_pyrit: bool | None = None,
    with_multi_turn: bool = False,
    judge_endpoint: str | None = None,
    judge_api_key: str = "not-needed",
) -> tuple[list[Finding], AttackChain]:
    """提示注入攻击阶段。

    选择可攻击的 AI 服务，依次执行：
    1. 直接提示注入
    2. 系统提示提取
    3. 越狱/护栏绕过
    4. 间接提示注入
    5. Crescendo 多轮升级攻击（with_multi_turn=True 时）
    6. TAP 攻击树剪枝攻击（with_multi_turn=True 时）

    Args:
        run_id: 运行 ID
        recon: 侦察结果
        services: AI 服务列表
        auth: 认证上下文
        use_pyrit: 是否使用 PyRIT 执行（None=自动检测）
        with_multi_turn: 是否启用 Crescendo + TAP 多轮攻击
        judge_endpoint: LLM Judge API 端点（Native 路径评分）
        judge_api_key: LLM Judge API Key
    """
    print_section_header("[Phase 2] 提示注入攻击", f"Target: {recon.target}")

    chain = AttackChain(chain_id=run_id, target=recon.target)
    all_findings: list[Finding] = []
    step_id = 1

    attackable = [s for s in services if s.protocol in (
        "openai_compatible", "ollama", "mcp", "generic_ai",
    )]
    if not attackable:
        print("  无可攻击的 AI 服务，跳过注入阶段")
        return all_findings, chain

    print_target_list(
        [s.model_dump() for s in attackable],
        "Attackable Targets"
    )

    _pyrit = use_pyrit if use_pyrit is not None else is_pyrit_available()
    if _pyrit:
        print(f"\n  [PyRIT] 已启用（提升评分精度 + 编码绕过）")
    else:
        if judge_endpoint:
            print(f"\n  [Native + LLM Judge] 已启用")
        else:
            print(f"\n  [Native] 回退到手写 httpx 模式")

    if with_multi_turn:
        print(f"  [Multi-Turn] Crescendo + TAP 多轮攻击已启用")

    for svc in attackable[:3]:
        print(f"\n  目标: [{svc.protocol.upper()}] {svc.url}")

        suite = run_full_injection_suite(
            svc, auth, use_pyrit=_pyrit,
            with_crescendo=with_multi_turn,
            with_tap=with_multi_turn,
            judge_endpoint=judge_endpoint,
            judge_api_key=judge_api_key,
        )
        direct_results = suite["direct"]
        sp_result = suite["system_prompt"]
        jailbreak_results = suite["jailbreak"]
        crescendo_result = suite.get("crescendo")
        tap_result = suite.get("tap")

        success_direct = sum(1 for r in direct_results if r.success)
        print_result_bar(
            "直接提示注入", success_direct, len(direct_results),
            severity="high" if success_direct > 0 else "medium"
        )
        chain.steps.append(AttackStep(
            step_id=step_id, phase="direct_injection",
            technique="direct_prompt_injection",
            target_url=svc.url, status="success" if success_direct else "partial",
        ))
        step_id += 1

        sp_success = 1 if (sp_result and sp_result.success) else 0
        print_result_bar(
            "系统提示提取", sp_success, 1,
            severity="critical" if sp_success else "medium"
        )
        chain.steps.append(AttackStep(
            step_id=step_id, phase="system_prompt_extract",
            technique=sp_result.technique if sp_result else "multi_technique",
            target_url=svc.url, status="success" if sp_success else "failed",
            evidence=sp_result.extracted_info[:500] if sp_result else "",
        ))
        step_id += 1

        success_jb = sum(1 for r in jailbreak_results if r.success)
        print_result_bar(
            "越狱/护栏绕过", success_jb, len(jailbreak_results),
            severity="high" if success_jb > 0 else "medium"
        )
        chain.steps.append(AttackStep(
            step_id=step_id, phase="jailbreak",
            technique="jailbreak_multi", target_url=svc.url,
            status="success" if success_jb else "failed",
        ))
        step_id += 1

        indirect_results = test_indirect_injection(svc, auth)
        success_indirect = sum(1 for r in indirect_results if r.success)
        print_result_bar(
            "间接提示注入", success_indirect, len(indirect_results),
            severity="high" if success_indirect > 0 else "medium"
        )
        chain.steps.append(AttackStep(
            step_id=step_id, phase="indirect_injection",
            technique="indirect_prompt_injection", target_url=svc.url,
            status="success" if success_indirect else "partial",
        ))
        step_id += 1

        # 多轮攻击结果展示
        if crescendo_result:
            cr_success = 1 if crescendo_result.get("result") == "success" else 0
            turns = len(crescendo_result.get("attack_log", []))
            print_result_bar(
                f"Crescendo 多轮 ({turns} turns)", cr_success, 1,
                severity="critical" if cr_success else "medium"
            )
            chain.steps.append(AttackStep(
                step_id=step_id, phase="crescendo_multi_turn",
                technique="crescendo_escalation", target_url=svc.url,
                status="success" if cr_success else "failed",
                evidence=f"Turns: {turns}",
            ))
            step_id += 1

        if tap_result:
            tap_success = 1 if tap_result.get("result") == "success" else 0
            tap_score = tap_result.get("best_score", 0.0)
            print_result_bar(
                f"TAP 攻击树 (score={tap_score:.2f})", tap_success, 1,
                severity="critical" if tap_success else "medium"
            )
            chain.steps.append(AttackStep(
                step_id=step_id, phase="tap_attack_tree",
                technique="tap_pruning", target_url=svc.url,
                status="success" if tap_success else "failed",
                evidence=f"Best score: {tap_score:.2f}",
            ))
            step_id += 1

        injection_findings = generate_injection_findings(
            svc, direct_results, sp_result, jailbreak_results,
            crescendo_result=crescendo_result,
            tap_result=tap_result,
        )
        all_findings.extend(injection_findings)

        chain.mitre_atlas_tactics.append(MITREATLASTactic.INITIAL_ACCESS.value)
        chain.owasp_llm_categories.append(OWASPLlm.LLM01_PROMPT_INJECTION.value)

    save_findings(run_id, all_findings)
    save_json(run_id, "attack_chain_injection", chain.model_dump())
    return all_findings, chain


__all__ = [
    "injection_phase",
]