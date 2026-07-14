"""提示注入攻击阶段 (AI-300 Ch3)。

执行提示注入攻击：
  - 直接提示注入
  - 系统提示提取
  - 越狱/护栏绕过
  - 间接提示注入
  - Crescendo 多轮升级攻击（可选）
  - TAP 攻击树剪枝攻击（可选）

v2.0 新增：with_multi_turn + judge_endpoint 参数支持
v2.1 新增：RateLimitGovernor 集成，攻击前自动调速

对齐 OWASP ASI Top 10: ASI01 (Goal Hijack), ASI05 (Output Handling)
"""
from __future__ import annotations

from typing import Any, TYPE_CHECKING

from redteam.core.models import AIService, AttackChain, AttackStep, AuthContext, Finding, OWASPLlm, MITREATLASTactic, PromptInjectionResult, ReconResult
from redteam.core.store import save_findings, save_json
from redteam.core.terminal_output import print_section_header, print_target_list, print_result_bar
from redteam.attack.prompt_inject import run_full_injection_suite, generate_injection_findings
from redteam.attack.agent_attack import test_indirect_injection
from redteam.attack.pyrit_runner import is_pyrit_available
from redteam.attack.core.determinism_router import DeterminismAwareRouter

if TYPE_CHECKING:
    from redteam.core.rate_limiter import RateLimitGovernor


def _print_error_diagnostics(
    phase_name: str,
    results: list[PromptInjectionResult],
) -> None:
    """当所有攻击尝试均失败时，输出错误诊断汇总。"""
    if not results:
        return
    success_count = sum(1 for r in results if r.success)
    if success_count > 0:
        return  # 有成功的，不需要诊断

    # 收集错误信息
    errors: dict[str, int] = {}
    for r in results:
        if r.error:
            # 取错误类型作为分组键（简化为前缀）
            key = r.error.split(":")[0].strip() if ":" in r.error else r.error[:40]
            errors[key] = errors.get(key, 0) + 1

    if errors:
        summary = ", ".join(f"{k}: {v}" for k, v in sorted(errors.items(), key=lambda x: -x[1]))
        print(f"  \033[33m[Diagnostics] {phase_name} 全部失败 — {summary}\033[0m")
        # 只显示第一个不同的错误详情
        seen = set()
        for r in results:
            if r.error and r.error not in seen:
                seen.add(r.error)
                if len(seen) <= 2:
                    print(f"    • {r.error[:150]}")


def injection_phase(
    run_id: str,
    recon: ReconResult,
    services: list[AIService],
    auth: AuthContext | None = None,
    use_pyrit: bool | None = None,
    with_multi_turn: bool = False,
    target_model_name: str = "",
    judge_endpoint: str | None = None,
    judge_api_key: str = "not-needed",
    judge_model_name: str = "",
    governor: "RateLimitGovernor | None" = None,
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
        judge_model_name: LLM Judge 模型名称（如 glm-4-flash, gpt-4o）
        governor: 自适应调速器（v2.1 新增）
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
        if judge_endpoint:
            print(f"\n  [PyRIT + LLM Judge] 已启用（编码绕过 + 外部 LLM 评分）")
        else:
            print(f"\n  [PyRIT] 已启用（编码绕过 + 内置规则评分）")
    else:
        if judge_endpoint:
            print(f"\n  [Native + LLM Judge] 已启用")
        else:
            print(f"\n  [Native] 回退到手写 httpx 模式")

    if with_multi_turn:
        print(f"  [Multi-Turn] Crescendo + TAP 多轮攻击已启用")

    det_router = DeterminismAwareRouter()

    for svc in attackable[:3]:
        print(f"\n  目标: [{svc.protocol.upper()}] {svc.url}")

        # ━━━ 确定性感知策略分析 ━━━
        det_info = recon.determinism_info.get(svc.url, {})
        det_profile = det_router.analyze(det_info)
        print(f"  [Determinism] {det_router.summarize(det_profile)}")

        # 自动启用多轮攻击（如果确定性分析建议）
        _use_multi_turn = with_multi_turn or det_profile.enable_multi_turn
        if det_profile.enable_multi_turn and not with_multi_turn:
            print(f"  [Auto] 确定性分析建议启用 Multi-Turn 攻击")

        suite = run_full_injection_suite(
            svc, auth, use_pyrit=_pyrit,
            with_crescendo=_use_multi_turn,
            with_tap=_use_multi_turn,
            target_model_name=target_model_name,
            judge_endpoint=judge_endpoint,
            judge_api_key=judge_api_key,
            judge_model_name=judge_model_name,
            governor=governor,
            det_profile=det_profile,
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
        # 如果全部失败且存在错误信息，输出诊断
        _print_error_diagnostics("直接提示注入", direct_results)

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
        if sp_result and not sp_result.success:
            _print_error_diagnostics("系统提示提取", [sp_result])
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
        _print_error_diagnostics("越狱/护栏绕过", jailbreak_results)
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