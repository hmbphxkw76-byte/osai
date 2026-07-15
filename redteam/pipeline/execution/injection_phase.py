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

from redteam.core.models import AIService, AttackChain, AttackStep, AuthContext, Finding, GuardrailType, OWASPLlm, MITREATLASTactic, PromptInjectionResult, ReconResult
from redteam.core.store import save_findings, save_json

from redteam.attack.prompt_inject import run_full_injection_suite, generate_injection_findings
from redteam.attack.agent import test_indirect_injection
from redteam.attack.engine.determinism_router import DeterminismAwareRouter
from rich.table import Table

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
        with_multi_turn: 是否启用 Crescendo + TAP 多轮攻击
        judge_endpoint: LLM Judge API 端点（Native 路径评分）
        judge_api_key: LLM Judge API Key
        judge_model_name: LLM Judge 模型名称（如 glm-4-flash, gpt-4o）
        governor: 自适应调速器（v2.1 新增）
    """
    chain = AttackChain(chain_id=run_id, target=recon.target)
    all_findings: list[Finding] = []
    step_id = 1

    attackable = [s for s in services if s.protocol in (
        "openai_compatible", "ollama", "mcp", "generic_ai",
    )]
    if not attackable:
        print("  无可攻击的 AI 服务，跳过注入阶段")
        return all_findings, chain

    # ━━━ 目标概览表 ━━━
    det_router = DeterminismAwareRouter()
    print(f"\n  [bold]攻击目标概览[/]")
    tgt_table = Table(show_lines=False, expand=True, pad_edge=False)
    tgt_table.add_column("目标", style="cyan", no_wrap=True)
    tgt_table.add_column("协议", style="dim")
    tgt_table.add_column("确定性", justify="center")
    tgt_table.add_column("护栏", justify="center")
    tgt_table.add_column("评分器", style="dim")
    for svc in attackable[:3]:
        det_info = recon.determinism_info.get(svc.url, {})
        det_profile = det_router.analyze(det_info)
        det_str = "否" if not det_profile.is_deterministic else "是"
        grd_str = "无" if not svc.guardrail_profile or svc.guardrail_profile.guardrail_type == GuardrailType.NONE else svc.guardrail_profile.guardrail_type.value
        scorer = "LLM Judge" if judge_endpoint else "Hybrid"
        tgt_table.add_row(
            svc.url[:50], svc.protocol.upper(), det_str, grd_str, scorer
        )
    print(tgt_table)

    multi_turn_str = "Crescendo + TAP" if with_multi_turn else "未启用"
    print(f"\n  多轮攻击: {multi_turn_str}")

    # ━━━ 执行攻击 ━━━
    results_summary: list[dict] = []

    for svc in attackable[:3]:
        det_info = recon.determinism_info.get(svc.url, {})
        det_profile = det_router.analyze(det_info)
        _use_multi_turn = with_multi_turn or det_profile.enable_multi_turn

        suite = run_full_injection_suite(
            svc, auth,
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
        sp_success = 1 if (sp_result and sp_result.success) else 0
        success_jb = sum(1 for r in jailbreak_results if r.success)
        indirect_results = test_indirect_injection(svc, auth)
        success_indirect = sum(1 for r in indirect_results if r.success)

        cr_success = 0
        cr_turns = 0
        if crescendo_result:
            cr_success = 1 if crescendo_result.get("result") == "success" else 0
            cr_turns = len(crescendo_result.get("attack_log", []))

        tap_success = 0
        tap_score = 0.0
        if tap_result:
            tap_success = 1 if tap_result.get("result") == "success" else 0
            tap_score = tap_result.get("best_score", 0.0)

        results_summary.append({
            "target": svc.protocol.upper(),
            "direct": (success_direct, len(direct_results)),
            "sys_prompt": (sp_success, 1),
            "jailbreak": (success_jb, len(jailbreak_results)),
            "indirect": (success_indirect, len(indirect_results)),
            "crescendo": (cr_success, cr_turns),
            "tap": (tap_success, tap_score),
        })

        # 错误诊断（仅在有错误时显示）
        for label, results in [("直接提示注入", direct_results), ("越狱/护栏绕过", jailbreak_results)]:
            _print_error_diagnostics(label, results)

        # 构建 attack chain
        for phase, tech, status, evidence in [
            ("direct_injection", "direct_prompt_injection", "success" if success_direct else "partial", ""),
            ("system_prompt_extract", sp_result.technique if sp_result else "multi_technique", "success" if sp_success else "failed", sp_result.extracted_info[:500] if sp_result else ""),
            ("jailbreak", "jailbreak_multi", "success" if success_jb else "failed", ""),
            ("indirect_injection", "indirect_prompt_injection", "success" if success_indirect else "partial", ""),
            ("crescendo_multi_turn", "crescendo_escalation", "success" if cr_success else "failed", f"Turns: {cr_turns}"),
            ("tap_attack_tree", "tap_pruning", "success" if tap_success else "failed", f"Best score: {tap_score:.2f}"),
        ]:
            if phase in ("crescendo_multi_turn", "tap_attack_tree") and not (crescendo_result or tap_result):
                continue
            chain.steps.append(AttackStep(
                step_id=step_id, phase=phase, technique=tech,
                target_url=svc.url, status=status, evidence=evidence,
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

    # ━━━ 攻击结果摘要表 ━━━
    print(f"\n  [bold]攻击结果摘要[/]")
    res_table = Table(show_lines=False, expand=True, pad_edge=False)
    res_table.add_column("目标", style="cyan")
    res_table.add_column("直接注入", justify="center")
    res_table.add_column("系统提示", justify="center")
    res_table.add_column("越狱绕过", justify="center")
    res_table.add_column("间接注入", justify="center")
    res_table.add_column("Crescendo", justify="center")
    res_table.add_column("TAP", justify="center")

    for r in results_summary:
        def _cell(success, total, score=None):
            if total == 0:
                return "[dim]—[/]"
            s, t = success, total
            if s > 0:
                return f"[red]⚠ {s}/{t}[/]"
            return f"[green]✓ 0/{t}[/]"

        res_table.add_row(
            r["target"],
            _cell(*r["direct"]),
            _cell(*r["sys_prompt"]),
            _cell(*r["jailbreak"]),
            _cell(*r["indirect"]),
            _cell(r["crescendo"][0], 1) if r["crescendo"][1] > 0 else "[dim]—[/]",
            _cell(r["tap"][0], 1, r["tap"][1]) if r["tap"][1] >= 0 else "[dim]—[/]",
        )
    print(res_table)

    save_findings(run_id, all_findings, subdir="detect")
    save_json(run_id, "attack_chain_injection", chain.model_dump(), subdir="recon")
    return all_findings, chain


__all__ = [
    "injection_phase",
]