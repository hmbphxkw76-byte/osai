"""
===============================================================================
PyRIT Red Team — 命令路由器
===============================================================================
从 main.py 提取命令分发逻辑，遵循:
  ✅ 单一职责 — 仅负责模式分发，不涉及细节实现
  ✅ 早返回模式 — 探索/渗透/legacy 均为早返回路径
  ✅ 薄封装 — 原生路径直接委托给 PyRITNativeOrchestrator

路由决策树:
  1. --exploring-template  → 探索模式（executor/exploring.py）
  2. --penetrating-mode     → 渗透模式（scenarios/ 模块）
  3. --orch legacy          → Legacy 兼容模式
  4. 其他                   → PyRIT 原生调度模式

使用方式:
  from entrypoint.router import route_command

  await route_command(args, ctx)
===============================================================================
"""
from __future__ import annotations

import os

from pyrit.prompt_target import OpenAIChatTarget
from rich.console import Console

from entrypoint.bootstrap import BootstrapContext

console = Console()


async def route_command(args, ctx: BootstrapContext | None) -> None:
    """根据 CLI 参数路由到对应的执行模式。

    Args:
        args: argparse.Namespace CLI 解析结果
        ctx: 环境初始化上下文（bootstrap 结果）
    """
    # ── 早返回路径 A: 探索模板模式 ──
    if args.exploring_template:
        from executor.exploring import run_exploring_mode
        await run_exploring_mode(args)
        return

    # ── 早返回路径 B: 渗透模式 ──
    if args.penetrating_mode:
        await _run_penetrating_mode_router(args)
        return

    # ── 早返回路径 C: Legacy 兼容模式 ──
    if args.orch == "legacy":
        preset_template = f"legacy_preset_{args.lang}.yaml"
        console.print(f"[dim]🔙 Legacy 引擎已迁移到 Preset 模板模式[/dim]")
        console.print(f"[dim]   模板: {preset_template} | 引擎: PenetratingOrchestrator[/dim]")
        args.penetrating_template = preset_template
        await _run_penetrating_mode_router(args)
        return

    # ── 环境初始化失败，不执行攻击 ──
    if ctx is None:
        return

    # ── 原生路径: PyRIT Native Orchestrator ──
    console.print(
        "[bold cyan]🚀 使用 PyRIT 原生调度引擎 (PromptSendingAttack + CrescendoAttack)[/bold cyan]\n"
        "   [dim]Memory: SQLiteMemory + CentralMemory | "
        "多轮: CrescendoAttack (原生渐进式越狱)[/dim]"
    )

    try:
        if args.auto_gate:
            await _run_native_phased(args, ctx)
        else:
            await _run_native_single_phase(args, ctx)
    finally:
        if ctx.attack_target and hasattr(ctx.attack_target, 'close') and callable(ctx.attack_target.close):
            await ctx.attack_target.close()


# ── 原生模式内部实现 ──

async def _run_native_single_phase(args, ctx: BootstrapContext) -> None:
    """PyRIT 原生单阶段/全量执行。"""
    from orchestrators.pyrit_orchestrator import PyRITNativeOrchestrator, AttackPhase

    json_file = os.path.join("datasets", f"test_cases_{args.lang}.json")

    phase_map = {
        "probe": AttackPhase.PROBE, "single": AttackPhase.SINGLE,
        "crescendo": AttackPhase.CRESCENDO,
        "pair": AttackPhase.PAIR, "tap": AttackPhase.TAP,
        "flip": AttackPhase.FLIP, "chunked": AttackPhase.CHUNKED,
        "manyshot": AttackPhase.MANYSHOT, "skeleton_key": AttackPhase.SKELETON_KEY,
        "indirect_inject": AttackPhase.SINGLE, "rag_poison": AttackPhase.SINGLE,
        "agent_attack": AttackPhase.SINGLE, "embedding_attack": AttackPhase.SINGLE,
        "sequence_chain": AttackPhase.SINGLE,
        "mcp_security": AttackPhase.SINGLE, "a2a_security": AttackPhase.SINGLE,
        "all": AttackPhase.ALL,
    }
    phase = phase_map.get(ctx.effective_phase, AttackPhase.ALL)

    phase_labels = {
        "probe": "PROBE Recon", "single": "Single-Turn Assault",
        "crescendo": "Crescendo Siege", "pair": "PAIR Jailbreak",
        "tap": "TAP Tree Search", "flip": "Flip Attack",
        "chunked": "Chunked Bypass", "manyshot": "ManyShot Flooding",
        "skeleton_key": "Skeleton Key",
        "indirect_inject": "Indirect Inject", "rag_poison": "RAG Poison",
        "agent_attack": "Agent Attack", "embedding_attack": "Embedding Attack",
        "sequence_chain": "Sequence Chain",
        "mcp_security": "MCP Security", "a2a_security": "A2A Security",
    }
    label = phase_labels.get(ctx.effective_phase, ctx.effective_phase.replace('_', ' ').title())

    orch = PyRITNativeOrchestrator(
        scorer_target=ctx.scorer_target or OpenAIChatTarget(temperature=0),
        max_concurrent=args.concurrent,
    )

    from datasets.loader import load_test_cases
    cases, _ = load_test_cases(json_file)

    if ctx.case_filter:
        _ids = set(ctx.case_filter)
        cases = [c for c in cases if c.get("id", "") in _ids]
    if ctx.exclude_filter:
        _exclude = set(ctx.exclude_filter)
        cases = [c for c in cases if c.get("id", "") not in _exclude]
    if ctx.effective_phase != "all":
        from executor import classify_case
        cases = [c for c in cases if classify_case(c) == ctx.effective_phase]

    if not cases:
        console.print(f"[yellow]⚠️ 无匹配的测试用例 ({ctx.effective_phase})，跳过[/yellow]")
        return

    results = await orch.run_campaign(
        cases=cases,
        attack_target=ctx.attack_target,
        phase=phase,
        case_filter=set(ctx.case_filter) if ctx.case_filter else None,
        exclude_filter=set(ctx.exclude_filter) if ctx.exclude_filter else None,
        combo_filter=set(ctx.combo_filter) if ctx.combo_filter else None,
    )

    # 结果导出
    campaign_name = f"PyRIT_RedTeam_{label.replace(' ', '_')}"
    orch.export_results(results, campaign_name)

    from reporting import analyze_and_visualize, print_detailed_report, generate_penetrating_report
    from utils import results_path, RESULTS_DIR
    from datetime import datetime
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    heatmap_file = results_path(f"pyrit_redteam_{ctx.effective_phase}_heatmap_{ts}.png")
    analyze_and_visualize(results, f"PyRIT Red Team {label} Success Matrix", heatmap_file)
    print_detailed_report(results, campaign_name)
    generate_penetrating_report(results, campaign_name, output_dir=RESULTS_DIR)


async def _run_native_phased(args, ctx: BootstrapContext) -> None:
    """PyRIT 原生阶梯式门控执行。"""
    from orchestrators.pyrit_orchestrator import PyRITNativeOrchestrator
    from datasets.loader import load_test_cases
    from reporting import print_detailed_report, generate_penetrating_report
    from utils import RESULTS_DIR

    json_file = os.path.join("datasets", f"test_cases_{args.lang}.json")
    cases, _ = load_test_cases(json_file)

    if ctx.case_filter:
        _ids = set(ctx.case_filter)
        cases = [c for c in cases if c.get("id", "") in _ids]
    if ctx.exclude_filter:
        _exclude = set(ctx.exclude_filter)
        cases = [c for c in cases if c.get("id", "") not in _exclude]

    if not cases:
        console.print("[yellow]⚠️ 无匹配的测试用例，跳过[/yellow]")
        return

    orch = PyRITNativeOrchestrator(
        scorer_target=ctx.scorer_target or OpenAIChatTarget(temperature=0),
        max_concurrent=args.concurrent,
    )

    results = await orch.run_phased_campaign(
        cases=cases,
        attack_target=ctx.attack_target,
        gate_threshold=args.gate_threshold,
        case_filter=set(ctx.case_filter) if ctx.case_filter else None,
        exclude_filter=set(ctx.exclude_filter) if ctx.exclude_filter else None,
        combo_filter=set(ctx.combo_filter) if ctx.combo_filter else None,
    )

    if results:
        print_detailed_report(results, "Red Team 阶梯式门控总战报")
        generate_penetrating_report(results, "PyRIT_RedTeam_Combined_All_Phases", output_dir=RESULTS_DIR)


# ── 渗透模式路由 ──

async def _run_penetrating_mode_router(args) -> None:
    """渗透模式路由 — 复用现有 scenarios/ 模块。

    遵循 PYrit 专家设计原则:
      ✅ 渗透期间仅修改 YAML 模板文件
      ✅ 攻击编排、提示词变体、目标调用、结果评分、报告生成全部预固化
    """
    from scenarios.schema import PenetratingPromptSet
    from scenarios.orchestrator import PenetratingOrchestrator
    from scenarios.reporter import PenetratingSecurityReporter
    from executor.exploring import _resolve_template_path
    from targets import load_env_config, create_scorer_target, build_custom_target
    from targets.auto_probe import auto_probe_target_model, auto_probe_target_type
    from targets.target_type_probe import generate_dynamic_prompts
    from utils import DEFAULT_MODEL_NAME, ensure_results_dir, results_path
    from pyrit.memory import SQLiteMemory, CentralMemory
    from pyrit.prompt_target import OpenAIChatTarget
    from datetime import datetime
    import json

    # ── 1. 加载提示词模板 ──
    template_path = _resolve_template_path(
        args.penetrating_template,
        search_dirs=["scenarios/templates"],
    )
    if not template_path:
        console.print(f"[bold red]❌ 渗透模板文件不存在: {args.penetrating_template}[/bold red]")
        return

    console.print(f"[bold cyan]📋 加载渗透提示词模板: {template_path}[/bold cyan]")
    try:
        if template_path.endswith(".json"):
            template = PenetratingPromptSet.from_json_file(template_path)
        else:
            template = PenetratingPromptSet.from_yaml_file(template_path)
    except Exception as e:
        console.print(f"[bold red]❌ 模板加载失败: {e}[/bold red]")
        return

    summary = template.get_summary()
    console.print(
        f"  [dim]提示词: {summary['total_prompts']} 个 | "
        f"单轮: {summary['single_turn']} | 多轮: {summary['multi_turn']} | "
        f"预估攻击: {summary['estimated_attacks']} 次[/dim]"
    )

    # ── 2. 构建目标 ──
    attacker_config, scorer_config = load_env_config(args.env_file)
    scorer_target = create_scorer_target(scorer_config) if scorer_config else OpenAIChatTarget(temperature=0)
    target_type_result = None

    if args.target_url:
        from targets.target_builder import build_attack_target_from_args
        attack_target = await build_attack_target_from_args(args, attacker_config, enable_probe=True)
        if attack_target is None:
            return
        # 架构类型探测
        target_type_result = await auto_probe_target_type(args, args.target_url, args.target_api_key)
    else:
        if not attacker_config or not attacker_config.get("model"):
            console.print("[bold red]❌ 攻击者模型未配置！[/bold red]")
            return
        from targets.factories import create_attack_target
        attack_target = create_attack_target(env_config=attacker_config)

    # ── 3. 初始化 PyRIT Memory ──
    ensure_results_dir()
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    db_path = results_path(f"pyrit_redteam_penetrating_memory_{ts}.db")
    memory = SQLiteMemory(db_path=db_path)
    CentralMemory.set_memory_instance(memory)
    console.print(f"[dim]PyRIT Memory 已初始化: {db_path}[/dim]")

    # ── 4. 动态注入针对性提示词 ──
    if target_type_result and target_type_result.confidence >= 0.30:
        from scenarios.schema import PenetratingPrompt, PromptCategory, DifficultyLevel, OWASPCategory
        dynamic_prompts = generate_dynamic_prompts(target_type_result, language=args.lang or "cn")
        if dynamic_prompts:
            existing_ids = {p.id for p in template.prompts}
            added_count = 0
            for dp in dynamic_prompts:
                if dp["id"] not in existing_ids:
                    try:
                        new_prompt = PenetratingPrompt(
                            id=dp["id"],
                            objective=dp["objective"],
                            criterion=dp["criterion"],
                            category=PromptCategory(dp.get("category", "custom")),
                            difficulty=DifficultyLevel(dp.get("difficulty", "medium")),
                            owasp_category=OWASPCategory(dp.get("owasp_category", "LLM01: Prompt Injection")),
                        )
                        template.prompts.append(new_prompt)
                        existing_ids.add(dp["id"])
                        added_count += 1
                    except Exception as e:
                        console.print(f"[dim]  跳过 {dp['id']}: {e}[/dim]")
            if added_count > 0:
                new_summary = template.get_summary()
                console.print(Panel(
                    f"[bold green]🎯 已根据目标架构（{target_type_result.target_type.value.upper()}）"
                    f"自动注入 {added_count} 个针对性提示词[/bold green]\n"
                    f"[dim]新提示词总数: {new_summary['total_prompts']} 个 | "
                    f"预估攻击: {new_summary['estimated_attacks']} 次[/dim]\n"
                    f"[dim]推荐策略: {target_type_result.recommended_category}[/dim]",
                    style="bold green",
                ))

    # ── 5. 执行渗透模式 ──
    orchestrator = PenetratingOrchestrator(
        template=template,
        attack_target=attack_target,
        scorer_target=scorer_target,
    )

    try:
        results = await orchestrator.run()
        reporter = PenetratingSecurityReporter(template)
        report_paths = reporter.generate_all(
            [r for r in results],
            campaign_name="PyRIT_RedTeam_Penetrating_Mode",
        )
        console.print(f"\n[bold green]✅ 渗透模式完成！[/bold green]")
        console.print(f"  Markdown 报告: {report_paths['markdown']}")
        console.print(f"  JSON 日志: {report_paths['json']}")
    finally:
        if hasattr(attack_target, 'close') and callable(attack_target.close):
            await attack_target.close()
