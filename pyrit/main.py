"""
===============================================================================
OffSec AI-300 终极红队演练平台 (v10.0 — PyRIT 原生 Orchestrator 版)
核心升级：
1. ✅ PyRIT 原生 Memory: SQLiteMemory + CentralMemory 全局单例（最佳实践）
2. ✅ PyRIT 原生 Orchestrator: PromptSendingAttack + CrescendoAttack（多轮自适应攻击）
3. ✅ PyRIT Scenarios 集成: A300ScenarioRunner 声明式阶段编排
4. ✅ 向后兼容: --orch legacy 回退旧版 execute_single/crescendo_attack
5. Crescendo 渐进式多轮攻击引擎，覆盖单轮无法突破的高阶考点
6. JailbreakBench Top5 模板 + 67组攻击组合（含17组三层链） + 防假阴性评分
7. --phase / --auto-gate 分阶段门控执行（PyRIT 最佳实践）
8. 2026 最热点攻击面：CoT/Constitution/MCP/A2A + 三层编码链全覆盖

架构变化:
  旧: engines/single.py + engines/crescendo.py + 手动 DuckDB
  新: orchestrator/pyrit_orchestrator.py (PyRIT 原生) + SQLiteMemory
  旧: main.py run_campaign() → 手动任务调度
  新: AI300Orchestrator.run_campaign() → PromptSendingAttack / CrescendoAttack

模块拆分:
- converters/   → 攻击策略转换器 & 攻击组合配置
- targets/      → .env 配置加载 & Target 工厂
- engines/      → 评分器 & 仪表盘 & 模板（引擎已下沉到 orchestrator/）
- orchestrator/ → 🆕 PyRIT 原生调度器 & Scenario 集成
- reporting/    → 结果分析与报告生成
- main.py       → CLI 入口 & 任务编排

===============================================================================
快速使用指南 (Quick Reference)
===============================================================================
  模式 A: 不指定 --target-url → 攻击 .env 中配置的 LLM API (如智谱 GLM-4.7-Flash):
    python main.py --lang cn --phase probe              # 仅 PROBE 快速探测
    python main.py --lang cn --phase single             # 仅单轮主力突破
    python main.py --lang cn --phase crescendo          # 仅 Crescendo 多轮攻坚
    python main.py --lang cn --auto-gate                # 自动门控 (阈值 10%)
    python main.py --lang cn --auto-gate --gate-threshold 0.20  # 自定义阈值
    python main.py --lang cn --phase all                # 中文全量 (向后兼容)
    python main.py --lang en --phase all --concurrent 9  # 英文全量, 9 并发

  模式 B: 指定 --target-url → 攻击自定义 Chat API (内网应用/自签证书):
    🆕 端点枚举 + 模型自动探测: 仅提供 IP:端口，系统自动完成:
      ① 并发枚举 50+ LLM API 端点（2~3秒）
      ② 识别可用 Chat/Models/Info 端点 + 推测框架
      ③ 自动探测模型名称 → 注入 PyRIT Pipeline
    python main.py --lang cn --target-url http://192.168.2.199:8501/ --phase probe
    python main.py --lang cn --target-url http://192.168.2.199:8501/ --auto-gate

  模式 C: --target-url + --target-api-format → 攻击非 OpenAI 格式 API (Gemini/Claude):
    python main.py --lang cn --phase probe --target-url https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent --target-api-key YOUR_GEMINI_KEY --target-api-format gemini
    python main.py --lang cn --phase probe --target-url https://api.anthropic.com/v1/messages --target-api-key YOUR_CLAUDE_KEY --target-api-format claude --target-model claude-3-sonnet-20240229

  模式 D: --target-url + --target-api-format raw → 攻击任意非标准内部 Web 应用 (考试场景):
    python main.py --lang cn --phase probe --target-url http://192.168.1.100/internal/chat --target-api-format raw --target-cookie "session_id=abc123; auth_token=xyz"

  注: 两种模式下，评分器 (Judge) 均使用 .env 中配置的 LLM 进行判定。
  回退旧版引擎: 添加 --orch legacy 回到旧版 execute_single/crescendo_attack 引擎
===============================================================================
"""
import asyncio
import os
import sys
import argparse
import json
import time
from datetime import datetime
import glob as _glob

# PyRIT 核心组件
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from pyrit.prompt_target import OpenAIChatTarget
from pyrit.memory import SQLiteMemory, CentralMemory
from pyrit.setup import initialize_pyrit_async

# 实时UI与进度追踪
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

# ── 项目模块 ──
from converters import (
    GLOBAL_ATTACK_COMBINATIONS, CONVERTER_MAP, CONVERTER_REGISTRY,
    resolve_converters,
    discover_converters, discover_converters_from_path,
    sync_pyrit_converters, get_converters_by_category,
)
from targets import (
    load_env_config,
    create_scorer_target, create_attack_target,
    SCENARIO_PRESETS, build_custom_target,
    probe_model_info, check_target_reachable,
)
from executor import (
    DashboardState, classify_case, _calc_success_rate,
    execute_single_attack, execute_crescendo_attack, PAYLOAD_VARS,
)
from reporting import (
    analyze_and_visualize, print_detailed_report, generate_exam_report,
)
from utils import DEFAULT_MODEL_NAME, get_default_model_name, ensure_results_dir, results_path, RESULTS_DIR
# ── 数据层（Pydantic 校验 + LLM Few-shot 生成就绪） ──
from datasets.loader import load_test_cases, load_payloads_module, apply_preset

# 🆕 PyRIT 原生 Orchestrator + Scenarios
from orchestrators.pyrit_orchestrator import AI300Orchestrator, AttackPhase
from orchestrators.scenario_runner import A300ScenarioRunner

console = Console()

# 全局初始化标记，防止重复初始化DuckDB导致报错
_pyrit_initialized = False


# ================= 模板路径解析工具 =================

def _resolve_template_path(template_arg: str, search_dirs: list[str] | None = None) -> str | None:
    """解析模板文件路径，按优先级依次搜索。

    Args:
        template_arg: 用户传入的模板路径
        search_dirs: 额外搜索目录列表（如 ["scenarios/templates"]）

    Returns:
        找到的绝对/相对路径，或 None
    """
    if os.path.exists(template_arg):
        return template_arg
    for d in (search_dirs or []):
        alt = os.path.join(d, os.path.basename(template_arg) if os.path.sep not in template_arg else template_arg)
        if os.path.exists(alt):
            return alt
    # 如果原始参数包含路径分隔符，尝试直接拼接
    for d in (search_dirs or []):
        alt = os.path.join(d, template_arg)
        if os.path.exists(alt):
            return alt
    return None


# ================= 🆕 技术模板模式入口 (Tech Mode) =================

async def _run_tech_mode(args) -> None:
    """技术模板模式入口：快速测试 converter 链对 prompt injection 的突破效果。

    与考试模式的核心区别：
      - 技术模式：关注"哪个 converter 链绕过了？" → 轻量、快速、converter 排名报告
      - 考试模式：关注"攻击面覆盖度 + 纵深突破深度" → 多策略、综合 OWASP 报告

    流程：
      1. 加载技术模板 YAML
      2. 对每个 prompt × 每个 converter_preset 链，执行 PromptSendingAttack
      3. 生成 converter 有效性排名报告
    """
    _tech_start = time.time()
    import yaml
    from scenarios.schema import ExamPromptSet, ExamPrompt, ExamModeConfig, PromptCategory, DifficultyLevel, OWASPCategory
    from converters import resolve_converters
    from executor.scorer import create_best_scorer
    from pyrit.prompt_normalizer import PromptConverterConfiguration

    # ── 1. 加载技术模板 ──
    template_path = _resolve_template_path(
        args.tech_template,
        search_dirs=["scenarios/templates"],
    )
    if not template_path:
        console.print(f"[bold red]❌ 技术模板文件不存在: {args.tech_template}[/bold red]")
        console.print(f"   [dim]搜索目录: scenarios/templates/[/dim]")
        return

    console.print(f"[bold cyan]🔧 加载技术模板: {template_path}[/bold cyan]")

    # 解析 YAML — 先原始加载获取 converter_presets，再通过 Pydantic 校验
    with open(template_path, "r", encoding="utf-8") as f:
        raw_data = yaml.safe_load(f)

    raw_config = raw_data.get("config", {})
    converter_presets: list[list[str]] = raw_config.get("converter_presets", [])

    if not converter_presets:
        console.print("[bold red]❌ 技术模板缺少 config.converter_presets 字段[/bold red]")
        console.print("   [dim]converter_presets 格式: [[\"base64\"], [\"dan_jailbreak\"], ...][/dim]")
        return

    template = ExamPromptSet.model_validate(raw_data)

    console.print(
        f"  [dim]提示词: {len(template.prompts)} 个 | "
        f"Converter 链: {len(converter_presets)} 组 | "
        f"总攻击次数: {len(template.prompts) * len(converter_presets)} 次[/dim]"
    )

    # ── 2. 构建目标 ──
    attacker_config, scorer_config = load_env_config(args.env_file)
    scorer_target = create_scorer_target(scorer_config) if scorer_config else OpenAIChatTarget(temperature=0)

    if args.target_url:
        extra_headers = {}
        if args.target_extra_headers:
            try:
                extra_headers = json.loads(args.target_extra_headers)
            except json.JSONDecodeError:
                console.print("[yellow]⚠️ --target-extra-headers JSON 解析失败[/yellow]")
        is_http_target = args.target_url.lower().startswith("http://")
        verify_ssl = (args.target_verify_ssl or not args.target_no_ssl) and not is_http_target

        # ── 🆕 模型自动探测 + 可达性检查 ──
        args.target_model, target_reachable = await _auto_probe_target_model(args, args.target_url, args.target_api_key)
        if not target_reachable:
            return []  # 目标不可达，跳过所有攻击任务

        attack_target = build_custom_target(
            endpoint=args.target_url, scenario=args.scenario or "",
            api_key=args.target_api_key or "", model=args.target_model or DEFAULT_MODEL_NAME,
            api_format=args.target_api_format, http_method=args.target_http_method,
            content_type=args.target_content_type, verify_ssl=verify_ssl,
            cookie=args.target_cookie or "", jwt_token=args.target_jwt or "",
            user_agent=args.target_user_agent or "",
            extra_headers=extra_headers if extra_headers else None,
        )
    else:
        if not attacker_config or not attacker_config.get("model"):
            console.print("[bold red]❌ 攻击者模型未配置！请在 .env 中设置或使用 --target-url[/bold red]")
            return
        attack_target = create_attack_target(env_config=attacker_config)

    # ── 3. 初始化 Memory ──
    ensure_results_dir()
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    db_path = results_path(f"ai300_tech_memory_{ts}.db")
    memory = SQLiteMemory(db_path=db_path)
    CentralMemory.set_memory_instance(memory)

    # ── 4. 并发执行所有 converter 链测试 ──
    max_concurrent = template.config.max_concurrent
    semaphore = asyncio.Semaphore(max_concurrent)

    # 结果结构: {prompt_id: {converter_chain_name: {"status", "response", "score"}}}
    tech_results: dict[str, dict[str, dict]] = {}

    total_tests = len(template.prompts) * len(converter_presets)
    console.print(f"\n[bold]⚔️ 执行 {total_tests} 次 Converter 链测试 (并发: {max_concurrent})...[/bold]")

    progress = Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
    )
    task_id = progress.add_task("🔬 Converter 链测试中...", total=total_tests)

    async def _test_one_chain(
        prompt: ExamPrompt, chain_names: list[str], chain_label: str
    ) -> tuple[str, str, dict]:
        """测试单个 converter 链对单个 prompt 的效果"""
        async with semaphore:
            # 解析 converter 列表
            converters = []
            for cn in chain_names:
                try:
                    resolved = resolve_converters([cn])
                    if resolved:
                        converters.extend(resolved)
                except Exception:
                    pass

            # 构建评分器
            scorer = create_best_scorer(
                chat_target=scorer_target,
                objective=prompt.objective,
                criterion=prompt.criterion,
            )
            scoring_config = AttackScoringConfig(objective_scorer=scorer)

            converter_config = None
            if converters:
                converter_config = AttackConverterConfig(
                    request_converters=[PromptConverterConfiguration(converters=converters)]
                )

            # 预应用转换器获取投送 prompt
            converted_prompt = prompt.objective
            if converters:
                for cv in converters:
                    try:
                        r = await cv.convert_async(prompt=converted_prompt)
                        converted_prompt = r.output_text if hasattr(r, "output_text") else str(r)
                    except Exception:
                        pass

            try:
                from pyrit.executor.attack import PromptSendingAttack
                attack = PromptSendingAttack(
                    objective_target=attack_target,
                    attack_converter_config=converter_config,
                    attack_scoring_config=scoring_config,
                    max_attempts_on_failure=3,
                )
                result = await attack.execute_async(
                    objective=prompt.objective,
                    memory_labels={
                        "tech_prompt_id": prompt.id,
                        "converter_chain": chain_label,
                        "mode": "tech_mode",
                    },
                )

                score_value = ""
                score_reason = ""
                response_text = ""
                if hasattr(result, "results") and result.results:
                    results_list = result.results if isinstance(result.results, list) else [result.results]
                    for res in results_list:
                        if hasattr(res, "scores") and res.scores:
                            score_value = str(getattr(res.scores[0], "score_value", ""))
                            score_reason = getattr(res.scores[0], "score_description", "")
                            if score_value.lower() == "true":
                                break
                        if hasattr(res, "response") and res.response:
                            response_text = getattr(res.response, "converted_value", "") or response_text

                is_success = score_value.lower() == "true"
                return (prompt.id, chain_label, {
                    "status": "SUCCESS" if is_success else "FAILURE",
                    "converted_prompt": converted_prompt[:500],
                    "response_text": response_text[:500],
                    "score_value": score_value,
                    "score_reason": score_reason,
                })
            except Exception as e:
                return (prompt.id, chain_label, {
                    "status": "ERROR",
                    "converted_prompt": converted_prompt[:500],
                    "response_text": "",
                    "score_value": "",
                    "score_reason": str(e)[:500],
                })

    coros = []
    for prompt in template.prompts:
        tech_results.setdefault(prompt.id, {})
        for chain in converter_presets:
            chain_label = " + ".join(chain)
            coros.append(_test_one_chain(prompt, chain, chain_label))

    with Live(
        Panel(progress, style="bold blue"), console=console, refresh_per_second=4
    ) as live:
        for coro in asyncio.as_completed(coros):
            pid, chain_label, result_dict = await coro
            tech_results[pid][chain_label] = result_dict
            progress.advance(task_id)
            live.update(Panel(
                f"{progress}\n"
                f"[dim]最新: {pid} × {chain_label} → {result_dict['status']}[/dim]",
                style="bold blue",
            ))

    # ── 6. 生成 Converter 有效性报告 ──
    elapsed = time.time() - _tech_start
    _print_tech_report(tech_results, template, elapsed)

    # ── 7. 保存结果 ──
    report_file = results_path(f"ai300_tech_report_{ts}.json")
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump({
            "template": template_path,
            "mode": "tech",
            "timestamp": datetime.now().isoformat(),
            "results": tech_results,
            "converter_presets": converter_presets,
            "summary": _build_tech_summary(tech_results),
        }, f, ensure_ascii=False, indent=2)
    console.print(f"\n[green]✅ 技术模式结果已保存: {report_file}[/green]")

    if hasattr(attack_target, 'close') and callable(attack_target.close):
        await attack_target.close()


def _build_tech_summary(results: dict[str, dict[str, dict]]) -> dict:
    """构建技术模板结果摘要"""
    converter_stats: dict[str, dict] = {}
    for pid, chains in results.items():
        for chain_label, r in chains.items():
            if chain_label not in converter_stats:
                converter_stats[chain_label] = {"total": 0, "success": 0, "failure": 0, "error": 0}
            converter_stats[chain_label]["total"] += 1
            if r["status"] == "SUCCESS":
                converter_stats[chain_label]["success"] += 1
            elif r["status"] == "FAILURE":
                converter_stats[chain_label]["failure"] += 1
            else:
                converter_stats[chain_label]["error"] += 1

    # 按成功率排序
    ranked = sorted(
        converter_stats.items(),
        key=lambda x: x[1]["success"] / max(x[1]["total"], 1),
        reverse=True,
    )
    return {
        "converter_rankings": [
            {
                "chain": name, "success_rate": round(stats["success"] / max(stats["total"], 1), 3),
                **stats,
            }
            for name, stats in ranked
        ],
        "best_converter": ranked[0][0] if ranked else "N/A",
        "total_prompts_tested": len(results),
    }


def _print_tech_report(results: dict[str, dict[str, dict]], template, elapsed: float):
    """打印技术模板 converter 有效性报告"""
    summary = _build_tech_summary(results)

    console.print(f"\n[bold cyan]━━━ Converter 链有效性排名 ━━━[/bold cyan]")
    table = Table(title="突破成功率排名")
    table.add_column("排名", style="dim", justify="right")
    table.add_column("Converter 链", style="cyan")
    table.add_column("总数", justify="right")
    table.add_column("成功", justify="right", style="green")
    table.add_column("失败", justify="right", style="red")
    table.add_column("成功率", justify="right", style="bold yellow")

    for idx, item in enumerate(summary["converter_rankings"], 1):
        rate = item["success_rate"]
        style_rate = f"[bold green]{rate:.0%}[/bold green]" if rate >= 0.5 else f"[yellow]{rate:.0%}[/yellow]" if rate > 0 else f"[red]{rate:.0%}[/red]"
        table.add_row(
            f"#{idx}", item["chain"],
            str(item["total"]), str(item["success"]), str(item["failure"]),
            style_rate,
        )

    console.print(table)
    console.print(f"\n[bold green]🏆 最佳 Converter 链: {summary['best_converter']}[/bold green]")
    console.print(f"[dim]测试 {summary['total_prompts_tested']} 个提示词，耗时 {elapsed:.1f}s[/dim]")

    # 按提示词显示最佳突破链
    console.print(f"\n[bold cyan]━━━ 提示词级别最佳突破链 ━━━[/bold cyan]")
    for pid, chains in results.items():
        successes = [(cl, r) for cl, r in chains.items() if r["status"] == "SUCCESS"]
        if successes:
            best = successes[0]
            console.print(f"  [green]✅[/green] {pid}: {best[0]}")
        else:
            console.print(f"  [red]❌[/red] {pid}: 无突破")


# ================= 🆕 考试模式入口 =================
async def _run_exam_mode(args) -> None:
    """考试模式入口：仅需提示词模板，系统自动完成全部攻击编排和报告。

    遵循 PYrit 专家设计原则：
      ✅ 考试期间仅修改 YAML 模板文件
      ✅ 攻击编排、提示词变体、目标调用、结果评分、报告生成全部预固化
      ✅ 完全适应不同考试目标和场景
    """
    from scenarios.schema import ExamPromptSet
    from scenarios.orchestrator import ExamAutoOrchestrator
    from scenarios.reporter import ExamSecurityReporter

    # ── 1. 加载提示词模板 ──
    template_path = _resolve_template_path(
        args.exam_template,
        search_dirs=["scenarios/templates"],
    )
    if not template_path:
        console.print(f"[bold red]❌ 考试模板文件不存在: {args.exam_template}[/bold red]")
        console.print(f"   [dim]搜索目录: scenarios/templates/[/dim]")
        return

    console.print(f"[bold cyan]📋 加载考试提示词模板: {template_path}[/bold cyan]")
    try:
        if template_path.endswith(".json"):
            template = ExamPromptSet.from_json_file(template_path)
        else:
            template = ExamPromptSet.from_yaml_file(template_path)
    except Exception as e:
        console.print(f"[bold red]❌ 模板加载失败: {e}[/bold red]")
        return

    summary = template.get_summary()
    console.print(
        f"  [dim]提示词: {summary['total_prompts']} 个 | "
        f"单轮: {summary['single_turn']} | 多轮: {summary['multi_turn']} | "
        f"预估攻击: {summary['estimated_attacks']} 次[/dim]"
    )

    # ── 2. 构建目标（复用 CLI 目标构建逻辑）──
    attacker_config, scorer_config = load_env_config(args.env_file)
    scorer_target = create_scorer_target(scorer_config) if scorer_config else OpenAIChatTarget(temperature=0)

    if args.target_url:
        extra_headers = {}
        if args.target_extra_headers:
            try:
                extra_headers = json.loads(args.target_extra_headers)
            except json.JSONDecodeError:
                console.print("[yellow]⚠️ --target-extra-headers JSON 解析失败[/yellow]")

        is_http_target = args.target_url.lower().startswith("http://")
        if is_http_target and args.target_verify_ssl:
            console.print("[yellow]⚠️ --target-verify-ssl 对 http:// 协议无效[/yellow]")
        verify_ssl = (args.target_verify_ssl or not args.target_no_ssl) and not is_http_target

        # ── 🆕 模型自动探测 + 可达性检查 ──
        args.target_model, target_reachable = await _auto_probe_target_model(args, args.target_url, args.target_api_key)
        if not target_reachable:
            return []  # 目标不可达，跳过所有攻击任务

        attack_target = build_custom_target(
            endpoint=args.target_url,
            scenario=args.scenario or "",
            api_key=args.target_api_key or "",
            model=args.target_model or DEFAULT_MODEL_NAME,
            api_format=args.target_api_format,
            http_method=args.target_http_method,
            content_type=args.target_content_type,
            verify_ssl=verify_ssl,
            cookie=args.target_cookie or "",
            jwt_token=args.target_jwt or "",
            user_agent=args.target_user_agent or "",
            extra_headers=extra_headers if extra_headers else None,
        )
    else:
        if not attacker_config or not attacker_config.get("model"):
            console.print("[bold red]❌ 攻击者模型未配置！请在 .env 中设置或使用 --target-url[/bold red]")
            return
        attack_target = create_attack_target(env_config=attacker_config)

    # ── 3. 初始化 PyRIT Memory ──
    ensure_results_dir()
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    db_path = results_path(f"ai300_exam_memory_{ts}.db")
    memory = SQLiteMemory(db_path=db_path)
    CentralMemory.set_memory_instance(memory)
    console.print(f"[dim]PyRIT Memory 已初始化: {db_path}[/dim]")

    # ── 4. 执行考试模式全自动编排 ──
    orchestrator = ExamAutoOrchestrator(
        template=template,
        attack_target=attack_target,
        scorer_target=scorer_target,
    )

    try:
        results = await orchestrator.run()

        # ── 5. 生成综合安全评估报告 ──
        reporter = ExamSecurityReporter(template)
        report_paths = reporter.generate_all(
            [r for r in results],
            campaign_name="AI-300_Exam_Mode",
        )

        console.print(f"\n[bold green]✅ 考试模式完成！[/bold green]")
        console.print(f"  Markdown 报告: {report_paths['markdown']}")
        console.print(f"  JSON 日志: {report_paths['json']}")

    finally:
        if hasattr(attack_target, 'close') and callable(attack_target.close):
            await attack_target.close()


# ================= 6. 主任务调度 =================
async def run_campaign(json_file, campaign_name, heatmap_title, heatmap_filename,
                       max_concurrent=5, phase_filter="all", attack_target=None, scorer_target=None,
                       case_filter=None, exclude_filter=None, combo_filter=None):
    global _pyrit_initialized

    try:
        cases, _ = load_test_cases(json_file)
    except Exception as e:
        console.print(f"[red]❌ Failed to load {json_file}: {e}[/red]")
        return []

    if not cases:
        console.print("[yellow]⚠️ 测试用例为空，退出执行[/yellow]")
        return []

    # 阶段过滤
    if phase_filter != "all":
        cases = [c for c in cases if classify_case(c) == phase_filter]
        if not cases:
            console.print(f"[yellow]⚠️ No '{phase_filter}' cases found in {json_file}, skipping[/yellow]")
            return []

    # case ID 白名单过滤（--case）
    if case_filter:
        _ids = set(case_filter)
        cases = [c for c in cases if c.get("id", "") in _ids]
        if not cases:
            console.print(f"[yellow]⚠️ No matching case IDs found in {json_file}, skipping[/yellow]")
            return []
        console.print(f"[dim]🔍 用例白名单过滤: {len(cases)} 个匹配 ({', '.join(c.get('id','') for c in cases)})[/dim]")

    # case ID 排除过滤（--exclude-case）
    if exclude_filter:
        _exclude = set(exclude_filter)
        before = len(cases)
        cases = [c for c in cases if c.get("id", "") not in _exclude]
        skipped = before - len(cases)
        if not cases:
            console.print(f"[yellow]⚠️ 所有用例已被 --exclude-case 排除[/yellow]")
            return []
        console.print(f"[dim]🚫 已排除 {skipped} 个用例，剩余 {len(cases)} 个[/dim]")

    # 数据库仅初始化一次（PyRIT 0.14.0: DUCK_DB → "SQLite", api 改名 + async）
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    db_path = results_path(f"ai300_memory_{ts}.duckdb")
    if not _pyrit_initialized:
        await initialize_pyrit_async(memory_db_type="SQLite", db_path=db_path)
        _pyrit_initialized = True

    # 使用外部传入的 target，若无则回退到默认 OpenAIChatTarget
    base_target = attack_target or OpenAIChatTarget(temperature=0.9)
    scorer_target = scorer_target or OpenAIChatTarget(temperature=0)
    semaphore = asyncio.Semaphore(max_concurrent)

    # 🆕 P2 重构: 创建 AI300Orchestrator 实例，legacy 引擎内部委托给 PyRIT 原生管道
    from orchestrators.pyrit_orchestrator import AI300Orchestrator
    _native_orch = AI300Orchestrator(
        scorer_target=scorer_target,
        max_concurrent=max_concurrent,
    )

    # 自动识别单轮/多轮用例，生成对应任务
    # combo_filter: set of (case_id, combo_name) — 仅运行精确匹配的 case+combo 对
    _cf = set(combo_filter) if combo_filter else None
    tasks = []
    for case in cases:
        raw_combos = case.get("attack_combos", GLOBAL_ATTACK_COMBINATIONS)
        combos = [{"name": c["name"], "converters": resolve_converters(c["converters"])} for c in raw_combos]

        # 判断用例类型：有multi_turn_objectives则走Crescendo多轮，否则走单轮
        is_multi_turn = "multi_turn_objectives" in case and len(case["multi_turn_objectives"]) > 0
        for combo in combos:
            # combo_filter 精确匹配：只跑 (case_id, combo_name) 在集合中的
            if _cf and (case.get("id", ""), combo["name"]) not in _cf:
                continue
            if is_multi_turn:
                tasks.append(("crescendo", case, combo))
            else:
                tasks.append(("single", case, combo))

    dashboard = DashboardState(len(tasks))
    all_results = []

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
    )
    task_id = progress.add_task(f"⚔️ Executing {len(tasks)} attacks...", total=len(tasks))

    # 启动 Live 实时仪表盘
    with Live(dashboard.get_layout(progress, task_id), console=console, refresh_per_second=4) as live:
        coros = []
        for task_type, case, combo in tasks:
            if task_type == "single":
                coro = execute_single_attack(
                    semaphore, case, combo, base_target, scorer_target, dashboard,
                    orchestrator=_native_orch,  # 🆕 P2: 自动委托 PyRIT 原生管道
                )
            else:
                coro = execute_crescendo_attack(
                    semaphore, case, combo, base_target, scorer_target, dashboard,
                    orchestrator=_native_orch,  # 🆕 P2: 自动委托 PyRIT 原生管道
                )
            coros.append(coro)

        for coro in asyncio.as_completed(coros):
            result = await coro
            all_results.append(result)
            progress.advance(task_id)
            live.update(dashboard.get_layout(progress, task_id))

    # 保存攻击日志（带时间戳）
    log_file = results_path(f"{campaign_name.replace(' ', '_')}_log_{ts}.json")
    with open(log_file, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)
    console.print(f"[green]✅ 攻击日志已保存: {log_file}[/green]")
    
    # 生成热力图分析报告（带时间戳）
    heatmap_file = results_path(heatmap_filename.replace('.png', f'_{ts}.png'))
    analyze_and_visualize(all_results, heatmap_title, heatmap_file)
    
    # 打印详细报告（含 prompt/response 证据）
    print_detailed_report(all_results, campaign_name)
    
    # 生成考试用漏洞报告（Markdown，默认输出到 results 目录）
    generate_exam_report(all_results, campaign_name, output_dir=RESULTS_DIR)
    
    return all_results


# ================= 6.5 阶段门控编排器 =================
async def run_phased_campaign(json_file: str, max_concurrent: int, gate_threshold: float,
                               attack_target=None, scorer_target=None,
                               case_filter=None, exclude_filter=None, combo_filter=None):
    """PyRIT 最佳实践：阶梯式门控执行。低成功率自动跳过当前阶段，升级到下一阶段。"""
    console.print(Panel(
        f"[bold]🚀 AI-300 阶梯式门控攻击 (阈值: {gate_threshold:.0%})[/bold]\n"
        f"[dim]STAGE 1: PROBE 快速探测 → STAGE 2: 单轮主力突破 → STAGE 3: Crescendo 攻坚战[/dim]",
        style="bold blue"))

    # ── STAGE 1: PROBE 快速健康检查 ──
    console.print("\n[bold cyan]━━━ STAGE 1/3: PROBE 快速探测 ━━━[/bold cyan]")
    results_s, results_c = [], []  # 预初始化，避免门控跳过时 UnboundLocalError
    results_p = await run_campaign(
        json_file=json_file,
        campaign_name="AI-300_PROBE_Recon",
        heatmap_title="AI-300 PROBE Success Matrix",
        heatmap_filename="ai300_probe_heatmap.png",
        max_concurrent=max_concurrent,
        phase_filter="probe",
        attack_target=attack_target,
        scorer_target=scorer_target,
        case_filter=case_filter,
        exclude_filter=exclude_filter,
        combo_filter=combo_filter,
    )
    probe_rate = _calc_success_rate(results_p)
    console.print(f"[bold]PROBE 阶段成功率: {probe_rate:.1%}[/bold]")

    # ── STAGE 2: 单轮攻击（可能被门控跳过） ──
    skip_single = probe_rate < gate_threshold
    single_rate = 0.0
    if skip_single:
        console.print(f"[yellow]⚠️ PROBE 成功率 ({probe_rate:.1%}) < 门控阈值 ({gate_threshold:.0%})[/yellow]")
        console.print("[yellow]→ 目标防线较强，跳过单轮阶段，直接升级 Crescendo 攻坚...[/yellow]")
    else:
        console.print(f"\n[bold cyan]━━━ STAGE 2/3: 单轮主力突破 ━━━[/bold cyan]")
        results_s = await run_campaign(
            json_file=json_file,
            campaign_name="AI-300_SingleTurn_Assault",
            heatmap_title="AI-300 Single-Turn Success Matrix",
            heatmap_filename="ai300_single_heatmap.png",
            max_concurrent=max_concurrent,
            phase_filter="single",
            attack_target=attack_target,
            scorer_target=scorer_target,
            case_filter=case_filter,
            exclude_filter=exclude_filter,
            combo_filter=combo_filter,
        )
        single_rate = _calc_success_rate(results_s)
        console.print(f"[bold]单轮阶段成功率: {single_rate:.1%}[/bold]")

    # ── STAGE 3: Crescendo 攻坚 ──
    skip_crescendo = (not skip_single) and single_rate < gate_threshold
    if skip_crescendo:
        console.print(f"[yellow]⚠️ 单轮成功率 ({single_rate:.1%}) < 门控阈值 ({gate_threshold:.0%})[/yellow]")
        console.print("[yellow]→ Crescendo 多轮攻击在此目标上成功率极低，跳过以节省考试时间。[/yellow]")
    else:
        reason = "单轮突破成功，乘胜追击" if not skip_single else "PROBE 未穿透，升级重型武器"
        console.print(f"\n[bold cyan]━━━ STAGE 3/3: Crescendo 攻坚 ({reason}) ━━━[/bold cyan]")
        results_c = await run_campaign(
            json_file=json_file,
            campaign_name="AI-300_Crescendo_Siege",
            heatmap_title="AI-300 Crescendo Success Matrix",
            heatmap_filename="ai300_crescendo_heatmap.png",
            max_concurrent=max_concurrent,
            phase_filter="crescendo",
            attack_target=attack_target,
            scorer_target=scorer_target,
            case_filter=case_filter,
            exclude_filter=exclude_filter,
            combo_filter=combo_filter,
        )

    console.print("\n[bold green]✅ 阶梯式门控攻击完成！[/bold green]")
    
    # 阶段完成后生成综合报告
    all_phase_results = results_p + (results_s if not skip_single else []) + (results_c if not skip_crescendo else [])
    if all_phase_results:
        print_detailed_report(all_phase_results, "AI-300 阶梯式门控总战报")
    
    # 尝试收集各阶段日志生成综合考试报告
    log_files = sorted(_glob.glob(results_path("AI-300_*_log_*.json")))
    if len(log_files) >= 2:
        all_results_combined = []
        for lf in log_files[-3:]:  # 最近3个阶段日志
            try:
                with open(lf, 'r', encoding='utf-8') as f:
                    all_results_combined.extend(json.load(f))
            except Exception:
                pass
        if all_results_combined:
            generate_exam_report(all_results_combined, "AI-300_Combined_All_Phases", output_dir=RESULTS_DIR)
    
    # 保存综合结果供调用方使用（修复 UnboundLocalError）
    return results_p + (results_s if not skip_single else []) + (results_c if not skip_crescendo else [])


# ================= 6.6 🆕 PyRIT 原生调度路径 =================

async def _run_campaign_native(json_file, campaign_name, heatmap_title, heatmap_filename,
                                max_concurrent=5, phase_filter="all", attack_target=None,
                                scorer_target=None, case_filter=None, exclude_filter=None,
                                combo_filter=None):
    """使用 AI300Orchestrator（PyRIT 原生）执行攻击战役。

    替代旧版 run_campaign()，全面对接 PyRIT 0.14.0 原生组件:
      - Memory:  SQLiteMemory + CentralMemory（已在 main() 中初始化）
      - 单轮:   PromptSendingAttack（自动管道: converters → target → scorer → memory）
      - 多轮:   CrescendoAttack（原生渐进式越狱算法）
    """
    try:
        cases, _ = load_test_cases(json_file)
    except Exception as e:
        console.print(f"[red]❌ Failed to load {json_file}: {e}[/red]")
        return []

    if not cases:
        console.print("[yellow]⚠️ 测试用例为空，退出执行[/yellow]")
        return []

    # ── 阶段过滤 ──
    if phase_filter != "all":
        cases = [c for c in cases if classify_case(c) == phase_filter]
        if not cases:
            console.print(f"[yellow]⚠️ No '{phase_filter}' cases found in {json_file}, skipping[/yellow]")
            return []

    # ── 用例白名单/排除过滤 ──
    if case_filter:
        _ids = set(case_filter)
        cases = [c for c in cases if c.get("id", "") in _ids]
        if not cases:
            console.print("[yellow]⚠️ No matching case IDs found, skipping[/yellow]")
            return []
        console.print(f"[dim]🔍 用例白名单过滤: {len(cases)} 个匹配 ({', '.join(c.get('id','') for c in cases)})[/dim]")

    if exclude_filter:
        _exclude = set(exclude_filter)
        before = len(cases)
        cases = [c for c in cases if c.get("id", "") not in _exclude]
        if not cases:
            console.print("[yellow]⚠️ 所有用例已被排除[/yellow]")
            return []
        console.print(f"[dim]🚫 已排除 {before - len(cases)} 个用例，剩余 {len(cases)} 个[/dim]")

    # ── 创建 AI300Orchestrator ──
    orch = AI300Orchestrator(
        scorer_target=scorer_target or OpenAIChatTarget(temperature=0),
        max_concurrent=max_concurrent,
    )
    # Memory 由 orchestrator._ensure_memory() 自动从 CentralMemory 发现
    # （main() 已调用 CentralMemory.set_memory_instance() 注册全局单例）

    # ── 执行 ──
    phase_map = {"probe": AttackPhase.PROBE, "single": AttackPhase.SINGLE,
                 "crescendo": AttackPhase.CRESCENDO,
                 "pair": AttackPhase.PAIR, "tap": AttackPhase.TAP,
                 "flip": AttackPhase.FLIP, "chunked": AttackPhase.CHUNKED,
                 "manyshot": AttackPhase.MANYSHOT, "skeleton_key": AttackPhase.SKELETON_KEY,
                 "indirect_inject": AttackPhase.SINGLE,    # 间接注入走单轮管道
                 "rag_poison": AttackPhase.SINGLE,         # RAG 投毒走单轮管道
                 "agent_attack": AttackPhase.SINGLE,       # Agent 攻击走单轮管道
                 "embedding_attack": AttackPhase.SINGLE,   # Embedding 攻击走单轮管道
                 "sequence_chain": AttackPhase.SINGLE,     # 策略管道走单轮管道
                 "mcp_security": AttackPhase.SINGLE,       # MCP 安全测试走单轮管道
                 "a2a_security": AttackPhase.SINGLE,       # A2A 安全测试走单轮管道
                 "all": AttackPhase.ALL}
    phase = phase_map.get(phase_filter, AttackPhase.ALL)

    results = await orch.run_campaign(
        cases=cases,
        attack_target=attack_target,
        phase=phase,
        case_filter=set(case_filter) if case_filter else None,
        exclude_filter=set(exclude_filter) if exclude_filter else None,
        combo_filter=set(combo_filter) if combo_filter else None,
    )

    # ── 结果导出 ──
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = orch.export_results(results, campaign_name)

    # 热力图 & 报告（复用 legacy reporting）
    heatmap_file = results_path(heatmap_filename.replace('.png', f'_{ts}.png'))
    analyze_and_visualize(results, heatmap_title, heatmap_file)
    print_detailed_report(results, campaign_name)
    generate_exam_report(results, campaign_name, output_dir=RESULTS_DIR)

    return results


async def _run_phased_campaign_native(json_file, max_concurrent, gate_threshold,
                                       attack_target=None, scorer_target=None,
                                       case_filter=None, exclude_filter=None, combo_filter=None):
    """使用 AI300Orchestrator 执行阶梯式门控攻击（PyRIT 原生）。"""
    try:
        cases, _ = load_test_cases(json_file)
    except Exception as e:
        console.print(f"[red]❌ Failed to load {json_file}: {e}[/red]")
        return []

    if not cases:
        console.print("[yellow]⚠️ 测试用例为空，退出执行[/yellow]")
        return []

    orch = AI300Orchestrator(
        scorer_target=scorer_target or OpenAIChatTarget(temperature=0),
        max_concurrent=max_concurrent,
    )
    # Memory 由 orchestrator._ensure_memory() 自动从 CentralMemory 发现

    results = await orch.run_phased_campaign(
        cases=cases,
        attack_target=attack_target,
        gate_threshold=gate_threshold,
        case_filter=set(case_filter) if case_filter else None,
        exclude_filter=set(exclude_filter) if exclude_filter else None,
        combo_filter=set(combo_filter) if combo_filter else None,
    )

    # 综合报告
    if results:
        print_detailed_report(results, "AI-300 阶梯式门控总战报（PyRIT 原生）")
        generate_exam_report(results, "AI-300_Combined_All_Phases_PyRIT", output_dir=RESULTS_DIR)

    return results


# ================= Payload 模板变量加载 =================
def _load_payload_vars(args) -> None:
    """加载 payload 变量到 engines.PAYLOAD_VARS。
    从 data/payloads_{lang}.py 加载（通过 data/loader.py）。
    顺序：Python 模块 → preset 预设 → --payload-vars 命令行覆盖（后者优先级更高）
    """
    ext = os.path.splitext(args.payloads)[1].lower() if args.payloads else ""

    if ext in (".yaml", ".yml"):
        # ── 降级方案: YAML 文件加载 ──
        if os.path.exists(args.payloads):
            try:
                from datasets.loader import load_payload_vars as _yaml_load
                vars_dict, registry = _yaml_load(args.payloads)
                PAYLOAD_VARS.update(vars_dict)
                console.print(f"[dim]📦 已从 YAML 加载 {len(PAYLOAD_VARS)} 个 payload 变量 ({args.payloads})[/dim]")
                if args.payload_preset and registry:
                    apply_preset(PAYLOAD_VARS, args.payload_preset, registry.extract_presets())
            except Exception as e:
                console.print(f"[yellow]⚠️ 加载 YAML 失败 ({args.payloads}): {e}[/yellow]")
        else:
            console.print(f"[yellow]⚠️ YAML 文件未找到: {args.payloads}[/yellow]")
    else:
        # ── 主方案: Python 模块加载 (data/payloads_{lang}.py) ──
        try:
            vars_dict, presets = load_payloads_module(args.lang)
            PAYLOAD_VARS.update(vars_dict)
            console.print(f"[dim]📦 已从 Python 模块加载 {len(vars_dict)} 个 payload 变量[/dim]")
            if args.payload_preset:
                apply_preset(PAYLOAD_VARS, args.payload_preset, presets)
        except Exception as e:
            console.print(f"[yellow]⚠️ 加载 Payload 模块失败: {e}[/yellow]")

    # ── 命令行额外变量覆盖（最高优先级）──
    if args.payload_vars:
        try:
            extra = json.loads(args.payload_vars)
            PAYLOAD_VARS.update(extra)
            console.print(f"[dim]🔧 命令行覆盖 {len(extra)} 个 payload 变量[/dim]")
        except json.JSONDecodeError as e:
            console.print(f"[yellow]⚠️ --payload-vars JSON 解析失败: {e}[/yellow]")


# ── 模型自动探测辅助函数 ──

async def _auto_probe_target_model(args, target_url: str, target_api_key: str) -> tuple[str, bool]:
    """自动探测目标 URL 的模型名称和可达性。

    PyRIT 最佳实践: 区分"目标不可达"与"目标可达但模型无法识别"。
      ❌ 目标不可达 → 返回 ("unreachable", False)  → 应中止 campaign
      ⚠️  目标可达但无法识别 → 返回 ("default", True) → 降级继续攻击
      ✅ 探测成功 → 返回 (model_name, True)             → 正常攻击

    Args:
        args: CLI 解析参数
        target_url: 目标 URL
        target_api_key: API Key（可选）

    Returns:
        (model_name, is_reachable) — 模型名和是否可达
    """
    current_model = args.target_model or ""

    # ── 跳过条件 ──
    if args.no_probe:
        console.print("[dim]⏭ --no-probe: 跳过模型自动探测[/dim]")
        return current_model if current_model else get_default_model_name(), True
    if not target_url:
        return current_model if current_model else get_default_model_name(), True
    if current_model and current_model != DEFAULT_MODEL_NAME:
        console.print(f"[dim]📌 已指定 --target-model={current_model}，跳过自动探测[/dim]")
        return current_model, True

    # ── 执行探测 ──
    console.print()
    result = await probe_model_info(
        target_url=target_url,
        api_key=target_api_key or "",
    )

    # ── PyRIT 最佳实践: 先判断可达性 ──
    is_reachable = check_target_reachable(result)

    if not is_reachable:
        console.print()
        console.print(Panel(
            f"[bold red]❌ 目标不可达: {target_url}[/bold red]\n\n"
            f"[red]所有探测策略均无法建立连接（ConnectionError / Timeout）。[/red]\n"
            f"[red]跳过该目标的所有攻击任务，避免无效重试和资源浪费。[/red]\n\n"
            f"[dim]建议:[/dim]\n"
            f"  [dim]1. 确认目标服务是否已启动[/dim]\n"
            f"  [dim]2. 检查防火墙/安全组/网络策略是否放行[/dim]\n"
            f"  [dim]3. 确认是否需要 VPN/代理访问内网目标[/dim]\n"
            f"  [dim]4. 修复后在终端重新运行相同命令[/dim]",
            style="bold red",
        ))
        return "unreachable", False

    # ── 速率限制建议（如有端点枚举数据） ──
    if result.discovery_summary:
        ds = result.discovery_summary
        if ds.get("has_rate_limit") or ds.get("recommended_concurrency"):
            console.print(
                f"[dim]⏱  API 速率建议: 并发 [cyan]{ds.get('recommended_concurrency', 5)}[/cyan], "
                f"RPM ~[cyan]{ds.get('recommended_rpm', 60)}[/cyan] "
                f"(类型: {ds.get('rate_limit_type', 'unknown')})[/dim]\n"
            )

    if result.model_name and result.confidence > 0:
        console.print(
            f"[bold green]✅ 模型自动识别: [cyan]{result.model_name}[/cyan] "
            f"(策略: {result.strategy}, 置信度: {result.confidence:.0%})[/bold green]"
        )
        console.print(f"[dim]   → 已自动注入 PyRIT 攻击管线 (--target-model {result.model_name})[/dim]\n")
        return result.model_name, True
    else:
        # 目标可达但无法识别模型 → 降级使用默认模型名
        console.print(
            f"[yellow]  → 目标可达但无法识别模型名称，使用 model='{get_default_model_name()}' 降级攻击[/yellow]"
        )
        console.print("[dim]    可通过 --target-model <模型名> 手动指定以提升攻击精准度[/dim]\n")
        return current_model or get_default_model_name(), True


# ================= CLI 入口 =================
async def main():
    parser = argparse.ArgumentParser(
        description="OffSec AI-300 Unified Red Team Platform v9.0 (Phased Execution) — 70 test cases across 3 attack strategies + 2026-hottest attack vectors (CoT/Constitution/MCP/A2A/Multimodal) + 17 triple-layer chains",
        epilog="EXAMPLES:\n"
               "  # [1] 🆕 端点枚举 + 模型探测 + 攻击 (考试最强全自动化)\n"
               "  python main.py --lang cn --target-url http://192.168.2.199:8501/ --phase probe\n\n"
               "  # [2] 跳过自动探测，手动指定模型\n"
               "  python main.py --lang cn --target-url http://192.168.2.199:8501/ --target-model gpt-4 --phase probe\n\n"
               "  # [3] 跳过自动探测 + raw 格式 (非标准 API)\n"
               "  python main.py --lang cn --target-url http://192.168.2.199:8501/ --target-api-format raw --phase probe --no-probe\n\n"
               "  # [4] 攻击内网自签证书的 Chat API (OpenAI 兼容)\n"
               "  python main.py --lang cn --target-url https://192.168.12.22/chat --phase probe\n\n"
               "  # [5] 攻击 HTTP 内网 Web 应用 + Cookie/Session 认证 (考试高频场景)\n"
               "  python main.py --lang cn --target-url http://192.168.1.100/api/chat --target-api-format raw --target-cookie \"session_id=abc123; auth_token=xyz\" --phase probe\n\n"
               "  # [6] 攻击 HTTPS 内部应用 + 自定义认证头 (X-API-Key / X-CSRF-Token 等)\n"
               "  python main.py --lang cn --target-url https://internal-app/api/v1/query --target-api-format raw --target-extra-headers '{\"X-API-Key\":\"sk-secret\",\"X-CSRF-Token\":\"csrf-xyz\"}' --target-no-ssl --phase probe\n\n"
               "  # [7] 攻击 Gemini API (非 OpenAI 格式)\n"
               "  python main.py --lang cn --target-url https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent --target-api-key YOUR_KEY --target-api-format gemini --phase probe\n\n"
               "  # [8] 攻击 Claude API (非 OpenAI 格式)\n"
               "  python main.py --lang cn --target-url https://api.anthropic.com/v1/messages --target-api-key YOUR_KEY --target-api-format claude --target-model claude-3-sonnet-20240229 --phase probe\n\n"
               "  # [6] 原方式：不指定 --target-url → 探测 .env 中配置的 LLM API (如智谱 GLM-4.7-Flash)\n"
               "  python main.py --lang cn --phase all",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--lang", choices=["cn", "en"], default="cn",
                        help="Test suite language: cn=Chinese, en=English (default: cn)")
    parser.add_argument("--phase", choices=["probe", "single", "crescendo", "pair", "tap", "flip",
                        "chunked", "manyshot", "skeleton_key",
                        "indirect_inject", "rag_poison", "agent_attack", "embedding_attack",
                        "sequence_chain", "mcp_security", "a2a_security", "all"],
                        default="probe",
                        help="Phase: probe/single/crescendo/pair/tap/flip/chunked/manyshot/"
                             "skeleton_key/indirect_inject/rag_poison/agent_attack/embedding_attack/"
                             "sequence_chain/mcp_security/a2a_security/all")
    parser.add_argument("--auto-gate", action="store_true", default=False,
                        help="Enable auto-gating: skip phases if success rate < --gate-threshold (PyRIT best practice)")
    parser.add_argument("--gate-threshold", type=float, default=0.10,
                        help="Success rate threshold for auto-gating, 0.0-1.0 (default: 0.10)")
    parser.add_argument("--concurrent", type=int, default=1,
                        help="Max concurrent API calls (default: 1)")
    
    # ── 自定义目标参数 ──
    parser.add_argument("--target-url", type=str, default="",
                        help="自定义攻击目标 Chat API URL（如 http://192.168.2.199:8501/）。不指定则攻击 .env 中配置的 LLM API。仅提供 IP:端口时会自动枚举所有二级/三级目录端点")
    parser.add_argument("--target-api-key", type=str, default="",
                        help="自定义目标的 API Key（放在 Authorization: Bearer header 中）")
    parser.add_argument("--target-model", type=str, default="",
                        help="自定义目标的模型名称（放在请求 body 中，默认从 .env 读取）")
    parser.add_argument("--target-api-format", type=str, default="openai", choices=["openai", "gemini", "claude", "raw"],
                        help="API 格式: openai(默认) / gemini / claude / raw(万能回退, 适配任意非标准内部Web应用)")
    parser.add_argument("--scenario", type=str, default="",
                        choices=[""] + list(SCENARIO_PRESETS.keys()),
                        help="场景预设，一键组合认证/传输参数（自动设置 api-format/http-method/content-type/ssl）")
    parser.add_argument("--target-no-ssl", action="store_true", default=True,
                        help="跳过 SSL 证书验证（内网自签证书，默认启用）")
    parser.add_argument("--target-verify-ssl", action="store_true", default=False,
                        help="验证 SSL 证书（覆盖 --target-no-ssl）")
    parser.add_argument("--target-extra-headers", type=str, default="",
                        help="自定义 HTTP 请求头，JSON 字符串格式（如 '{\"X-API-Key\":\"xxx\",\"X-Auth-Token\":\"yyy\"}'）用于内部Web应用的非标准认证")
    parser.add_argument("--target-cookie", type=str, default="",
                        help="Cookie 字符串（如 'session_id=abc; csrf_token=xyz'），自动转为 Cookie 请求头，适配 Web 应用 Session 认证")
    parser.add_argument("--target-user-agent", type=str, default="",
                        help="自定义 User-Agent（默认使用 Chrome/131 浏览器 UA 伪装 WAF）")
    parser.add_argument("--target-content-type", type=str, default="application/json",
                        choices=["application/json", "application/x-www-form-urlencoded", "text/plain"],
                        help="POST 请求 Content-Type，决定 body 编码: json(默认) / form(URL编码) / text(纯文本)")
    parser.add_argument("--target-jwt", type=str, default="",
                        help="JWT Token — 快捷方式，自动转为 Authorization: Bearer <jwt>（优先级高于 --target-api-key）")
    parser.add_argument("--target-http-method", type=str, default="POST",
                        choices=["POST", "GET", "PUT", "DELETE", "PATCH"],
                        help="HTTP 方法: POST(默认, Chat API) / GET(信息收集/探测)")
    parser.add_argument("--no-probe", action="store_true", default=False,
                        help="跳过模型自动探测 + 端点枚举，直接使用 --target-model(default) 进行攻击")
    parser.add_argument("--payloads", type=str, default="",
                        help="Payload 变量文件路径（支持 .json / .yaml / .yml；用于 objective {key} 模板替换），留空则按 --lang 自动选择 data/payloads.py 中的语言版本")
    parser.add_argument("--payload-preset", type=str, default="",
                        help="载荷预设名称（stealth/bruteforce/redteam/academic/minimal），一键切换整组载荷策略")
    parser.add_argument("--payload-vars", type=str, default="",
                        help="额外 Payload 变量，JSON 字符串（如 '{\"shell_type\":\"Python\"}'），优先级高于 preset 和文件")
    parser.add_argument("--env-file", type=str, default=".env",
                        help=".env 配置文件路径（默认: .env）")
    parser.add_argument("--case", type=str, default="",
                        help="仅测试指定用例 ID（逗号分隔），快捷别名: all-probe / all-single / all-crescendo / all-error（重跑上次ERROR）")
    parser.add_argument("--exclude-case", type=str, default="",
                        help="排除指定用例 ID（逗号分隔），如 'CAP_009_explosive_device,CAP_041_gcg_adversarial_suffix'")
    parser.add_argument("--orch", choices=["pyrit", "legacy"], default="pyrit",
                        help="调度引擎: pyrit(默认, PyRIT原生Orchestrator) / legacy(旧版自定义引擎)")
    parser.add_argument("--mode", choices=["multi", "capstone", "all"], default="capstone",
                        help="[Deprecated] Legacy mode flag, use --phase instead")
    # ── 🆕 模板模式参数（技术模板 / 考试模板两套独立体系）──
    parser.add_argument("--tech-template", type=str, default="",
                        help="[技术模板] 指定 YAML 模板文件，快速测试 converter 链对 prompt injection 的突破效果")
    parser.add_argument("--exam-mode", action="store_true", default=False,
                        help="[考试模式] 仅需提供提示词模板，系统自动完成变体生成、攻击编排、评分和报告")
    parser.add_argument("--exam-template", type=str, default="exam_prompts.yaml",
                        help="考试模式提示词模板文件路径（默认: exam_prompts.yaml，自动搜索 scenarios/templates/）")
    args = parser.parse_args()

    # ── 显示完整命令行参数 ──
    cli_parts = [f"python {os.path.basename(__file__)}"]
    cli_parts.append(f"--lang {args.lang}")
    cli_parts.append(f"--phase {args.phase}")
    cli_parts.append(f"--concurrent {args.concurrent}")
    if args.auto_gate:
        cli_parts.append(f"--auto-gate --gate-threshold {args.gate_threshold}")
    if args.target_url:
        cli_parts.append(f"--target-url {args.target_url}")
    if args.target_api_key:
        cli_parts.append(f"--target-api-key {args.target_api_key}")
    if args.target_model:
        cli_parts.append(f"--target-model {args.target_model}")
    if args.target_api_format != "openai":
        cli_parts.append(f"--target-api-format {args.target_api_format}")
    if args.scenario:
        cli_parts.append(f"--scenario {args.scenario}")
    if args.target_extra_headers:
        cli_parts.append(f"--target-extra-headers '{args.target_extra_headers}'")
    if args.target_cookie:
        cli_parts.append(f"--target-cookie '{args.target_cookie}'")
    if args.payload_preset:
        cli_parts.append(f"--payload-preset {args.payload_preset}")
    if args.case:
        cli_parts.append(f"--case {args.case}")
    if args.exclude_case:
        cli_parts.append(f"--exclude-case {args.exclude_case}")
    if args.target_user_agent:
        cli_parts.append(f"--target-user-agent '{args.target_user_agent}'")
    if args.target_content_type != "application/json":
        cli_parts.append(f"--target-content-type {args.target_content_type}")
    if args.target_jwt:
        cli_parts.append(f"--target-jwt {args.target_jwt[:20]}...")
    if args.target_http_method != "POST":
        cli_parts.append(f"--target-http-method {args.target_http_method}")
    if args.no_probe:
        cli_parts.append("--no-probe")
    if args.target_verify_ssl:
        cli_parts.append("--target-verify-ssl")
    if args.env_file != ".env":
        cli_parts.append(f"--env-file {args.env_file}")
    if args.orch != "pyrit":
        cli_parts.append(f"--orch {args.orch}")
    if args.exam_mode:
        cli_parts.append(f"--exam-mode --exam-template {args.exam_template}")
    if args.tech_template:
        cli_parts.append(f"--tech-template {args.tech_template}")
    console.print(f"[bold cyan]📋 执行参数:[/bold cyan] {' '.join(cli_parts)}")

    # ── 🆕 技术模板模式：早返回路径 ──
    if args.tech_template:
        await _run_tech_mode(args)
        return

    # ── 🆕 考试模式：早返回路径 ──
    if args.exam_mode:
        await _run_exam_mode(args)
        return

    # ── 0. 初始化 PyRIT Memory（SQLiteMemory + CentralMemory 全局单例，PyRIT 最佳实践） ──
    global _pyrit_initialized
    ensure_results_dir()
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')

    if args.orch == "pyrit":
        # 🆕 PyRIT 原生 Memory: SQLiteMemory + CentralMemory 全局单例
        db_path = results_path(f"ai300_pyrit_memory_{ts}.db")
        memory = SQLiteMemory(db_path=db_path)
        CentralMemory.set_memory_instance(memory)
        console.print(f"[green]✅ PyRIT Memory 已初始化 (SQLiteMemory + CentralMemory)[/green]")
        console.print(f"   [dim]db_path: {db_path}[/dim]")
    else:
        # 🔙 Legacy: initialize_pyrit_async
        db_path = results_path(f"ai300_memory_{ts}.duckdb")
        if not _pyrit_initialized:
            await initialize_pyrit_async(memory_db_type="SQLite", db_path=db_path)
            _pyrit_initialized = True
            console.print(f"[green]✅ Legacy PyRIT Memory 已初始化[/green]")
            console.print(f"   [dim]db_path: {db_path}[/dim]")

    # ── 0.1 加载 .env 配置 ──
    attacker_config, scorer_config = load_env_config(args.env_file)

    # ── 0.2 模型配置校验 ──
    # 自定义 API（--target-url）: 忽略 CHAT_MODEL，仅需 SCORER_MODEL
    # 非自定义 API: CHAT_MODEL 和 SCORER_MODEL 都必须设置
    if args.target_url:
        if not scorer_config or not scorer_config.get("model"):
            console.print(
                "[bold red]❌ 自定义 API 模式下，评分器模型未配置！[/bold red]\n"
                "    请在 .env 中设置评分器:\n"
                "      SCORER_PLATFORM_SELECTOR=ZHIPU\n"
                "      [ZHIPU]\\n"
                "      SCORER_MODEL=GLM-5.2\n"
                "    或使用默认平台:\n"
                "      PLATFORM_SELECTOR=ZHIPU\n"
                "      [ZHIPU]\\n"
                "      SCORER_MODEL=GLM-5.2"
            )
            return
        console.print("[blue]ℹ️  自定义 API 模式: 已忽略 CHAT_MODEL，仅使用 SCORER_MODEL 配置评分器[/blue]")
    else:
        if not attacker_config or not attacker_config.get("model"):
            console.print(
                "[bold red]❌ 攻击者模型未配置！[/bold red]\n"
                "    请在 .env 中设置 PLATFORM_SELECTOR 并在对应节配置 CHAT_MODEL=模型名\n"
                "    或使用 --target-url 指定自定义 API 目标"
            )
            return
        if not scorer_config or not scorer_config.get("model"):
            console.print(
                "[bold red]❌ 评分器模型未配置！[/bold red]\n"
                "    请在 [PLATFORM] 节中设置 SCORER_MODEL=模型名\n"
                "    例: SCORER_MODEL=GLM-5.2"
            )
            return

    # ── 0.3 创建评分器 Target（使用独立评分器配置） ──
    scorer_target = create_scorer_target(scorer_config)
    
    # ── 0.4 创建攻击目标 Target ──
    # 如果指定了 --target-url，使用场景预设 + CustomHttpChatTarget 攻击该 URL
    # 否则攻击 .env 中配置的 LLM API
    if args.target_url:
        # 解析自定义 HTTP 请求头（JSON 字符串）
        extra_headers = {}
        if args.target_extra_headers:
            try:
                extra_headers = json.loads(args.target_extra_headers)
            except json.JSONDecodeError as e:
                console.print(f"[bold red]❌ --target-extra-headers JSON 解析失败: {e}[/bold red]")
                return

        # 协议校验：--target-verify-ssl 对 http:// 无效
        is_http_target = args.target_url.lower().startswith("http://")
        if is_http_target and args.target_verify_ssl:
            console.print("[yellow]⚠️ --target-verify-ssl 对 http:// 协议无效（HTTP 不使用 SSL），已自动忽略[/yellow]")
        verify_ssl = (args.target_verify_ssl or not args.target_no_ssl) and not is_http_target

        # ── 🆕 模型自动探测 + 可达性检查（PyRIT 最佳实践：自动识别目标模型名称）──
        args.target_model, target_reachable = await _auto_probe_target_model(args, args.target_url, args.target_api_key)
        if not target_reachable:
            return  # 目标不可达，跳过所有攻击任务

        # 场景预设 → 合并 CLI 覆盖 → 构建 Target（headers/cookie/jwt/ssl/ua 全由 scenarios.py 处理）
        attack_target = build_custom_target(
            endpoint=args.target_url,
            scenario=args.scenario,
            api_key=args.target_api_key or "",
            model=args.target_model or DEFAULT_MODEL_NAME,
            api_format=args.target_api_format,
            http_method=args.target_http_method,
            content_type=args.target_content_type,
            verify_ssl=verify_ssl,
            cookie=args.target_cookie,
            jwt_token=args.target_jwt,
            user_agent=args.target_user_agent,
            extra_headers=extra_headers if extra_headers else None,
        )
    else:
        attack_target = create_attack_target(env_config=attacker_config)

    # ── 0.5 加载 Payload 模板变量（Python 模块，通过 data/loader.py）──
    if not args.payloads:
        console.print(f"[dim]📦 从 Python 模块加载 Payload (lang={args.lang})[/dim]")
    _load_payload_vars(args)

    # ── 0.5.3 自动发现转换器（考试零改动原则）──
    n_discovered = discover_converters("converters")
    n_synced = sync_pyrit_converters()
    if n_discovered or n_synced:
        console.print(f"[dim]🔍 自动发现: +{n_discovered} 自定义 + {n_synced} PyRIT 原生转换器[/dim]")

    # ── 0.5.5 攻击特征库概况 ──
    n_converters = len(CONVERTER_MAP)
    n_combos = len(GLOBAL_ATTACK_COMBINATIONS)
    n_triple = sum(1 for c in GLOBAL_ATTACK_COMBINATIONS if len(c["converters"]) >= 3)
    n_double = sum(1 for c in GLOBAL_ATTACK_COMBINATIONS if len(c["converters"]) == 2)
    n_single = sum(1 for c in GLOBAL_ATTACK_COMBINATIONS if len(c["converters"]) == 1)
    console.print(
        f"[dim]🎯 攻击特征库: {n_converters} 个转换器 + {n_combos} 组攻击组合 "
        f"(单层: {n_single} | 双层: {n_double} | 三层链: {n_triple})[/dim]"
    )

    # ── 0.6 解析用例白名单/排除列表（支持 all-probe / all-single / all-crescendo 快捷别名）──
    case_filter = [x.strip() for x in args.case.split(",") if x.strip()] if args.case else None
    exclude_filter = [x.strip() for x in args.exclude_case.split(",") if x.strip()] if args.exclude_case else None

    _CASE_SHORTCUTS = {"all-probe": "probe", "all-single": "single", "all-crescendo": "crescendo"}
    _phase_from_case = None
    _combo_filter = None  # (case_id, combo_name) 精确过滤集（all-error 专用）
    if case_filter:
        for sc, ph in _CASE_SHORTCUTS.items():
            if sc in case_filter:
                _phase_from_case = ph
                case_filter.remove(sc)
        # ── all-error: 从最新日志中提取 (case_id, combo_name) 精确对 ──
        if "all-error" in case_filter:
            case_filter.remove("all-error")
            import glob as _glob
            _log_files = _glob.glob(os.path.join(RESULTS_DIR, "*_log_*.json"))
            if _log_files:
                _latest_log = max(_log_files, key=os.path.getmtime)
                import json as _json
                with open(_latest_log, "r", encoding="utf-8") as _f:
                    _prev_results = _json.load(_f)
                _error_pairs = sorted(set(
                    (r["case_id"], r.get("combo_name", "")) for r in _prev_results if r.get("status") == "ERROR"
                ))
                if _error_pairs:
                    _combo_filter = _error_pairs
                    _error_ids = sorted(set(cid for cid, _ in _error_pairs))
                    case_filter = list(set(case_filter or []) | set(_error_ids))
                    # 从错误用例 ID 前缀自动推断阶段
                    def _infer_phase(cid: str) -> str:
                        if cid.startswith("probe_") or cid.upper().startswith("PROBE_"):
                            return "probe"
                        if cid.startswith("multi_crescendo_"):
                            return "crescendo"
                        if cid.startswith("single_"):
                            return "single"
                        return "crescendo"  # CAP_xxx 多轮用例默认
                    _error_phases = {_infer_phase(cid) for cid in _error_ids}
                    if len(_error_phases) == 1:
                        _phase_from_case = _error_phases.pop()
                    console.print(
                        f"[yellow]📋 从最新日志提取 {len(_error_pairs)} 个 ERROR (case+combo) 精确对，"
                        f"覆盖 {len(_error_ids)} 个用例{' → ' + _phase_from_case if _phase_from_case else ''}[/yellow]"
                    )
                else:
                    console.print("[green]✅ 最新日志中无 ERROR 用例，无需重跑[/green]")
            else:
                console.print("[red]❌ 未找到历史日志文件，--case all-error 无效[/red]")
            # _combo_filter 在作用域外赋值，传递给 run_campaign
        if not case_filter:
            case_filter = None

    # 确定测试用例文件（datasets/ 目录下）
    DATA_DIR = "datasets"
    json_filename = "test_cases_en.json" if args.lang == "en" else "test_cases_cn.json"
    json_file = os.path.join(DATA_DIR, json_filename)

    # 快捷别名推断阶段
    if _phase_from_case:
        if args.phase != "all" and args.phase != _phase_from_case:
            console.print(f"[yellow]⚠ --phase={args.phase} 与 --case 快捷别名冲突，以快捷别名 {_phase_from_case} 为准[/yellow]")
        args.phase = _phase_from_case

    try:
        if args.orch == "pyrit":
            # 🆕 PyRIT 原生 Orchestrator 路径
            console.print("[bold cyan]🚀 使用 PyRIT 原生调度引擎 (PromptSendingAttack + CrescendoAttack)[/bold cyan]\n"
                          "   [dim]Memory: SQLiteMemory + CentralMemory | "
                          "多轮: CrescendoAttack (原生渐进式越狱)[/dim]")
            if args.auto_gate:
                await _run_phased_campaign_native(json_file, args.concurrent, args.gate_threshold,
                                                   attack_target, scorer_target,
                                                   case_filter=case_filter, exclude_filter=exclude_filter,
                                                   combo_filter=_combo_filter)
            elif args.phase != "all":
                phase_labels = {"probe": "PROBE Recon", "single": "Single-Turn Assault",
                               "crescendo": "Crescendo Siege", "pair": "PAIR Jailbreak",
                               "tap": "TAP Tree Search", "flip": "Flip Attack",
                               "chunked": "Chunked Bypass", "manyshot": "ManyShot Flooding",
                               "skeleton_key": "Skeleton Key",
                               "indirect_inject": "Indirect Inject", "rag_poison": "RAG Poison",
                               "agent_attack": "Agent Attack", "embedding_attack": "Embedding Attack",
                               "sequence_chain": "Sequence Chain",
                               "mcp_security": "MCP Security", "a2a_security": "A2A Security"}
                label = phase_labels[args.phase]
                await _run_campaign_native(
                    json_file=json_file,
                    campaign_name=f"AI-300_{label.replace(' ', '_')}",
                    heatmap_title=f"AI-300 {label} Success Matrix",
                    heatmap_filename=f"ai300_{args.phase}_heatmap.png",
                    max_concurrent=args.concurrent,
                    phase_filter=args.phase,
                    attack_target=attack_target,
                    scorer_target=scorer_target,
                    case_filter=case_filter,
                    exclude_filter=exclude_filter,
                    combo_filter=_combo_filter,
                )
            else:
                await _run_campaign_native(
                    json_file=json_file,
                    campaign_name="AI-300_Full_Campaign",
                    heatmap_title="AI-300 Full Campaign Success Matrix",
                    heatmap_filename="ai300_full_heatmap.png",
                    max_concurrent=args.concurrent,
                    attack_target=attack_target,
                    scorer_target=scorer_target,
                    case_filter=case_filter,
                    exclude_filter=exclude_filter,
                )
        else:
            # 🔙 Legacy 引擎路径
            console.print("[dim]🔙 使用旧版调度引擎 (legacy engines)[/dim]")
            if args.auto_gate:
                await run_phased_campaign(json_file, args.concurrent, args.gate_threshold,
                                           attack_target, scorer_target,
                                           case_filter=case_filter, exclude_filter=exclude_filter,
                                           combo_filter=_combo_filter)
            elif args.phase != "all":
                phase_labels = {"probe": "PROBE Recon", "single": "Single-Turn Assault",
                               "crescendo": "Crescendo Siege", "pair": "PAIR Jailbreak",
                               "tap": "TAP Tree Search", "flip": "Flip Attack",
                               "chunked": "Chunked Bypass", "manyshot": "ManyShot Flooding",
                               "skeleton_key": "Skeleton Key",
                               "indirect_inject": "Indirect Inject", "rag_poison": "RAG Poison",
                               "agent_attack": "Agent Attack", "embedding_attack": "Embedding Attack",
                               "sequence_chain": "Sequence Chain",
                               "mcp_security": "MCP Security", "a2a_security": "A2A Security"}
                label = phase_labels[args.phase]
                await run_campaign(
                    json_file=json_file,
                    campaign_name=f"AI-300_{label.replace(' ', '_')}",
                    heatmap_title=f"AI-300 {label} Success Matrix",
                    heatmap_filename=f"ai300_{args.phase}_heatmap.png",
                    max_concurrent=args.concurrent,
                    phase_filter=args.phase,
                    attack_target=attack_target,
                    scorer_target=scorer_target,
                    case_filter=case_filter,
                    exclude_filter=exclude_filter,
                    combo_filter=_combo_filter,
                )
            else:
                await run_campaign(
                    json_file=json_file,
                    campaign_name="AI-300_Full_Campaign",
                    heatmap_title="AI-300 Full Campaign Success Matrix",
                    heatmap_filename="ai300_full_heatmap.png",
                    max_concurrent=args.concurrent,
                    attack_target=attack_target,
                    scorer_target=scorer_target,
                    case_filter=case_filter,
                    exclude_filter=exclude_filter,
                )
    finally:
        # 清理自定义 Target 的 HTTP session（duck typing：有 close 方法就调用）
        if hasattr(attack_target, 'close') and callable(attack_target.close):
            await attack_target.close()

if __name__ == "__main__":
    asyncio.run(main())
