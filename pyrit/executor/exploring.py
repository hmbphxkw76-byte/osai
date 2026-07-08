"""
===============================================================================
PyRIT Red Team — 探索模板模式引擎（Tech Mode / Exploring Mode）
===============================================================================
从 main.py 提取，遵循单一职责原则。

探索模式 vs 渗透模式:
  - 探索模式：关注"哪个 converter 链绕过了？" → 轻量、快速、converter 排名报告
  - 渗透模式：关注"攻击面覆盖度 + 纵深突破深度" → 多策略、综合 OWASP 报告

流程:
  1. 加载探索模板 YAML
  2. 对每个 prompt × 每个 converter_preset 链，执行 PromptSendingAttack
  3. 生成 converter 有效性排名报告

使用方式:
  from executor.exploring import run_exploring_mode

  await run_exploring_mode(args)
===============================================================================
"""
from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime

import yaml
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table

from pyrit.prompt_target import OpenAIChatTarget
from pyrit.memory import SQLiteMemory, CentralMemory
from pyrit.prompt_normalizer import PromptConverterConfiguration
from pyrit.executor.attack import (
    PromptSendingAttack,
    AttackScoringConfig,
    AttackConverterConfig,
)

from targets import load_env_config, create_scorer_target, create_attack_target, build_custom_target
from targets.auto_probe import auto_probe_target_model, auto_probe_target_type
from converters import resolve_converters
from executor.scorer import create_best_scorer
from utils import DEFAULT_MODEL_NAME, ensure_results_dir, results_path

console = Console()


# ── 模板路径解析工具 ──

def _resolve_template_path(template_arg: str, search_dirs: list[str] | None = None) -> str | None:
    """解析模板文件路径，按优先级依次搜索。"""
    import os
    if os.path.exists(template_arg):
        return template_arg
    for d in (search_dirs or []):
        alt = os.path.join(d, os.path.basename(template_arg) if os.path.sep not in template_arg else template_arg)
        if os.path.exists(alt):
            return alt
    for d in (search_dirs or []):
        alt = os.path.join(d, template_arg)
        if os.path.exists(alt):
            return alt
    return None


# ── Converter 链测试核心 ──

async def _test_one_chain(
    prompt,
    chain_names: list[str],
    chain_label: str,
    attack_target,
    scorer_target,
    semaphore: asyncio.Semaphore,
) -> tuple[str, str, dict]:
    """测试单个 converter 链对单个 prompt 的效果。

    Args:
        prompt: PenetratingPrompt 实例
        chain_names: converter 名称列表
        chain_label: converter 链的人类可读标签
        attack_target: 攻击目标 PromptTarget
        scorer_target: 评分器 PromptTarget
        semaphore: 并发控制信号量

    Returns:
        (prompt_id, chain_label, result_dict)
    """
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


# ── 报告生成 ──

def _build_tech_summary(results: dict[str, dict[str, dict]]) -> dict:
    """构建探索模板结果摘要"""
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
                "chain": name,
                "success_rate": round(stats["success"] / max(stats["total"], 1), 3),
                **stats,
            }
            for name, stats in ranked
        ],
        "best_converter": ranked[0][0] if ranked else "N/A",
        "total_prompts_tested": len(results),
    }


def _print_tech_report(results: dict[str, dict[str, dict]], template, elapsed: float):
    """打印探索模板 converter 有效性报告"""
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
        if rate >= 0.5:
            style_rate = f"[bold green]{rate:.0%}[/bold green]"
        elif rate > 0:
            style_rate = f"[yellow]{rate:.0%}[/yellow]"
        else:
            style_rate = f"[red]{rate:.0%}[/red]"
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


# ── 探索模式主入口 ──

async def run_exploring_mode(args) -> None:
    """探索模板模式入口：快速测试 converter 链对 prompt injection 的突破效果。

    流程:
      1. 加载探索模板 YAML
      2. 对每个 prompt × 每个 converter_preset 链，执行 PromptSendingAttack
      3. 生成 converter 有效性排名报告
    """
    _tech_start = time.time()
    from scenarios.schema import PenetratingPromptSet, PenetratingPrompt

    # ── 1. 加载探索模板 ──
    template_path = _resolve_template_path(
        args.exploring_template,
        search_dirs=["scenarios/templates"],
    )
    if not template_path:
        console.print(f"[bold red]❌ 探索模板文件不存在: {args.exploring_template}[/bold red]")
        console.print(f"   [dim]搜索目录: scenarios/templates/[/dim]")
        return

    console.print(f"[bold cyan]🔧 加载探索模板: {template_path}[/bold cyan]")

    # 解析 YAML — 先原始加载获取 converter_presets，再通过 Pydantic 校验
    with open(template_path, "r", encoding="utf-8") as f:
        raw_data = yaml.safe_load(f)

    raw_config = raw_data.get("config", {})
    converter_presets: list[list[str]] = raw_config.get("converter_presets", [])

    if not converter_presets:
        console.print("[bold red]❌ 探索模板缺少 config.converter_presets 字段[/bold red]")
        console.print('   [dim]converter_presets 格式: [["base64"], ["dan_jailbreak"], ...][/dim]')
        return

    template = PenetratingPromptSet.model_validate(raw_data)

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

        args.target_model, target_reachable = await auto_probe_target_model(
            args, args.target_url, args.target_api_key
        )
        if not target_reachable:
            return

        await auto_probe_target_type(args, args.target_url, args.target_api_key)

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
    db_path = results_path(f"pyrit_redteam_exploring_memory_{ts}.db")
    memory = SQLiteMemory(db_path=db_path)
    CentralMemory.set_memory_instance(memory)

    # ── 4. 并发执行所有 converter 链测试 ──
    max_concurrent = template.config.max_concurrent
    semaphore = asyncio.Semaphore(max_concurrent)

    tech_results: dict[str, dict[str, dict]] = {}
    total_tests = len(template.prompts) * len(converter_presets)
    console.print(f"\n[bold]⚔️ 执行 {total_tests} 次 Converter 链测试 (并发: {max_concurrent})...[/bold]")

    progress = Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
    )
    task_id = progress.add_task("🔬 Converter 链测试中...", total=total_tests)

    coros = []
    for prompt in template.prompts:
        tech_results.setdefault(prompt.id, {})
        for chain in converter_presets:
            chain_label = " + ".join(chain)
            coros.append(_test_one_chain(
                prompt, chain, chain_label,
                attack_target, scorer_target, semaphore,
            ))

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

    # ── 5. 生成 Converter 有效性报告 ──
    elapsed = time.time() - _tech_start
    _print_tech_report(tech_results, template, elapsed)

    # ── 6. 保存结果 ──
    report_file = results_path(f"pyrit_redteam_exploring_report_{ts}.json")
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump({
            "template": template_path,
            "mode": "exploring",
            "timestamp": datetime.now().isoformat(),
            "results": tech_results,
            "converter_presets": converter_presets,
            "summary": _build_tech_summary(tech_results),
        }, f, ensure_ascii=False, indent=2)
    console.print(f"\n[green]✅ 探索模式结果已保存: {report_file}[/green]")

    if hasattr(attack_target, 'close') and callable(attack_target.close):
        await attack_target.close()
