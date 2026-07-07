"""
===============================================================================
OffSec AI-300 — 终端战报输出
===============================================================================
"""
from rich.console import Console
from rich.panel import Panel

from reporting.engine import build_followup_suggestions

console = Console()


def print_detailed_report(results: list, campaign_name: str = ""):
    """执行后打印详细攻击报告，展示所有发现的漏洞详情。"""
    if not results:
        console.print("[yellow]⚠️ 无结果数据[/yellow]")
        return

    successes = [r for r in results if r.get("status") == "SUCCESS"]
    failures = [r for r in results if r.get("status") == "FAILURE"]
    errors = [r for r in results if r.get("status") == "ERROR"]

    # ── 总体战报 ──
    total = len(results)
    rate = len(successes) / total * 100 if total > 0 else 0
    console.print("=" * 70)
    console.print(Panel(
        f"[bold]📊 {campaign_name}[/bold]  "
        f"总攻击: {total}  |  🎯 成功: [bold green]{len(successes)}[/bold green] ({rate:.1f}%)  |  "
        f"❌ 失败: [bold red]{len(failures)}[/bold red]  |  ⚠️ 错误: [bold yellow]{len(errors)}[/bold yellow]",
        style="bold blue"))

    # ── 漏洞详情 — 按用例分组 ──
    if successes:
        console.print("[bold green]━━ 🔓 发现的漏洞 (SUCCESS) ━━[/bold green]")
        vuln_map: dict[str, list] = {}
        for r in successes:
            vuln_map.setdefault(r["case_id"], []).append(r)

        for idx, (case_id, entries) in enumerate(vuln_map.items(), 1):
            console.print(f"[bold cyan]━━ 漏洞 #{idx}: {case_id} ━━[/bold cyan]")
            console.print(f"  [dim]判定标准: {entries[0].get('criterion', 'N/A')[:200]}[/dim]")

            for entry in entries:
                combo = entry["combo_name"]
                turns = entry.get("turns", 1)
                mode = entry.get("mode", "single")
                turns_label = f"多轮(第{turns}轮突破)" if mode == "crescendo" else "单轮"

                console.print(f"  [bold]🔧 攻击手法: {combo} ({turns_label})[/bold]")

                prompt_text = entry.get("converted_prompt", entry.get("objective", ""))
                prompt_preview = prompt_text[:300].replace("\n", "\\n")
                console.print(f"  [yellow]📤 攻击Prompt:[/yellow] {prompt_preview}...")

                resp_text = entry.get("response_text", "")
                resp_preview = resp_text[:400].replace("\n", "\\n")
                console.print(f"  [magenta]📥 目标响应:[/magenta] {resp_preview}{'...' if len(resp_text) > 400 else ''}")

                score_reason = entry.get("score_reason", "")
                if score_reason:
                    console.print(f"  [dim]📋 评分理由: {score_reason[:200]}[/dim]")
    else:
        console.print("[bold red]⚠ 未发现任何漏洞 — 目标模型安全防御较强[/bold red]")

    # ── 失败统计 ──
    if failures:
        console.print(f"[bold red]━━ 🛡 防御成功的攻击 ({len(failures)} 次) ━━[/bold red]")
        fail_by_case: dict[str, list[str]] = {}
        for r in failures:
            fail_by_case.setdefault(r["case_id"], []).append(r["combo_name"])
        for case_id, combos in sorted(fail_by_case.items()):
            console.print(f"  [red]✗[/red] {case_id}: 被 {len(combos)} 种攻击手法成功防御")

    # ── 下一步攻击命令 ──
    _render_followup_terminal(results)

    console.print("=" * 70)


# ═══════════════════════════════════════════════════════════════════
# 终端版后续攻击命令渲染
# ═══════════════════════════════════════════════════════════════════

def _render_followup_terminal(results: list):
    """终端输出：基于引擎推荐数据渲染 Rich 格式的下一步攻击命令。"""
    suggestions = build_followup_suggestions(results)
    if suggestions is None:
        return

    console.print("\n" * 3)
    console.print("[bold cyan]━━ 🚀 下一步攻击命令 (基于已发现的漏洞自动生成) ━━[/bold cyan]")
    console.print("  [dim]以下命令可按编号复制到终端执行[/dim]")
    cmd_counter = 0

    # ═══ PART 1: PROBE 漏洞 → 预定义映射 ═══
    for probe_idx, pf in enumerate(suggestions["probe_followups"], 1):
        console.print(f"  [bold white]📌 PROBE-{probe_idx}: {pf['probe_id']} — {pf['title']}[/bold white]")
        console.print(f"     [dim]突破口: {', '.join(pf['combos'])} {pf['breakthrough'][:120]}[/dim]")
        for desc, case_ids in pf.get("single", []):
            cmd_counter += 1
            console.print(f"     [bold green]第 {cmd_counter} 条[/bold green]: [yellow]{desc}[/yellow]")
            console.print(f"       [bold]python main.py --lang cn --phase single --case {case_ids}[/bold]")
        for desc, case_ids in pf.get("probe", []):
            cmd_counter += 1
            console.print(f"     [bold green]第 {cmd_counter} 条[/bold green]: [yellow]{desc}[/yellow]")
            console.print(f"       [bold]python main.py --lang cn --phase probe --case {case_ids}[/bold]")
        for desc, case_ids in pf.get("crescendo", []):
            cmd_counter += 1
            console.print(f"     [bold green]第 {cmd_counter} 条[/bold green]: [yellow]{desc}[/yellow]")
            console.print(f"       [bold]python main.py --lang cn --phase crescendo --case {case_ids}[/bold]")

    # ═══ PART 2: 单轮突破 — 按攻击手法×领域精准扩散 ═══
    if suggestions["single_diffusions"]:
        console.print("  [bold white]📌 单轮突破 — 按攻击手法 × 领域精准推荐[/bold white]")
        for sd in suggestions["single_diffusions"]:
            console.print(f"     [dim]攻击手法: [bold]{sd['combo']}[/bold][/dim]")
            for entry in sd["entries"]:
                cmd_counter += 1
                console.print(f"     [bold green]第 {cmd_counter} 条[/bold green]: [yellow]用 {sd['combo']} 横扫「{entry['category']}」类其他用例[/yellow]")
                console.print(f"       [bold]python main.py --lang cn --phase single --case {','.join(entry['other_ids'])}[/bold]")

    # ═══ PART 3: 多轮突破 — 按攻击手法×领域精准扩散 ═══
    if suggestions["cresc_diffusions"]:
        console.print("  [bold white]📌 多轮突破 — 按攻击手法 × 领域精准推荐[/bold white]")
        for cd in suggestions["cresc_diffusions"]:
            console.print(f"     [dim]攻击手法: [bold]{cd['combo']}[/bold][/dim]")
            for entry in cd["entries"]:
                cmd_counter += 1
                console.print(f"     [bold green]第 {cmd_counter} 条[/bold green]: [yellow]用 {cd['combo']} 横扫「{entry['category']}」类其他用例[/yellow]")
                console.print(f"       [bold]python main.py --lang cn --phase crescendo --case {','.join(entry['other_ids'])}[/bold]")

    # ═══ 最快聚合路径 ═══
    merged_s = suggestions["merged_single_ids"]
    merged_c = suggestions["merged_crescendo_ids"]

    console.print("  [bold cyan]⚡ 最快路径 — 一键覆盖全部攻击面:[/bold cyan]")
    if merged_s:
        console.print("     [bold green]第 1 条[/bold green]: 集合所有推荐单轮用例")
        console.print("       [bold]python main.py --lang cn --case all-single[/bold]")
    if merged_c:
        console.print("     [bold green]第 2 条[/bold green]: 集合所有推荐多轮用例")
        console.print("       [bold]python main.py --lang cn --case all-crescendo[/bold]")
    console.print("     [bold green]第 3 条[/bold green]: 全自动门控阶梯式攻击")
    console.print("       [bold]python main.py --lang cn --auto-gate --gate-threshold 0.10 --concurrent 3[/bold]")
