"""命令行交互入口（Typer + Rich）。

AI-300 红队攻击流水线的 CLI 界面。
提供：
  - redteam wizard: 交互式引导
  - redteam run: 非交互式运行
  - redteam recon: 仅侦察
  - redteam inject: 仅提示注入
  - redteam report: 重新生成报告

对齐 OffSec AI-300 8 阶段攻击链：
  recon → injection → agent → rag → embeddings → supply_chain → infra → report
"""
from __future__ import annotations

import sys

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .pipeline import AIPipeline

app = typer.Typer(
    help="RedTeam_AI — AI-300 红队自动化攻击流水线",
    invoke_without_command=True,
)
console = Console()


@app.callback()
def callback() -> None:
    """RedTeam_AI CLI"""


@app.command()
def wizard() -> None:
    """交互式 AI 红队评估向导"""
    console.print(Panel.fit(
        "[bold cyan]RedTeam_AI[/] — AI-300 红队评估向导\n"
        "[dim]基于 OffSec AI-300: Advanced AI Red Teaming[/]\n\n"
        "⚠️  仅用于已授权的安全测试",
        title="AI Red Team Pipeline",
    ))

    target = typer.prompt("\n目标 URL")
    header_file = typer.prompt("F12 请求头文件路径（可留空）", default="")
    header_text = None
    if not header_file:
        header_text = typer.prompt("或直接粘贴请求头文本（可留空）", default="")

    pipe = AIPipeline()

    with console.status("[cyan]Phase 1: AI 攻击面侦察...[/]"):
        run_id, recon, services = pipe.recon_phase(
            target,
            header_text=header_text or None,
            header_file=header_file or None,
        )

    # 展示侦察结果
    table = Table(title="发现的 AI 服务")
    table.add_column("协议", style="cyan")
    table.add_column("URL", style="white")
    table.add_column("模型", style="green")
    table.add_column("认证", style="yellow")
    for svc in services:
        table.add_row(
            svc.protocol.upper(),
            svc.url[:60],
            ", ".join(svc.models[:2]) if svc.models else "-",
            "需要" if svc.auth_required else "不需要",
        )
    console.print(table)

    if not services:
        console.print("[yellow]未发现 AI 服务，尝试推进后续阶段（可能无效果）[/]")

    with console.status("[cyan]Phase 2: 提示注入攻击...[/]"):
        auth = None  # recon_phase 已处理
        inj_findings, chain = pipe.injection_phase(run_id, recon, services)
    console.print(f"[green]✓[/] 注入阶段完成，发现 {len(inj_findings)} 个漏洞")

    with console.status("[cyan]Phase 3: Agent 攻击...[/]"):
        agent_findings = pipe.agent_attack_phase(run_id, services)
    console.print("[green]✓[/] Agent 攻击完成")

    with console.status("[cyan]Phase 4: RAG 攻击...[/]"):
        rag_findings = pipe.rag_attack_phase(run_id, services)
    console.print("[green]✓[/] RAG 攻击完成")

    with console.status("[cyan]Phase 5: 嵌入模型攻击...[/]"):
        emb_findings = pipe.embeddings_attack_phase(run_id, services)
    console.print("[green]✓[/] 嵌入攻击完成")

    with console.status("[cyan]Phase 6: AI 供应链攻击...[/]"):
        sc_findings = pipe.supply_chain_phase(run_id, services)
    console.print("[green]✓[/] 供应链攻击完成")

    with console.status("[cyan]Phase 7: MCP + 基础设施攻击...[/]"):
        infra_findings = pipe.infra_attack_phase(run_id, recon, services)
    console.print("[green]✓[/] 基础设施攻击完成")

    with console.status("[cyan]Phase 8: 威胁建模与报告生成...[/]"):
        report = pipe.report_phase(run_id, recon, infra_findings, chain)
    console.print("[green]✓[/] 报告已生成")

    console.print("\n[bold green]评估完成![/]")
    console.print(f"  Run ID: {run_id}")
    console.print(f"  报告: [cyan]reports/{run_id}/AI300_Report.md[/]")
    console.print(f"  原始数据: reports/{run_id}/")


@app.command()
def run(
    target: str = typer.Option(..., "--target", "-t", help="目标 URL"),
    header_file: str = typer.Option(None, "--header-file", "-H", help="F12 请求头文件路径"),
    header_text: str = typer.Option(None, "--header-text", help="F12 请求头文本"),
    run_id: str = typer.Option(None, "--run-id", help="指定 run_id（续跑）"),
    phase: str = typer.Option(
        "all",
        "--phase", "-p",
        help="指定阶段: all / recon / injection / agent / rag / embeddings / supply_chain / infra / report",
    ),
) -> None:
    """运行 AI 红队评估（非交互式）"""
    pipe = AIPipeline()

    phases: list[str] | None = None
    if phase != "all":
        phase_order = ["recon", "injection", "agent", "rag", "embeddings", "supply_chain", "infra", "report"]
        idx = phase_order.index(phase)
        phases = phase_order[idx:]

    result = pipe.run_all(
        target=target,
        header_text=header_text,
        header_file=header_file,
        run_id=run_id,
        phases=phases,
    )

    findings = result["findings"]
    sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev_count[f.get("severity", "info")] = sev_count.get(f.get("severity", "info"), 0) + 1

    console.print(f"\n[green]done[/] run_id={result['run_id']} "
                  f"findings={len(findings)} "
                  f"duration={result['total_duration_seconds']}s")
    console.print(f"  Critical: {sev_count['critical']} | High: {sev_count['high']} | Medium: {sev_count['medium']}")


@app.command()
def recon(
    target: str = typer.Option(..., "--target", "-t", help="目标 URL"),
    header_file: str = typer.Option(None, "--header-file", "-H"),
    header_text: str = typer.Option(None, "--header-text"),
) -> None:
    """仅执行 AI 攻击面侦察"""
    pipe = AIPipeline()
    run_id, recon, services = pipe.recon_phase(
        target, header_text=header_text, header_file=header_file,
    )
    console.print(f"\n[green]侦察完成[/] Run ID: {run_id}")
    console.print(f"  AI 服务: {len(services)} | 组件: {recon.components} | 模型: {recon.models}")


@app.command()
def inject(
    run_id: str = typer.Argument(..., help="已有侦察的 run_id"),
) -> None:
    """仅执行提示注入攻击（需先完成侦察）"""
    from .core.store import load_json

    recon_data = load_json(run_id, "recon")
    services_data = load_json(run_id, "services")

    if not recon_data or not services_data:
        console.print("[red]错误: 未找到侦察数据，请先运行 recon[/]")
        raise typer.Exit(1)

    from .core.models import ReconResult, AIService
    recon = ReconResult(**recon_data)
    services = [AIService(**s) for s in services_data]

    pipe = AIPipeline()
    findings, chain = pipe.injection_phase(run_id, recon, services)
    console.print(f"\n[green]注入完成[/] 发现 {len(findings)} 个漏洞")


@app.command("report")
def report(run_id: str = typer.Argument(..., help="已有 run_id")) -> None:
    """重新生成报告"""
    pipe = AIPipeline()
    from .core.store import load_json
    recon_data = load_json(run_id, "recon")
    findings_data = load_json(run_id, "findings")
    chain_data = load_json(run_id, "attack_chain_injection")

    from .core.models import ReconResult, Finding, AttackChain
    recon = ReconResult(**recon_data) if recon_data else ReconResult(target="unknown")
    findings = [Finding(**f) if isinstance(f, dict) else f for f in (findings_data or [])]
    chain = AttackChain(**chain_data) if chain_data else None

    report = pipe.report_phase(run_id, recon, findings, chain)
    console.print(f"[green]报告已生成[/] reports/{run_id}/AI300_Report.md")


def main() -> None:
    if len(sys.argv) == 1:
        wizard()
    else:
        app()


if __name__ == "__main__":
    main()
