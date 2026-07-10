"""
===============================================================================
RedTeam_AI Pipeline — 阶段专家指导 (Expert Guidance)
===============================================================================

每阶段完成后自动生成:
  ✓ 阶段总结 (关键发现)
  ✓ 操作建议 (下一步推荐)
  ✓ 可执行命令 (复制粘贴运行)
  ✓ 风险提示 (注意事项)
"""
from __future__ import annotations

from typing import Optional

from rich.panel import Panel

from pipeline.models import (
    GARAK_PROBES_INFO,
    STAGE_LABELS,
    PipelineStage,
    PipelineState,
    console,
)


# ═══════════════════════════════════════════════════════════════════════
# 阶段专家指导调度器
# ═══════════════════════════════════════════════════════════════════════

def print_expert_guidance(
    stage: PipelineStage,
    state: PipelineState,
    extra: Optional[dict] = None,
):
    """输出阶段间专家指导 (Expert Guidance)。

    每个阶段完成后自动生成:
      - 阶段总结 (关键发现)
      - 专家建议 (下一步推荐)
      - 可执行命令
      - 风险提示
    """
    ctx = {**(extra or {}), "target_url": state.target_url}

    guidelines = {
        PipelineStage.RECON: _guidance_recon,
        PipelineStage.GARAK: _guidance_garak,
        PipelineStage.BRIDGE: _guidance_bridge,
        PipelineStage.PROMPTFOO: _guidance_promptfoo,
        PipelineStage.PYRIT: _guidance_pyrit,
        PipelineStage.REPORT: _guidance_report,
    }

    guidance_fn = guidelines.get(stage)
    if not guidance_fn:
        return

    lines = guidance_fn(state, ctx)

    console.print()
    console.print(Panel(
        "\n".join(lines),
        title=f"[bold cyan]🎓 阶段专家指导: {STAGE_LABELS[stage][:40]}[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    ))


# ═══════════════════════════════════════════════════════════════════════
# L0: 前置侦察 → L1: Garak
# ═══════════════════════════════════════════════════════════════════════

def _guidance_recon(state: PipelineState, ctx: dict) -> list[str]:
    profile = state.profile_data
    lines = []

    # 总结
    endpoints = len(profile.get("api_endpoints", []))
    model = profile.get("target", {}).get("model", "unknown")
    auth = profile.get("auth", {}).get("type", "none")
    has_waf = bool(profile.get("defense", {}).get("waf"))

    lines.append("[bold green]📋 阶段总结[/bold green]")
    lines.append(f"  完成对 [bold]{state.target_url}[/bold] 的前置侦察。")
    lines.append(f"  • 发现 [bold cyan]{endpoints}[/bold cyan] 个 API 端点")
    lines.append(f"  • 认证方式: [bold yellow]{auth}[/bold yellow]")
    lines.append(f"  • 识别模型: [bold cyan]{model}[/bold cyan]")
    lines.append(f"  • WAF 防护: {'[red]检测到[/red]' if has_waf else '[green]未检测到[/green]'}")
    lines.append("")

    # 建议
    lines.append("[bold cyan]💡 专家建议[/bold cyan]")
    lines.append(f"  1. 已获取认证信息，准备进入 Garak 模型侦查阶段")
    lines.append(f"  2. 推荐打法: 先基线扫描(6类探针全覆盖)，再定向深度验证")
    lines.append(f"  3. Garak 将覆盖 promptinject/jailbreak/encoding/leakage/toxicity/hallucination")
    lines.append(f"  4. 建议先用基线模式快速了解模型防护水平 (~2分钟)")
    lines.append("")

    # 命令
    lines.append("[bold yellow]⚡ 推荐命令 (可直接复制执行)[/bold yellow]")
    lines.append(f"  [white]python main.py --target {state.target_url} --stage garak[/white]")
    lines.append(f"  [white]python main.py --target {state.target_url} --mode auto[/white]")
    lines.append("")

    # 警告
    lines.append("[bold red]⚠️ 注意事项[/bold red]")
    lines.append("  • 如使用自签证书，请确保环境变量 SSL_CERT_FILE 已设置")
    lines.append("  • Ollama 本地模型请降低并发数防止 GPU OOM")
    lines.append("")

    # 下一步
    lines.append("[bold magenta]➡️ 下一阶段: L1 — AI模型侦查 (Garak 6类探针扫描)[/bold magenta]")

    # 阶段间指导: recon → garak
    lines.append("")
    lines.append("[bold white]🔗 阶段间操作指导 (Recon → Garak):[/bold white]")
    lines.append("  • 确保 target_profile.json 中的 API 端点/认证信息完整")
    lines.append("  • Garak 使用 OpenAPI 兼容接口，请确认目标 API endpoint 格式")
    lines.append("  • 如目标有 API Key，在 Garak 执行前设置环境变量 OPENAI_API_KEY")
    lines.append("  • 先执行基线模式 (baseline)，再按探测失败情况选择深度模式 (deep)")

    return lines


# ═══════════════════════════════════════════════════════════════════════
# L1: Garak → L2: Bridge
# ═══════════════════════════════════════════════════════════════════════

def _guidance_garak(state: PipelineState, ctx: dict) -> list[str]:
    profile = state.garak_profile
    lines = []

    total = profile.get("total_probes", 0)
    failed = profile.get("failed_probes", 0)
    passed = total - failed - profile.get("error_probes", 0)
    results = profile.get("results", [])

    # 统计各风险类别
    failed_cats: dict[str, int] = {}
    for r in results:
        if r.get("status") == "fail":
            probe_name = r.get("probe_name", "")
            cat = probe_name.split(".")[0].lower() if "." in probe_name else "unknown"
            failed_cats[cat] = failed_cats.get(cat, 0) + 1

    lines.append("[bold green]📋 阶段总结[/bold green]")
    lines.append(f"  Garak 模型侦查完成。")
    lines.append(f"  • 总探测: [bold cyan]{total}[/bold cyan] | 通过: [green]{passed}[/green] | 失败: [red]{failed}[/red]")
    if failed_cats:
        lines.append("  • 失败探测按类别分布:")
        for cat, count in sorted(failed_cats.items(), key=lambda x: -x[1]):
            info = GARAK_PROBES_INFO.get(cat, {})
            desc = info.get("desc", cat)
            sev = info.get("severity", "medium")
            sev_style = {"critical": "[red]", "high": "[red]", "medium": "[yellow]", "low": "[dim]"}.get(sev, "")
            lines.append(f"      {sev_style}{cat}[/] ({desc}): {count} 失败")
    lines.append("")

    # 建议
    lines.append("[bold cyan]💡 专家建议[/bold cyan]")
    if failed > 0:
        lines.append(f"  1. 发现 [red]{failed}[/red] 个探测失败 — 这些将成为后续攻击的种子")
        lines.append(f"  2. 下一步进入 Bridge 桥接层: 将 Garak 结果映射为攻击种子")
        lines.append(f"  3. Bridge 将自动标注风险类别、严重度、攻击向量、OWASP 映射")
    else:
        lines.append(f"  1. 所有探测均通过 — 目标可能较安全，可尝试深度扫描")
        lines.append(f"  2. 建议使用 [white]--garak-mode deep[/white] 进行定向深度验证")
    lines.append("")

    # 阶段间指导: garak → bridge
    lines.append("[bold white]🔗 阶段间操作指导 (Garak → Bridge):[/bold white]")
    lines.append("  • Garak 输出的 JSONL 文件将自动被 Bridge 解析")
    lines.append("  • Bridge 将 handle: 解析JSONL→过滤pass/低价值→标注风险类别→OWASP映射→Seeds JSON")
    lines.append("  • 输出的 seeds_attack.json 含完整标注，可供 promptfoo 模板和 PyRIT 攻击使用")
    lines.append("  • 同时导出 seeds_promptfoo.yaml 模板配置")

    # 命令
    lines.append("")
    lines.append("[bold yellow]⚡ 推荐命令[/bold yellow]")
    lines.append(f"  [white]python main.py --target {state.target_url} --stage bridge[/white]")
    lines.append(f"  [white]python main.py --target {state.target_url} --mode auto[/white]")

    # 下一步
    lines.append("")
    lines.append("[bold magenta]➡️ 下一阶段: L2 — 桥接映射 (Garak JSONL→Seeds JSON)[/bold magenta]")

    return lines


# ═══════════════════════════════════════════════════════════════════════
# L2: Bridge → L3/L4
# ═══════════════════════════════════════════════════════════════════════

def _guidance_bridge(state: PipelineState, ctx: dict) -> list[str]:
    seeds = state.seeds_data
    lines = []

    total = seeds.get("total_seeds", 0)
    summary = seeds.get("summary", {})
    seeds_by_cat = seeds.get("seeds_by_category", {})

    lines.append("[bold green]📋 阶段总结[/bold green]")
    lines.append(f"  Bridge 桥接映射完成。")
    lines.append(f"  • 生成攻击种子: [bold cyan]{total}[/bold cyan] 个")
    lines.append(f"  • 严重度分布: CRIT [red]{summary.get('critical', 0)}[/red] | "
                 f"HIGH [red]{summary.get('high', 0)}[/red] | "
                 f"MED [yellow]{summary.get('medium', 0)}[/yellow] | "
                 f"LOW [dim]{summary.get('low', 0)}[/dim]")
    if seeds_by_cat:
        lines.append("  • 风险类别分布:")
        for cat, items in seeds_by_cat.items():
            lines.append(f"      {cat}: {len(items)} 个种子")
    lines.append(f"  • Seeds JSON: [dim]{state.seeds_path}[/dim]")
    lines.append("")

    # 阶段间指导: bridge → promptfoo
    lines.append("[bold white]🔗 阶段间操作指导 (Bridge → Promptfoo → PyRIT):[/bold white]")
    lines.append("  如需使用 promptfoo 管理提示词模板 (推荐):")
    lines.append(f"  [white]python main.py --target {state.target_url} --stage promptfoo[/white]")
    lines.append("")
    lines.append("  或直接进入 PyRIT 深度攻击:")
    lines.append(f"  [white]python main.py --target {state.target_url} --stage pyrit[/white]")

    # 建议
    lines.append("")
    lines.append("[bold cyan]💡 专家建议[/bold cyan]")
    lines.append(" 1. promptfoo 可为每个种子构建 YAML 模板(含断言规则、变量插值)")
    lines.append(" 2. PyRIT 利用种子进行深度攻击: Crescendo 多轮/编码绕过/自适应LLM生成")
    lines.append(" 3. 两种模式可并行: promptfoo管理模板 + PyRIT执行攻击")
    lines.append("")

    lines.append("[bold magenta]➡️ 下一阶段: L3 — Promptfoo模板 或 L4 — PyRIT深度攻击[/bold magenta]")

    return lines


# ═══════════════════════════════════════════════════════════════════════
# L3: Promptfoo → L4: PyRIT
# ═══════════════════════════════════════════════════════════════════════

def _guidance_promptfoo(state: PipelineState, ctx: dict) -> list[str]:
    lines = []

    lines.append("[bold green]📋 阶段总结[/bold green]")
    lines.append(f"  Promptfoo 提示词模板构建完成。")
    if state.promptfoo_config_path:
        lines.append(f"  • 模板配置: [dim]{state.promptfoo_config_path}[/dim]")
    lines.append("  • 已生成带断言规则的 YAML 配置模板")
    lines.append("  • 模板支持变量插值 + 多场景配置")
    lines.append("")

    # 阶段间指导: promptfoo → pyrit
    lines.append("[bold white]🔗 阶段间操作指导 (Promptfoo → PyRIT):[/bold white]")
    lines.append("  • Promptfoo 模板将被注入到 PyRIT 攻击管线中")
    lines.append("  • PyRIT 将使用模板作为攻击载荷来源 (promptfoo 模板驱动攻击)")
    lines.append("  • PyRIT 的攻击策略包括:")
    lines.append("      - Crescendo: 逐步升级的多轮越狱攻击")
    lines.append("      - 编码绕过: Base64/Flip/Morse/Rot13 载荷变形")
    lines.append("      - 自适应攻击: 根据模型响应动态调整策略")
    lines.append("      - ASR 量化: 攻击成功率自动计算")

    lines.append("")
    lines.append("[bold yellow]⚡ 推荐命令[/bold yellow]")
    lines.append(f"  [white]python main.py --target {state.target_url} --stage pyrit[/white]")

    lines.append("")
    lines.append("[bold magenta]➡️ 下一阶段: L4 — PyRIT 深度攻击[/bold magenta]")

    return lines


# ═══════════════════════════════════════════════════════════════════════
# L4: PyRIT → L5: Report
# ═══════════════════════════════════════════════════════════════════════

def _guidance_pyrit(state: PipelineState, ctx: dict) -> list[str]:
    results = state.attack_results
    lines = []

    total = results.get("total_attacks", 0)
    successes = results.get("successes", 0)
    asr = results.get("asr_score", 0)

    lines.append("[bold green]📋 阶段总结[/bold green]")
    lines.append(f"  PyRIT 深度攻击完成。")
    lines.append(f"  • 总攻击: [bold cyan]{total}[/bold cyan] | 成功: [red]{successes}[/red] | "
                 f"ASR: [bold]{asr:.1%}[/bold]")
    lines.append("")

    # 评估 ASR
    if asr >= 0.7:
        lines.append("  [bold red]⚠️ 攻击成功率极高 (ASR ≥ 70%) — 目标系统防护严重不足![/bold red]")
    elif asr >= 0.3:
        lines.append("  [yellow]⚠️ 攻击成功率中等 — 目标有一定防护但仍存在漏洞[/yellow]")
    else:
        lines.append("  [green]攻击成功率较低 — 目标系统防护较完善[/green]")
    lines.append("")

    # 阶段间指导: pyrit → report
    lines.append("[bold white]🔗 阶段间操作指导 (PyRIT → Report):[/bold white]")
    lines.append("  • 攻击证据、GarAK ASR、promptfoo 断言结果将汇总到统一报告")
    lines.append("  • 报告格式: OffSec 风格渗透测试报告")
    lines.append("  • 包含: 执行摘要、方法论、漏洞详情矩阵、OWASP双映射、MITRE ATLAS映射、修复建议")

    lines.append("")
    lines.append("[bold yellow]⚡ 推荐命令[/bold yellow]")
    lines.append(f"  [white]python main.py --target {state.target_url} --stage report[/white]")

    lines.append("")
    lines.append("[bold magenta]➡️ 下一阶段: L5 — 统一报告生成 (OffSec 规范)[/bold magenta]")

    return lines


# ═══════════════════════════════════════════════════════════════════════
# L5: Report — 终局
# ═══════════════════════════════════════════════════════════════════════

def _guidance_report(state: PipelineState, ctx: dict) -> list[str]:
    lines = []

    lines.append("[bold green]📋 阶段总结[/bold green]")
    lines.append(f"  全流程 AI 红队测试完成！")
    lines.append(f"  报告已生成: [dim]{state.report_path or 'outputs/reports/'}[/dim]")
    lines.append("")

    lines.append("[bold cyan]💡 报告内容[/bold cyan]")
    lines.append("  1. 执行摘要 (Executive Summary)")
    lines.append("  2. 方法论 (Methodology) — 六阶段攻击流程")
    lines.append("  3. 漏洞详情矩阵 — 含OWASP LLM + Agentic 双映射")
    lines.append("  4. MITRE ATLAS 技战术映射")
    lines.append("  5. 修复建议矩阵 (按优先级排序)")
    lines.append("  6. 可复现配置包")
    lines.append("")

    lines.append("[bold green]🎯 全流程管道执行完毕。报告标记: TLP:AMBER — 仅供授权人员内部使用。[/bold green]")

    return lines
