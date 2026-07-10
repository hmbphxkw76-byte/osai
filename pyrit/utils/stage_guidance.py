"""
===============================================================================
阶段间专家指导引擎 — 六阶段全生命周期攻击导航
===============================================================================
职责:
  - 每个阶段完成后，基于当前结果动态生成下一步专家建议
  - 提供可直接复制粘贴的 CLI 命令
  - 风险评级驱动的工作流推荐
  - 数据驱动（基于 attack_surface_report / garak_results / 攻击成功率）

指导输出格式:
  1. 阶段总结（当前阶段的关键发现）
  2. 专家建议（文本形式的操作建议）
  3. 推荐命令（可直接执行的 CLI 命令）
  4. 风险提示（需要注意的事项）

使用方式:
  from utils.stage_guidance import generate_guidance

  guidance = generate_guidance(stage="recon", context={"profile": {...}})
  console.print(guidance.render())
===============================================================================
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

console = Console()


# ═══════════════════════════════════════════════════════════════════════
# 数据模型
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class GuidanceBlock:
    """单条专家指导块。"""
    summary: str = ""                     # 阶段总结
    advice: list[str] = field(default_factory=list)  # 专家建议
    commands: list[str] = field(default_factory=list)  # 推荐命令
    warnings: list[str] = field(default_factory=list)  # 注意事项
    next_stage: str = ""                  # 下一阶段名称


@dataclass
class StageGuidance:
    """完整的阶段指导。"""
    stage_name: str
    stage_number: int
    block: GuidanceBlock = field(default_factory=GuidanceBlock)

    def render(self) -> Panel:
        """渲染为 Rich Panel。"""
        lines = []

        # 总结
        if self.block.summary:
            lines.append(f"[bold green]📋 阶段总结[/bold green]")
            lines.append(f"  {self.block.summary}")

        # 建议
        if self.block.advice:
            lines.append(f"\n[bold cyan]💡 专家建议[/bold cyan]")
            for i, a in enumerate(self.block.advice, 1):
                lines.append(f"  {i}. {a}")

        # 命令
        if self.block.commands:
            lines.append(f"\n[bold yellow]⚡ 推荐命令（可直接复制执行）[/bold yellow]")
            for cmd in self.block.commands:
                lines.append(f"  [dim]$[/dim] [white]{cmd}[/white]")

        # 警告
        if self.block.warnings:
            lines.append(f"\n[bold red]⚠️ 注意事项[/bold red]")
            for w in self.block.warnings:
                lines.append(f"  • {w}")

        # 下一步
        if self.block.next_stage:
            lines.append(f"\n[bold magenta]➡️ 下一步: {self.block.next_stage}[/bold magenta]")

        return Panel(
            "\n".join(lines),
            title=f"[bold]{self.stage_name}[/bold]",
            border_style="cyan",
            padding=(1, 2),
        )


# ═══════════════════════════════════════════════════════════════════════
# 六阶段指导生成器
# ═══════════════════════════════════════════════════════════════════════

def generate_guidance(stage: str, context: Optional[dict] = None) -> StageGuidance:
    """根据阶段名称和上下文生成阶段指导。

    Args:
        stage: 阶段标识 ("recon", "ai_detect", "attack_surface", "risk_select", "attack", "report")
        context: 阶段上下文数据 (profile, findings, results 等)

    Returns:
        StageGuidance 对象，可通过 .render() 输出 Rich Panel
    """
    context = context or {}
    generators = {
        "recon": _guidance_recon,
        "ai_detect": _guidance_ai_detect,
        "attack_surface": _guidance_attack_surface,
        "risk_select": _guidance_risk_select,
        "attack": _guidance_attack,
        "report": _guidance_report,
    }
    generator = generators.get(stage, _guidance_default)
    return generator(context)


# ── Stage 0: 侦察 ──

def _guidance_recon(ctx: dict) -> StageGuidance:
    profile = ctx.get("profile", {})
    target_url = ctx.get("target_url", "")

    # 分析侦察结果
    endpoints_count = len(profile.get("api_endpoints", []))
    auth_type = profile.get("auth", {}).get("type", "none")
    has_jwt = bool(profile.get("auth", {}).get("jwt_token"))
    has_api_key = bool(profile.get("auth", {}).get("api_key"))
    model = profile.get("target", {}).get("model", "unknown")
    has_waf = bool(profile.get("defense", {}).get("waf", False))

    summary = (
        f"完成对 {target_url} 的前置侦察。\n"
        f"  • 发现 {endpoints_count} 个 API 端点\n"
        f"  • 认证方式: {auth_type}\n"
        f"  • 识别模型: {model}\n"
        f"  • WAF 检测: {'已部署' if has_waf else '未检测到'}"
    )

    advice = [
        f"已获取 {'JWT Token' if has_jwt else '无 JWT'}, {'API Key' if has_api_key else '无 API Key'} — 请在后续阶段注入认证信息",
        "建议下一步执行 AI 场景探测（RAG/Agent 检测）并启动 Garak 基线扫描",
        "如果有账户登录后的业务页面，请先通过 Web UI 完成浏览器登录获取完整 Cookie",
    ]

    commands = [
        f"# 执行 AI 场景探测 + Garak 基线扫描",
        f"cd pyrit/",
        f"python main.py --target-url {target_url} --garak-mode baseline --recon-profile ../ai-recon/outputs/target_profile_*.json",
        f"",
        f"# 或通过全流程管道一键执行",
        f'python -m orchestrators.full_pipeline --target-url {target_url} --stage ai_detect',
    ]

    warnings = [
        "如目标使用自签证书，请添加 --ssl-skip 参数",
        "Ollama 本地模型请设置 --concurrent 1 防止 GPU OOM",
        "确认 target_profile.json 中的认证信息已正确提取后再进行攻击",
    ]

    return StageGuidance(
        stage_name="第零层: 前置侦察 (Recon)",
        stage_number=0,
        block=GuidanceBlock(
            summary=summary,
            advice=advice,
            commands=[" \\\n  ".join(commands)] if len(commands) > 2 else commands,
            warnings=warnings,
            next_stage="第一层: AI 安全侦查 (Garak)",
        ),
    )


# ── Stage 1: AI 场景探测 ──

def _guidance_ai_detect(ctx: dict) -> StageGuidance:
    ai_profile = ctx.get("ai_profile", {})
    target_type = ctx.get("target_type", "unknown")
    garak_results = ctx.get("garak_results", {})
    total_probes = garak_results.get("total_probes", 0)
    failed_probes = garak_results.get("failed_probes", 0)

    summary = (
        f"AI 场景探测完成。\n"
        f"  • 目标架构: {target_type}\n"
        f"  • Garak 扫描: {total_probes} 探测, {failed_probes} 失败"
    )

    # 根据目标类型给出不同建议
    if target_type == "rag":
        advice = [
            "检测到 RAG (检索增强生成) 系统 — 重点关注检索注入和文档投毒攻击",
            "建议使用 Promptfoo 管理 RAG 专用提示词，然后由 PyRIT 执行攻击",
            "Garak 扫描结果中失败的探测项应作为下一步攻击面的重点",
        ]
        commands = [
            "# 构建攻击面分析报告 (包含 OWASP 映射)",
            f"python -m orchestrators.full_pipeline --stage attack_surface --target-type rag",
        ]
    elif target_type == "agent":
        advice = [
            "检测到 Agent 智能体系统 — 重点关注工具滥用、自主行为、通信劫持",
            "如为多 Agent 系统，还需要执行 L4 多 Agent 攻击模块",
            "建议对 Agent 暴露的工具逐一进行安全性评估",
        ]
        commands = [
            "# 构建攻击面分析 + Agent 专项分析",
            f"python -m orchestrators.full_pipeline --stage attack_surface --target-type agent",
        ]
    else:
        advice = [
            "目标为基础 LLM 系统 — 重点执行直接提示注入和越狱攻击",
            "建议先执行快速基线扫描了解防护水平，再定向深度攻击",
            "可立即进入攻击面分析阶段，生成 OWASP 风险映射",
        ]
        commands = [
            "# 构建攻击面分析报告",
            f"python -m orchestrators.full_pipeline --stage attack_surface",
        ]

    warnings = [
        "Garak 扫描可能需要较长时间（深度模式约 10-30 分钟）",
        "如 Garak 未安装: pip install garak",
    ]

    return StageGuidance(
        stage_name="第一层: AI 安全侦查 (Garak)",
        stage_number=1,
        block=GuidanceBlock(
            summary=summary,
            advice=advice,
            commands=commands,
            warnings=warnings,
            next_stage="第三层: 攻击面分析 (OWASP 映射)",
        ),
    )


# ── Stage 2: 攻击面分析 ──

def _guidance_attack_surface(ctx: dict) -> StageGuidance:
    report = ctx.get("attack_surface", {})
    critical = report.get("critical_count", 0)
    high = report.get("high_count", 0)
    medium = report.get("medium_count", 0)
    total = report.get("total_findings", 0)

    summary = (
        f"攻击面分析完成。\n"
        f"  • 总计 {total} 个漏洞发现\n"
        f"  • CRITICAL: {critical} | HIGH: {high} | MEDIUM: {medium}\n"
        f"  • OWASP LLM Top 10 + OWASP Agentic Top 10 双映射已生成"
    )

    advice = [
        f"发现 {critical + high} 个高风险漏洞 — 强烈建议立即进入深度攻击阶段",
        "可选择按风险等级筛选攻击目标: --min-risk high（仅攻击 HIGH 及以上风险）",
        "攻击前建议先用 Promptfoo 管理提示词，提升攻击载荷质量",
        '已自动生成攻击路线图（见 attack_surface.json → "attack_paths"）',
    ]

    commands = [
        "# 筛选 HIGH 及以上风险，进入攻击准备",
        "python -m orchestrators.full_pipeline --stage risk_select --min-risk high",
        "",
        "# 或直接攻击所有 HIGH+ 风险",
        "python -m orchestrators.full_pipeline --stage attack --min-risk high --use-promptfoo",
    ]

    warnings = [
        "CRITICAL 风险可能对目标系统造成实际影响，请确保在授权环境执行",
        "攻击前确认目标速率限制设置正确 (--concurrent, --rate-limit)",
        "如使用 Promptfoo，确保已安装: npm install -g promptfoo",
    ]

    return StageGuidance(
        stage_name="攻击面分析 (OWASP 双映射)",
        stage_number=2,
        block=GuidanceBlock(
            summary=summary,
            advice=advice,
            commands=commands,
            warnings=warnings,
            next_stage="第四层: 风险筛选 + 攻击执行 (PyRIT)",
        ),
    )


# ── Stage 3: 风险选择 ──

def _guidance_risk_select(ctx: dict) -> StageGuidance:
    selected = ctx.get("selected_findings", [])
    prompt_needed = ctx.get("prompt_needed_count", 0)
    direct_attack = ctx.get("direct_attack_count", 0)

    summary = (
        f"风险筛选完成。\n"
        f"  • 选中 {len(selected)} 个漏洞进行深度攻击\n"
        f"  • 需要提示词管理: {prompt_needed} 个 → Promptfoo\n"
        f"  • 可直接攻击: {direct_attack} 个 → PyRIT 直接攻击"
    )

    advice = []
    commands = []

    if prompt_needed > 0 and direct_attack > 0:
        advice = [
            f"{prompt_needed} 个漏洞需要提示词优化 — 先用 Promptfoo 管理，再交给 PyRIT",
            f"{direct_attack} 个漏洞可直接攻击 — PyRIT 可立即开始",
            "建议分两路并行: Promptfoo 管理提示词 + PyRIT 直接攻击",
        ]
        commands = [
            "# 并行执行: Promptfoo 提示词管理 + PyRIT 直接攻击",
            "python -m orchestrators.full_pipeline --stage attack --attack-mode parallel",
        ]
    elif prompt_needed > 0:
        advice = [
            f"所有 {prompt_needed} 个漏洞需要提示词管理",
            "先将提示词导入 Promptfoo 进行优化评估，再交由 PyRIT 攻击",
            "推荐使用 Promptfoo Manager 自动筛选最优载荷",
        ]
        commands = [
            "# 先管理提示词",
            "python -m executor.promptfoo_manager --filter-high-risk --export",
            "# 然后用优化后的提示词执行 PyRIT 攻击",
            "python -m orchestrators.full_pipeline --stage attack --use-promptfoo",
        ]
    else:
        advice = [
            f"所有 {direct_attack} 个漏洞可直接攻击 — PyRIT 全自动执行",
            "建议启用 --auto-gate 门控机制自动筛选有效载荷",
        ]
        commands = [
            "# PyRIT 直接攻击",
            "python -m orchestrators.full_pipeline --stage attack --auto-gate",
        ]

    warnings = [
        "使用 Promptfoo 管理提示词时，确保已配置评分器 (SCORER_PLATFORM_SELECTOR)",
        "如目标有速率限制，请设置 --rate-limit 和 --concurrent 参数",
    ]

    return StageGuidance(
        stage_name="风险筛选 (Risk Selection)",
        stage_number=3,
        block=GuidanceBlock(
            summary=summary,
            advice=advice,
            commands=commands,
            warnings=warnings,
            next_stage="第五层: 攻击执行 (PyRIT + Promptfoo)",
        ),
    )


# ── Stage 4: 攻击执行 ──

def _guidance_attack(ctx: dict) -> StageGuidance:
    results = ctx.get("attack_results", {})
    total_attacks = results.get("total_attacks", 0)
    successes = results.get("successes", 0)
    asr = results.get("asr_score", 0.0)
    promptfoo_used = ctx.get("promptfoo_used", False)

    summary = (
        f"攻击执行完成。\n"
        f"  • 总攻击: {total_attacks} | 成功: {successes} | ASR: {asr:.1%}\n"
        f"  • 使用 Promptfoo: {'是' if promptfoo_used else '否（直接攻击）'}"
    )

    advice = [
        f"ASR = {asr:.1%} — {'需要进一步优化攻击策略' if asr < 0.3 else '攻击效果良好' if asr < 0.7 else '目标防护较弱，建议提级处理'}",
        "将攻击结果写入 Neo4j 图数据库，构建完整攻击图",
        "生成 OffSec 风格 AI 红队报告",
    ]

    commands = [
        "# 写入 Neo4j + 生成报告",
        "python -m orchestrators.full_pipeline --stage report --export-neo4j --export-json",
        "",
        "# 查看 Neo4j 攻击图",
        "# 打开浏览器访问 http://localhost:7474 (Neo4j Browser)",
        "# 执行查询: MATCH (t:Target)-[*]->(a:AttackResult) RETURN t, a",
    ]

    warnings = [
        "Neo4j 需要运行中: docker run -p 7474:7474 -p 7687:7687 neo4j:latest",
        "如不使用 Neo4j，攻击数据仍会以 JSON 格式保存在 outputs/ 目录",
    ]

    return StageGuidance(
        stage_name="攻击执行 (PyRIT + Promptfoo)",
        stage_number=4,
        block=GuidanceBlock(
            summary=summary,
            advice=advice,
            commands=commands,
            warnings=warnings,
            next_stage="第六层: 数据入库 + 报告生成",
        ),
    )


# ── Stage 5: 报告生成 ──

def _guidance_report(ctx: dict) -> StageGuidance:
    report_path = ctx.get("report_path", "")
    neo4j_exported = ctx.get("neo4j_exported", False)
    json_exported = ctx.get("json_exported", False)

    summary = (
        f"管道执行完毕。\n"
        f"  • Neo4j 入库: {'✅' if neo4j_exported else '❌ (使用 JSON 备份)'}\n"
        f"  • JSON 导出: {'✅' if json_exported else '❌'}\n"
        f"  • 报告路径: {report_path or 'auto-generated'}"
    )

    advice = [
        "报告包含: 执行摘要、方法论、漏洞详情、OWASP 双映射、修复建议矩阵",
        "MITRE ATLAS 技战术映射已自动标注",
        "建议将报告与攻击图（Neo4j）一起存档，作为合规审计证据",
        "可复现测试配置已保存 — 下次可直接复用",
    ]

    commands = [
        f"# 查看报告",
        f"cat {report_path or 'pyrit/outputs/reports/*_Report_*.md'}",
        "",
        f"# 重新生成报告（修改格式）",
        f"python main.py --report full --report-style {ctx.get('report_style', 'offsec')}",
    ]

    warnings = [
        "报告标记为 TLP:AMBER — 仅供授权人员内部使用",
        "所有敏感数据（Token/Key）在报告中已自动脱敏",
    ]

    return StageGuidance(
        stage_name="报告生成 (OffSec 风格)",
        stage_number=5,
        block=GuidanceBlock(
            summary=summary,
            advice=advice,
            commands=commands,
            warnings=warnings,
            next_stage="完成 — 可重新开始新一轮测试",
        ),
    )


def _guidance_default(ctx: dict) -> StageGuidance:
    return StageGuidance(
        stage_name="管道初始化",
        stage_number=-1,
        block=GuidanceBlock(
            summary="管道就绪。",
            advice=["选择目标 URL 后从侦察阶段开始", "或从已有 profile 恢复执行"],
            commands=["python -m orchestrators.full_pipeline --stage recon --target-url <URL>"],
        ),
    )
