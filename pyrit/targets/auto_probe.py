"""
===============================================================================
PyRIT Red Team — 目标自动探测函数（Auto Probe）
===============================================================================
PyRIT 最佳实践: 在正式攻击前自动识别目标 LLM 的模型名称和架构类型，
确保后续 PyRIT Pipeline 中的所有攻击流量携带正确的 model 参数并
自动选择最优攻击组合。

从 main.py 提取，归入 targets/ 模块以遵循单一职责原则。

探测维度:
  1. 模型探测 — 自动识别目标模型名称（OpenAI/Ollama/自我识别/端点枚举）
  2. 架构探测 — 自动识别目标架构类型（RAG/MCP/Agent/LLM）

使用方式:
  from targets.auto_probe import auto_probe_target_model, auto_probe_target_type

  model_name, is_reachable = await auto_probe_target_model(
      args, target_url="http://192.168.2.199:8501/", target_api_key=""
  )
  target_type_result = await auto_probe_target_type(
      args, target_url="http://192.168.2.199:8501/", target_api_key=""
  )
===============================================================================
"""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from targets.model_probe import probe_model_info, check_target_reachable
from targets.target_type_probe import probe_target_type, TargetTypeResult
from utils import DEFAULT_MODEL_NAME, get_default_model_name

console = Console()


async def auto_probe_target_model(args, target_url: str, target_api_key: str) -> tuple[str, bool]:
    """自动探测目标 URL 的模型名称和可达性。

    PyRIT 最佳实践: 区分"目标不可达"与"目标可达但模型无法识别"。
      ❌ 目标不可达 → 返回 ("unreachable", False)  → 应中止 campaign
      ⚠️  目标可达但无法识别 → 返回 ("default", True) → 降级继续攻击
      ✅ 探测成功 → 返回 (model_name, True)             → 正常攻击

    Args:
        args: CLI 解析参数（需包含 target_model, no_probe 等属性）
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


async def auto_probe_target_type(args, target_url: str, target_api_key: str):
    """自动探测目标架构类型（RAG/MCP/Agent/LLM）。

    PyRIT 最佳实践: 在模型探测完成后，发送特征探针推断目标架构，
    从而自动选择最优攻击组合（RAG 投毒/MCP 滥用/Agent 劫持等）。

    Args:
        args: CLI 解析参数（需包含 no_probe 属性）
        target_url: 目标 URL
        target_api_key: API Key（可选）

    Returns:
        TargetTypeResult 或 None（探测失败时）
    """
    # ── 跳过条件 ──
    if args.no_probe:
        console.print("[dim]⏭ --no-probe: 跳过目标架构类型探测[/dim]")
        return None
    if not target_url:
        return None

    console.print()
    try:
        result = await probe_target_type(
            target_url=target_url,
            api_key=target_api_key or "",
        )
        return result
    except Exception as e:
        console.print(f"[yellow]⚠ 目标架构类型探测失败: {e}[/yellow]")
        return None
