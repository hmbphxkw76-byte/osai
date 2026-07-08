"""
===============================================================================
PyRIT Red Team — 目标自动探测函数（Auto Probe）v11.0
===============================================================================
精简变化:
  ✅ auto_probe_target_model 新增 normalized_auth 参数用于认证头注入
===============================================================================
"""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from targets.model_probe import probe_model_info, check_target_reachable
from targets.target_type_probe import probe_target_type, TargetTypeResult
from utils import DEFAULT_MODEL_NAME, get_default_model_name

console = Console()


async def auto_probe_target_model(args, target_url: str, target_api_key: str,
                                  normalized_auth: dict | None = None) -> tuple[str, bool]:
    """自动探测目标 URL 的模型名称和可达性。

    Args:
        args: CLI 解析参数（需包含 target_model, no_probe 等属性）
        target_url: 目标 URL
        target_api_key: API Key（可选）
        normalized_auth: 🆕 归一化认证字典 (from normalize_auth_value)

    Returns:
        (model_name, is_reachable) — 模型名和是否可达
    """
    current_model = args.target_model if hasattr(args, 'target_model') and args.target_model else ""

    # ── 跳过条件 ──
    if args.no_probe:
        console.print("[dim]⏭ --no-probe: 跳过模型自动探测[/dim]")
        return current_model if current_model else get_default_model_name(), True
    if not target_url:
        return current_model if current_model else get_default_model_name(), True
    if current_model and current_model != DEFAULT_MODEL_NAME:
        console.print(f"[dim]📌 已指定模型={current_model}，跳过自动探测[/dim]")
        return current_model, True

    # 🆕 构建认证头（从 normalized_auth 提取）
    extra_auth_headers = {}
    if normalized_auth:
        if normalized_auth.get("jwt_token"):
            extra_auth_headers["Authorization"] = f"Bearer {normalized_auth['jwt_token']}"
        elif normalized_auth.get("api_key"):
            extra_auth_headers["Authorization"] = f"Bearer {normalized_auth['api_key']}"
        if normalized_auth.get("extra_headers"):
            extra_auth_headers.update(normalized_auth["extra_headers"])

    # ── 执行探测 ──
    console.print()
    result = await probe_model_info(
        target_url=target_url,
        api_key=target_api_key or "",
        extra_auth_headers=extra_auth_headers if extra_auth_headers else None,
    )

    # 保存 probe 结果给 bootstrap 提取推荐并发
    if hasattr(args, '_probe_result') is False:
        args._probe_result = result

    # ── 可达性判断 ──
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

    # ── 速率限制建议 ──
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
        console.print(f"[dim]   → 已自动注入 PyRIT 攻击管线[/dim]\n")
        return result.model_name, True
    else:
        console.print(
            f"[yellow]  → 目标可达但无法识别模型名称，使用 model='{get_default_model_name()}' 降级攻击[/yellow]"
        )
        console.print("[dim]    可通过手动指定模型名以提升攻击精准度[/dim]\n")
        return current_model or get_default_model_name(), True


async def auto_probe_target_type(args, target_url: str, target_api_key: str):
    """自动探测目标架构类型（RAG/MCP/Agent/LLM）。"""
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
