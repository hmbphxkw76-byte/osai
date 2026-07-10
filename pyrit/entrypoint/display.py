"""
===============================================================================
PyRIT Red Team — 显示工具 (v11.0 Streamlined)
===============================================================================
精简变化:
  ✅ 回显参数适配精简后的 CLI (--auth / --ssl-skip / --payload)
===============================================================================
"""
from __future__ import annotations

import os

from rich.console import Console

console = Console()


def print_cli_args(args) -> None:
    """将解析后的 CLI 参数回显到控制台（精简版）。"""
    cli_parts = [f"python {os.path.basename('main.py')}"]
    cli_parts.append(f"--lang {args.lang}")
    cli_parts.append(f"--phase {args.phase}")

    concurrent = getattr(args, 'concurrent', 0)
    if concurrent > 0:
        cli_parts.append(f"--concurrent {concurrent}")
    else:
        cli_parts.append("--concurrent auto")

    if args.auto_gate:
        cli_parts.append(f"--auto-gate --gate-threshold {args.gate_threshold}")

    if args.target_url:
        cli_parts.append(f"--target-url {args.target_url}")

    auth = getattr(args, 'auth', '')
    auth_file = getattr(args, 'auth_file', '')
    if auth:
        # 脱敏显示
        if auth.startswith("eyJ"):
            display_auth = f"{auth[:20]}..."
        elif len(auth) > 12:
            display_auth = f"{auth[:8]}...{auth[-4:]}"
        else:
            display_auth = auth
        cli_parts.append(f"--auth {display_auth}")
    elif auth_file:
        cli_parts.append(f"--auth-file {auth_file}")
    elif os.getenv("PYRIT_AUTH"):
        env_auth = os.getenv("PYRIT_AUTH", "")
        if env_auth.startswith("eyJ"):
            display_env = f"{env_auth[:20]}..."
        elif len(env_auth) > 12:
            display_env = f"{env_auth[:8]}...{env_auth[-4:]}"
        else:
            display_env = env_auth
        cli_parts.append(f"PYRIT_AUTH={display_env} [env]")

    ssl_skip = getattr(args, 'ssl_skip', False)
    if ssl_skip:
        cli_parts.append("--ssl-skip")

    if args.scenario:
        cli_parts.append(f"--scenario {args.scenario}")

    payload = getattr(args, 'payload', '')
    if payload:
        if len(payload) > 30:
            display_payload = f"{payload[:20]}..."
        else:
            display_payload = payload
        cli_parts.append(f"--payload {display_payload}")

    if args.case:
        cli_parts.append(f"--case {args.case}")
    if args.exclude_case:
        cli_parts.append(f"--exclude-case {args.exclude_case}")

    if args.no_probe:
        cli_parts.append("--no-probe")
    if args.env_file != ".env":
        cli_parts.append(f"--env-file {args.env_file}")
    if args.orch != "pyrit":
        cli_parts.append(f"--orch {args.orch}")

    adaptive = getattr(args, 'adaptive', False)
    if adaptive:
        cli_parts.append("--adaptive")
        vendor = getattr(args, 'target_vendor', 'auto')
        if vendor != 'auto':
            cli_parts.append(f"--target-vendor {vendor}")
        if getattr(args, 'use_dedup_cache', False):
            cli_parts.append("--use-dedup-cache")
        if getattr(args, 'enable_early_stop', False):
            cli_parts.append("--enable-early-stop")

    if args.target_type != "auto":
        cli_parts.append(f"--target-type {args.target_type}")

    if args.penetrating_mode:
        cli_parts.append(f"--penetrating-mode --penetrating-template {args.penetrating_template}")
    if args.exploring_template:
        cli_parts.append(f"--exploring-template {args.exploring_template}")

    console.print(f"[bold cyan]📋 执行参数:[/bold cyan] {' '.join(cli_parts)}")


def print_target_classification(target_type: str, target_url: str) -> None:
    """打印目标分类结果。"""
    if target_type == "model":
        console.print(
            f"\n[bold green]✅ 目标分类: [已知模型 API][/bold green]\n"
            f"   [dim]URL: {target_url}[/dim]\n"
            f"   [dim]策略: 跳过应用层侦察（端点枚举/架构探测），直接执行模型层攻击[/dim]\n"
            f"   [dim]适配策略: jailbreak / injection / bypass / prompt-leaking / data-exfil[/dim]"
        )
    else:
        console.print(
            f"\n[bold cyan]🔗 目标分类: [自定义 AI 应用][/bold cyan]\n"
            f"   [dim]URL: {target_url}[/dim]\n"
            f"   [dim]策略: 完整侦察流程 — 端点枚举 → 架构探测 → 策略推荐[/dim]\n"
            f"   [dim]适配策略: RAG投毒 / MCP滥用 / Agent劫持 / A2A欺骗 / 供应链攻击[/dim]"
        )


def print_runtime_info(n_converters: int, n_combos: int,
                       n_single: int, n_double: int, n_triple: int,
                       n_discovered: int, n_synced: int) -> None:
    """打印运行时统计信息。"""
    if n_discovered or n_synced:
        console.print(f"[dim]🔍 自动发现: +{n_discovered} 自定义 + {n_synced} PyRIT 原生转换器[/dim]")
    console.print(
        f"[dim]🎯 攻击特征库: {n_converters} 个转换器 + {n_combos} 组攻击组合 "
        f"(单层: {n_single} | 双层: {n_double} | 三层链: {n_triple})[/dim]"
    )
