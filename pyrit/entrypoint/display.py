"""
===============================================================================
PyRIT Red Team — 显示工具
===============================================================================
从 main.py 提取控制台显示逻辑，遵循:
  ✅ 单一职责 — 仅负责 Rich Console 输出格式化
  ✅ 无业务逻辑 — 不执行计算或 I/O
  ✅ 参数回显 — 将 CLI 参数转译为人类可读的命令行

使用方式:
  from entrypoint.display import print_cli_args, print_runtime_info
===============================================================================
"""
from __future__ import annotations

import os

from rich.console import Console

console = Console()


def print_cli_args(args) -> None:
    """将解析后的 CLI 参数回显到控制台。

    Args:
        args: argparse.Namespace 解析结果
    """
    cli_parts = [f"python {os.path.basename('main.py')}"]
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
    if args.penetrating_mode:
        cli_parts.append(f"--penetrating-mode --penetrating-template {args.penetrating_template}")
    if args.exploring_template:
        cli_parts.append(f"--exploring-template {args.exploring_template}")
    console.print(f"[bold cyan]📋 执行参数:[/bold cyan] {' '.join(cli_parts)}")


def print_runtime_info(n_converters: int, n_combos: int,
                       n_single: int, n_double: int, n_triple: int,
                       n_discovered: int, n_synced: int) -> None:
    """打印运行时统计信息。

    Args:
        n_converters: 转换器总数
        n_combos: 攻击组合总数
        n_single: 单层链组合数
        n_double: 双层链组合数
        n_triple: 三层链组合数
        n_discovered: 自定义转换器发现数
        n_synced: PyRIT 原生转换器同步数
    """
    if n_discovered or n_synced:
        console.print(f"[dim]🔍 自动发现: +{n_discovered} 自定义 + {n_synced} PyRIT 原生转换器[/dim]")

    console.print(
        f"[dim]🎯 攻击特征库: {n_converters} 个转换器 + {n_combos} 组攻击组合 "
        f"(单层: {n_single} | 双层: {n_double} | 三层链: {n_triple})[/dim]"
    )
