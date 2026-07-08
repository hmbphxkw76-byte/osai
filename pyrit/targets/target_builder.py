"""
===============================================================================
PyRIT Red Team — 统一 Target 构建工厂（消除三处重复逻辑）
===============================================================================
PyRIT 最佳实践: 将探索模式/渗透模式/原生模式的 Target 构建逻辑统一为
单一入口点，消除 DRY 违规。

使用方式:
  from targets.target_builder import build_attack_target_from_args

  attack_target = await build_attack_target_from_args(
      args, attacker_config, enable_probe=True
  )
  # 返回 None 表示目标不可达或配置错误
===============================================================================
"""
from __future__ import annotations

import json
from typing import Optional

from rich.console import Console

from pyrit.prompt_target import PromptTarget

from targets.factories import create_attack_target
from targets.scenarios import build_custom_target
from targets.auto_probe import auto_probe_target_model
from utils import DEFAULT_MODEL_NAME

console = Console()


async def build_attack_target_from_args(
    args,
    attacker_config: dict,
    *,
    enable_probe: bool = True,
) -> Optional[PromptTarget]:
    """根据 CLI 参数统一构建攻击目标 Target。

    三种场景统一处理:
      1. --target-url 指定 → 自动探测 + build_custom_target
      2. .env 配置模式    → create_attack_target
      3. 配置缺失         → 返回 None

    Args:
        args: CLI 解析参数（需包含 target_url, target_model, target_api_key,
              scenario, target_api_format, target_http_method, target_content_type,
              target_verify_ssl, target_no_ssl, target_cookie, target_jwt,
              target_user_agent, target_extra_headers, env_file, no_probe 等属性）
        attacker_config: .env 加载的 attacker 配置
        enable_probe: 是否启用模型自动探测 + 架构类型探测（默认 True）

    Returns:
        PromptTarget 实例，或 None（目标不可达/配置错误时）
    """
    if not args.target_url:
        # ── .env 配置模式 ──
        if not attacker_config or not attacker_config.get("model"):
            console.print("[bold red]❌ 攻击者模型未配置！请在 .env 中设置或使用 --target-url[/bold red]")
            return None
        return create_attack_target(env_config=attacker_config)

    # ── 自定义 Target 模式 ──
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

    # ── 模型自动探测 + 可达性检查 ──
    if enable_probe:
        args.target_model, target_reachable = await auto_probe_target_model(
            args, args.target_url, args.target_api_key
        )
        if not target_reachable:
            return None  # 目标不可达
    else:
        args.target_model = args.target_model or DEFAULT_MODEL_NAME

    return build_custom_target(
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
