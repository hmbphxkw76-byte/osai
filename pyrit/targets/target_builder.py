"""
===============================================================================
PyRIT Red Team — 统一 Target 构建工厂 v11.0 (Streamlined)
===============================================================================
精简变化:
  ✅ 接受归一化后的认证参数（api_key/cookie/jwt/extra_headers）
  ✅ SSL 通过 --ssl-skip 控制
  ✅ api_format 自动推断（model→openai, app→raw）
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
    normalized_auth: dict | None = None,
) -> Optional[PromptTarget]:
    """根据 CLI 参数统一构建攻击目标 Target（精简版）。

    Args:
        args: CLI 解析参数
        attacker_config: .env 加载的 attacker 配置
        enable_probe: 是否启用模型自动探测
        normalized_auth: 🆕 归一化认证 (from normalize_auth_value)

    Returns:
        PromptTarget 实例，或 None
    """
    if not args.target_url:
        if not attacker_config or not attacker_config.get("model"):
            console.print("[bold red]❌ 攻击者模型未配置！请在 .env 中设置或使用 --target-url[/bold red]")
            return None
        return create_attack_target(env_config=attacker_config)

    if normalized_auth is None:
        normalized_auth = {}

    # ── 从归一化 auth 提取 ──
    effective_api_key = normalized_auth.get("api_key", "") or getattr(args, 'target_api_key', '')
    effective_cookie = normalized_auth.get("cookie", "") or getattr(args, 'target_cookie', '')
    effective_jwt = normalized_auth.get("jwt_token", "") or getattr(args, 'target_jwt', '')

    auth_extra_headers = dict(normalized_auth.get("extra_headers", {}))
    # 也可合并 CLI extra_headers
    cli_extra_headers = getattr(args, 'target_extra_headers', '')
    if cli_extra_headers:
        try:
            parsed = json.loads(cli_extra_headers) if isinstance(cli_extra_headers, str) else cli_extra_headers
            auth_extra_headers.update(parsed)
        except (json.JSONDecodeError, TypeError):
            pass

    # SSL: --ssl-skip 或 HTTP 协议自动关闭
    is_http_target = args.target_url.lower().startswith("http://")
    verify_ssl = not is_http_target and not getattr(args, 'ssl_skip', False)

    # ── 模型自动探测 ──
    if enable_probe:
        args.target_model, target_reachable = await auto_probe_target_model(
            args, args.target_url, effective_api_key,
            normalized_auth=normalized_auth,
        )
        if not target_reachable:
            return None
    else:
        args.target_model = getattr(args, 'target_model', '') or DEFAULT_MODEL_NAME

    # 🆕 API 格式自动推断
    cli_target_type = getattr(args, 'target_type', 'auto')
    if cli_target_type == "model":
        api_format = "openai"
    else:
        api_format = "raw"

    # 🆕 探测结果覆盖: endpoint_type 比 target_type 更精确
    probe_result = getattr(args, '_probe_result', None)
    if probe_result and probe_result.endpoint_type:
        et = probe_result.endpoint_type
        if et in ("ollama", "ollama_compat"):
            api_format = "ollama"
        elif et == "openai":
            api_format = "openai"
        elif et == "gemini":
            api_format = "gemini"
        elif et in ("anthropic", "claude"):
            api_format = "claude"

    return build_custom_target(
        endpoint=args.target_url,
        scenario=getattr(args, 'scenario', '') or "",
        api_key=effective_api_key or "",
        model=args.target_model or DEFAULT_MODEL_NAME,
        api_format=api_format,
        http_method="POST",
        content_type="application/json",
        verify_ssl=verify_ssl,
        cookie=effective_cookie or "",
        jwt_token=effective_jwt or "",
        user_agent="",
        extra_headers=auth_extra_headers if auth_extra_headers else None,
    )
