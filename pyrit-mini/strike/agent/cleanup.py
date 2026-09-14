# -*- coding: utf-8 -*-
"""strike/agent/cleanup.py — I13 副作用清理（agent 组件）。

对应 config/components/agent.yaml `cleanup: [unregister_rogue_tool, restore_agent_tools]`。
两个动作均**已实装并注册**（与 multimodal_upload/cleanup.py 同款 `@register_cleanup_action`）。

注意（接线缺口，见 BL-093）：agent 当前无专用攻击分发器（无 `run_agent_attack`），
故 `preflight_cleanup` / `run_side_effect_cleanup` 尚未被调用——
动作实装完成，但「真实攻击路径中执行清理」需待 agent 分发器落地后接线。
在接线前，非 dry-run 真实攻击的副作用清理不执行（I13 安全保证待 BL-093 闭环）。

动作签名：async fn(ctx, artifacts) -> dict（与 core.cleanup.register_cleanup_action 一致）。
学术依据：OWASP ASI10 恶意工具注册的逆向清理（撤销越权工具副作用）。
"""

from __future__ import annotations

import logging
from typing import Any

from core.side_effect_cleanup import register_cleanup_action

logger = logging.getLogger(__name__)


@register_cleanup_action("unregister_rogue_tool")
async def unregister_rogue_tool(ctx: Any, artifacts: dict[str, Any]) -> dict[str, Any]:
    """注销 agent 工具集中被注入的恶意/rogue 工具（副作用清理，I13）。

    artifacts:
        target_url: 目标基础 URL
        tool_unregister_endpoint: 工具注销端点（缺省 /tools/unregister）
        rogue_tool_names: 待注销的工具名列表
        headers: 可选请求头
    """
    target_url = (artifacts.get("target_url") or "").rstrip("/")
    endpoint = (artifacts.get("tool_unregister_endpoint") or "/tools/unregister").rstrip("/")
    names = [str(n) for n in (artifacts.get("rogue_tool_names") or []) if str(n).strip()]
    headers = artifacts.get("headers") or None

    if not target_url or not names:
        return {"status": "ok", "success": True, "removed": [], "skipped": True, "reason": "无待注销工具"}

    removed: list[str] = []
    failed: list[dict[str, Any]] = []
    timeout = int(getattr(getattr(ctx, "args", None), "timeout", 30) or 30)
    try:
        import aiohttp
    except ImportError:  # 可选依赖缺席 → 明确失败，禁止静默降级（R-H1）
        return {"status": "failed", "success": False, "removed": [], "failed": [], "error": "aiohttp 不可用"}

    async with aiohttp.ClientSession() as session:
        for name in names:
            url = f"{target_url}{endpoint}"
            try:
                async with session.post(url, json={"name": name}, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                    if resp.status < 400:
                        removed.append(name)
                    else:
                        failed.append({"name": name, "status": resp.status})
            except Exception as exc:
                failed.append({"name": name, "error": str(exc)})

    if failed:
        logger.warning("[cleanup] unregister_rogue_tool partial failure: %s", failed)
    return {
        "status": "ok" if not failed else "failed",
        "success": not failed,
        "removed": removed,
        "failed": failed,
        "attempted": len(names),
    }


@register_cleanup_action("restore_agent_tools")
async def restore_agent_tools(ctx: Any, artifacts: dict[str, Any]) -> dict[str, Any]:
    """恢复 agent 原始工具集（撤销 rogue 工具注册造成的基线漂移，I13）。

    artifacts:
        target_url: 目标基础 URL
        tool_restore_endpoint: 工具恢复端点（缺省 /tools/restore）
        baseline_toolset: 应恢复到的工具名列表
        headers: 可选请求头
    """
    target_url = (artifacts.get("target_url") or "").rstrip("/")
    endpoint = (artifacts.get("tool_restore_endpoint") or "/tools/restore").rstrip("/")
    baseline = [str(t) for t in (artifacts.get("baseline_toolset") or []) if str(t).strip()]
    headers = artifacts.get("headers") or None

    if not target_url:
        return {"status": "ok", "success": True, "restored": [], "skipped": True, "reason": "无目标"}

    restored: list[str] = []
    failed: list[dict[str, Any]] = []
    timeout = int(getattr(getattr(ctx, "args", None), "timeout", 30) or 30)
    try:
        import aiohttp
    except ImportError:
        return {"status": "failed", "success": False, "restored": [], "failed": [], "error": "aiohttp 不可用"}

    async with aiohttp.ClientSession() as session:
        for name in baseline:
            url = f"{target_url}{endpoint}"
            try:
                async with session.post(url, json={"name": name}, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                    if resp.status < 400:
                        restored.append(name)
                    else:
                        failed.append({"name": name, "status": resp.status})
            except Exception as exc:
                failed.append({"name": name, "error": str(exc)})

    if failed:
        logger.warning("[cleanup] restore_agent_tools partial failure: %s", failed)
    return {
        "status": "ok" if not failed else "failed",
        "success": not failed,
        "restored": restored,
        "failed": failed,
        "attempted": len(baseline),
    }
