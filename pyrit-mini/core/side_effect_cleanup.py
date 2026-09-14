# -*- coding: utf-8 -*-
"""core/side_effect_cleanup — I13 副作用清理共享注册表 / preflight / 执行。

背景：组件 YAML 的 `cleanup: [...]` 此前是**纯声明、零消费方**（实测全仓无分发机制）。
按蓝图不变量 **I13**：「未声明 cleanup 的副作用步在 dry-run 之外禁止执行」，
仅有声明而无实装同样不满足 I13。本模块提供跨组件共享机制（原实装于
`strike/multimodal_upload/cleanup.py`，因 I13 为跨组件不变量、且 `agent` 等组件
亦需复用，上提为共享基建）：

    1. `CLEANUP_ACTIONS` 动作注册表（已实装的动作才能通过 preflight）
    2. `preflight_cleanup()` —— 非 dry-run 时，声明动作**全部已实装**才允许执行副作用步
    3. `run_side_effect_cleanup()` —— 执行清理并记录结果（绝不静默失败，C9 / R-H2）

裁决与依据：CP-004 §8.11 后续执行批次；BL-064（multimodal_upload P0）/ BL-093（agent）。
学术依据（副作用治理）：
    - Greshake et al. (arXiv:2302.12173) — 上传/注入产物在目标侧的持久性污染
    - Zou et al. (arXiv:2406.04245) — 投毒残留导致后续检索持续受影响
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

logger = logging.getLogger(__name__)

# 动作签名：(ctx, artifacts) -> dict；artifacts 为副作用步产出的可清理引用
CleanupFn = Callable[[Any, dict[str, Any]], Awaitable[dict[str, Any]]]

# 已实装的清理动作。键必须与组件 YAML `cleanup:` 中声明的名字逐一对应。
CLEANUP_ACTIONS: dict[str, CleanupFn] = {}


def register_cleanup_action(name: str) -> Callable[[CleanupFn], CleanupFn]:
    """注册一个已实装的清理动作（装饰器）。

    未注册的动作 = 未实装 → `preflight_cleanup()` 在非 dry-run 下拒绝执行副作用步（I13）。
    """

    def _decorator(fn: CleanupFn) -> CleanupFn:
        CLEANUP_ACTIONS[name] = fn
        return fn

    return _decorator


def declared_cleanup_actions(component_key: str) -> list[str]:
    """读取组件 YAML 声明的 cleanup 动作名（SSOT = `config/components/*.yaml`）。"""
    try:
        from core.registry import get_registry

        spec = get_registry().spec(component_key)
    except Exception as exc:  # 注册表不可用时退化为"无声明"，由调用方按 I13 处理
        logger.debug("[cleanup] registry lookup failed for %s: %s", component_key, exc)
        return []
    if spec is None:
        return []
    return [str(a) for a in (getattr(spec, "cleanup", None) or [])]


def preflight_cleanup(ctx: Any, component_key: str, *, dry_run: bool) -> dict[str, Any]:
    """I13 preflight：判断副作用步是否允许执行。

    Returns:
        dict：`allowed`（是否允许）、`status`、`reason`、`missing`（未实装的动作名）。
    """
    declared = declared_cleanup_actions(component_key)
    missing = [a for a in declared if a not in CLEANUP_ACTIONS]

    if dry_run:
        return {
            "allowed": True,
            "status": "skipped_dry_run",
            "reason": "dry-run：不产生真实副作用，清理不执行",
            "declared": declared,
            "missing": missing,
        }

    if not declared:
        return {
            "allowed": False,
            "status": "blocked",
            "reason": f"I13：组件 {component_key} 未声明 cleanup，非 dry-run 禁止执行副作用步",
            "declared": [],
            "missing": [],
        }

    if missing:
        return {
            "allowed": False,
            "status": "blocked",
            "reason": (
                f"I13：组件 {component_key} 声明的 cleanup 动作未实装 {missing}，"
                "非 dry-run 禁止执行副作用步"
            ),
            "declared": declared,
            "missing": missing,
        }

    return {"allowed": True, "status": "ok", "reason": "cleanup 已声明且已实装", "declared": declared, "missing": []}


async def run_side_effect_cleanup(
    ctx: Any,
    component_key: str,
    artifacts: dict[str, Any],
    *,
    dry_run: bool,
) -> dict[str, Any]:
    """执行该组件声明的全部清理动作。

    绝不静默失败：任一动作失败 → `status="failed"` 且 `failed` 列出动作名（C9 / R-H2）。
    """
    pre = preflight_cleanup(ctx, component_key, dry_run=dry_run)
    if dry_run:
        return pre
    if not pre["allowed"]:
        return pre

    results: dict[str, dict[str, Any]] = {}
    failed: list[str] = []
    for action in pre["declared"]:
        fn = CLEANUP_ACTIONS[action]
        try:
            outcome = await fn(ctx, artifacts)
            results[action] = outcome
            if not outcome.get("success"):
                failed.append(action)
        except Exception as exc:  # 单个动作失败不影响其余动作（故障隔离）
            logger.warning("[cleanup] action %s raised: %s", action, exc)
            results[action] = {"success": False, "error": str(exc)}
            failed.append(action)

    status = "ok" if not failed else "failed"
    if failed:
        logger.warning("[cleanup] component=%s failed actions=%s", component_key, failed)
    return {"allowed": pre["allowed"], "status": status, "failed": failed, "actions": results}
