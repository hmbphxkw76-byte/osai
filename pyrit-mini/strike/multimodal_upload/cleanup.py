# -*- coding: utf-8 -*-
"""I13 副作用清理（side-effect cleanup）——动作注册表 / preflight / 执行。

背景：组件 YAML 的 `cleanup: [...]` 此前是**纯声明、零消费方**（实测全仓无任何分发
机制）。按蓝图不变量 **I13**：「未声明 cleanup 的副作用步在 dry-run 之外禁止执行」，
仅有声明而无实装同样不满足 I13 —— 故本模块提供：

    1. `CLEANUP_ACTIONS` 动作注册表（已实装的动作才能通过 preflight）
    2. `preflight_cleanup()` —— 非 dry-run 时，声明动作**全部已实装**才允许执行副作用步
    3. `run_side_effect_cleanup()` —— 执行清理并记录结果（绝不静默失败，C9 / R-H2）

裁决与依据：CP-004 §8.11 后续执行批次；BL-064（P0）。
学术依据（副作用治理）：
    - Greshake et al. (arXiv:2302.12173) — 上传文档在目标侧的持久性污染
    - Zou et al. (arXiv:2406.04245) — 投毒文档残留导致后续检索持续受影响
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


# 常见响应体中"文档标识"的键名（黑盒推断，不含白盒假设）
_DOC_ID_KEYS = ("doc_id", "document_id", "file_id", "id", "uuid")


def extract_doc_id(response_body: Any) -> str | None:
    """从上传响应体中黑盒推断文档标识（供清理定位）。

    支持 dict 与 dict 列表；取第一个命中的字符串/数字标识。
    """
    candidates: list[Any] = []
    if isinstance(response_body, dict):
        candidates.append(response_body)
        for value in response_body.values():
            if isinstance(value, dict):
                candidates.append(value)
    elif isinstance(response_body, list):
        candidates.extend([v for v in response_body if isinstance(v, dict)])

    for candidate in candidates:
        for key in _DOC_ID_KEYS:
            value = candidate.get(key)
            if isinstance(value, (str, int)) and str(value).strip():
                return str(value).strip()
    return None


@register_cleanup_action("delete_uploaded_document")
async def delete_uploaded_document(ctx: Any, artifacts: dict[str, Any]) -> dict[str, Any]:
    """删除本次上传留在目标侧的文档（副作用清理，I13）。

    artifacts:
        target_url: 目标基础 URL
        upload_endpoint: 上传端点路径（删除端点缺省为其子路径 `/{doc_id}`）
        doc_ids: 待删除的文档标识列表
        headers: 可选请求头（如 Authorization）

    Note:
        使用 `aiohttp`（与 `file_upload_executor` 同款，NEG-4 未引入新依赖）。
        删除失败**不算成功**——调用方必须据 `success` 决定是否标记 partial（C9）。
    """
    target_url = (artifacts.get("target_url") or "").rstrip("/")
    endpoint = (artifacts.get("upload_endpoint") or "").rstrip("/")
    doc_ids = [str(d) for d in (artifacts.get("doc_ids") or []) if str(d).strip()]
    headers = artifacts.get("headers") or None

    if not target_url or not doc_ids:
        return {"status": "ok", "success": True, "removed": [], "skipped": True, "reason": "无待清理文档"}

    removed: list[str] = []
    failed: list[dict[str, Any]] = []
    timeout = int(getattr(getattr(ctx, "args", None), "timeout", 30) or 30)

    try:
        import aiohttp
    except ImportError:  # 可选依赖缺席 → 明确失败，禁止静默降级（R-H1）
        return {"status": "failed", "success": False, "removed": [], "failed": [], "error": "aiohttp 不可用"}

    async with aiohttp.ClientSession() as session:
        for doc_id in doc_ids:
            url = f"{target_url}{endpoint}/{doc_id}"
            try:
                async with session.delete(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                    if resp.status < 400:
                        removed.append(doc_id)
                    else:
                        failed.append({"doc_id": doc_id, "status": resp.status})
            except Exception as exc:
                failed.append({"doc_id": doc_id, "error": str(exc)})

    if failed:
        logger.warning("[cleanup] delete_uploaded_document partial failure: %s", failed)
    return {
        "status": "ok" if not failed else "failed",
        "success": not failed,
        "removed": removed,
        "failed": failed,
        "attempted": len(doc_ids),
    }
