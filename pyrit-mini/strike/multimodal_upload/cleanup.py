# -*- coding: utf-8 -*-
"""I13 副作用清理（multimodal_upload 组件动作）。

通用注册表 / preflight / 执行机制已上提到 `core.side_effect_cleanup`（I13 为跨组件
不变量，multimodal_upload 与 agent 等组件共享）；本模块仅实装本组件的
`delete_uploaded_document` 动作并复用共享机制（下方再从 `core.side_effect_cleanup`
再导出 `preflight_cleanup` / `run_side_effect_cleanup`，保持既有导入兼容）。

裁决与依据：CP-004 §8.11 后续执行批次；BL-064（P0）。
学术依据（副作用治理）：
    - Greshake et al. (arXiv:2302.12173) — 上传文档在目标侧的持久性污染
    - Zou et al. (arXiv:2406.04245) — 投毒文档残留导致后续检索持续受影响
"""

from __future__ import annotations

import logging
from typing import Any

# I13 共享基建（注册表 / preflight / 执行）已上提至 `core.side_effect_cleanup`；
# 再导出以保持既有 `from strike.multimodal_upload.cleanup import ...` 兼容。
from core.side_effect_cleanup import (  # noqa: F401
    CLEANUP_ACTIONS,
    declared_cleanup_actions,
    preflight_cleanup,
    register_cleanup_action,
    run_side_effect_cleanup,
)

logger = logging.getLogger(__name__)


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
