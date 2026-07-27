# -*- coding: utf-8 -*-
"""
工具输出 → UnifiedFinding 转换器
"""

from __future__ import annotations

import uuid
from typing import Any, Dict

from ai300_schemas import Evidence, UnifiedFinding


def _new_id() -> str:
    """生成短 UUID 作为 finding_id 后缀"""
    return str(uuid.uuid4())[:8]


def _safe_str(value: Any) -> str:
    """将任意值安全转换为字符串"""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return str(value)
    except Exception:
        return ""


def _safe_dict(value: Any) -> Dict[str, Any]:
    """尝试将对象转换为字典，用于 raw 字段"""
    if isinstance(value, dict):
        return value
    if hasattr(value, "to_dict"):
        try:
            return value.to_dict()
        except Exception:
            pass
    if hasattr(value, "__dict__"):
        return value.__dict__
    return {"value": _safe_str(value)}


def finding_from_giskard(
    issue: Any,
    target: str = "",
    endpoint_url: str = "",
) -> UnifiedFinding:
    """
    把 Giskard 单个 issue 转换为 UnifiedFinding。

    Giskard issue 对象通常包含：
      - category: 问题类别（如 robustness / harmfulness / bias）
      - description: 问题描述
      - examples: 触发的输入输出示例
      - meta: 元数据
    """
    # 提取 category
    category_obj = getattr(issue, "category", None)
    category = ""
    if category_obj is not None:
        # category 可能是字符串或对象
        category = _safe_str(getattr(category_obj, "name", category_obj)).lower()
    if not category:
        category = "unknown"

    # 提取描述
    description = _safe_str(getattr(issue, "description", ""))
    title = _safe_str(getattr(issue, "title", f"Giskard issue: {category}")) or description[:80]

    # 提取示例用于证据
    examples = getattr(issue, "examples", None)
    evidence_text = ""
    if examples is not None:
        try:
            evidence_text = _safe_str(examples)
        except Exception:
            evidence_text = ""

    # 提取元数据
    meta = getattr(issue, "meta", {})

    # 风险评级：Giskard issue 默认至少 medium
    severity = _category_to_severity(category)
    owasp = _category_to_owasp(category)
    payload_class = category

    return UnifiedFinding(
        finding_id=f"giskard-{_new_id()}",
        source_tool="giskard",
        task_type="rag_eval" if category == "rag" else "ai_gauntlet",
        target=target,
        endpoint_url=endpoint_url,
        severity=severity,
        confidence=0.75,
        category=category,
        owasp_llm_id=owasp,
        title=title,
        description=description,
        remediation="Review the model's behavior on the reported inputs and consider adding safety filters or fine-tuning.",
        evidence=Evidence(
            request="",
            response=evidence_text,
            extra={"giskard_meta": _safe_dict(meta)},
        ),
        ai_payload_class=payload_class,
        raw={"giskard_issue": _safe_dict(issue)},
    )


def _category_to_owasp(category: str) -> str:
    """将 Giskard 类别映射到 OWASP LLM Top 10 编号"""
    mapping = {
        "robustness": "LLM01:2025",
        "prompt_injection": "LLM01:2025",
        "jailbreak": "LLM01:2025",
        "harmfulness": "LLM01:2025",
        "sensitive_info": "LLM06:2025",
        "sensitive_information_disclosure": "LLM06:2025",
        "data_exfil": "LLM06:2025",
        "bias": "LLM07:2025",
        "stereotypes": "LLM07:2025",
        "hallucination": "LLM07:2025",
        "rag": "LLM02:2025",
        "agent": "LLM08:2025",
        "excessive_agency": "LLM08:2025",
    }
    return mapping.get(category.lower(), "")


def _category_to_severity(category: str) -> str:
    """根据类别推断严重级别"""
    category_lower = category.lower()
    if category_lower in {"harmfulness", "sensitive_info", "sensitive_information_disclosure", "data_exfil"}:
        return "high"
    if category_lower in {"prompt_injection", "jailbreak", "excessive_agency", "agent"}:
        return "high"
    if category_lower in {"robustness", "bias", "stereotypes"}:
        return "medium"
    if category_lower == "hallucination":
        return "medium"
    return "medium"
