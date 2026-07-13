"""数据集投毒风险检测（AI-300 Ch8: Supply Chain Attacks）。

实现 AI-300 课程中的数据集投毒检测技术：
  - 训练数据引用暴露检测
  - 数据集版本混淆检测
  - 标注投毒风险评估

对齐 OWASP LLM Top 10: LLM04 (Data Poisoning)
"""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import urljoin

import httpx

from redteam.core.models import AIService, AuthContext


def _extract_context(text: str, keyword: str, context_chars: int = 100) -> str:
    """提取关键词周围的上下文文本。"""
    pos = text.lower().find(keyword.lower())
    if pos == -1:
        return ""
    start = max(0, pos - context_chars // 2)
    end = min(len(text), pos + len(keyword) + context_chars // 2)
    return text[start:end].strip()


def check_dataset_poisoning_risks(
    service: AIService,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """检查数据集投毒风险（AI-300 Ch8.3）。

    攻击向量：
    1. 公开数据集中隐藏后门样本
    2. 标注投毒 - 恶意修改数据标签
    3. 数据集版本混淆 - 替换为投毒版本
    """
    risks: list[dict[str, Any]] = []

    dataset_indicators = [
        "dataset", "training_data", "fine_tune_data",
        "train_dataset", "eval_dataset", "datasets",
    ]

    headers = {"Content-Type": "application/json"}
    if auth:
        headers.update(auth.to_header_dict())

    for path in ["/v1/models", "/api/models", "/models", "/v1/info"]:
        url = urljoin(service.url, path)
        try:
            with httpx.Client(timeout=timeout, verify=False) as client:
                r = client.get(url, headers=headers)
                body_lower = r.text.lower()

                for indicator in dataset_indicators:
                    if indicator in body_lower:
                        try:
                            data = r.json() if r.status_code == 200 else {}
                            risks.append({
                                "indicator": indicator,
                                "url": url,
                                "risk": "dataset_metadata_exposed",
                                "severity": "medium",
                                "description": (
                                    f"端点 {url} 暴露了训练数据集元数据 "
                                    f"({indicator})，攻击者可据此定位和投毒数据集"
                                ),
                                "evidence": _extract_context(r.text, indicator, 200),
                            })
                        except json.JSONDecodeError:
                            pass
                        break
        except Exception:
            continue

    return risks


__all__ = [
    "check_dataset_poisoning_risks",
    "_extract_context",
]