"""Pickle 反序列化 RCE 检测（AI-300 Ch8: Supply Chain Attacks）。

实现 AI-300 课程中的 pickle 反序列化风险检测：
  - torch.load / pickle.load RCE 漏洞检测
  - 模型上传端点探测
  - safetensors vs pickle 格式识别

对齐 OWASP LLM Top 10: LLM03 (Supply Chain Vulnerabilities)
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin

import httpx

from redteam.core.models import AIService, AuthContext

_PICKLE_RISK_PATTERNS: list[str] = [
    r"torch\.load\(",
    r"pickle\.load",
    r"joblib\.load",
    r"safetensors",
]


def check_pickle_deserialization_risk(
    service: AIService,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """检测 pickle 反序列化 RCE 风险（AI-300 Ch8.2）。

    技术背景：
    torch.save / pickle.load 可以执行任意 Python 代码。
    攻击者上传恶意的 .pt / .pth / .pkl 文件到共享模型仓库，
    当受害者通过 torch.load() 加载模型时触发 RCE。
    """
    results: list[dict[str, Any]] = []
    headers = {"Content-Type": "application/json"}
    if auth:
        headers.update(auth.to_header_dict())

    upload_paths = [
        "/v1/models/upload",
        "/api/models/upload",
        "/models/upload",
        "/v1/fine-tunes",
        "/api/fine-tune",
        "/api/artifacts/upload",
    ]

    for path in upload_paths:
        url = urljoin(service.url, path)
        try:
            with httpx.Client(timeout=timeout, verify=False) as client:
                r = client.get(url, headers=headers)
                body = r.text[:3000]

                if r.status_code != 404:
                    risk_entry: dict[str, Any] = {
                        "url": url,
                        "status": r.status_code,
                        "vulnerable": False,
                        "findings": [],
                    }

                    for pattern in _PICKLE_RISK_PATTERNS:
                        if re.search(pattern, body, re.IGNORECASE):
                            if "safetensors" in pattern:
                                risk_entry["findings"].append("safetensors_detected")
                            else:
                                risk_entry["findings"].append(f"pickle_usage: {pattern}")
                                risk_entry["vulnerable"] = True

                    if r.status_code in (200, 405):
                        risk_entry["vulnerable"] = True
                        risk_entry["findings"].append("upload_endpoint_accessible")

                    if risk_entry["findings"]:
                        results.append(risk_entry)

        except Exception:
            continue

    if "huggingface.co" in service.url.lower() or "/models/" in service.url.lower():
        results.append({
            "url": service.url,
            "status": 200,
            "vulnerable": True,
            "findings": [
                "hf_model_format_risk",
                "pickle_deserialization_possible",
            ],
            "note": "HuggingFace 模型可能包含恶意 pickle 文件（safetensors 是安全替代方案）",
        })

    return results


__all__ = [
    "check_pickle_deserialization_risk",
    "_PICKLE_RISK_PATTERNS",
]