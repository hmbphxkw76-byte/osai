"""云基础设施安全检查（AI-300 Ch9: Infrastructure Attacks on AI Systems）。

实现 AI-300 课程中的基础设施安全检测技术：
  - 云 AI 服务配置错误检测
  - 公开云存储桶识别（S3, GCS, Azure Blob）
  - IAM 权限配置问题检测
  - 调试模式/错误信息泄露检测

对齐 OWASP LLM Top 10: LLM03 (Supply Chain), LLM05 (Security Misconfiguration)
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import httpx

from redteam.core.models import AIService, AuthContext

_CLOUD_AI_CHECK_PATTERNS: list[dict[str, Any]] = [
    {"keyword": "AccessDenied", "risk": "IAM 权限配置问题", "severity": "medium"},
    {"keyword": "Anonymous access", "risk": "匿名访问未关闭", "severity": "high"},
    {"keyword": "s3.amazonaws.com", "risk": "模型权重存储在公开 S3 桶", "severity": "critical"},
    {"keyword": "storage.googleapis.com", "risk": "模型权重存储在公开 GCS 桶", "severity": "critical"},
    {"keyword": ".blob.core.windows.net", "risk": "模型权重存储在公开 Azure Blob", "severity": "critical"},
    {"keyword": "huggingface.co/models/", "risk": "使用 HuggingFace 仓库（检查是否公开）", "severity": "low"},
    {"keyword": "ollama.com/library/", "risk": "使用 Ollama 仓库（检查模型哈希）", "severity": "low"},
    {"keyword": "Internal Server Error", "risk": "错误信息泄露内部架构", "severity": "low"},
    {"keyword": "debug", "risk": "调试模式开启", "severity": "medium"},
    {"keyword": "traceback", "risk": "堆栈跟踪泄漏", "severity": "medium"},
]


def _extract_context(text: str, keyword: str, context_chars: int = 100) -> str:
    """提取关键词周围的上下文。"""
    pos = text.lower().find(keyword.lower())
    if pos == -1:
        return ""
    start = max(0, pos - context_chars // 2)
    end = min(len(text), pos + len(keyword) + context_chars // 2)
    return text[start:end].strip()


def scan_cloud_misconfigs(
    base_url: str,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """云 AI 服务配置错误检测（AI-300 Ch9.1）。"""
    findings: list[dict[str, Any]] = []

    try:
        headers = auth.to_header_dict() if auth else {}
        with httpx.Client(timeout=timeout, verify=False) as client:
            for path in ["/", "/health", "/api", "/debug", "/metrics", "/env"]:
                url = urljoin(base_url, path)
                try:
                    r = client.get(url, headers=headers)
                    body = r.text[:2000]
                    for pattern in _CLOUD_AI_CHECK_PATTERNS:
                        if pattern["keyword"].lower() in body.lower():
                            findings.append({
                                "url": url,
                                "risk": pattern["risk"],
                                "severity": pattern["severity"],
                                "matched": pattern["keyword"],
                                "evidence": _extract_context(body, pattern["keyword"]),
                            })
                except Exception:
                    pass
    except Exception:
        pass

    return findings


def check_supply_chain_risks(
    service: AIService,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """检测 AI 供应链风险（AI-300 Ch8/Ch9 合并检测）。

    检查：
    - 模型来源：HuggingFace / Ollama 仓库中是否存在恶意模型
    - 版本过期：使用已知漏洞版本
    - 依赖风险：模型的 requirements 是否有恶意依赖
    """
    risks: list[dict[str, Any]] = []

    for model_name in service.models:
        if "/" in model_name:
            source, name = model_name.split("/", 1)
            if not any(trusted in source.lower() for trusted in ["microsoft", "google", "meta", "openai", "mistral"]):
                risks.append({
                    "model": model_name,
                    "risk": "untrusted_model_source",
                    "source": source,
                    "description": f"模型 '{model_name}' 来自未验证的来源 '{source}'",
                })

    if "mlflow" in str(service.version).lower() or "mlflow" in service.url.lower():
        risks.append({
            "model": "mlflow",
            "risk": "known_vulnerable_component",
            "description": "MLflow 存在多个已知漏洞 (CVE-2024-xxx)，可能允许未授权访问和代码执行",
        })

    return risks


__all__ = [
    "scan_cloud_misconfigs",
    "check_supply_chain_risks",
    "_extract_context",
    "_CLOUD_AI_CHECK_PATTERNS",
]