"""HuggingFace 模型来源检测（AI-300 Ch8: Supply Chain Attacks）。

实现 AI-300 课程中的模型来源可信度检查：
  - 可信来源验证（Microsoft, Google, Meta, OpenAI 等）
  - 高风险来源检测（anonymous, user, test 等）
  - 模型名称异常检测（backdoor, poison, malware 等）
  - safetensors vs pickle 格式识别

对齐 OWASP LLM Top 10: LLM03 (Supply Chain Vulnerabilities)
"""
from __future__ import annotations

import re
from typing import Any

from redteam.core.models import AIService

_TRUSTED_MODEL_SOURCES: set[str] = {
    "microsoft", "google", "meta", "openai", "mistral",
    "anthropic", "deepseek", "qwen", "baichuan", "yi",
    "nvidia", "intel", "ibm", "amazon", "baai",
    "sentence-transformers", "thenlper", "huggingface",
}

_HIGH_RISK_SOURCES: set[str] = {
    "anonymous", "user", "test", "demo", "temp", "tmp",
    "backup", "old", "deprecated", "staging", "dev",
}


def detect_hf_model_source(
    service: AIService,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """检测 HuggingFace 模型来源的可信度（AI-300 Ch8.1）。"""
    results: list[dict[str, Any]] = []

    for model_name in service.models:
        result: dict[str, Any] = {
            "model_name": model_name,
            "source": "unknown",
            "trusted": False,
            "risk_level": "unknown",
            "issues": [],
        }

        if "/" in model_name:
            source, name = model_name.split("/", 1)
            result["source"] = source
            result["model_short_name"] = name

            source_lower = source.lower()

            if any(trusted in source_lower for trusted in _TRUSTED_MODEL_SOURCES):
                result["trusted"] = True
                result["risk_level"] = "low"

            if any(high_risk in source_lower for high_risk in _HIGH_RISK_SOURCES):
                result["risk_level"] = "high"
                result["issues"].append("suspicious_source_name")

            if re.search(r"(backdoor|poison|malware|exploit|trojan)", name.lower()):
                result["risk_level"] = "critical"
                result["issues"].append("malicious_name_pattern")

            if "safetensors" in name.lower():
                result["issues"].append("uses_safetensors_format")
            else:
                result["issues"].append("possible_pickle_format")

        elif any(model_name.startswith(p) for p in ["gpt-", "claude-", "gemini-", "llama-"]):
            result["source"] = "proprietary"
            result["trusted"] = True
            result["risk_level"] = "low"
            result["issues"].append("closed_source_model")

        else:
            result["source"] = "inline"
            result["risk_level"] = "medium"
            result["issues"].append("unknown_format")

        results.append(result)

    if "hf.space" in service.url.lower() or "huggingface" in service.url.lower():
        results.append({
            "model_name": "hf_inference_endpoint",
            "source": "huggingface_spaces",
            "trusted": False,
            "risk_level": "medium",
            "issues": ["public_hf_endpoint", "inference_api_exposed"],
            "note": "HuggingFace Spaces 推理端点暴露，可能存在无认证调用风险",
        })

    return results


__all__ = [
    "detect_hf_model_source",
    "_TRUSTED_MODEL_SOURCES",
    "_HIGH_RISK_SOURCES",
]