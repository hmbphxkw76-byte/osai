# -*- coding: utf-8 -*-
"""
Target Profile
==============

ai300-recon 对 ai300-schemas 的薄封装。

侦察阶段与攻击/评估阶段的数据契约由 ai300-schemas 统一维护，
本模块仅保留 ai300-recon 特有的 recon 后处理方法（如 PyRIT target 构造）。
"""

from __future__ import annotations

from typing import Any, Dict

from ai300_schemas import (
    FingerprintData,
    TargetProfile,
    VulnerabilityFinding,
)

__all__ = [
    "FingerprintData",
    "TargetProfile",
    "VulnerabilityFinding",
    "build_pyrit_target",
]


def build_pyrit_target(profile: TargetProfile) -> Dict[str, Any]:
    """
    从 TargetProfile 导出 PyRIT 兼容的 target 配置。

    PyRIT 常见 target 类型：
      - AzureOpenAITarget / OpenAITarget / HTTPClientTarget
      - PromptTarget 子类通常需要 endpoint + api_key + model_name
    """
    api_entries = [ep for ep in profile.entry_points if ep.get("type") == "api"]
    web_entries = [ep for ep in profile.entry_points if ep.get("type") == "web_ui"]

    # 取最合适的 API 入口作为攻击目标：优先 chat/completions，其次 generate，最后取首个
    primary_api: Dict[str, Any] = {}
    if api_entries:
        for entry in api_entries:
            url = entry.get("url", "").lower().split("?")[0].split("#")[0].rstrip("/")
            if url.endswith("/chat/completions") or url.endswith("/generate"):
                primary_api = entry
                break
        if not primary_api:
            primary_api = api_entries[0]
    primary_web = web_entries[0] if web_entries else {}

    target: Dict[str, Any] = {
        "target_type": "http_client" if primary_api else "web_ui",
        "endpoint": primary_api.get("url", profile.target),
        "model_name": primary_api.get("model_name", profile.fingerprint.model_name),
        "api_type": primary_api.get("api_type", "openai_compatible"),
        "deployment_platform": profile.fingerprint.deployment_platform,
        "protocols": profile.fingerprint.protocols,
        "headers": {},
    }

    # 从 LLM API 端点原始请求头中恢复 Authorization（优先）
    primary_endpoint = None
    for ep in profile.fingerprint.llm_api_endpoints:
        if ep.get("url") == primary_api.get("url"):
            primary_endpoint = ep
            break
    if not primary_endpoint and profile.fingerprint.llm_api_endpoints:
        primary_endpoint = profile.fingerprint.llm_api_endpoints[0]

    if primary_endpoint:
        req_headers = primary_endpoint.get("request_headers", {})
        for hname, hvalue in req_headers.items():
            lower = hname.lower()
            if lower in ("authorization", "x-api-key", "api-key") and hvalue:
                # 导出时掩码敏感 token，只保留前 12 个字符
                parts = hvalue.split()
                if len(parts) == 2 and parts[0].lower() in ("bearer", "token"):
                    target["headers"][hname] = f"{parts[0]} {parts[1][:12]}..."
                else:
                    target["headers"][hname] = f"{hvalue[:12]}..."

    # 从提取到的凭据中恢复 Authorization / Cookie（兜底）
    for cred in profile.fingerprint.extracted_credentials:
        for key in cred.get("keys", []):
            if key.get("type") == "api_key_header" and key.get("header"):
                target["headers"][key["header"]] = f"Bearer {key.get('prefix', '')}..."

    if primary_web:
        target["web_ui"] = {
            "url": profile.target,
            "input_selector": primary_web.get("selector", ""),
            "send_selector": primary_web.get("send_selector", ""),
            "response_selector": primary_web.get("response_selector", ""),
        }

    return target
