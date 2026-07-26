# -*- coding: utf-8 -*-
"""
Target Profile
==============

侦察阶段与攻击阶段的数据契约。

定义 FingerprintData、VulnerabilityFinding、TargetProfile，
统一描述目标 LLM 应用的入口点、攻击面、指纹与风险等级。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class FingerprintData:
    """目标指纹数据"""

    title: str = ""
    url: str = ""
    domain: str = ""
    detected_selectors: Dict[str, Any] = field(default_factory=dict)
    llm_api_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    model_name: str = ""
    # 模型族，如 deepseek / qwen / gpt / claude 等
    model_family: str = ""
    # 服务提供商，如 volcengine / openai / aliyun 等
    provider: str = ""
    # 上下文窗口大小（若可识别）
    context_window: Optional[int] = None
    # 系统提示词泄漏证据
    system_prompt: Optional[str] = None
    auth_mode: str = "none"
    notes: str = ""
    # 部署平台推断：ollama / openai / azure_openai / aws_bedrock / cloudflare / aliyun / baidu / iflytek / moonshot / zhipu / deepseek / unknown
    deployment_platform: str = "unknown"
    # 聊天/交互 URL 列表（页面 URL + 跳转到的聊天页 URL）
    chat_urls: List[str] = field(default_factory=list)
    # 提取到的 API keys / tokens（注意：仅用于本地复用，禁止外传）
    extracted_credentials: List[Dict[str, Any]] = field(default_factory=list)
    # 检测到的通信协议：sse/websocket/grpc-web/http
    protocols: List[str] = field(default_factory=list)
    # RAG 特征证据
    rag_features: List[Dict[str, Any]] = field(default_factory=list)
    # Agent / Copilot / MCP 特征证据
    agent_features: List[Dict[str, Any]] = field(default_factory=list)
    # 聚合的 LLM 特征标签（如 openai_compatible, sse_streaming, rag_enabled 等）
    llm_features: List[str] = field(default_factory=list)
    # 模型能力参数，如 {"stream": true}
    capabilities: Dict[str, Any] = field(default_factory=dict)
    # 探测阶段得到的响应容器（DOM）
    response_containers: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "url": self.url,
            "domain": self.domain,
            "detected_selectors": self.detected_selectors,
            "llm_api_endpoints": self.llm_api_endpoints,
            "model_name": self.model_name,
            "model_family": self.model_family,
            "provider": self.provider,
            "context_window": self.context_window,
            "system_prompt": self.system_prompt,
            "auth_mode": self.auth_mode,
            "deployment_platform": self.deployment_platform,
            "chat_urls": self.chat_urls,
            "extracted_credentials": self.extracted_credentials,
            "protocols": self.protocols,
            "rag_features": self.rag_features,
            "agent_features": self.agent_features,
            "llm_features": self.llm_features,
            "capabilities": self.capabilities,
            "response_containers": self.response_containers,
        }


@dataclass
class VulnerabilityFinding:
    """侦察阶段发现的潜在漏洞/攻击面"""

    owasp_category: str = ""
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    risk_level: str = "low"
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "owasp_category": self.owasp_category,
            "description": self.description,
            "evidence": self.evidence,
            "risk_level": self.risk_level,
            "remediation": self.remediation,
        }


@dataclass
class TargetProfile:
    """
    目标侦察 Profile：侦察 → 攻击阶段的统一契约
    """

    target: str = ""
    target_type: str = "web_ui"  # web_ui / api / spa / unknown
    created_at: str = ""
    recon_depth: str = "standard"
    tools_used: List[str] = field(default_factory=lambda: ["pyrit-web-recon"])
    fingerprint: FingerprintData = field(default_factory=FingerprintData)
    surfaces: List[str] = field(default_factory=list)
    entry_points: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)
    raw_results: Dict[str, Any] = field(default_factory=dict)
    risk_level: str = "low"
    # 攻击建议
    attack_recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "created_at": self.created_at,
            "recon_depth": self.recon_depth,
            "tools_used": self.tools_used,
            "fingerprint": self.fingerprint.to_dict(),
            "surfaces": self.surfaces,
            "entry_points": self.entry_points,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "raw_results": self.raw_results,
            "risk_level": self.risk_level,
            "attack_recommendations": self.attack_recommendations,
        }

    def add_entry_point(
        self,
        entry_type: str,
        selector: str = "",
        url: str = "",
        api_type: str = "",
        model_name: str = "",
        score: float = 0.0,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        """添加攻击入口点"""
        entry: Dict[str, Any] = {
            "type": entry_type,
            "selector": selector,
            "url": url,
            "api_type": api_type,
            "model_name": model_name,
            "score": score,
        }
        if extra:
            entry.update(extra)
        self.entry_points.append(entry)

    def add_vulnerability(
        self,
        owasp_category: str,
        description: str,
        evidence: Optional[Dict[str, Any]] = None,
        risk_level: str = "low",
        remediation: str = "",
    ) -> None:
        """添加漏洞发现"""
        self.vulnerabilities.append(
            VulnerabilityFinding(
                owasp_category=owasp_category,
                description=description,
                evidence=evidence or {},
                risk_level=risk_level,
                remediation=remediation,
            )
        )

    def classify_risk(self) -> str:
        """根据发现的攻击面评估风险等级"""
        risk_scores = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        max_score = 0
        for v in self.vulnerabilities:
            max_score = max(max_score, risk_scores.get(v.risk_level, 1))
        if self.entry_points:
            api_entries = [e for e in self.entry_points if e["type"] == "api"]
            if api_entries:
                max_score = max(max_score, 3)
        reverse_map = {v: k for k, v in risk_scores.items()}
        return reverse_map.get(max_score, "low")

    def summarize(self) -> str:
        """文本摘要"""
        lines = [
            f"Target: {self.target}",
            f"Type: {self.target_type}",
            f"Risk: {self.risk_level}",
            f"Surfaces: {', '.join(self.surfaces) or 'none'}",
            f"Entry Points: {len(self.entry_points)}",
            f"Vulnerabilities: {len(self.vulnerabilities)}",
        ]
        return "\n".join(lines)

    def to_pyrit_target(self) -> Dict[str, Any]:
        """
        导出 PyRIT 兼容的 target 配置。

        PyRIT 常见 target 类型：
          - AzureOpenAITarget / OpenAITarget / HTTPClientTarget
          - PromptTarget 子类通常需要 endpoint + api_key + model_name
        """
        api_entries = [ep for ep in self.entry_points if ep.get("type") == "api"]
        web_entries = [ep for ep in self.entry_points if ep.get("type") == "web_ui"]

        # 取最合适的 API 入口作为攻击目标：优先 chat/completions，其次 generate，最后取首个
        primary_api = {}
        if api_entries:
            for entry in api_entries:
                url = entry.get("url", "").lower().split("?")[0].split("#")[0].rstrip("/")
                if url.endswith("/chat/completions") or url.endswith("/generate"):
                    primary_api = entry
                    break
            if not primary_api:
                primary_api = api_entries[0]
        primary_web = web_entries[0] if web_entries else {}

        target = {
            "target_type": "http_client" if primary_api else "web_ui",
            "endpoint": primary_api.get("url", self.target),
            "model_name": primary_api.get("model_name", self.fingerprint.model_name),
            "api_type": primary_api.get("api_type", "openai_compatible"),
            "deployment_platform": self.fingerprint.deployment_platform,
            "protocols": self.fingerprint.protocols,
            "headers": {},
        }

        # 从提取到的凭据中恢复 Authorization / Cookie
        for cred in self.fingerprint.extracted_credentials:
            for key in cred.get("keys", []):
                if key.get("type") == "api_key_header" and key.get("header"):
                    target["headers"][key["header"]] = f"Bearer {key.get('prefix', '')}..."

        if primary_web:
            target["web_ui"] = {
                "url": self.target,
                "input_selector": primary_web.get("selector", ""),
                "send_selector": primary_web.get("send_selector", ""),
                "response_selector": primary_web.get("response_selector", ""),
            }

        return target
