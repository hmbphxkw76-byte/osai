# -*- coding: utf-8 -*-
"""
TargetProfile
=============

侦察阶段与攻击/评估阶段的数据契约。

定义 FingerprintData、VulnerabilityFinding、TargetProfile，
统一描述目标 LLM 应用的入口点、攻击面、指纹与风险等级。

本模块只包含纯数据模型，不包含任何 recon 业务逻辑或浏览器操作方法。
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
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
    # 部署平台推断
    deployment_platform: str = "unknown"
    # 聊天/交互 URL 列表
    chat_urls: List[str] = field(default_factory=list)
    # 提取到的 API keys / tokens（注意：仅用于本地复用，禁止外传）
    extracted_credentials: List[Dict[str, Any]] = field(default_factory=list)
    # 检测到的通信协议：sse/websocket/grpc-web/http
    protocols: List[str] = field(default_factory=list)
    # RAG 特征证据
    rag_features: List[Dict[str, Any]] = field(default_factory=list)
    # Agent / Copilot / MCP 特征证据
    agent_features: List[Dict[str, Any]] = field(default_factory=list)
    # 聚合的 LLM 特征标签
    llm_features: List[str] = field(default_factory=list)
    # 模型能力参数
    capabilities: Dict[str, Any] = field(default_factory=dict)
    # 探测阶段得到的响应容器（DOM）
    response_containers: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FingerprintData":
        # 只使用类中定义的字段，过滤未知字段保证向前兼容
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


@dataclass
class VulnerabilityFinding:
    """侦察阶段发现的潜在漏洞/攻击面"""

    owasp_category: str = ""
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    risk_level: str = "low"
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VulnerabilityFinding":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


@dataclass
class TargetProfile:
    """
    目标侦察 Profile：侦察 → 攻击/评估阶段的统一契约
    """

    target: str = ""
    target_type: str = "web_ui"  # web_ui / api / spa / unknown
    created_at: str = ""
    recon_depth: str = "standard"
    tools_used: List[str] = field(default_factory=lambda: ["ai300-recon"])
    fingerprint: FingerprintData = field(default_factory=FingerprintData)
    surfaces: List[str] = field(default_factory=list)
    entry_points: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)
    raw_results: Dict[str, Any] = field(default_factory=dict)
    risk_level: str = "low"
    # 攻击/评估建议
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

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TargetProfile":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known}

        if "fingerprint" in filtered and isinstance(filtered["fingerprint"], dict):
            filtered["fingerprint"] = FingerprintData.from_dict(filtered["fingerprint"])

        if "vulnerabilities" in filtered and isinstance(filtered["vulnerabilities"], list):
            filtered["vulnerabilities"] = [
                VulnerabilityFinding.from_dict(v) if isinstance(v, dict) else v
                for v in filtered["vulnerabilities"]
            ]

        return cls(**filtered)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    @classmethod
    def from_json(cls, text: str) -> "TargetProfile":
        return cls.from_dict(json.loads(text))

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
            api_entries = [e for e in self.entry_points if e.get("type") == "api"]
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
            f"Model: {self.fingerprint.model_name or 'unknown'}",
            f"Deployment: {self.fingerprint.deployment_platform}",
        ]
        return "\n".join(lines)
