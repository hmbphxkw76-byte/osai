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
    auth_mode: str = "none"
    notes: str = ""
    # 提取到的 API keys / tokens（注意：仅用于本地复用，禁止外传）
    extracted_credentials: List[Dict[str, Any]] = field(default_factory=list)
    # 检测到的通信协议：sse/websocket/grpc-web/http
    protocols: List[str] = field(default_factory=list)
    # RAG 特征证据
    rag_features: List[Dict[str, Any]] = field(default_factory=list)
    # Agent / Copilot / MCP 特征证据
    agent_features: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "url": self.url,
            "domain": self.domain,
            "detected_selectors": self.detected_selectors,
            "llm_api_endpoints": self.llm_api_endpoints,
            "model_name": self.model_name,
            "auth_mode": self.auth_mode,
            "notes": self.notes,
            "extracted_credentials": self.extracted_credentials,
            "protocols": self.protocols,
            "rag_features": self.rag_features,
            "agent_features": self.agent_features,
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
    fingerprint: FingerprintData = field(default_factory=FingerprintData)
    surfaces: List[str] = field(default_factory=list)
    entry_points: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)
    raw_results: Dict[str, Any] = field(default_factory=dict)
    risk_level: str = "low"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "fingerprint": self.fingerprint.to_dict(),
            "surfaces": self.surfaces,
            "entry_points": self.entry_points,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "raw_results": self.raw_results,
            "risk_level": self.risk_level,
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
