# -*- coding: utf-8 -*-
"""
UnifiedFinding Schema
=====================

跨工具（pyrit-web-recon、AI-Infra-Guard、RedAmon）统一发现格式，
作为 Result Layer 去重、关联、评分、入库的公共数据契约。
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class Evidence:
    """发现证据容器"""

    # 原始请求/响应摘要
    request: Optional[str] = None
    response: Optional[str] = None
    # 截图、流量、日志等可引用外部存储
    screenshot_ref: Optional[str] = None
    transcript_ref: Optional[str] = None
    traffic_ref: Optional[str] = None
    # 任意附加证据
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UnifiedFinding:
    """统一发现模型"""

    # 基础身份
    finding_id: str = ""
    source_tool: str = ""          # pyrit-web-recon / ai-infra-guard / redamon
    task_type: str = ""            # recon / ai_infra_scan / agent_scan / model_redteam_report / mcp_scan / ai_gauntlet

    # 目标定位
    target: str = ""               # 目标域名或 IP
    endpoint_url: str = ""         # 具体端点 URL
    method: str = ""               # HTTP 方法（如适用）
    parameter: str = ""            # 参数名（如适用）

    # 风险评级
    severity: str = "info"         # critical / high / medium / low / info
    confidence: float = 0.0        # 0.0 ~ 1.0

    # 分类映射
    category: str = ""             # 工具内部分类
    owasp_llm_id: str = ""         # 如 LLM01:2025
    atlas_technique: str = ""      # 如 AML.T0051
    cwe_id: str = ""
    capec_id: str = ""
    cve_id: str = ""

    # 描述与修复
    title: str = ""
    description: str = ""
    remediation: str = ""

    # AI 红队专用指标
    ai_asr: Optional[float] = None            # Attack Success Rate
    ai_trials: Optional[int] = None           # 试验次数
    ai_payload_class: str = ""                # 如 jailbreak / prompt_injection / data_exfil
    ai_transcript_ref: Optional[str] = None   # 对话记录引用

    # 证据与溯源
    evidence: Evidence = field(default_factory=Evidence)
    session_id: str = ""           # 外部工具任务会话 ID
    raw: Dict[str, Any] = field(default_factory=dict)

    # 元数据
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        data = asdict(self)
        data["evidence"] = asdict(self.evidence)
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UnifiedFinding":
        """从字典反序列化"""
        evidence_data = data.pop("evidence", {}) or {}
        evidence = Evidence(**evidence_data)
        return cls(evidence=evidence, **data)


def dedup_findings(findings: List[UnifiedFinding]) -> List[UnifiedFinding]:
    """
    基于 (endpoint_url, owasp_llm_id, source_tool, ai_payload_class) 去重，
    同一 source_tool 的重复发现保留置信度最高的一条。
    """
    buckets: Dict[str, List[UnifiedFinding]] = {}
    for f in findings:
        key = "|".join([
            f.endpoint_url or f.target or "",
            f.owasp_llm_id or f.cwe_id or f.category or "",
            f.source_tool,
            f.ai_payload_class or "",
        ])
        buckets.setdefault(key, []).append(f)

    out: List[UnifiedFinding] = []
    for group in buckets.values():
        # 按 source_tool 再分组，保留最高置信度
        by_tool: Dict[str, UnifiedFinding] = {}
        for f in group:
            existing = by_tool.get(f.source_tool)
            if existing is None or f.confidence > existing.confidence:
                by_tool[f.source_tool] = f
        out.extend(by_tool.values())

    # 按严重级别排序：critical > high > medium > low > info
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    out.sort(key=lambda x: severity_order.get(x.severity.lower(), 99), reverse=False)
    return out
