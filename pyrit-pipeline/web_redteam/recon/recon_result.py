# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""侦察结果数据模型。.

定义 ReconResult 及其子结构, 贯穿 Stage 0 → Bridge → 主 Pipeline。

数据流:
  Stage 0 (Recon) 产出 ReconResult
    → Bridge 将 ReconResult 注入 PipelineContext.metadata["recon_result"]
    → Stage 1.5 (WebAuth) 读取 ReconResult 增强 Target 创建
    → Stage 2 (Scenario) 读取 AttackRecommendation 选择攻击场景

> **日期**: 2026-8-2
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class EndpointType(str, Enum):
    """发现的 API 端点类型。."""

    MODEL_API = "model_api"          # /v1/chat/completions, /v1/responses
    RAG_API = "rag_api"              # /api/search, /api/retrieve, /api/embeddings
    AGENT_TOOL_API = "agent_tool_api"  # /tools/, /function/, fetch_website
    AUTH_API = "auth_api"            # /oauth/, /token, /login
    FILE_UPLOAD = "file_upload"      # 文件上传端点 (知识库投毒入口)
    UNKNOWN = "unknown"


class InjectionSurfaceType(str, Enum):
    """DOM 注入面类型。."""

    FILE_UPLOAD_FORM = "file_upload_form"    # 文件上传表单
    MULTIMODAL_INPUT = "multimodal_input"    # 图像/音频上传
    AGENT_TOOL_PANEL = "agent_tool_panel"    # Agent 工具面板
    CHAT_INPUT = "chat_input"                # 聊天输入框
    CUSTOM_INPUT = "custom_input"            # 其他自定义输入


@dataclass
class DiscoveredEndpoint:
    """发现的 API 端点。.

    Attributes:
        url: 端点 URL.
        method: HTTP 方法 (GET/POST/PUT/DELETE).
        endpoint_type: 端点类型分类.
        status_code: HTTP 响应状态码 (如有).
        content_type: 响应 Content-Type (如有).
        request_headers: 请求头摘要 (认证 Token 等, 脱敏).
        response_body_preview: 响应体预览 (前 200 字符).
        discovered_at: 发现时间戳 (ISO 格式).
    """

    url: str
    method: str = "GET"
    endpoint_type: EndpointType = EndpointType.UNKNOWN
    status_code: int | None = None
    content_type: str | None = None
    request_headers: dict[str, str] = field(default_factory=dict)
    response_body_preview: str = ""
    discovered_at: str = ""

    def to_dict(self) -> dict[str, object]:
        """序列化为字典。."""
        return {
            "url": self.url,
            "method": self.method,
            "endpoint_type": self.endpoint_type.value,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "request_headers": _sanitize_headers(self.request_headers),
            "response_body_preview": self.response_body_preview[:200],
            "discovered_at": self.discovered_at,
        }


@dataclass
class InjectionSurface:
    """DOM 注入面。.

    Attributes:
        selector: CSS 选择器.
        surface_type: 注入面类型.
        element_tag: HTML 标签.
        attributes: 关键属性 (accept, multiple 等).
        owasp_ids: 关联的 OWASP LLM 类别.
        description: 人类可读描述.
    """

    selector: str
    surface_type: InjectionSurfaceType = InjectionSurfaceType.CHAT_INPUT
    element_tag: str = ""
    attributes: dict[str, str] = field(default_factory=dict)
    owasp_ids: list[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict[str, object]:
        """序列化为字典。."""
        return {
            "selector": self.selector,
            "surface_type": self.surface_type.value,
            "element_tag": self.element_tag,
            "attributes": self.attributes,
            "owasp_ids": self.owasp_ids,
            "description": self.description,
        }


@dataclass
class AttackRecommendation:
    """基于侦察结果的攻击推荐。.

    Attributes:
        owasp_id: 关联的 OWASP LLM 类别 (LLM01-LLM10).
        attack_strategy: 推荐的 PyRIT 攻击策略.
        target_type: 推荐的 PyRIT Target 类型.
        converter: 推荐的 PyRIT Converter (可选).
        rationale: 推荐理由.
        priority: 优先级 (1=最高, 5=最低).
        related_endpoints: 关联的端点 URL 列表.
        related_surfaces: 关联的注入面选择器列表.
    """

    owasp_id: str
    attack_strategy: str
    target_type: str
    converter: str | None = None
    rationale: str = ""
    priority: int = 3
    related_endpoints: list[str] = field(default_factory=list)
    related_surfaces: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """序列化为字典。."""
        return {
            "owasp_id": self.owasp_id,
            "attack_strategy": self.attack_strategy,
            "target_type": self.target_type,
            "converter": self.converter,
            "rationale": self.rationale,
            "priority": self.priority,
            "related_endpoints": self.related_endpoints,
            "related_surfaces": self.related_surfaces,
        }


@dataclass
class ReconResult:
    """完整侦察结果。.

    汇总 NetworkInterceptor + DOMAnalyzer + AuthProbe 的发现,
    并包含 AttackRecommender 生成的攻击推荐列表。

    Attributes:
        target_url: 目标 URL.
        auth_type: 认证拓扑 ("none" | "same_domain" | "cross_domain").
        endpoints: 发现的 API 端点列表.
        injection_surfaces: 发现的 DOM 注入面列表.
        recommendations: 攻击推荐列表 (按优先级排序).
        domain_transitions: 域名跳转链.
        recon_duration_seconds: 侦察耗时 (秒).
    """

    target_url: str = ""
    auth_type: str = "none"
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    injection_surfaces: list[InjectionSurface] = field(default_factory=list)
    recommendations: list[AttackRecommendation] = field(default_factory=list)
    domain_transitions: list[str] = field(default_factory=list)
    recon_duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, object]:
        """序列化为字典 (供 JSON 持久化和 Bridge 传递)。."""
        return {
            "target_url": self.target_url,
            "auth_type": self.auth_type,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "injection_surfaces": [s.to_dict() for s in self.injection_surfaces],
            "recommendations": [r.to_dict() for r in self.recommendations],
            "domain_transitions": self.domain_transitions,
            "recon_duration_seconds": self.recon_duration_seconds,
        }

    @property
    def has_agent_tools(self) -> bool:
        """是否发现 Agent 工具调用端点。."""
        return any(
            e.endpoint_type == EndpointType.AGENT_TOOL_API for e in self.endpoints
        )

    @property
    def has_rag_endpoints(self) -> bool:
        """是否发现 RAG API 端点。."""
        return any(
            e.endpoint_type == EndpointType.RAG_API for e in self.endpoints
        )

    @property
    def has_file_upload(self) -> bool:
        """是否发现文件上传表单。."""
        return any(
            s.surface_type == InjectionSurfaceType.FILE_UPLOAD_FORM
            for s in self.injection_surfaces
        )

    @property
    def has_multimodal_input(self) -> bool:
        """是否发现多模态输入面。."""
        return any(
            s.surface_type == InjectionSurfaceType.MULTIMODAL_INPUT
            for s in self.injection_surfaces
        )

    def get_recommendations_by_owasp(self, owasp_id: str) -> list[AttackRecommendation]:
        """按 OWASP ID 过滤攻击推荐。."""
        return [r for r in self.recommendations if r.owasp_id == owasp_id]

    def summary(self) -> str:
        """人类可读的侦察摘要。."""
        lines = [
            "ReconResult Summary:",
            f"  Target: {self.target_url}",
            f"  Auth: {self.auth_type}",
            f"  Endpoints: {len(self.endpoints)} found",
            f"    Model API: {sum(1 for e in self.endpoints if e.endpoint_type == EndpointType.MODEL_API)}",
            f"    RAG API: {sum(1 for e in self.endpoints if e.endpoint_type == EndpointType.RAG_API)}",
            f"    Agent Tool: {sum(1 for e in self.endpoints if e.endpoint_type == EndpointType.AGENT_TOOL_API)}",
            f"    File Upload: {sum(1 for e in self.endpoints if e.endpoint_type == EndpointType.FILE_UPLOAD)}",
            f"  Injection Surfaces: {len(self.injection_surfaces)} found",
            f"  Recommendations: {len(self.recommendations)} (priority sorted)",
        ]
        for rec in self.recommendations[:5]:
            lines.append(f"    [{rec.priority}] {rec.owasp_id} → {rec.attack_strategy} ({rec.target_type})")
        return "\n".join(lines)


def _sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    """脱敏请求头 (隐藏 Authorization / Cookie 值)。."""
    sensitive_keys = {"authorization", "cookie", "x-api-key", "x-auth-token"}
    sanitized: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in sensitive_keys:
            sanitized[key] = f"***{value[-4:]}" if len(value) > 4 else "***"
        else:
            sanitized[key] = value
    return sanitized
