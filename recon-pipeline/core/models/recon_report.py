# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""ReconReport: 统一侦察结果数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EndpointType(str, Enum):
    MODEL_API = "model_api"
    RAG_API = "rag_api"
    AGENT_TOOL_API = "agent_tool_api"
    MCP_SERVER = "mcp_server"
    EMBEDDING_API = "embedding_api"
    AUTH_API = "auth_api"
    FILE_UPLOAD = "file_upload"
    UNKNOWN = "unknown"


class InjectionSurfaceType(str, Enum):
    FILE_UPLOAD_FORM = "file_upload_form"
    MULTIMODAL_INPUT = "multimodal_input"
    AGENT_TOOL_PANEL = "agent_tool_panel"
    CHAT_INPUT = "chat_input"
    CUSTOM_INPUT = "custom_input"


@dataclass
class DiscoveredEndpoint:
    url: str
    method: str = "GET"
    endpoint_type: EndpointType = EndpointType.UNKNOWN
    status_code: int | None = None
    content_type: str | None = None
    request_headers: dict[str, str] = field(default_factory=dict)
    response_body_preview: str = ""
    discovered_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "endpoint_type": self.endpoint_type.value,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "response_body_preview": self.response_body_preview[:200],
            "discovered_at": self.discovered_at,
        }


@dataclass
class LLMFingerprint:
    model_family: str = ""
    model_name: str = ""
    system_prompt_hint: str = ""
    capabilities: list[str] = field(default_factory=list)
    guardrail_detected: bool = False
    endpoint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_family": self.model_family,
            "model_name": self.model_name,
            "system_prompt_hint": self.system_prompt_hint[:200],
            "capabilities": self.capabilities,
            "guardrail_detected": self.guardrail_detected,
            "endpoint": self.endpoint,
        }


@dataclass
class MCPToolInfo:
    tool_name: str = ""
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    risk_level: str = "low"
    shadowing_detected: bool = False
    server_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "description": self.description[:200],
            "risk_level": self.risk_level,
            "shadowing_detected": self.shadowing_detected,
            "server_url": self.server_url,
        }


@dataclass
class InjectionSurface:
    selector: str = ""
    surface_type: InjectionSurfaceType = InjectionSurfaceType.CHAT_INPUT
    element_tag: str = ""
    attributes: dict[str, str] = field(default_factory=dict)
    owasp_ids: list[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
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
    owasp_id: str = ""
    attack_strategy: str = ""
    target_type: str = ""
    converter: str | None = None
    rationale: str = ""
    priority: int = 3
    related_endpoints: list[str] = field(default_factory=list)
    related_surfaces: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
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
class ReconReport:
    target_url: str = ""
    auth_type: str = "none"
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    llm_fingerprints: list[LLMFingerprint] = field(default_factory=list)
    mcp_tools: list[MCPToolInfo] = field(default_factory=list)
    injection_surfaces: list[InjectionSurface] = field(default_factory=list)
    recommendations: list[AttackRecommendation] = field(default_factory=list)
    domain_transitions: list[str] = field(default_factory=list)
    recon_duration_seconds: float = 0.0
    probe_results: dict[str, Any] = field(default_factory=dict)

    def merge(self, probe_name: str, result: dict[str, Any]) -> None:
        self.probe_results[probe_name] = result
        for ep_data in result.get("endpoints", []):
            if isinstance(ep_data, DiscoveredEndpoint):
                self.endpoints.append(ep_data)
            elif isinstance(ep_data, dict):
                self.endpoints.append(DiscoveredEndpoint(**ep_data))
        for fp in result.get("llm_fingerprints", []):
            if isinstance(fp, LLMFingerprint):
                self.llm_fingerprints.append(fp)
        for tool in result.get("mcp_tools", []):
            if isinstance(tool, MCPToolInfo):
                self.mcp_tools.append(tool)
        for s in result.get("injection_surfaces", []):
            if isinstance(s, InjectionSurface):
                self.injection_surfaces.append(s)

    @property
    def has_model_api(self) -> bool:
        return any(e.endpoint_type == EndpointType.MODEL_API for e in self.endpoints)

    @property
    def has_rag_api(self) -> bool:
        return any(e.endpoint_type == EndpointType.RAG_API for e in self.endpoints)

    @property
    def has_agent_tools(self) -> bool:
        return any(e.endpoint_type == EndpointType.AGENT_TOOL_API for e in self.endpoints)

    @property
    def has_mcp_server(self) -> bool:
        return any(e.endpoint_type == EndpointType.MCP_SERVER for e in self.endpoints) or bool(self.mcp_tools)

    @property
    def has_embedding_api(self) -> bool:
        return any(e.endpoint_type == EndpointType.EMBEDDING_API for e in self.endpoints)

    @property
    def has_file_upload(self) -> bool:
        return any(s.surface_type == InjectionSurfaceType.FILE_UPLOAD_FORM for s in self.injection_surfaces)

    @property
    def has_multimodal_input(self) -> bool:
        return any(s.surface_type == InjectionSurfaceType.MULTIMODAL_INPUT for s in self.injection_surfaces)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "auth_type": self.auth_type,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "llm_fingerprints": [f.to_dict() for f in self.llm_fingerprints],
            "mcp_tools": [t.to_dict() for t in self.mcp_tools],
            "injection_surfaces": [s.to_dict() for s in self.injection_surfaces],
            "recommendations": [r.to_dict() for r in self.recommendations],
            "domain_transitions": self.domain_transitions,
            "recon_duration_seconds": self.recon_duration_seconds,
            "has_model_api": self.has_model_api,
            "has_rag_api": self.has_rag_api,
            "has_agent_tools": self.has_agent_tools,
            "has_mcp_server": self.has_mcp_server,
            "has_embedding_api": self.has_embedding_api,
            "has_file_upload": self.has_file_upload,
            "has_multimodal_input": self.has_multimodal_input,
        }

    def to_summary_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "auth_type": self.auth_type,
            "endpoint_count": len(self.endpoints),
            "llm_fingerprint_count": len(self.llm_fingerprints),
            "mcp_tool_count": len(self.mcp_tools),
            "surface_count": len(self.injection_surfaces),
            "recommendation_count": len(self.recommendations),
            "has_model_api": self.has_model_api,
            "has_rag_api": self.has_rag_api,
            "has_agent_tools": self.has_agent_tools,
            "has_mcp_server": self.has_mcp_server,
            "has_embedding_api": self.has_embedding_api,
            "has_file_upload": self.has_file_upload,
            "has_multimodal_input": self.has_multimodal_input,
            "recommendations": [r.to_dict() for r in self.recommendations],
        }

    def summary(self) -> str:
        lines = [
            "ReconReport Summary:",
            f"  Target: {self.target_url}",
            f"  Auth: {self.auth_type}",
            f"  Endpoints: {len(self.endpoints)} found",
            f"  LLM Fingerprints: {len(self.llm_fingerprints)}",
            f"  MCP Tools: {len(self.mcp_tools)}",
            f"  Injection Surfaces: {len(self.injection_surfaces)}",
            f"  Recommendations: {len(self.recommendations)}",
        ]
        return "\n".join(lines)
