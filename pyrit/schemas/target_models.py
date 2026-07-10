"""目标系统数据模型 — TargetProfile, ModelInfo, DefenseProfile 等."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


# ============================================================
# Enums
# ============================================================

class TargetArchitecture(str, Enum):
    """目标系统架构类型."""

    BASIC_LLM = "basic_llm"                # 单模型 API
    RAG_SYSTEM = "rag_system"              # RAG 增强系统
    AGENT_SYSTEM = "agent_system"          # 单 Agent 工具调用
    MULTI_AGENT = "multi_agent"            # 多 Agent 协作
    CUSTOM = "custom"                      # 自定义架构


class GuardType(str, Enum):
    """防护类型."""

    NONE = "none"
    WAF = "waf"                            # Web 应用防火墙
    CONTENT_FILTER = "content_filter"      # 内容过滤
    INPUT_VALIDATION = "input_validation"  # 输入校验
    OUTPUT_MODERATION = "output_moderation"  # 输出审核
    RATE_LIMITING = "rate_limiting"        # 速率限制
    UNKNOWN = "unknown"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class ModelInfo:
    """模型信息."""

    provider: str = "openai"
    model_name: str = "gpt-4o"
    model_version: str = ""
    endpoint: str = "http://localhost:8080/v1"
    api_key: str = ""
    api_version: str = ""

    # 模型能力
    max_tokens: int = 4096
    supports_vision: bool = False
    supports_function_calling: bool = False
    supports_streaming: bool = True
    context_window: int = 128000

    # 元数据
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class TargetEndpoint:
    """目标端点配置."""

    url: str = ""
    method: str = "POST"
    headers: dict[str, str] = field(default_factory=dict)
    timeout: int = 60
    verify_ssl: bool = True
    proxy: Optional[str] = None


@dataclass
class DefenseProfile:
    """防护画像 — 描述目标的防御能力."""

    guard_types: list[GuardType] = field(default_factory=list)
    has_input_filter: bool = False
    has_output_filter: bool = False
    has_rate_limit: bool = False
    has_guardrails: bool = False
    rate_limit_rpm: int = 0
    rate_limit_tpm: int = 0

    # 已知绕过难度 (0.0=无防护, 1.0=极难绕过)
    bypass_difficulty: float = 0.0

    # 已知防御细节
    filter_keywords: list[str] = field(default_factory=list)
    blocked_patterns: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class TargetProfile:
    """目标系统画像 — 完整的攻击目标描述."""

    target_id: str = field(default_factory=lambda: f"target_{uuid.uuid4().hex[:8]}")
    name: str = ""
    description: str = ""

    # 架构
    architecture: TargetArchitecture = TargetArchitecture.BASIC_LLM

    # 模型
    primary_model: ModelInfo = field(default_factory=ModelInfo)
    secondary_models: list[ModelInfo] = field(default_factory=list)

    # 端点
    endpoints: list[TargetEndpoint] = field(default_factory=list)

    # 防护
    defense: DefenseProfile = field(default_factory=DefenseProfile)

    # RAG 特有属性
    has_rag: bool = False
    rag_vector_store: str = ""
    rag_document_count: int = 0
    rag_accessible_docs: list[str] = field(default_factory=list)

    # Agent 系统特有属性
    has_agents: bool = False
    agent_count: int = 0
    agent_tools: list[str] = field(default_factory=list)
    agent_roles: list[str] = field(default_factory=list)
    inter_agent_protocol: str = ""             # 如 "openai-assistants" / "langgraph" 等

    # 安全画像 (由 L1 Garak 填充)
    security_profile: Optional[Any] = None     # Garak SecurityProfile 引用
    known_vulnerabilities: list[str] = field(default_factory=list)
    vulnerability_score: float = 0.0

    # 元数据
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = ""
    tags: list[str] = field(default_factory=list)

    @property
    def is_rag_system(self) -> bool:
        """是否为 RAG 系统."""
        return self.architecture == TargetArchitecture.RAG_SYSTEM or self.has_rag

    @property
    def is_agent_system(self) -> bool:
        """是否为 Agent 系统."""
        return self.architecture in (TargetArchitecture.AGENT_SYSTEM, TargetArchitecture.MULTI_AGENT) or self.has_agents

    @property
    def is_multi_agent(self) -> bool:
        """是否为多 Agent 系统."""
        return self.architecture == TargetArchitecture.MULTI_AGENT

    @property
    def attack_surface_summary(self) -> dict[str, Any]:
        """生成攻击面摘要."""
        surface: dict[str, Any] = {
            "architecture": self.architecture.value,
            "model": self.primary_model.model_name,
            "defenses": [g.value for g in self.defense.guard_types],
            "vectors": [],
        }
        surface["vectors"].append("direct_injection")
        surface["vectors"].append("jailbreak")
        if self.is_rag_system:
            surface["vectors"].extend(["rag_retrieval", "rag_poisoning", "rag_knowledge_leak"])
        if self.is_agent_system:
            surface["vectors"].extend(["agent_tool_abuse", "agent_business_exploit"])
        if self.is_multi_agent:
            surface["vectors"].extend(["comm_hijack", "cascade_failure", "memory_poisoning"])
        surface["vectors"].extend(["xpia", "model_extraction", "membership_inference"])
        return surface
