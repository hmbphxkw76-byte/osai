"""
===============================================================================
Target Data Models — 目标系统数据模型
===============================================================================
定义目标 AI 系统的标准化描述格式，
支持 basic_llm / RAG / Agent / Multi-Agent 四种架构。
===============================================================================
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class TargetArchitecture(str, Enum):
    """目标架构枚举。"""
    BASIC_LLM = "basic_llm"
    RAG = "rag"
    AGENT = "agent"
    MULTI_AGENT = "multi_agent"
    UNKNOWN = "unknown"


@dataclass
class ModelInfo:
    """模型信息。"""
    name: str = ""
    vendor: str = ""       # openai / anthropic / google / deepseek / qwen / zhipu
    architecture: TargetArchitecture = TargetArchitecture.UNKNOWN
    context_size: int = 4096
    capabilities: list[str] = field(default_factory=list)
    is_multimodal: bool = False
    supports_streaming: bool = False
    supports_function_call: bool = False


@dataclass
class DefenseProfile:
    """防御面画像。"""
    has_waf: bool = False
    waf_vendors: list[str] = field(default_factory=list)
    waf_count: int = 0
    has_guardrail: bool = False
    guardrail_type: str = ""        # input_only / output_only / both
    has_rate_limit: bool = False
    rpm_limit: int = 0
    tpm_limit: int = 0
    recommended_concurrency: int = 5
    content_filter_strength: str = "unknown"  # strict / moderate / lenient / unknown


@dataclass
class TargetProfile:
    """目标 AI 系统完整画像。

    由 L1 Recon 层输出，L2 编排层消费。
    """
    target_id: str = ""
    target_url: str = ""
    endpoint: str = ""
    api_format: str = "openai"  # openai / anthropic / gemini / raw

    # 认证
    auth_type: str = "none"     # none / api_key / bearer / cookie / jwt
    auth_value: str = ""

    # 模型与架构
    model: ModelInfo = field(default_factory=ModelInfo)
    architecture: TargetArchitecture = TargetArchitecture.UNKNOWN

    # 防御
    defenses: DefenseProfile = field(default_factory=DefenseProfile)

    # 资产
    endpoints_discovered: int = 0
    chat_endpoints: int = 0
    api_keys_leaked: int = 0
    credentials_leaked: int = 0

    # 元数据
    scan_timestamp: str = ""
    profile_source: str = ""  # recon / manual / cached


__all__ = [
    "TargetArchitecture", "ModelInfo", "DefenseProfile", "TargetProfile",
]
