"""基础设施模块。

核心组件：
  - models.py: pydantic 数据模型（AI-300 课程数据契约）
  - store.py: 本地存储抽象层
  - tools.py: 通用工具函数
  - http_client.py: 统一 HTTP 客户端（支持 httpx → requests → urllib 降级）
"""
from .models import (
    AIProtocol, AIStackLayer, AIService, AuthContext,
    AttackChain, AttackStep, ContentCategory, Finding,
    GuardrailProfile, GuardrailType, MITREATLASTactic,
    ModelFingerprint, OWASPLlm, PromptInjectionResult,
    RAGPipelineProfile, RAGSource, ReconResult, ReportConfig,
    Severity,
)
from .store import (
    save_json, load_json, save_recon, load_recon,
    save_findings, load_findings, make_run_id,
)
from .tools import ToolResolver
from .http_client import (
    send_post, send_get, send_chat,
)

__all__ = [
    # 模型
    "AIProtocol", "AIStackLayer", "AIService", "AuthContext",
    "AttackChain", "AttackStep", "ContentCategory", "Finding",
    "GuardrailProfile", "GuardrailType", "MITREATLASTactic",
    "ModelFingerprint", "OWASPLlm", "PromptInjectionResult",
    "RAGPipelineProfile", "RAGSource", "ReconResult", "ReportConfig",
    "Severity",
    # 存储
    "save_json", "load_json", "save_recon", "load_recon",
    "save_findings", "load_findings", "make_run_id",
    # 工具
    "ToolResolver",
    # HTTP 客户端
    "send_post", "send_get", "send_chat",
]