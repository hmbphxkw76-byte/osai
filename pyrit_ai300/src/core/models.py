"""
Core Models
===========

本模块定义框架各层之间传递的数据结构（遵循开发规则 1.4.4）。

所有数据结构使用 Pydantic 模型，确保类型安全和可验证性。
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from pydantic import BaseModel, Field

# PyRIT 原生 TargetCapabilities（对齐 L5 专家水准）
# 原生模型为 frozen=True，使用 frozenset[frozenset[str]] 模态表示
# 详见 pyrit.models.target.target_capabilities
from pyrit.models import TargetCapabilities as _PyRITTargetCapabilities

# Re-export 原生 TargetCapabilities，使项目代码统一使用原生类型
TargetCapabilities = _PyRITTargetCapabilities

# ============================================================
# 枚举类型
# ============================================================


class AISystemType(str, Enum):
    """AI 系统类型（标注 PyRIT 攻击能力）"""

    LLM = "llm"
    MULTI_AGENT = "multi_agent"
    MCP_SERVER = "mcp_server"
    RAG = "rag"
    EMBEDDINGS = "embeddings"  # 非PyRIT优势，仅端点识别
    INFRASTRUCTURE = "infrastructure"  # 非PyRIT优势，仅端点识别
    UNKNOWN = "unknown"

    def is_pyrit_attackable(self) -> bool:
        """判断该类型是否可用 PyRIT 攻击"""
        return self in (AISystemType.LLM, AISystemType.MULTI_AGENT, AISystemType.MCP_SERVER, AISystemType.RAG)


class AuthType(str, Enum):
    """认证类型"""

    NONE = "none"
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer_token"
    COOKIE = "cookie"
    OAUTH = "oauth"
    FORM_BASED = "form_based"
    SPA_WEB = "spa_web"
    UNKNOWN = "unknown"


class AuthStatus(str, Enum):
    """认证状态"""

    SUCCESS = "success"
    FAILED = "failed"
    CAPTCHA_REQUIRED = "captcha_required"
    MFA_REQUIRED = "mfa_required"
    TOKEN_EXPIRED = "token_expired"
    AUTH_FAILED = "auth_failed"


# ============================================================
# 侦察层模型
# ============================================================


# TargetCapabilities 已使用 PyRIT 原生类型（上方 re-export）
# 如需可变能力对象，请使用 model_copy(update={...}) 创建新实例


class ReconResult(BaseModel):
    """侦察结果（侦察层 → 认证层）"""

    target_url: str
    detected_endpoint: str
    auth_type: AuthType
    auth_config: Dict[str, Any] = Field(default_factory=dict)
    ai_system_type: AISystemType
    capabilities: TargetCapabilities = Field(default_factory=TargetCapabilities)
    tech_stack: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # 外部工具推荐（仅非 PyRIT 优势类型）
    external_tools: Optional[List[str]] = None

    # 原始能力探测响应（扩展字段，不在原生 TargetCapabilities 中）
    raw_capability_response: Optional[Dict[str, Any]] = None

    # 模型过滤强度等级（探测式或静态推断）
    # "strong" — 强内容过滤 (GPT-4o, Claude 4, Gemini 2.5 Pro 等)
    # "moderate" — 中等过滤 (Llama 3.3, Qwen 3, DeepSeek V3 等)
    # "weak" — 弱过滤 (小参数开源模型等)
    # "unknown" — 未知
    model_tier: str = "unknown"
    # 探测详情（探针响应摘要，供调试/展示使用）
    model_tier_probe_detail: Optional[Dict[str, Any]] = None

    # v3.0: PyRIT Target 类型名（由 TargetFactory.detect_target_type 检测）
    # 用于载荷预筛选 + Target 感知 Converter 路由
    # 如 "openai_chat", "http_api", "playwright" 等
    target_type: str = ""


# ============================================================
# 认证元数据模型（用于侦察 → 分析层数据传递）
# 注意：实际 Target 认证由 TargetFactory + PyRIT 原生 pyrit.auth 处理
# ============================================================


class AuthResult(BaseModel):
    """认证结果元数据（侦察层 → 分析层）"""

    target_url: str
    auth_type: AuthType
    status: AuthStatus
    error_message: Optional[str] = None
    auth_headers: Dict[str, str] = Field(default_factory=dict)
    session_data: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================
# 分析层模型
# ============================================================


class StrategySelection(BaseModel):
    """策略选择结果（分析层 → 攻击层）"""

    ai_system_type: AISystemType
    scenario_name: str
    attack_techniques: List[str]
    dataset_names: List[str]
    max_concurrency: int
    memory_labels: Dict[str, str] = Field(default_factory=dict)

    # 注意：AttackScoringConfig 和 AttackConverterConfig 是 PyRIT 原生类型
    # 不包含在 Pydantic 模型中，由 analysis 层直接构造

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================
# 报告层模型
# ============================================================


class OWASPFinding(BaseModel):
    """
    OWASP 漏洞发现

    支持两个 OWASP 安全标准：
    - OWASP Top 10 for LLM Applications 2025: owasp_id 为 LLM01-LLM10
    - OWASP Top 10 for Agentic AI: owasp_id 为 ASI01-ASI10
    """

    owasp_id: str  # LLM01-LLM10 或 ASI01-ASI10
    owasp_name: str
    owasp_framework: str = "llm"  # "llm" (2025) 或 "agentic"
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: float
    attack_type: str
    description: str
    indicators: List[str]
    remediation: List[str]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    kill_chain_phases: List[str] = Field(default_factory=list)


class AttackEvidence(BaseModel):
    """攻击证据"""

    evidence_id: str
    attack_type: str
    scenario_name: str
    objective: str
    conversation_id: str
    timestamp: datetime
    score: float
    response_text: str
    is_successful: bool
    converter_chain: Optional[List[str]] = None


class ReportSummary(BaseModel):
    """报告摘要"""

    total_targets: int
    pyrit_attackable_targets: int
    external_tool_targets: int
    total_attacks: int
    successful_attacks: int
    total_scenarios: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    success_rate: float

    # 反馈循环统计
    upgrade_attempts: int = 0
    upgrade_success: int = 0

    # 技术分布统计
    attack_technique_distribution: Dict[str, int] = Field(default_factory=dict)
    converter_chain_usage: Dict[str, int] = Field(default_factory=dict)

    # 失败分析
    failure_analysis: Dict[str, Any] = Field(default_factory=dict)

    # P1-3: 多样性分析指标
    diversity_metrics: Dict[str, Any] = Field(default_factory=dict)


class ReportResult(BaseModel):
    """报告结果（报告层最终输出）"""

    report_path: str
    owasp_findings: List[OWASPFinding]
    summary: ReportSummary
    evidence_archive: Optional[str] = None
    start_time: datetime
    end_time: datetime
    duration_seconds: float

    attack_evidence: List[AttackEvidence] = Field(default_factory=list)

    # P1-6: 多格式报告输出路径
    report_html_path: Optional[str] = None
    report_pdf_path: Optional[str] = None


# ============================================================
# 考试专用模型
# ============================================================


class TargetPriority(BaseModel):
    """目标优先级"""

    target_url: str
    ai_system_type: AISystemType
    priority_score: int = Field(ge=0, le=100)
    allocated_time_minutes: int
    attack_suitability: float = Field(ge=0.0, le=1.0)  # PyRIT 攻击适用性评分


class TimeWarning(BaseModel):
    """时间警告"""

    warning_time: datetime
    remaining_time_seconds: int
    message: str
    priority: str  # INFO, WARNING, CRITICAL


class ExamProgress(BaseModel):
    """考试进度"""

    exam_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    total_duration_hours: int
    elapsed_time_seconds: float
    remaining_time_seconds: float
    completed_targets: int
    total_targets: int
    completed_attacks: int
    successful_attacks: int


# ============================================================
# 实用函数
# ============================================================


def create_recon_result(
    target_url: str,
    detected_endpoint: str,
    auth_type: AuthType,
    ai_system_type: AISystemType,
    capabilities: TargetCapabilities,
    tech_stack: Optional[List[str]] = None,
    external_tools: Optional[List[str]] = None,
    raw_capability_response: Optional[Dict[str, Any]] = None,
    model_tier: str = "unknown",
    model_tier_probe_detail: Optional[Dict[str, Any]] = None,
    target_type: str = "",
) -> ReconResult:
    """创建侦察结果"""
    return ReconResult(
        target_url=target_url,
        detected_endpoint=detected_endpoint,
        auth_type=auth_type,
        ai_system_type=ai_system_type,
        capabilities=capabilities,
        tech_stack=tech_stack or [],
        external_tools=external_tools,
        raw_capability_response=raw_capability_response,
        model_tier=model_tier,
        model_tier_probe_detail=model_tier_probe_detail,
        target_type=target_type,
    )


def create_strategy_selection(
    ai_system_type: AISystemType,
    scenario_name: str,
    attack_techniques: List[str],
    dataset_names: List[str],
    max_concurrency: int = 4,
    memory_labels: Optional[Dict[str, str]] = None,
) -> StrategySelection:
    """创建策略选择结果"""
    return StrategySelection(
        ai_system_type=ai_system_type,
        scenario_name=scenario_name,
        attack_techniques=attack_techniques,
        dataset_names=dataset_names,
        max_concurrency=max_concurrency,
        memory_labels=memory_labels or {},
    )