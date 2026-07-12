"""AI-300 红队数据契约（pydantic）。

基于 OffSec AI-300 课程 11 模块的完整攻击链建模：
  侦察(Ch2) → Agent攻击(Ch3) → 多智能体(Ch4) → RAG(Ch5) → 嵌入(Ch6) → MCP(Ch7) → 供应链(Ch8) → 基础设施(Ch9) → 威胁建模(Ch10) → 综合红队(Ch11)

对齐标准：OWASP LLM Top 10 2025 / MITRE ATLAS v5.1 / NIST AI RMF

Library-First：使用 pydantic 作为单一类型源，不重复造轮子。
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ===== OWASP LLM Top 10 2025 分类 =====
class OWASPLlm(str, Enum):
    LLM01_PROMPT_INJECTION = "LLM01"       # 提示注入
    LLM02_SENSITIVE_INFO = "LLM02"          # 敏感信息泄露
    LLM03_SUPPLY_CHAIN = "LLM03"            # 供应链
    LLM04_DATA_POISONING = "LLM04"           # 数据与模型投毒
    LLM05_OUTPUT_HANDLING = "LLM05"         # 输出处理不当
    LLM06_EXCESSIVE_AGENCY = "LLM06"        # 过度代理
    LLM07_SYSTEM_PROMPT_LEAK = "LLM07"      # 系统提示词泄露
    LLM08_VECTOR_WEAKNESS = "LLM08"         # 向量与嵌入弱点
    LLM09_MISINFORMATION = "LLM09"          # 错误信息
    LLM10_UNBOUNDED_CONSUMPTION = "LLM10"   # 无限制消费


# ===== MITRE ATLAS 战术 =====
class MITREATLASTactic(str, Enum):
    RECON = "Reconnaissance"
    RESOURCE_DEV = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    ML_ATTACK_STAGING = "ML Attack Staging"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    DEFENSE_EVASION = "Defense Evasion"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


# ===== AI 组件栈（AI-300 Ch2 定义的五层模型） =====
class AIStackLayer(str, Enum):
    UI = "user_interface"
    API = "api_gateway"
    ORCHESTRATION = "orchestration"   # Agent / Multi-Agent / RAG 编排
    MODEL = "model"                   # LLM / Embedding 模型
    INFRASTRUCTURE = "infrastructure" # K8s / Cloud / GPU 集群


# ===== AI 协议/框架 =====
class AIProtocol(str, Enum):
    MCP = "mcp"
    OLLAMA = "ollama"
    VLLM = "vllm"
    LITELLM = "litellm"
    LANGSERVE = "langserve"
    GRADIO = "gradio"
    COMFYUI = "comfyui"
    OPENWEBUI = "openwebui"
    FLOWISE = "flowise"
    A2A = "agent_to_agent"           # Google A2A 协议
    OPENAI_COMPATIBLE = "openai_compatible"
    GENERIC_AI = "generic_ai"

    @classmethod
    def detect(cls, url: str, headers: dict | None = None) -> "AIProtocol | None":
        """从 URL/响应头启发式检测 AI 协议。"""
        u = url.lower()
        for p in cls:
            if p.value.replace("_", "") in u.replace("-", "").replace("_", ""):
                return p
        return None


# ===== 严重程度 =====
class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def normalize(cls, value: str) -> "Severity":
        try:
            return cls(str(value).lower())
        except ValueError:
            return cls.INFO


# ===== 认证模型 =====
class BasicAuth(BaseModel):
    username: str
    password: str


class AuthContext(BaseModel):
    """从浏览器 F12 请求头解析的认证信息。"""
    cookies: dict[str, str] = Field(default_factory=dict)
    bearer: Optional[str] = None
    basic_auth: Optional[BasicAuth] = None
    api_keys: dict[str, str] = Field(default_factory=dict)
    extra_headers: dict[str, str] = Field(default_factory=dict)

    def to_header_dict(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if self.bearer:
            headers["Authorization"] = f"Bearer {self.bearer}"
        elif self.basic_auth:
            import base64
            cred = base64.b64encode(
                f"{self.basic_auth.username}:{self.basic_auth.password}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {cred}"
        headers.update(self.api_keys)
        headers.update(self.extra_headers)
        return headers

    def mask(self) -> "AuthContext":
        return AuthContext(
            cookies={k: "***" for k in self.cookies},
            bearer="***" if self.bearer else None,
            basic_auth=BasicAuth(username="***", password="***") if self.basic_auth else None,
            api_keys={k: "***" for k in self.api_keys},
            extra_headers={k: "***" for k in self.extra_headers},
        )


# ===== AI 服务发现 =====
class AIService(BaseModel):
    """侦察阶段发现的 AI 服务。"""
    url: str
    protocol: str = AIProtocol.GENERIC_AI.value
    models: list[str] = Field(default_factory=list)      # 暴露的模型名
    tools: list[str] = Field(default_factory=list)        # agent tools / MCP tools
    stack_layer: AIStackLayer = AIStackLayer.MODEL
    auth_required: bool = False
    auth_type: str = ""
    tls: bool = True
    version: str = ""
    system_prompt_hints: list[str] = Field(default_factory=list)  # 探测到的系统提示片段
    guardrail_keywords: list[str] = Field(default_factory=list)   # 检测到的护栏关键词
    raw_probe_response: str = ""  # 原始探测响应用于后续分析


# ===== 护栏画像 =====
class GuardrailProfile(BaseModel):
    """Agent 护栏检测机制画像（AI-300 Ch3 核心概念）。"""
    input_blocked_phrases: list[str] = Field(default_factory=list)
    output_filtered_patterns: list[str] = Field(default_factory=list)
    rate_limit_rpm: int = 0
    bypass_methods: list[str] = Field(default_factory=list)
    evasion_variants: list[str] = Field(default_factory=list)


# ===== 提示注入结果 =====
class PromptInjectionResult(BaseModel):
    """单次提示注入攻击的结构化结果。"""
    technique: str  # direct / indirect / jailbreak / roleplay / encoding / delimiter / translation / few_shot
    payload: str
    response_preview: str = ""  # 前 500 字符
    success: bool = False
    extracted_info: str = ""
    bypass_method: str = ""
    guardrail_triggered: bool = False


# ===== 攻击步骤 =====
class AttackStep(BaseModel):
    """攻击链中的一个步骤。"""
    step_id: int
    phase: str  # recon / prompt_inject / system_prompt_extract / rag_attack / mcp_attack / infra_attack
    technique: str
    target_url: str = ""
    payload: str = ""
    result: Optional[PromptInjectionResult] = None
    status: str = "pending"  # pending / running / success / failed / skipped
    evidence: str = ""


# ===== 攻击链（AI-300 Ch11 Capstone） =====
class AttackChain(BaseModel):
    """完整攻击链：从侦察到域控的完整过程。"""
    chain_id: str
    target: str
    steps: list[AttackStep] = Field(default_factory=list)
    mitre_atlas_tactics: list[str] = Field(default_factory=list)
    owasp_llm_categories: list[str] = Field(default_factory=list)
    total_time_seconds: float = 0.0


# ===== 统一发现/漏洞 =====
class Finding(BaseModel):
    """统一漏洞/暴露面模型（贯穿全流程）。"""
    source: str
    category: str
    severity: str = Severity.INFO.value
    title: str
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    endpoint: Optional[str] = None
    # AI-300 标准映射
    owasp_llm: Optional[OWASPLlm] = None
    mitre_atlas_tactic: Optional[MITREATLASTactic] = None
    mitre_atlas_technique_id: str = ""
    cve_refs: list[str] = Field(default_factory=list)

    @classmethod
    def normalize_severity(cls, value: str) -> str:
        return Severity.normalize(value).value


# ===== 侦察结果 =====
class ReconResult(BaseModel):
    """侦察阶段汇总。"""
    target: str
    ai_services: list[AIService] = Field(default_factory=list)
    endpoints: list[dict] = Field(default_factory=list)  # url/status/kind
    components: list[str] = Field(default_factory=list)   # ollama/vllm/mcp/gradio...
    models: list[str] = Field(default_factory=list)       # 所有暴露模型
    risk_summary: dict[str, str] = Field(default_factory=dict)


# ===== 向后兼容：AIMap 需要的旧模型 =====
class AIFingerprint(BaseModel):
    """AI 服务详细指纹（保留兼容 aimap_runner）。"""
    protocol: str = ""
    version: str = ""
    tools: list[str] = Field(default_factory=list)
    models: list[str] = Field(default_factory=list)
    auth_required: bool = False
    auth_type: str = ""
    tls: bool = True
    cors_open: bool = False
    system_prompt_leaked: bool = False
    uncensored_model: bool = False
    risk_factors: list[str] = Field(default_factory=list)
    raw_info: dict = Field(default_factory=dict)

    @property
    def risk_score(self) -> float:
        score = 0.0
        if not self.auth_required and self.auth_type == "none":
            score += 4.0
        elif self.auth_type == "unknown":
            score += 1.0
        if len(self.tools) >= 10:
            score += 2.0
        critical_tools = {"exec_code", "run_shell", "execute_command", "shell_exec", "run_command"}
        ct_count = sum(1 for t in self.tools if t.lower() in critical_tools)
        score += ct_count * 1.0
        if self.cors_open:
            score += 1.0
        if not self.tls:
            score += 0.5
        if self.system_prompt_leaked:
            score += 0.5
        if self.uncensored_model:
            score += 2.0
        if not self.auth_required and ct_count > 0:
            score += 1.0
        return min(score, 10.0)


class Endpoint(BaseModel):
    """端点模型（保留兼容 aimap_runner）。"""
    url: str
    kind: str = "web"
    method: str = "POST"
    status_code: int = 0
    tags: list[str] = Field(default_factory=list)
    auth: Optional[AuthContext] = None
    requires_auth: bool = False
    discovered_by: Optional[str] = None
    ai_fingerprint: Optional[AIFingerprint] = None
    risk_score: float = 0.0
    risk_level: str = ""
    response_headers: dict = Field(default_factory=dict)
    content_type: str = ""
    tech_stack: list[str] = Field(default_factory=list)
    page_type: str = ""


# ===== 报告配置 =====
class ReportConfig(BaseModel):
    """AI-300 风格报告配置。"""
    target: str
    run_id: str
    engagement_type: str = "AI Red Team Assessment"
    methodology: str = "OffSec AI-300 Advanced AI Red Teaming"
    scope: str = ""
    summary: str = ""
    recon: Optional[ReconResult] = None
    attack_chain: Optional[AttackChain] = None
    findings: list[Finding] = Field(default_factory=list)
