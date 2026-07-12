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
    guardrail_profile: Optional[GuardrailProfile] = None          # 护栏画像（侦察阶段填充）
    raw_probe_response: str = ""  # 原始探测响应用于后续分析


# ===== 护栏画像 =====
class GuardrailType(str, Enum):
    """护栏产品指纹（AI-300 Ch2 侦察阶段识别）。"""
    NONE = "none"                    # 无护栏
    OPENAI_MODERATION = "openai_moderation"
    AZURE_CONTENT_SAFETY = "azure_content_safety"
    LLAMA_GUARD = "llama_guard"
    NEMO_GUARDRAILS = "nemo_guardrails"
    AWS_BEDROCK_GUARDRAILS = "aws_bedrock_guardrails"
    CUSTOM_WEAK = "custom_weak"      # 自定义护栏，易绕过
    CUSTOM_MEDIUM = "custom_medium"
    CUSTOM_STRONG = "custom_strong"  # 自定义护栏，难绕过
    UNKNOWN = "unknown"


class ContentCategory(str, Enum):
    """护栏过滤的内容类别（用于分类测试）。"""
    HARMFUL_CONTENT = "harmful"       # 暴力/非法内容
    SYSTEM_OVERRIDE = "system"        # 系统提示覆盖/指令注入
    JAILBREAK = "jailbreak"           # 角色扮演/越狱
    PII_EXTRACTION = "pii"            # 个人信息提取
    CODE_EXECUTION = "code_exec"      # 代码生成/执行


class GuardrailProfile(BaseModel):
    """Agent 护栏检测机制画像（AI-300 Ch2+Ch3 完整版）。

    三阶段分析：
      1. 指纹识别：识别护栏产品/类型
      2. 分类测试：检测哪些内容类别被阻断
      3. 绕过评估：评估绕过难度并推荐 Phase 2 攻击策略
    """
    # 指纹
    guardrail_type: GuardrailType = GuardrailType.UNKNOWN
    guardrail_confidence: float = 0.0  # 指纹置信度 0-1

    # 分类测试结果
    blocked_categories: list[ContentCategory] = Field(default_factory=list)
    category_results: dict[str, bool] = Field(default_factory=dict)  # category -> blocked?

    # 绕过评估
    bypass_difficulty: str = "unknown"  # none/easy/medium/hard

    # Phase 2 攻击策略推荐（按优先级排序的 technique 列表）
    recommended_techniques: list[str] = Field(default_factory=list)
    discouraged_techniques: list[str] = Field(default_factory=list)

    # 基础信息（向后兼容）
    input_blocked_phrases: list[str] = Field(default_factory=list)
    output_filtered_patterns: list[str] = Field(default_factory=list)
    rate_limit_rpm: int = 0
    evasion_variants: list[str] = Field(default_factory=list)

    # 原始探针结果（用于报告证据）
    probe_evidence: list[dict] = Field(default_factory=list)


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
