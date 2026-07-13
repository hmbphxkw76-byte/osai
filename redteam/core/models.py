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

    @property
    def auth_type(self) -> str:
        """返回认证类型组合标签。

        Returns:
            认证类型字符串，多个类型用 '+' 连接。
            可能值: jwt, jwt+cookie, jwt+api_key, bearer, bearer+cookie,
                    cookie, basic, api_key, none
        """
        types: list[str] = []

        # 检测 JWT（三段 base64url 由点分隔）
        is_jwt = False
        if self.bearer:
            parts = self.bearer.split(".")
            if len(parts) == 3 and all(parts):
                is_jwt = True

        if is_jwt:
            types.append("jwt")
        elif self.bearer:
            types.append("bearer")

        if self.cookies:
            types.append("cookie")

        if self.basic_auth:
            types.append("basic")

        if self.api_keys:
            types.append("api_key")

        if not types:
            return "none"
        return "+".join(types)

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
    model_fingerprint: Optional[ModelFingerprint] = None          # 模型指纹（AI-300 Ch2.3）
    rag_pipeline: Optional[RAGPipelineProfile] = None              # RAG 流水线画像（AI-300 Ch2.3）
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
    evasion_variants: list[str] = Field(default_factory=list)

    # 速率限制信息（TCM rate_limit_tester.py / temperature_probe.py 融合）
    rate_limit_detected: bool = False
    rate_limit_rpm: int = 0
    rate_limit_status_code: int = 0
    rate_limit_error_message: str = ""
    rate_limit_retry_after: str = ""

    # 原始探针结果（用于报告证据）
    probe_evidence: list[dict] = Field(default_factory=list)


# ===== 模型指纹（AI-300 Ch2.3 Model Fingerprinting） =====
class ModelFingerprint(BaseModel):
    """模型指纹识别结果（AI-300 Ch2.3 完整实现）。

    七种指纹识别技术：
      1. 直接身份探测：询问模型身份
      2. 矛盾测试：用错误身份断言诱导纠正
      3. 知识截止日期测试：询问特定日期后的事件
      4. 行为特征测试：代码生成风格、响应详细程度
      5. 上下文窗口测试：标记注入 + 溢出测试
      6. 能力边界测试：算术能力、推理能力
      7. 确定性测试：多次相同请求的响应一致性
    """
    # 模型身份信息
    claimed_model: str = ""
    claimed_vendor: str = ""
    corrected_identity: str = ""  # 矛盾测试中模型纠正的身份
    
    # 知识截止日期
    claimed_cutoff: str = ""
    estimated_cutoff: str = ""  # 通过测试推断的截止日期
    
    # 行为特征
    response_verbosity: str = ""  # concise / detailed / verbose
    code_style: str = ""           # minimal / docstring / example
    
    # 能力边界
    context_window_estimate: int = 0  # 估计的上下文窗口大小（token）
    arithmetic_capability: str = ""   # weak / moderate / strong
    reasoning_capability: str = ""    # weak / moderate / strong
    
    # 确定性分析（TCM temperature_probe.py 融合）
    is_deterministic: bool = False
    unique_response_count: int = 0
    total_response_count: int = 0
    response_variance: float = 0.0
    avg_response_length_tokens: float = 0.0
    median_response_length_tokens: float = 0.0
    min_response_length_tokens: int = 0
    max_response_length_tokens: int = 0
    
    # 元数据泄露
    metadata_provider: str = ""
    metadata_model: str = ""
    
    # 置信度
    identity_confidence: float = 0.0
    fingerprint_confidence: float = 0.0


# ===== RAG 流水线画像（AI-300 Ch2.3 RAG Pipeline Recon） =====
class RAGSource(BaseModel):
    """RAG 检索来源信息。"""
    title: str = ""
    chunk_id: str = ""
    text_snippet: str = ""
    vector_score: float = 0.0
    bm25_score: float = 0.0
    combined_score: float = 0.0


class RAGPipelineProfile(BaseModel):
    """RAG 流水线侦察画像（AI-300 Ch2.3 完整实现）。

    侦察技术（文档完整覆盖）：
      1. RAG 激活检测：通用知识 vs 公司特定查询
      2. 来源引用提取：文档名、chunk ID、相似度分数
      3. 知识库映射：跨多个主题探测收集文档名称
      4. 检索阈值推断：精确术语 vs 同义词 vs 拼写错误
      5. 嵌入模型身份识别：通过错误提示和响应特征推断
      6. 向量数据库类型检测：分析响应格式和元数据
      7. 分块边界探测：通过精确查询定位 chunk 边界
      8. 嵌入相似度分析：比较不同查询的检索分数分布
    """
    # RAG 状态
    rag_active: bool = False
    retrieval_threshold: float = 0.0  # 估计的检索相似度阈值
    
    # 检索来源
    known_sources: list[str] = Field(default_factory=list)  # 已知文档名称
    source_details: list[RAGSource] = Field(default_factory=list)
    
    # 文档结构
    chunking_strategy: str = ""  # text / ast_aware / semantic
    estimated_chunk_size: int = 0
    estimated_document_count: int = 0
    
    # 检索信息
    retrieval_time_ms: float = 0.0
    generation_time_ms: float = 0.0
    
    # 供应商信息
    embedding_provider: str = ""
    embedding_model: str = ""
    vector_db_type: str = ""


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
