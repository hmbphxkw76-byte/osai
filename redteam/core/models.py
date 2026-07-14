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


# ===== A2A Agent Card 解析模型（AI-300 Ch4 Multi-Agent） =====
class A2AAgentSkill(BaseModel):
    """Agent Card 中的单个技能/能力。"""
    id: str = ""
    name: str = ""
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    examples: list[str] = Field(default_factory=list)
    input_modes: list[str] = Field(default_factory=list)
    output_modes: list[str] = Field(default_factory=list)


class A2AAgentCard(BaseModel):
    """A2A Agent Card 完整解析结果（AI-300 Ch4.1 Agent Card Discovery）。"""
    name: str = ""
    description: str = ""
    url: str = ""
    protocol_version: str = ""
    service_endpoint: str = ""
    preferred_transport: str = ""  # JSONRPC, gRPC, HTTP+JSON, etc.
    capabilities: dict = Field(default_factory=dict)  # streaming, pushNotifications, stateTransitionHistory
    skills: list[A2AAgentSkill] = Field(default_factory=list)
    default_input_modes: list[str] = Field(default_factory=list)
    default_output_modes: list[str] = Field(default_factory=list)
    security_schemes: dict = Field(default_factory=dict)
    security: list[dict] = Field(default_factory=list)
    model_info: dict = Field(default_factory=dict)  # model name, provider, context window
    supports_skills: bool = False
    coordination_pattern: str = ""  # orchestrator / peer_to_peer / hierarchical / pipeline
    raw_card: dict = Field(default_factory=dict)


# ===== MCP 配置侦察模型（AI-300 Ch7） =====
class MCPConfigInfo(BaseModel):
    """MCP 服务器配置信息（AI-300 Ch7.1 Developer Workstation Enumeration）。"""
    config_file_path: str = ""
    server_name: str = ""
    transport_type: str = ""  # stdio / sse / streamable-http
    command: str = ""
    args: list[str] = Field(default_factory=list)
    env_vars: dict[str, str] = Field(default_factory=dict)
    disabled: bool = False
    auto_approve: list[str] = Field(default_factory=list)
    remote_url: str = ""  # 远程 MCP 服务器 URL


# ===== 基础设施侦察模型（AI-300 Ch9 Infra） =====
class InfraServiceInfo(BaseModel):
    """云/基础设施服务发现结果（AI-300 Ch9）。"""
    service_type: str = ""  # s3 / iam / k8s / vault / ec2 / lambda / sagemaker
    endpoint: str = ""
    status: str = ""
    details: dict = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list)
    credentials_found: list[dict] = Field(default_factory=list)


# ===== 域服务侦察模型（AI-300 Ch11 Capstone） =====
class DomainServiceInfo(BaseModel):
    """AD/域服务侦察结果（AI-300 Ch11）。"""
    domain_name: str = ""
    domain_controllers: list[str] = Field(default_factory=list)
    ldap_accessible: bool = False
    spn_accounts: list[dict] = Field(default_factory=list)
    rds_gateway: str = ""
    ai_services_on_domain: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


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
    ANTHROPIC = "anthropic"          # Claude API
    GEMINI = "gemini"                # Google Gemini API
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
    
    # 推理引擎指纹（新增）
    inference_engine: str = ""  # vllm / tgi / openwebui / litellm / ollama / langserve
    engine_version: str = ""
    engine_fingerprint_confidence: float = 0.0
    
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
    score: float = 0.0        # 评分器分数 (0.0 ~ 1.0)
    error: str = ""           # 错误详情（连接失败/超时等）
    latency_ms: float = 0.0   # 请求耗时（毫秒）


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
    # CVSS 3.1 评分
    cvss_vector: str = ""  # e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    cvss_score: float = 0.0
    cvss_severity: str = ""  # None/Low/Medium/High/Critical

    @classmethod
    def normalize_severity(cls, value: str) -> str:
        return Severity.normalize(value).value

    def compute_cvss(self) -> float:
        """计算 CVSS 3.1 基础分数（简化版）。

        基于 Finding 属性自动推断 CVSS 向量参数：
          - critical severity → higher scores
          - 网络可达 → AV:N
          - 无认证要求 → PR:N

        Returns:
            CVSS 3.1 基础分数 (0.0-10.0)
        """
        # 基于严重程度推断 CVSS 参数
        sev_map = {
            Severity.CRITICAL.value: ("C:H/I:H/A:H", "Critical"),
            Severity.HIGH.value: ("C:H/I:L/A:L", "High"),
            Severity.MEDIUM.value: ("C:L/I:L/A:N", "Medium"),
            Severity.LOW.value: ("C:N/I:L/A:N", "Low"),
            Severity.INFO.value: ("C:N/I:N/A:N", "None"),
        }
        impact, sev_name = sev_map.get(self.severity, ("C:N/I:N/A:N", "None"))

        # 修正：如果有端点则网络可达
        av = "N" if self.endpoint else "L"
        ac = "L"  # 攻击复杂度低（payload 直接可用）
        pr = "N"  # 无需权限（红队场景）
        ui = "N"  # 无需用户交互

        self.cvss_vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:C/{impact}"
        self.cvss_score = round(self._calc_cvss_base(av, ac, pr, ui, "C", impact), 1)
        self.cvss_severity = sev_name

        # 根据分数调整严重等级名称
        if self.cvss_score >= 9.0:
            self.cvss_severity = "Critical"
        elif self.cvss_score >= 7.0:
            self.cvss_severity = "High"
        elif self.cvss_score >= 4.0:
            self.cvss_severity = "Medium"
        elif self.cvss_score >= 0.1:
            self.cvss_severity = "Low"
        else:
            self.cvss_severity = "None"

        return self.cvss_score

    @staticmethod
    def _calc_cvss_base(av: str, ac: str, pr: str, ui: str, s: str, impact: str) -> float:
        """简化 CVSS 3.1 基础分计算。

        Args:
            av: Attack Vector (N/A/L/P)
            ac: Attack Complexity (L/H)
            pr: Privileges Required (N/L/H)
            ui: User Interaction (N/R)
            s: Scope (U/C)
            impact: CIA impact string (e.g. "C:H/I:H/A:H")

        Returns:
            CVSS 基础分
        """
        # Exploitability 子分数
        av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_map = {"L": 0.77, "H": 0.44}
        pr_map = {"N": 0.85, "L": 0.68, "H": 0.50}
        ui_map = {"N": 0.85, "R": 0.62}

        exp = 8.22 * av_map.get(av, 0.85) * ac_map.get(ac, 0.77) * pr_map.get(pr, 0.85) * ui_map.get(ui, 0.85)

        # Impact 子分数
        impact_parts = impact.split("/")
        cia_map = {"N": 0.0, "L": 0.22, "H": 0.56}
        c_val = cia_map.get(impact_parts[0][2:], 0.0) if len(impact_parts) > 0 else 0.0
        i_val = cia_map.get(impact_parts[1][2:], 0.0) if len(impact_parts) > 1 else 0.0
        a_val = cia_map.get(impact_parts[2][2:], 0.0) if len(impact_parts) > 2 else 0.0

        impact_sub = 1 - ((1 - c_val) * (1 - i_val) * (1 - a_val))

        if s == "U":
            impact_score = 6.42 * impact_sub
        else:
            impact_score = 7.52 * (impact_sub - 0.029) - 3.25 * (impact_sub - 0.02) ** 15

        # 基础分
        if impact_sub <= 0:
            return 0.0

        if s == "U":
            base = min(exp + impact_score, 10.0)
        else:
            base = min(1.08 * (exp + impact_score), 10.0)

        return round(base, 1)


# ===== 侦察结果 =====
class ReconResult(BaseModel):
    """侦察阶段汇总。"""
    target: str
    ai_services: list[AIService] = Field(default_factory=list)
    endpoints: list[dict] = Field(default_factory=list)  # url/status/kind
    components: list[str] = Field(default_factory=list)   # ollama/vllm/mcp/gradio...
    models: list[str] = Field(default_factory=list)       # 所有暴露模型
    risk_summary: dict[str, str] = Field(default_factory=dict)

    # 目标类型识别（来自连通性测试）
    target_type: str = ""  # ollama / openai / model_platform / ai_website / web_app / unknown
    connectivity_summary: dict = Field(default_factory=dict)
    
    # MCP 协议侦察结果
    mcp_info: dict = Field(default_factory=dict)
    
    # A2A 协议侦察结果
    a2a_info: dict = Field(default_factory=dict)
    
    # 规避分析结果
    rate_limit_info: dict = Field(default_factory=dict)
    determinism_info: dict = Field(default_factory=dict)
    detection_signatures: dict = Field(default_factory=dict)
    js_client_analysis: dict = Field(default_factory=dict)
    
    # 源代码仓库侦察结果
    source_recon_info: dict = Field(default_factory=dict)

    # 基础设施侦察结果 (AI-300 Ch9)
    infra_recon_info: dict = Field(default_factory=dict)

    # 域侦察结果 (AI-300 Ch11)
    domain_recon_info: dict = Field(default_factory=dict)



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


# ===== OWASP LLM Top 10 2025 覆盖率追踪 (R2 规则要求) =====
# ✅ = 已覆盖, ⚠️ = 部分覆盖, ❌ = 未覆盖
OWASP_COVERAGE: dict[str, dict[str, str]] = {
    "LLM01": {
        "name": "提示注入 (Prompt Injection)",
        "status": "✅",
        "module": "attack/prompt_inject.py",
        "payload_dir": "config/payloads/llm01/",
    },
    "LLM02": {
        "name": "敏感信息泄露 (Sensitive Information Disclosure)",
        "status": "✅",
        "module": "attack/prompt_inject.py",
        "payload_dir": "config/payloads/llm02/",
    },
    "LLM03": {
        "name": "供应链 (Supply Chain)",
        "status": "✅",
        "module": "attack/supply_chain.py",
        "payload_dir": "config/payloads/llm03/",
    },
    "LLM04": {
        "name": "数据与模型投毒 (Data and Model Poisoning)",
        "status": "✅",
        "module": "attack/rag_attack.py",
        "payload_dir": "config/payloads/llm04/",
    },
    "LLM05": {
        "name": "输出处理不当 (Insecure Output Handling)",
        "status": "✅",
        "module": "attack/agent_attack.py",
        "payload_dir": "config/payloads/llm05/",
    },
    "LLM06": {
        "name": "过度代理 (Excessive Agency)",
        "status": "✅",
        "module": "attack/agent_attack.py",
        "payload_dir": "config/payloads/llm06/",
    },
    "LLM07": {
        "name": "系统提示词泄露 (System Prompt Leakage)",
        "status": "✅",
        "module": "attack/prompt_inject.py",
        "payload_dir": "config/payloads/llm07/",
    },
    "LLM08": {
        "name": "向量与嵌入弱点 (Vector and Embedding Weaknesses)",
        "status": "✅",
        "module": "attack/embeddings_attack.py",
        "payload_dir": "config/payloads/llm08/",
    },
    "LLM09": {
        "name": "错误信息 (Misinformation)",
        "status": "✅",
        "module": "attack/prompt_inject.py",
        "payload_dir": "config/payloads/llm09/",
    },
    "LLM10": {
        "name": "无限制消费 (Unbounded Consumption)",
        "status": "✅",
        "module": "attack/infra_attack.py",
        "payload_dir": "config/payloads/llm10/",
    },
}
