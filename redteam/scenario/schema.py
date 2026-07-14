"""场景Schema模块 — 攻击场景数据结构定义。

基于 AI-300 考试需求设计：
  - AttackScenario: 顶层场景定义
  - AttackPhase: 攻击阶段（PROBE/ENCODING/SEMANTIC/ADVANCED）
  - AttackStrategy: 攻击策略枚举（30+种）
  - PayloadTemplate: 载荷模板
  - AttackConfig: 攻击配置
  - ScenarioResult: 场景执行结果


Library-First: 配置即攻击，考试期间仅需修改YAML载荷文件
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class AttackTargetType(str, Enum):
    """攻击目标类型 — AI-300考试高频目标全覆盖。"""

    AGENT = "agent"
    MCP = "mcp"
    RAG = "rag"
    EMBEDDINGS = "embeddings"
    SUPPLY_CHAIN = "supply_chain"
    INFRA = "infra"
    GENERIC = "generic"
    MULTI_AGENT = "multi_agent"
    BASIC_LLM = "basic_llm"


class AttackStrategy(str, Enum):
    """攻击策略枚举 — AI-300考试高频策略优先。

    按攻击领域分类：
      - 侦察：probe, recon, permission_map
      - 注入：direct_inject, indirect_inject, jailbreak
      - 编码：base64, rot13, unicode, leetspeak, morse, encoding
      - 语义：roleplay, stealth, academic, translation
      - 高级：crescendo, tap, pair, flip, adversarial_suffix, many_shot
      - Agent/工具：memory_poison, system_prompt_extract, goal_hijack, tool_hijack, parameter_pollution, cross_agent
      - RAG/向量：rag_poison, retrieval_leak, vector_db_attack
      - Embeddings: membership_inference, attribute_inference, embedding_inversion, adversarial_embedding, unicode_embedding, vector_perturbation
      - 供应链：dataset_poison, dependency_trojan, config_json_hijack, code_obfuscation, dependency_hiding
      - 云/基础设施：cloud_misconfig, ssrf, metadata_extract, iam_enum, policy_read, trust_chain_map, passrole, role_assumption, privilege_esc, s3_access, secrets_enum, service_discovery, sagemaker_abuse, mlflow_rce, model_deploy
      - MCP投毒：tool_poison, system_instruct_inject, keyword_trigger, chain_execution, data_exfil, lateral_movement, ui_spoof, credential_theft, phishing, dual_layer
      - 规避：character_spacing, payload_splitting, css_hidden
      - A2A/多Agent：cross_agent_inject, dns_spoof, workflow_bypass, sql_inject_via_agent
      - 前沿：frontier
    """

    # 侦察
    PROBE = "probe"
    RECON = "recon"
    PERMISSION_MAP = "permission_map"

    # 注入
    DIRECT_INJECT = "direct_inject"
    INDIRECT_INJECT = "indirect_inject"
    JAILBREAK = "jailbreak"

    # 编码
    BASE64 = "base64"
    ROT13 = "rot13"
    UNICODE = "unicode"
    LEETSPEAK = "leetspeak"
    MORSE = "morse"
    ENCODING = "encoding"                     # 泛用编码绕过

    # 语义
    ROLEPLAY = "roleplay"
    STEALTH = "stealth"
    ACADEMIC = "academic"
    TRANSLATION = "translation"

    # 高级 (多轮原生)
    CRESCENDO = "crescendo"
    TAP = "tap"
    PAIR = "pair"
    FLIP = "flip"
    ADVERSARIAL_SUFFIX = "adversarial_suffix"  # GCG 对抗性后缀
    MANY_SHOT = "many_shot"                    # Many-Shot 越狱

    # Agent/工具攻击
    MEMORY_POISON = "memory_poison"
    SYSTEM_PROMPT_EXTRACT = "system_prompt_extract"
    GOAL_HIJACK = "goal_hijack"
    TOOL_HIJACK = "tool_hijack"
    PARAMETER_POLLUTION = "parameter_pollution"
    CROSS_AGENT = "cross_agent"

    # RAG/向量
    RAG_POISON = "rag_poison"
    RETRIEVAL_LEAK = "retrieval_leak"
    VECTOR_DB_ATTACK = "vector_db_attack"

    # Embedding 攻击 (Ch6)
    MEMBERSHIP_INFERENCE = "membership_inference"
    ATTRIBUTE_INFERENCE = "attribute_inference"
    EMBEDDING_INVERSION = "embedding_inversion"
    ADVERSARIAL_EMBEDDING = "adversarial_embedding"
    UNICODE_EMBEDDING = "unicode_embedding"
    VECTOR_PERTURBATION = "vector_perturbation"

    # 供应链 (Ch8)
    DATASET_POISON = "dataset_poison"
    DEPENDENCY_TROJAN = "dependency_trojan"
    CONFIG_JSON_HIJACK = "config_json_hijack"
    CODE_OBFUSCATION = "code_obfuscation"
    DEPENDENCY_HIDING = "dependency_hiding"

    # 云/基础设施 (Ch9)
    CLOUD_MISCONFIG = "cloud_misconfig"
    SSRF = "ssrf"
    METADATA_EXTRACT = "metadata_extract"
    IAM_ENUM = "iam_enum"
    POLICY_READ = "policy_read"
    TRUST_CHAIN_MAP = "trust_chain_map"
    PASSROLE = "passrole"
    ROLE_ASSUMPTION = "role_assumption"
    PRIVILEGE_ESC = "privilege_esc"
    S3_ACCESS = "s3_access"
    SECRETS_ENUM = "secrets_enum"
    SERVICE_DISCOVERY = "service_discovery"
    SAGEMAKER_ABUSE = "sagemaker_abuse"
    MLFLOW_RCE = "mlflow_rce"
    MODEL_DEPLOY = "model_deploy"

    # MCP 投毒 (Ch7)
    TOOL_POISON = "tool_poison"
    TOOL_DESCRIBE_POISON = "tool_describe_poison"  # 工具描述投毒
    SYSTEM_INSTRUCT_INJECT = "system_instruct_inject"
    KEYWORD_TRIGGER = "keyword_trigger"
    CHAIN_EXECUTION = "chain_execution"
    DATA_EXFIL = "data_exfil"
    LATERAL_MOVEMENT = "lateral_movement"
    UI_SPOOF = "ui_spoof"
    CREDENTIAL_THEFT = "credential_theft"
    PHISHING = "phishing"
    DUAL_LAYER = "dual_layer"

    # 规避 (SIEM/检测绕过)
    CHARACTER_SPACING = "character_spacing"    # 字符间隔绕过
    PAYLOAD_SPLITTING = "payload_splitting"    # 载荷拆分
    CSS_HIDDEN = "css_hidden"                  # CSS 隐藏注入
    DOCUMENT_SPLITTING = "document_splitting"  # 文档拆分规避
    LOG_INJECTION = "log_injection"            # 日志注入规避
    TRAFFIC_MASKING = "traffic_masking"        # 流量伪装

    # RAG 专用策略 (Ch5)
    CROSS_DOC_SPLIT = "cross_doc_split"        # 跨文档指令拆分

    # LLM09 误导信息专用策略
    BOUNDARY_TEST = "boundary_test"            # 知识边界探测
    HALLUCINATION_INDUCE = "hallucination_induce"  # 幻觉诱导
    AUTHORITY_HIJACK = "authority_hijack"      # 权威性接管
    FAKE_CITATION = "fake_citation"            # 虚假引用生成
    SOCIAL_ENGINEERING = "social_engineering"  # 深度伪造社工
    IMPERSONATION = "impersonation"            # 身份冒充
    CHAIN_HALLUCINATION = "chain_hallucination" # 链式幻觉

    # 模型检查点攻击专用策略 (Ch8)
    CHECKPOINT_ENUM = "checkpoint_enum"        # 检查点侦察
    EPOCH_OVERRIDE = "epoch_override"          # 高Epoch覆盖
    AUTO_LOADER_ABUSE = "auto_loader_abuse"    # 自动加载器利用
    CHECKPOINT_POISON = "checkpoint_poison"    # 检查点投毒
    SAFETENSOR_BYPASS = "safetensor_bypass"    # SafeTensors绕过
    GGUF_EXPLOIT = "gguf_exploit"              # GGUF格式利用
    FORMAT_CONFUSION = "format_confusion"      # 格式混淆
    NAMESPACE_REUSE = "namespace_reuse"        # 命名空间复用
    REPO_HIJACK = "repo_hijack"                # 仓库劫持
    TOKEN_ABUSE = "token_abuse"                # Token滥用
    JOBLIB_RCE = "joblib_rce"                  # Joblib RCE
    IMPORT_HIJACK = "import_hijack"            # Python导入劫持

    # 基础设施专用策略 (Ch9)
    K8S_ESCAPE = "k8s_escape"                  # K8s容器逃逸
    CONTAINER_BREAKOUT = "container_breakout"  # 容器突破
    CREDENTIAL_EXPOSURE = "credential_exposure" # 凭证暴露

    # A2A/多Agent 专用策略
    CROSS_AGENT_INJECT = "cross_agent_inject"  # 跨Agent间接注入
    DNS_SPOOF = "dns_spoof"                    # Agent Card DNS欺骗
    WORKFLOW_BYPASS = "workflow_bypass"        # 工作流完整性绕过
    SQL_INJECT_VIA_AGENT = "sql_inject_via_agent"  # 通过Agent的SQL注入

    # 前沿
    FRONTIER = "frontier"


class AttackPhaseType(str, Enum):
    """攻击阶段类型。

    AI-300 章节语义映射:
      probe → 侦察/探测阶段
      injection → 提示注入阶段 (Ch3/Ch4)
      encoding → 编码绕过阶段
      semantic → 语义/越狱阶段
      advanced → 高级攻击阶段
      poisoning → 投毒攻击阶段 (Ch5/Ch6)
      retrieval → 检索操纵阶段 (Ch5)
      exploitation → 工具/配置利用阶段 (Ch7/Ch9)
      deserialization → 反序列化攻击阶段 (Ch8)
      access → 内部访问阶段 (Ch9)
      evasion → 规避检测阶段
      frontier → 前沿漏洞阶段
    """

    PROBE = "probe"
    INJECTION = "injection"
    ENCODING = "encoding"
    SEMANTIC = "semantic"
    ADVANCED = "advanced"
    POISONING = "poisoning"
    RETRIEVAL = "retrieval"
    EXPLOITATION = "exploitation"
    DESERIALIZATION = "deserialization"
    ACCESS = "access"
    EVASION = "evasion"
    INFERENCE = "inference"          # 嵌入推断阶段 (Ch6)
    ENUMERATION = "enumeration"      # IAM/权限枚举阶段 (Ch9)
    LATERAL = "lateral"              # 横向移动阶段 (Ch9)
    FRONTIER = "frontier"


class Severity(str, Enum):
    """漏洞严重等级。"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class GrayscaleLevel(str, Enum):
    """灰度评分等级。"""

    FULL_SUCCESS = "full_success"
    SUCCESS_DISCLAIMER = "success_disclaimer"
    AMBIGUOUS = "ambiguous"
    REFUSAL_LEAK = "refusal_leak"
    FULL_REFUSAL = "full_refusal"


class ScorerType(str, Enum):
    """评分器类型。"""

    RULE_BASED = "rule_based"
    HYBRID = "hybrid"
    FAST_GRAYSCALE = "fast_grayscale"
    KEYWORD_DENSITY = "keyword_density"
    REFUSAL_PATTERN = "refusal_pattern"
    LLM_JUDGE = "llm_judge"


class PayloadTemplate(BaseModel):
    """载荷模板 — 支持占位符替换。"""

    id: str = Field(..., description="载荷唯一标识")
    name: str = Field(..., description="载荷名称")
    description: str = Field("", description="载荷描述")
    payload: str = Field(..., description="载荷内容（支持{objective}等占位符）")
    technique: str = Field("", description="技术类型")
    difficulty: str = Field("medium", description="难度等级：easy/medium/hard")
    strategy: AttackStrategy = Field(..., description="关联策略")
    category: str = Field("", description="攻击类别")
    success_patterns: list[str] = Field([], description="成功匹配模式")
    failure_patterns: list[str] = Field([], description="失败匹配模式")
    tags: list[str] = Field([], description="标签")

    @field_validator("difficulty")
    @classmethod
    def validate_difficulty(cls, v):
        if v not in ["easy", "medium", "hard"]:
            raise ValueError("difficulty must be easy/medium/hard")
        return v


class AttackPhase(BaseModel):
    """攻击阶段 — 包含多个策略。"""

    name: str = Field(..., description="阶段名称")
    phase_type: AttackPhaseType = Field(..., description="阶段类型")
    strategies: list[AttackStrategy] = Field(..., description="该阶段使用的策略列表")
    payload_templates: list[str] = Field([], description="引用的载荷模板ID列表")
    enabled: bool = Field(True, description="是否启用")
    max_concurrent: int = Field(5, description="最大并发数")
    timeout_seconds: float = Field(30.0, description="超时时间")

    @field_validator("strategies")
    @classmethod
    def validate_strategies(cls, v):
        if not v:
            raise ValueError("strategies cannot be empty")
        return v


class AttackConfig(BaseModel):
    """攻击配置 — 全局配置。"""

    target_url: str = Field(..., description="目标URL")
    target_type: AttackTargetType = Field(AttackTargetType.GENERIC, description="目标类型")
    objectives: list[str] = Field(..., description="攻击目标描述列表")
    scorers: list[ScorerType] = Field([ScorerType.FAST_GRAYSCALE], description="评分器列表（考试推荐: fast_grayscale）")
    min_success_score: float = Field(0.5, description="最小成功分数")
    max_attempts: int = Field(100, description="最大尝试次数")
    enable_concurrent: bool = Field(True, description="是否启用并发")
    max_concurrent: int = Field(5, description="全局最大并发数")
    timeout_seconds: float = Field(30.0, description="全局超时时间")
    save_results: bool = Field(True, description="是否保存结果")
    generate_report: bool = Field(True, description="是否生成报告")
    report_format: str = Field("markdown", description="报告格式")
    log_level: str = Field("INFO", description="日志级别")

    @field_validator("scorers")
    @classmethod
    def validate_scorers(cls, v):
        if not v:
            return [ScorerType.RULE_BASED]
        return v

    @field_validator("min_success_score")
    @classmethod
    def validate_min_score(cls, v):
        if not (0.0 <= v <= 1.0):
            raise ValueError("min_success_score must be between 0.0 and 1.0")
        return v


class AttackScenario(BaseModel):
    """攻击场景 — 顶层定义。

    考试期间使用方式：
      1. 在 config/scenarios/ 下创建目标类型对应的YAML文件
      2. 修改 payloads 中的载荷内容
      3. 运行: redteam scenario run --scenario agent --target https://xxx

    扩展机制（AI-300 考试对齐）：
      - extends: 跨场景继承（如 agent.yaml extends generic 复用通用阶段/载荷）
      - payload_sources: 引用 config/payloads/ 高质量载荷库
    """

    model_config = {"extra": "allow"}  # 允许 extends/payload_sources 等扩展字段

    id: str = Field(..., description="场景唯一标识")
    name: str = Field(..., description="场景名称")
    description: str = Field("", description="场景描述")
    author: str = Field("", description="作者")
    version: str = Field("1.0.0", description="版本号")
    target_type: AttackTargetType = Field(..., description="目标类型")
    attack_config: AttackConfig = Field(..., description="攻击配置")
    phases: list[AttackPhase] = Field(..., description="攻击阶段列表")
    payloads: list[PayloadTemplate] = Field(..., description="载荷模板列表（含内嵌 + 桥接注入的库载荷）")
    metadata: dict[str, Any] = Field({}, description="元数据")

    @field_validator("phases")
    @classmethod
    def validate_phases(cls, v):
        if not v:
            raise ValueError("phases cannot be empty")
        return v

    @field_validator("payloads")
    @classmethod
    def validate_payloads(cls, v):
        ids = [p.id for p in v]
        if len(ids) != len(set(ids)):
            raise ValueError("payload ids must be unique")
        return v

    def get_payload_by_id(self, payload_id: str) -> Optional[PayloadTemplate]:
        """根据ID获取载荷模板。"""
        for p in self.payloads:
            if p.id == payload_id:
                return p
        return None

    def get_payloads_by_strategy(self, strategy: AttackStrategy) -> list[PayloadTemplate]:
        """根据策略获取载荷模板列表。"""
        return [p for p in self.payloads if p.strategy == strategy]

    def get_phase_by_name(self, name: str) -> Optional[AttackPhase]:
        """根据名称获取攻击阶段。"""
        for p in self.phases:
            if p.name == name:
                return p
        return None

    def get_enabled_phases(self) -> list[AttackPhase]:
        """获取所有启用的攻击阶段。"""
        return [p for p in self.phases if p.enabled]

    def replace_placeholders(self, payload: str, **kwargs) -> str:
        """替换载荷中的占位符。"""
        result = payload
        for key, value in kwargs.items():
            result = result.replace(f"{{{key}}}", str(value))
        return result


class StrategyResult(BaseModel):
    """策略执行结果。"""

    strategy: AttackStrategy = Field(..., description="策略名称")
    payload: str = Field(..., description="实际发送的载荷")
    payload_template_id: str = Field("", description="载荷模板ID")
    objective: str = Field("", description="攻击目标")
    response: str = Field("", description="响应内容")
    response_preview: str = Field("", description="响应预览")
    success: bool = Field(False, description="是否成功")
    score: float = Field(0.0, description="评分")
    grayscale_level: GrayscaleLevel = Field(GrayscaleLevel.FULL_REFUSAL, description="灰度等级")
    guardrail_triggered: bool = Field(False, description="是否触发护栏")
    extracted_info: str = Field("", description="提取的信息")
    error: str = Field("", description="错误信息")
    latency_ms: float = Field(0.0, description="延迟(毫秒)")
    timestamp: str = Field("", description="时间戳")


class PhaseResult(BaseModel):
    """阶段执行结果。"""

    phase_name: str = Field(..., description="阶段名称")
    phase_type: AttackPhaseType = Field(..., description="阶段类型")
    strategies: list[str] = Field(..., description="执行的策略列表")
    total_attempts: int = Field(0, description="总尝试次数")
    success_count: int = Field(0, description="成功次数")
    success_rate: float = Field(0.0, description="成功率")
    results: list[StrategyResult] = Field([], description="策略结果列表")
    elapsed_seconds: float = Field(0.0, description="耗时(秒)")


class VulnerabilityFinding(BaseModel):
    """漏洞发现结果。"""

    id: str = Field(..., description="漏洞ID")
    title: str = Field(..., description="漏洞标题")
    description: str = Field("", description="漏洞描述")
    severity: Severity = Field(Severity.MEDIUM, description="严重等级")
    owasp_llm: str = Field("", description="OWASP LLM分类")
    mitre_atlas: str = Field("", description="MITRE ATLAS分类")
    attack_vector: str = Field("", description="攻击向量")
    evidence: str = Field("", description="证据")
    payload: str = Field("", description="利用载荷")
    response: str = Field("", description="响应")
    recommendation: str = Field("", description="修复建议")
    discovered_by: str = Field("", description="发现者")
    discovered_at: str = Field("", description="发现时间")


class ScenarioResult(BaseModel):
    """场景执行结果 — 完整报告数据。"""

    scenario_id: str = Field(..., description="场景ID")
    scenario_name: str = Field(..., description="场景名称")
    target_url: str = Field(..., description="目标URL")
    target_type: AttackTargetType = Field(..., description="目标类型")
    objectives: list[str] = Field(..., description="攻击目标列表")
    phases: list[PhaseResult] = Field(..., description="阶段结果列表")
    findings: list[VulnerabilityFinding] = Field([], description="漏洞发现列表")
    total_attempts: int = Field(0, description="总尝试次数")
    success_count: int = Field(0, description="总成功次数")
    success_rate: float = Field(0.0, description="总成功率")
    elapsed_seconds: float = Field(0.0, description="总耗时(秒)")
    run_id: str = Field("", description="运行ID")
    timestamp: str = Field("", description="开始时间")

    def calculate_summary(self):
        """计算汇总统计。"""
        self.total_attempts = sum(p.total_attempts for p in self.phases)
        self.success_count = sum(p.success_count for p in self.phases)
        self.success_rate = (
            round(self.success_count / max(self.total_attempts, 1) * 100, 2)
            if self.total_attempts > 0
            else 0.0
        )
        self.elapsed_seconds = sum(p.elapsed_seconds for p in self.phases)


STRATEGY_TO_CONVERTER_MAP: dict[AttackStrategy, list[str]] = {
    AttackStrategy.BASE64: ["Base64Converter"],
    AttackStrategy.ROT13: ["ROT13Converter"],
    AttackStrategy.UNICODE: ["UnicodeConfusableConverter"],
    AttackStrategy.LEETSPEAK: ["LeetspeakConverter"],
    AttackStrategy.MORSE: ["MorseConverter"],
    AttackStrategy.ROLEPLAY: ["RoleplayJailbreakConverter"],
    AttackStrategy.STEALTH: ["academic"],
    AttackStrategy.ACADEMIC: ["academic"],
    AttackStrategy.TRANSLATION: ["translation"],
    AttackStrategy.CRESCENDO: ["roleplay"],
    AttackStrategy.TAP: ["many_shot"],
    AttackStrategy.PAIR: ["pair"],
    AttackStrategy.FLIP: ["flip_attack"],
    AttackStrategy.JAILBREAK: ["RoleplayJailbreakConverter"],
    AttackStrategy.ADVERSARIAL_SUFFIX: ["PairConverter"],      # GCG 后缀 → PAIR
    AttackStrategy.MANY_SHOT: ["TapConverter"],                # Many-Shot → TAP
    # 以下策略无 converter（纯 payload 层面操作）
    AttackStrategy.CHARACTER_SPACING: [],
    AttackStrategy.PAYLOAD_SPLITTING: [],
    AttackStrategy.CSS_HIDDEN: [],
    AttackStrategy.ENCODING: [],
}

PHASE_DEFAULT_STRATEGIES: dict[AttackPhaseType, list[AttackStrategy]] = {
    AttackPhaseType.PROBE: [AttackStrategy.PROBE, AttackStrategy.RECON],
    AttackPhaseType.ENCODING: [AttackStrategy.BASE64, AttackStrategy.ROT13, AttackStrategy.UNICODE],
    AttackPhaseType.SEMANTIC: [AttackStrategy.ROLEPLAY, AttackStrategy.STEALTH, AttackStrategy.TRANSLATION],
    AttackPhaseType.ADVANCED: [AttackStrategy.CRESCENDO, AttackStrategy.TAP, AttackStrategy.PAIR, AttackStrategy.ADVERSARIAL_SUFFIX, AttackStrategy.MANY_SHOT],
    AttackPhaseType.EVASION: [AttackStrategy.CHARACTER_SPACING, AttackStrategy.PAYLOAD_SPLITTING, AttackStrategy.CSS_HIDDEN, AttackStrategy.ENCODING],
    AttackPhaseType.FRONTIER: [AttackStrategy.FRONTIER],
}

TARGET_DEFAULT_STRATEGIES: dict[AttackTargetType, list[AttackStrategy]] = {
    AttackTargetType.AGENT: [
        AttackStrategy.PROBE,
        AttackStrategy.RECON,
        AttackStrategy.DIRECT_INJECT,
        AttackStrategy.INDIRECT_INJECT,
        AttackStrategy.JAILBREAK,
        AttackStrategy.BASE64,
        AttackStrategy.ROLEPLAY,
        AttackStrategy.MEMORY_POISON,
        AttackStrategy.SYSTEM_PROMPT_EXTRACT,
        AttackStrategy.GOAL_HIJACK,
        AttackStrategy.TOOL_HIJACK,
        AttackStrategy.ADVERSARIAL_SUFFIX,
        AttackStrategy.CROSS_AGENT_INJECT,
    ],
    AttackTargetType.MULTI_AGENT: [
        AttackStrategy.PROBE,
        AttackStrategy.RECON,
        AttackStrategy.DIRECT_INJECT,
        AttackStrategy.INDIRECT_INJECT,
        AttackStrategy.JAILBREAK,
        AttackStrategy.BASE64,
        AttackStrategy.SYSTEM_PROMPT_EXTRACT,
        AttackStrategy.CROSS_AGENT,
        AttackStrategy.CROSS_AGENT_INJECT,
        AttackStrategy.DNS_SPOOF,
        AttackStrategy.WORKFLOW_BYPASS,
        AttackStrategy.SQL_INJECT_VIA_AGENT,
        AttackStrategy.GOAL_HIJACK,
        AttackStrategy.TOOL_HIJACK,
    ],
    AttackTargetType.MCP: [
        AttackStrategy.PROBE,
        AttackStrategy.DIRECT_INJECT,
        AttackStrategy.BASE64,
        AttackStrategy.ROLEPLAY,
        AttackStrategy.TOOL_HIJACK,
        AttackStrategy.PARAMETER_POLLUTION,
        AttackStrategy.CLOUD_MISCONFIG,
    ],
    AttackTargetType.RAG: [
        AttackStrategy.PROBE,
        AttackStrategy.DIRECT_INJECT,
        AttackStrategy.RAG_POISON,
        AttackStrategy.RETRIEVAL_LEAK,
        AttackStrategy.VECTOR_DB_ATTACK,
        AttackStrategy.BASE64,
    ],
    AttackTargetType.EMBEDDINGS: [
        AttackStrategy.PROBE,
        AttackStrategy.DIRECT_INJECT,
        AttackStrategy.BASE64,
        AttackStrategy.RAG_POISON,
    ],
    AttackTargetType.SUPPLY_CHAIN: [
        AttackStrategy.PROBE,
        AttackStrategy.DATASET_POISON,
        AttackStrategy.DEPENDENCY_TROJAN,
    ],
    AttackTargetType.INFRA: [
        AttackStrategy.PROBE,
        AttackStrategy.CLOUD_MISCONFIG,
        AttackStrategy.BASE64,
    ],
    AttackTargetType.GENERIC: [
        AttackStrategy.PROBE,
        AttackStrategy.DIRECT_INJECT,
        AttackStrategy.INDIRECT_INJECT,
        AttackStrategy.JAILBREAK,
        AttackStrategy.BASE64,
        AttackStrategy.ROT13,
        AttackStrategy.ROLEPLAY,
        AttackStrategy.STEALTH,
        AttackStrategy.ADVERSARIAL_SUFFIX,
        AttackStrategy.CHARACTER_SPACING,
    ],
}


__all__ = [
    "AttackTargetType",
    "AttackStrategy",
    "AttackPhaseType",
    "Severity",
    "GrayscaleLevel",
    "ScorerType",
    "PayloadTemplate",
    "AttackPhase",
    "AttackConfig",
    "AttackScenario",
    "StrategyResult",
    "PhaseResult",
    "VulnerabilityFinding",
    "ScenarioResult",
    "STRATEGY_TO_CONVERTER_MAP",
    "PHASE_DEFAULT_STRATEGIES",
    "TARGET_DEFAULT_STRATEGIES",
]