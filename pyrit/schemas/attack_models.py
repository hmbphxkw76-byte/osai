"""攻击数据模型 - AttackProfile, AttackStrategy, AttackResult 等."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Optional


# ============================================================
# Enums
# ============================================================

class AttackPhase(str, Enum):
    """攻击阶段枚举 — 覆盖完整攻击链."""

    RECON = "recon"                          # 目标侦查
    ROUTING = "routing"                      # 策略路由
    DIRECT_INJECTION = "direct_injection"    # 3a: 直接提示注入
    JAILBREAK = "jailbreak"                  # 3a: 越狱
    XPIA = "xpia"                            # 3b: 间接提示注入
    RAG_ATTACK = "rag_attack"                # 3c: RAG 专项攻击
    AGENT_ABUSE = "agent_abuse"              # 3d: Agent 工具滥用
    MODEL_EXTRACTION = "model_extraction"    # 3e: 模型提取/反演
    MULTI_AGENT = "multi_agent"              # L4: 多 Agent 攻击
    EVALUATION = "evaluation"                # 评估判定
    REPORTING = "reporting"                  # 报告生成


class AttackCategory(str, Enum):
    """攻击类别枚举."""

    DIRECT_INJECTION = "direct_injection"
    JAILBREAK = "jailbreak"
    XPIA_IMAGE = "xpia_image"
    XPIA_DOCUMENT = "xpia_document"
    XPIA_WEBPAGE = "xpia_webpage"
    XPIA_MULTI_TURN = "xpia_multi_turn"
    RAG_RETRIEVAL_INJECTION = "rag_retrieval_injection"
    RAG_DOCUMENT_POISONING = "rag_document_poisoning"
    RAG_KNOWLEDGE_LEAK = "rag_knowledge_leak"
    AGENT_MODEL_CALL = "agent_model_call"
    AGENT_BUSINESS_EXPLOIT = "agent_business_exploit"
    MODEL_EXTRACTION_DATA = "model_extraction_data"
    MODEL_EXTRACTION_PARAM = "model_extraction_param"
    MEMBERSHIP_INFERENCE = "membership_inference"
    COMM_HIJACK = "comm_hijack"
    CASCADE_FAILURE = "cascade_failure"
    MEMORY_POISONING = "memory_poisoning"
    TRUST_EXPLOITATION = "trust_exploitation"


class AttackStatus(str, Enum):
    """攻击执行状态."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    PARTIAL = "partial"
    ERROR = "error"
    SKIPPED = "skipped"


class RiskLevel(str, Enum):
    """风险等级."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class ConverterConfig:
    """载荷转换器配置 — 用于变换攻击载荷形态."""

    name: str                                    # 转换器名称
    params: dict[str, Any] = field(default_factory=dict)
    order: int = 0                               # 转换顺序
    enabled: bool = True

    # 预定义转换器常量
    BASE64 = "base64_encode"
    ROT13 = "rot13_encode"
    LEETSPEAK = "leetspeak"
    UNICODE_BYPASS = "unicode_bypass"
    PREFIX_INJECTION = "prefix_injection"
    SUFFIX_INJECTION = "suffix_injection"
    ROLE_PLAY = "role_play"
    FEW_SHOT_MANIPULATION = "few_shot_manipulation"
    CODE_INJECTION = "code_injection"
    MULTI_LINGUAL = "multi_lingual"
    CHARACTER_SPLIT = "character_split"
    MARKDOWN_ESCAPE = "markdown_escape"
    JSON_EMBED = "json_embed"


@dataclass
class AttackStrategy:
    """攻击策略 — 定义具体攻击的执行方案."""

    strategy_id: str = field(default_factory=lambda: f"strategy_{uuid.uuid4().hex[:8]}")
    name: str = ""
    category: AttackCategory = AttackCategory.DIRECT_INJECTION
    phase: AttackPhase = AttackPhase.DIRECT_INJECTION

    # 载荷配置
    prompt_template: str = ""
    prompt_params: dict[str, Any] = field(default_factory=dict)
    converter_chain: list[ConverterConfig] = field(default_factory=list)

    # 迭代配置
    max_turns: int = 5
    max_retries: int = 3
    temperature: float = 0.7

    # 判定配置
    success_criteria: list[str] = field(default_factory=list)
    failure_patterns: list[str] = field(default_factory=list)

    # 元数据
    owasp_mapping: str = ""
    mitre_atlas_mapping: str = ""
    risk_level: RiskLevel = RiskLevel.MEDIUM
    weight: float = 1.0                         # 多策略调度权重
    tags: list[str] = field(default_factory=list)


@dataclass
class AttackProfile:
    """攻击画像 — 针对特定目标的完整攻击计划."""

    profile_id: str = field(default_factory=lambda: f"profile_{uuid.uuid4().hex[:12]}")
    target_id: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    # 攻击策略列表
    strategies: list[AttackStrategy] = field(default_factory=list)

    # 执行参数
    concurrency: int = 1
    timeout_seconds: int = 300
    retry_on_failure: bool = True

    # 预算控制
    max_tokens: int = 100_000
    max_cost_usd: float = 10.0

    # 元数据
    source: str = "router"                       # router / manual / feedback
    notes: str = ""

    @property
    def category_counts(self) -> dict[str, int]:
        """统计各攻击类别的策略数量."""
        counts: dict[str, int] = {}
        for s in self.strategies:
            cat = s.category.value
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    @property
    def high_risk_strategies(self) -> list[AttackStrategy]:
        """返回高风险/严重等级的策略."""
        return [s for s in self.strategies if s.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)]


@dataclass
class AttackResult:
    """攻击结果 — 单次攻击执行的完整记录."""

    result_id: str = field(default_factory=lambda: f"result_{uuid.uuid4().hex[:8]}")
    strategy_id: str = ""
    profile_id: str = ""

    # 状态
    status: AttackStatus = AttackStatus.PENDING
    phase: AttackPhase = AttackPhase.DIRECT_INJECTION
    category: AttackCategory = AttackCategory.DIRECT_INJECTION

    # 内容
    prompt_sent: str = ""
    response_received: str = ""
    converter_chain_used: list[str] = field(default_factory=list)

    # 指标
    tokens_used: int = 0
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    turns_executed: int = 0

    # 判定
    success: bool = False
    confidence: float = 0.0                     # 成功置信度 0.0~1.0
    jailbreak_score: float = 0.0                # 越狱评分
    harm_score: float = 0.0                     # 危害评分
    eval_details: dict[str, Any] = field(default_factory=dict)

    # 时间
    started_at: str = ""
    completed_at: str = ""

    # 元数据
    raw_log: str = ""
    error_message: str = ""
    tags: list[str] = field(default_factory=list)

    def to_eval_dict(self) -> dict[str, Any]:
        """转换为 L5 统一评估所需格式."""
        return {
            "result_id": self.result_id,
            "strategy_id": self.strategy_id,
            "status": self.status.value,
            "category": self.category.value,
            "phase": self.phase.value,
            "prompt": self.prompt_sent,
            "response": self.response_received,
            "success": self.success,
            "confidence": self.confidence,
            "jailbreak_score": self.jailbreak_score,
            "harm_score": self.harm_score,
            "tokens_used": self.tokens_used,
            "cost_usd": self.cost_usd,
            "latency_ms": self.latency_ms,
            "turns": self.turns_executed,
            "converters": self.converter_chain_used,
            "eval_details": self.eval_details,
            "tags": self.tags,
        }


@dataclass
class AttackFeedback:
    """攻击反馈 — 用于动态闭环调优."""

    profile_id: str = ""
    strategy_id: str = ""
    iteration: int = 0

    # 成功率指标
    asr: float = 0.0                            # Attack Success Rate
    block_rate: float = 0.0
    avg_tokens: float = 0.0

    # 策略奖励 (用于 Bandit 算法)
    reward: float = 0.0

    # 调优建议
    suggested_adjustments: dict[str, Any] = field(default_factory=dict)
    should_continue: bool = True
    early_stop_reason: str = ""


@dataclass
class RiskProfile:
    """风险评估画像 — 汇总整个攻击链的风险评估."""

    profile_id: str = ""
    target_id: str = ""
    overall_risk: RiskLevel = RiskLevel.INFO
    risk_score: float = 0.0                     # 0.0~100.0

    # 分维度风险
    injection_risk: float = 0.0
    jailbreak_risk: float = 0.0
    xpia_risk: float = 0.0
    rag_risk: float = 0.0
    agent_abuse_risk: float = 0.0
    extraction_risk: float = 0.0
    multi_agent_risk: float = 0.0

    # 漏洞统计
    total_attacks: int = 0
    successful_attacks: int = 0
    blocked_attacks: int = 0
    critical_vulns: int = 0
    high_vulns: int = 0

    # 建议
    recommendations: list[str] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def overall_asr(self) -> float:
        """整体攻击成功率."""
        if self.total_attacks == 0:
            return 0.0
        return self.successful_attacks / self.total_attacks
