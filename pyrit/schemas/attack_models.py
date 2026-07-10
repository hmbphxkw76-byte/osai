"""
===============================================================================
Attack Data Models — L2/L3 攻击数据模型
===============================================================================
标准化攻击编排与执行之间的数据传递格式。
所有模型使用 dataclass，支持 JSON 序列化。
===============================================================================
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class AttackPhase(str, Enum):
    """攻击阶段枚举 — 对应 PyRIT 原生攻击策略。"""
    PROBE = "probe"                   # 快速探测
    SINGLE = "single"                 # 单轮突破 (PromptSendingAttack)
    CRESCENDO = "crescendo"           # 多轮自适应越狱 (CrescendoAttack)
    PAIR = "pair"                     # 迭代反驳式越狱 (PAIRAttack)
    TAP = "tap"                       # 树搜索越狱 (TAPAttack)
    FLIP = "flip"                     # 对话翻转攻击 (FlipAttack)
    CHUNKED = "chunked"               # 分块请求绕过 (ChunkedRequestAttack)
    MANYSHOT = "manyshot"             # Many-shot 上下文攻击 (ManyShotJailbreakAttack)
    SKELETON_KEY = "skeleton_key"     # Skeleton Key 越狱 (SkeletonKeyAttack)


class AttackCategory(str, Enum):
    """攻击类别枚举。"""
    DIRECT_INJECTION = "3a_direct_injection"     # 直接提示注入 + 越狱
    XPIA = "3b_xpia"                             # 间接提示注入 (XPIA)
    RAG_ATTACK = "3c_rag"                        # RAG 专项攻击
    AGENT_ABUSE = "3d_agent_abuse"               # Agent 工具滥用
    MODEL_EXTRACTION = "3e_model_extraction"     # 模型提取/反演


class RiskLevel(str, Enum):
    """风险等级枚举。"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class AttackProfile:
    """攻击安全画像 — 由 L2 编排层根据侦察结果生成。

    包含:
      - 目标架构特征
      - 推荐攻击向量与优先级
      - 转换器链配置
      - Token 预算与速率限制
    """
    target_id: str = ""
    architecture: str = "unknown"  # basic_llm / rag / agent / multi_agent
    model_family: str = ""         # openai / anthropic / google / deepseek / qwen
    model_name: str = ""

    # 防御面评估
    has_guardrail: bool = False
    has_waf: bool = False
    waf_count: int = 0
    has_rate_limit: bool = False
    rpm_limit: int = 0

    # 攻击面评估
    recommended_phases: list[AttackPhase] = field(default_factory=list)
    attack_vectors: list[AttackStrategy] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.MEDIUM

    # 资源预算
    max_concurrent: int = 5
    token_budget: int = 100000
    rate_limit_rpm: int = 60

    # 时间戳
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class AttackStrategy:
    """单个攻击向量定义。

    包含攻击名称、优先级、使用的转换器链、目标阶段等。
    """
    name: str
    category: AttackCategory = AttackCategory.DIRECT_INJECTION
    priority: str = "medium"  # critical / high / medium / low
    phase: AttackPhase = AttackPhase.SINGLE
    converter_chain: list[str] = field(default_factory=list)
    success_probability: float = 0.5
    description: str = ""
    preconditions: list[str] = field(default_factory=list)
    prompt_templates: list[str] = field(default_factory=list)


@dataclass
class AttackResult:
    """单次攻击执行结果 — 标准化格式。

    所有 L3 攻击模块输出此格式，L2 编排层收集聚合，
    L5 评估层统一评分。
    """
    case_id: str
    combo_name: str = ""
    category: AttackCategory = AttackCategory.DIRECT_INJECTION
    phase: AttackPhase = AttackPhase.SINGLE
    status: str = "PENDING"  # PENDING / SUCCESS / FAILURE / ERROR / SKIPPED

    # 攻击内容
    objective: str = ""
    criterion: str = ""
    converted_prompt: str = ""
    response_text: str = ""

    # 评分
    asr_score: float = 0.0         # Attack Success Rate (0.0~1.0)
    pyrit_score: float = 0.0
    promptfoo_score: float = 0.0
    garak_confirmed: bool = False
    risk_level: RiskLevel = RiskLevel.NONE

    # OWASP 映射
    owasp_llm_category: str = ""
    owasp_agentic_category: str = ""
    mitre_atlas_technique: str = ""

    # 元数据
    turns: int = 0
    duration_ms: int = 0
    score_reason: str = ""
    details: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class AttackFeedback:
    """攻击反馈 — L3 → L2 动态反馈闭环。

    每次攻击完成后，L3 通过此结构将结果反馈给 L2 编排层，
    L2 据此动态调整后续攻击策略。
    """
    attack_result: AttackResult
    combo_name: str
    success: bool
    elapsed_ms: int = 0
    token_used: int = 0
    rate_limit_hit: bool = False
    recommendation: str = ""  # L2 可提供的策略调整建议


@dataclass
class RiskProfile:
    """风险画像 — 聚合评估结果。

    由 L5 评估层输出，用于生成最终报告。
    """
    target_id: str = ""
    overall_asr: float = 0.0
    overall_risk: RiskLevel = RiskLevel.NONE
    categories_affected: list[str] = field(default_factory=list)
    owasp_llm_coverage: list[str] = field(default_factory=list)
    owasp_agentic_coverage: list[str] = field(default_factory=list)
    mitre_atlas_coverage: list[str] = field(default_factory=list)
    top_vulnerabilities: list[dict] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


__all__ = [
    "AttackPhase", "AttackCategory", "RiskLevel",
    "AttackProfile", "AttackStrategy", "AttackResult",
    "AttackFeedback", "RiskProfile",
]
