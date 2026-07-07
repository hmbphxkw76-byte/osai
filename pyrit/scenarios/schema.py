"""
===============================================================================
OffSec AI-300 — 考试提示词模板 Schema (Pydantic v2)
===============================================================================
标准化 YAML/JSON 模板格式：考试期间仅需编辑此格式的模板文件，
其余所有攻击编排、提示词变体、目标交互、结果评分均由系统自动完成。

模板结构：
  exam_prompts.yaml
  ├── metadata        — 考试元信息
  ├── config          — 执行参数（并发/策略选择/深度等）
  └── prompts[]       — 提示词列表（核心：考试期间仅修改此项）

提示词字段说明：
  id                 — 唯一标识（如 P001）
  objective          — 原始攻击目标文本（必填）
  criterion          — 成功判定标准（必填）
  category           — 攻击类别（jailbreak/extraction/injection/tool_use/...）
  difficulty          — 难度预估（basic/medium/hard）
  owasp_category     — OWASP LLM Top 10 分类
  multi_turn         — 是否多轮渐进式攻击
  multi_turn_stages  — 多轮各阶段子目标（可选）
  strategy_overrides — 强制指定的攻击策略列表（可选，留空则全策略覆盖）
===============================================================================
"""
from __future__ import annotations

from enum import Enum
from typing import Optional, Literal
from pydantic import BaseModel, Field, field_validator, model_validator


# ═══════════════════════════════════════════════════════════════════
# 枚举定义
# ═══════════════════════════════════════════════════════════════════

class TemplateMode(str, Enum):
    """模板模式 — 区分 tech（技术模板）和 exam（考试模板）"""
    TECH = "tech"    # 🅰 技术模板：关注 converter 链突破效果
    EXAM = "exam"    # 🅱 考试模板：关注攻击面覆盖 + 纵深突破


class PromptCategory(str, Enum):
    """攻击类别 — 影响变体生成策略和评分器选择"""
    JAILBREAK = "jailbreak"           # 越狱攻击（绕过安全对齐）
    EXTRACTION = "extraction"         # 信息提取（系统提示词/内部数据）
    INJECTION = "injection"           # 注入攻击（SQL/XSS/命令注入）
    TOOL_USE = "tool_use"             # 工具调用滥用（MCP/Function Calling）
    TOXICITY = "toxicity"             # 有害内容生成
    PRIVACY = "privacy"               # 隐私泄露
    MISINFO = "misinfo"               # 虚假信息/误导
    EXPLOIT = "exploit"               # 漏洞利用代码生成
    SOCIAL = "social"                 # 社会工程
    MCP_ABUSE = "mcp_abuse"           # MCP 协议滥用
    A2A_ABUSE = "a2a_abuse"           # A2A 协议滥用
    RAG_POISON = "rag_poison"         # RAG 投毒（Module 8）
    RAG_EXPLOIT = "rag_exploit"       # RAG 利用（检索操纵/数据泄露）
    AGENT_HIJACK = "agent_hijack"     # Agent 工具劫持（Module 9）
    MULTI_AGENT = "multi_agent"       # 多智能体利用（Module 10）
    MODEL_EXTRACT = "model_extract"   # 模型提取（Module 11）
    DATA_POISON = "data_poison"       # 训练数据投毒（Module 12）
    SUPPLY_CHAIN = "supply_chain"     # AI 供应链攻击（Module 13）
    INFRA_ATTACK = "infra_attack"     # AI 基础设施攻击（Module 14-16）
    CUSTOM = "custom"                 # 自定义（考试不限类别）


class DifficultyLevel(str, Enum):
    BASIC = "basic"
    MEDIUM = "medium"
    HARD = "hard"


class OWASPCategory(str, Enum):
    """OWASP LLM Top 10 映射"""
    LLM01 = "LLM01: Prompt Injection"
    LLM02 = "LLM02: Insecure Output Handling"
    LLM03 = "LLM03: Training Data Poisoning"
    LLM04 = "LLM04: Model Denial of Service"
    LLM05 = "LLM05: Supply Chain Vulnerabilities"
    LLM06 = "LLM06: Sensitive Information Disclosure"
    LLM07 = "LLM07: Insecure Plugin Design"
    LLM08 = "LLM08: Excessive Agency"
    LLM09 = "LLM09: Overreliance"
    LLM10 = "LLM10: Model Theft"
    MCP01 = "MCP: Tool Poisoning"
    MCP02 = "MCP: Credential Leak"
    A2A01 = "A2A: Agent Card Spoofing"
    A2A02 = "A2A: Task Hijacking"


# ═══════════════════════════════════════════════════════════════════
# 攻击策略枚举（系统内置，考试期间不可修改）
# ═══════════════════════════════════════════════════════════════════

class AttackStrategy(str, Enum):
    """系统内置攻击策略 — 考试期间不可修改"""
    # ── 对话型攻击策略（原 19 个）──
    PROBE = "probe"                    # 基础探测
    BASE64 = "base64"                  # Base64 编码混淆
    ROT13 = "rot13"                    # ROT13 编码混淆
    ROLEPLAY = "roleplay"              # 角色扮演越狱
    ACADEMIC = "academic"              # 学术伪装
    STEALTH = "stealth"                # 术语混淆/隐身
    BRUTEFORCE = "bruteforce"          # 直接攻击
    TRANSLATION = "translation"        # 翻译绕过
    ENCODING = "encoding"              # 多层编码链
    FEWSHOT = "fewshot"                # Few-shot 前置
    DEEPINCEPTION = "deepinception"    # 深度嵌套
    JSON_HIJACK = "json_hijack"        # JSON 结构化劫持
    CRESCENDO = "crescendo"            # 多轮渐进式
    PAIR = "pair"                      # 迭代反驳式
    TAP = "tap"                        # 树搜索
    FLIP = "flip"                      # 对话翻转
    CHUNKED = "chunked"                # 分块请求
    MANYSHOT = "manyshot"              # Many-shot 淹没
    SKELETON_KEY = "skeleton_key"      # Skeleton Key 直接解除
    NONE = "none"                      # 不应用策略（原始提示词）
    # ── RAG 攻击策略（Module 8）──
    RAG_POISON_DOC = "rag_poison_doc"       # 文档投毒注入
    RAG_RETRIEVAL = "rag_retrieval"          # 检索结果操纵
    RAG_LEAK = "rag_leak"                    # RAG 数据泄露探测
    # ── 多智能体攻击策略（Module 9-10）──
    CROSS_AGENT_INJECT = "cross_agent_inject"    # 跨代理注入
    TOOL_CALL_HIJACK = "tool_call_hijack"         # 工具调用劫持
    ORCHESTRATOR_MANIP = "orchestrator_manip"     # 编排器操纵
    MEMORY_POISON = "memory_poison"               # 代理记忆投毒
    # ── 基础设施/供应链攻击策略（Module 11-16）──
    API_FUZZ = "api_fuzz"                        # AI API 模糊测试
    MODEL_SERVING_EXPLOIT = "model_serving_exploit"  # 模型服务利用
    SUPPLY_CHAIN_SCAN = "supply_chain_scan"       # 供应链扫描探测


# ═══════════════════════════════════════════════════════════════════
# 转换器映射（考试期间预固化）
# ═══════════════════════════════════════════════════════════════════

# 策略 → 转换器名称映射（预固化，考试不修改）
STRATEGY_CONVERTER_MAP: dict[AttackStrategy, str] = {
    AttackStrategy.BASE64: "Base64Converter",
    AttackStrategy.ROT13: "ROT13Converter",
    AttackStrategy.ROLEPLAY: "RoleplayJailbreakConverter",
    AttackStrategy.ACADEMIC: "AcademicResearchConverter",
    AttackStrategy.STEALTH: "AcademicResearchConverter",       # 借用 Academic 语义
    AttackStrategy.BRUTEFORCE: "ContextualPrimingConverter",
    AttackStrategy.TRANSLATION: "TranslationBypassConverter",
    AttackStrategy.ENCODING: "Base64Converter",                # 多层编码入口
    AttackStrategy.FEWSHOT: "FewShotPrimingConverter",
    AttackStrategy.DEEPINCEPTION: "DeepInceptionConverter",
    AttackStrategy.JSON_HIJACK: "JSONStructuredOutputHijackConverter",
    AttackStrategy.NONE: "",
}

# 策略分类（预固化）
STRATEGY_CATEGORIES: dict[str, list[AttackStrategy]] = {
    "encoding": [
        AttackStrategy.BASE64, AttackStrategy.ROT13, AttackStrategy.ENCODING,
    ],
    "jailbreak_prefix": [
        AttackStrategy.ROLEPLAY, AttackStrategy.ACADEMIC, AttackStrategy.STEALTH,
    ],
    "bypass": [
        AttackStrategy.TRANSLATION, AttackStrategy.DEEPINCEPTION, AttackStrategy.FEWSHOT,
    ],
    "advanced": [
        AttackStrategy.PAIR, AttackStrategy.TAP, AttackStrategy.FLIP,
        AttackStrategy.CHUNKED, AttackStrategy.MANYSHOT, AttackStrategy.SKELETON_KEY,
    ],
    "multiturn": [
        AttackStrategy.CRESCENDO,
    ],
    "brutal": [
        AttackStrategy.BRUTEFORCE,
    ],
    "rag": [
        AttackStrategy.RAG_POISON_DOC, AttackStrategy.RAG_RETRIEVAL, AttackStrategy.RAG_LEAK,
    ],
    "agent": [
        AttackStrategy.CROSS_AGENT_INJECT, AttackStrategy.TOOL_CALL_HIJACK,
        AttackStrategy.ORCHESTRATOR_MANIP, AttackStrategy.MEMORY_POISON,
    ],
    "infra": [
        AttackStrategy.API_FUZZ, AttackStrategy.MODEL_SERVING_EXPLOIT, AttackStrategy.SUPPLY_CHAIN_SCAN,
    ],
}

# 默认全策略覆盖（考试期间自动选择最优策略组合）
DEFAULT_FULL_STRATEGIES: list[AttackStrategy] = [
    AttackStrategy.PROBE,
    AttackStrategy.BASE64,
    AttackStrategy.ROT13,
    AttackStrategy.ROLEPLAY,
    AttackStrategy.ACADEMIC,
    AttackStrategy.BRUTEFORCE,
    AttackStrategy.STEALTH,
    AttackStrategy.TRANSLATION,
    AttackStrategy.DEEPINCEPTION,
    AttackStrategy.FEWSHOT,
    AttackStrategy.JSON_HIJACK,
    AttackStrategy.ENCODING,
]

# 多轮专用策略
MULTI_TURN_STRATEGIES: list[AttackStrategy] = [
    AttackStrategy.CRESCENDO,
    AttackStrategy.PAIR,
    AttackStrategy.TAP,
]


# ═══════════════════════════════════════════════════════════════════
# Pydantic 模型
# ═══════════════════════════════════════════════════════════════════

class ExamModeConfig(BaseModel):
    """考试模式全局配置 — 考试期间可少量调整"""
    # 🆕 模板模式（tech vs exam）
    mode: TemplateMode = Field(default=TemplateMode.EXAM,
        description="模板模式: tech（技术模板）或 exam（考试模板）")
    # 并发数
    max_concurrent: int = Field(default=3, ge=1, le=9,
        description="最大并发攻击数")
    # 评分阈值
    gate_threshold: float = Field(default=0.10, ge=0.0, le=1.0,
        description="门控阈值：PROBE成功率低于此值自动升级策略")
    # 变体生成数量
    variants_per_prompt: int = Field(default=5, ge=1, le=10,
        description="每个提示词生成的变体数量")
    # 语言
    language: Literal["cn", "en"] = "cn"
    # 是否包含高级策略（PAIR/TAP/FLIP等）
    enable_advanced: bool = Field(default=True,
        description="启用高级攻击策略（考试时间充裕时推荐开启）")
    # 是否包含多轮策略
    enable_multiturn: bool = Field(default=True,
        description="启用多轮渐进式攻击")
    # 超时（秒）
    prompt_timeout: int = Field(default=120, ge=30, le=600,
        description="单次攻击超时秒数")


class ExamPrompt(BaseModel):
    """单个考试提示词 — 考试期间仅需填写此结构"""
    id: str = Field(..., min_length=1,
        description="提示词唯一标识（如 P001_jailbreak_system）")
    objective: str = Field(..., min_length=1,
        description="原始攻击目标文本")
    criterion: str = Field(..., min_length=1,
        description="成功判定标准（Judge LLM 判定依据）")

    # ── 可选元信息（用于自动优化策略选择）──
    category: PromptCategory = PromptCategory.CUSTOM
    difficulty: DifficultyLevel = DifficultyLevel.MEDIUM
    owasp_category: OWASPCategory = OWASPCategory.LLM01

    # ── 多轮攻击配置 ──
    multi_turn: bool = Field(default=False,
        description="是否为多轮渐进式攻击")
    multi_turn_stages: Optional[list[str]] = Field(default=None,
        description="多轮各阶段子目标（multi_turn=true 时必填）")

    # ── 策略覆盖（考试期间可选，用于微调）──
    strategy_overrides: Optional[list[str]] = Field(default=None,
        description="强制指定攻击策略列表（留空=全策略自动覆盖）")
    exclude_strategies: Optional[list[str]] = Field(default=None,
        description="排除的攻击策略列表")

    # ── 模板变量注入（{key} → 值替换，考试期间可选）──
    template_vars: Optional[dict[str, str]] = Field(default=None,
        description="模板变量（{key} 自动替换为对应值）")

    @field_validator("id")
    @classmethod
    def _validate_id(cls, v: str) -> str:
        """确保 ID 不含特殊字符"""
        import re
        if not re.match(r'^[A-Za-z0-9_\-]+$', v):
            raise ValueError(f"ID '{v}' 只能包含字母、数字、下划线和连字符")
        return v

    @model_validator(mode="after")
    def _validate_multi_turn(self) -> "ExamPrompt":
        if self.multi_turn and not self.multi_turn_stages:
            raise ValueError(
                f"多轮提示词 {self.id} 必须提供 multi_turn_stages"
            )
        return self

    def resolve_strategies(self, config: ExamModeConfig) -> list[AttackStrategy]:
        """根据配置和提示词属性自动选择最优攻击策略组合。

        选择逻辑（预固化，考试期间不修改）：
          1. 若有 strategy_overrides → 使用指定策略
          2. 若有 exclude_strategies → 排除指定策略
          3. multi_turn → 优先多轮策略 + 编码策略
          4. 按 difficulty 调整策略深度
          5. 按 category 选择专用策略组合
        """
        # 用户强制指定
        if self.strategy_overrides:
            strategies = []
            for s in self.strategy_overrides:
                try:
                    strategies.append(AttackStrategy(s))
                except ValueError:
                    pass
            if strategies:
                return strategies

        # 自动选择
        strategies: list[AttackStrategy] = []

        # 基础编码策略（所有提示词都适用）
        strategies.extend([
            AttackStrategy.PROBE,
            AttackStrategy.BASE64,
            AttackStrategy.ROT13,
            AttackStrategy.ROLEPLAY,
            AttackStrategy.ACADEMIC,
            AttackStrategy.STEALTH,
            AttackStrategy.TRANSLATION,
            AttackStrategy.BRUTEFORCE,
        ])

        # 按难度深加
        if self.difficulty in (DifficultyLevel.MEDIUM, DifficultyLevel.HARD):
            strategies.extend([
                AttackStrategy.DEEPINCEPTION,
                AttackStrategy.FEWSHOT,
                AttackStrategy.ENCODING,
            ])

        if self.difficulty == DifficultyLevel.HARD:
            strategies.extend([
                AttackStrategy.JSON_HIJACK,
            ])

        # 按类别加专项
        category_extras = {
            PromptCategory.EXTRACTION: [
                AttackStrategy.JSON_HIJACK,
                AttackStrategy.FEWSHOT,
            ],
            PromptCategory.INJECTION: [
                AttackStrategy.JSON_HIJACK,
                AttackStrategy.CHUNKED,
            ],
            PromptCategory.TOOL_USE: [
                AttackStrategy.CHUNKED,
                AttackStrategy.JSON_HIJACK,
            ],
            PromptCategory.MCP_ABUSE: [
                AttackStrategy.CHUNKED,
                AttackStrategy.JSON_HIJACK,
            ],
            PromptCategory.RAG_POISON: [
                AttackStrategy.RAG_POISON_DOC,
                AttackStrategy.RAG_RETRIEVAL,
                AttackStrategy.FEWSHOT,
                AttackStrategy.ENCODING,
            ],
            PromptCategory.RAG_EXPLOIT: [
                AttackStrategy.RAG_RETRIEVAL,
                AttackStrategy.RAG_LEAK,
                AttackStrategy.RAG_POISON_DOC,
                AttackStrategy.JSON_HIJACK,
            ],
            PromptCategory.AGENT_HIJACK: [
                AttackStrategy.TOOL_CALL_HIJACK,
                AttackStrategy.CROSS_AGENT_INJECT,
                AttackStrategy.JSON_HIJACK,
                AttackStrategy.CHUNKED,
            ],
            PromptCategory.MULTI_AGENT: [
                AttackStrategy.CROSS_AGENT_INJECT,
                AttackStrategy.TOOL_CALL_HIJACK,
                AttackStrategy.ORCHESTRATOR_MANIP,
                AttackStrategy.MEMORY_POISON,
                AttackStrategy.CHUNKED,
            ],
            PromptCategory.MODEL_EXTRACT: [
                AttackStrategy.API_FUZZ,
                AttackStrategy.MODEL_SERVING_EXPLOIT,
                AttackStrategy.FEWSHOT,
            ],
            PromptCategory.DATA_POISON: [
                AttackStrategy.RAG_POISON_DOC,
                AttackStrategy.SUPPLY_CHAIN_SCAN,
                AttackStrategy.ENCODING,
            ],
            PromptCategory.SUPPLY_CHAIN: [
                AttackStrategy.SUPPLY_CHAIN_SCAN,
                AttackStrategy.MODEL_SERVING_EXPLOIT,
                AttackStrategy.API_FUZZ,
            ],
            PromptCategory.INFRA_ATTACK: [
                AttackStrategy.API_FUZZ,
                AttackStrategy.MODEL_SERVING_EXPLOIT,
                AttackStrategy.SUPPLY_CHAIN_SCAN,
                AttackStrategy.CHUNKED,
            ],
        }
        for s in category_extras.get(self.category, []):
            if s not in strategies:
                strategies.append(s)

        # 高级策略（全局开关）
        if config.enable_advanced:
            strategies.extend([
                AttackStrategy.PAIR,
                AttackStrategy.TAP,
                AttackStrategy.FLIP,
                AttackStrategy.CHUNKED,
                AttackStrategy.MANYSHOT,
                AttackStrategy.SKELETON_KEY,
            ])

        # 多轮策略
        if self.multi_turn and config.enable_multiturn:
            strategies.extend([
                AttackStrategy.CRESCENDO,
            ])

        # 排除
        if self.exclude_strategies:
            exclude_set = set()
            for s in self.exclude_strategies:
                try:
                    exclude_set.add(AttackStrategy(s))
                except ValueError:
                    pass
            strategies = [s for s in strategies if s not in exclude_set]

        # 去重
        seen = set()
        unique = []
        for s in strategies:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        return unique


class ExamPromptSet(BaseModel):
    """完整考试提示词模板集 — YAML/JSON 顶层结构"""
    metadata: dict = Field(default_factory=lambda: {
        "version": "1.0",
        "framework_version": "AI-300 v10.0",
        "description": "OffSec AI-300 考试提示词模板",
    })
    config: ExamModeConfig = Field(default_factory=ExamModeConfig)
    prompts: list[ExamPrompt] = Field(..., min_length=1)

    @classmethod
    def from_yaml_file(cls, filepath: str) -> "ExamPromptSet":
        """从 YAML 文件加载考试模板"""
        import yaml
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not data:
            raise ValueError(f"YAML 文件为空: {filepath}")
        return cls.model_validate(data)

    @classmethod
    def from_json_file(cls, filepath: str) -> "ExamPromptSet":
        """从 JSON 文件加载考试模板"""
        import json
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.model_validate(data)

    def get_summary(self) -> dict:
        """获取模板概览统计"""
        cats = {}
        diffs = {}
        multi_turns = 0
        for p in self.prompts:
            cats[p.category.value] = cats.get(p.category.value, 0) + 1
            diffs[p.difficulty.value] = diffs.get(p.difficulty.value, 0) + 1
            if p.multi_turn:
                multi_turns += 1
        total_strategies = sum(
            len(p.resolve_strategies(self.config)) for p in self.prompts
        )
        return {
            "total_prompts": len(self.prompts),
            "multi_turn": multi_turns,
            "single_turn": len(self.prompts) - multi_turns,
            "categories": cats,
            "difficulties": diffs,
            "estimated_attacks": total_strategies * self.config.variants_per_prompt,
            "total_strategies_applied": total_strategies,
        }


# ═══════════════════════════════════════════════════════════════════
# 变体定义
# ═══════════════════════════════════════════════════════════════════

class VariantType(str, Enum):
    """提示词变体类型"""
    BASE64 = "base64"                # Base64 编码
    ROT13 = "rot13"                  # ROT13 编码
    LEETSPEAK = "leetspeak"         # 字符替换混淆
    ROLEPLAY = "roleplay"           # 角色扮演包装
    ACADEMIC = "academic"           # 学术研究包装
    STEALTH = "stealth"             # 术语混淆隐身
    TRANSLATION_EN = "translation_en"  # 英文翻译绕过
    TRANSLATION_MIXED = "translation_mixed"  # 中英混合
    ZEROWIDTH = "zerowidth"         # 零宽字符注入
    DEIDENTIFICATION = "deidentification"  # 去标识化（代词替换）
    SCENARIO_WRAP = "scenario_wrap" # 场景包装（红队/授权/测试）
    SYNONYM_SWAP = "synonym_swap"   # 同义词替换
    MULTILAYER = "multilayer"       # 多层编码链（Base64→ROT13→Binary）
    RAW = "raw"                     # 原始无变换


PromptVariant = dict  # {"type": VariantType, "prompt": str}
