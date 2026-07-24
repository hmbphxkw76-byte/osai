"""
Payloads Models
===============

本模块定义批量多源攻击的数据模型，包括提示词条目、提示词批次、攻击模式和攻击计划。
"""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ============================================================
# 枚举类型
# ============================================================


class AttackMode(str, Enum):
    """攻击模式 - 决定编排策略"""

    SINGLE_TURN = "single_turn"                # 单轮直接攻击
    MULTI_TURN = "multi_turn"                  # 多轮渐进攻击
    CONVERTER_ENHANCED = "converter_enhanced"  # 编码转换增强
    SEQUENTIAL = "sequential"                  # 顺序组合攻击


# ============================================================
# 提示词数据模型
# ============================================================


class SequentialStep(BaseModel):
    """顺序组合攻击的单个步骤"""

    attack_technique: str       # 攻击技术名称 (来自 ATTACK_CLASS_MAP)
    objective: str              # 该步骤的攻击目标
    converter_chain: Optional[str] = None  # 可选的 Converter 链


class PromptItem(BaseModel):
    """单个提示词条目"""

    id: str
    objective: str
    attack_mode: AttackMode
    owasp_id: Optional[str] = None
    source_id: Optional[str] = None
    category: Optional[str] = None

    # 仅 CONVERTER_ENHANCED 模式
    converter_chains: List[str] = Field(default_factory=list)

    # 仅 MULTI_TURN 模式
    multi_turn_steps: List[str] = Field(default_factory=list)

    # 仅 SEQUENTIAL 模式
    sequential_steps: List[SequentialStep] = Field(default_factory=list)

    metadata: Dict[str, Any] = Field(default_factory=dict)


class PromptBatch(BaseModel):
    """提示词批次（对应一个 YAML 文件）"""

    source_id: str
    owasp_id: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None
    prompts: List[PromptItem] = Field(default_factory=list)


# ============================================================
# 攻击计划模型
# ============================================================


class AttackPlan(BaseModel):
    """单个攻击执行计划"""

    plan_id: str
    prompt_item: PromptItem
    attack_technique: str          # 来自 ATTACK_CLASS_MAP 的键
    converter_chain_name: Optional[str] = None  # 使用的 Converter 链名称
    memory_labels: Dict[str, str] = Field(default_factory=dict)
    max_turns: int = 1             # 多轮攻击最大轮次
    priority: int = 50             # 执行优先级 (0-100, 越高越先执行)
    owasp_id: Optional[str] = None
    scorer_type: str = "general"   # 评分器类型 (general/leakage_detection/injection_detection/code_safety)
    scenario_name: str = ""        # 所属 Scenario 名称


# ============================================================
# 批量执行结果模型
# ============================================================


class BatchAttackResult(BaseModel):
    """批量攻击结果"""

    total_plans: int = 0
    executed: int = 0
    succeeded: int = 0
    failed: int = 0
    errored: int = 0
    results: List[Any] = Field(default_factory=list)  # AttackResult 列表
    errors: List[Dict[str, Any]] = Field(default_factory=list)

    # 反馈循环统计
    upgrade_attempts: int = 0          # 升级重试次数
    upgrade_success: int = 0           # 升级重试成功次数

    @property
    def success_rate(self) -> float:
        if self.executed == 0:
            return 0.0
        return self.succeeded / self.executed

    @property
    def upgrade_success_rate(self) -> float:
        if self.upgrade_attempts == 0:
            return 0.0
        return self.upgrade_success / self.upgrade_attempts
