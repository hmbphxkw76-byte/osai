"""
===============================================================================
PyRIT Red Team — 自适应攻击策略选择器 (P0)
===============================================================================
侦察驱动的自适应 combo 选择 + 跨用例策略共享 + 实时反馈。

核心功能:
  1. 根据侦察阶段输出智能选择攻击组合
  2. 跨用例攻击策略共享（某 combo 在 case_A 成功后自动推广到其他 case）
  3. Bandit 算法调度：实时根据成功率动态调整组合权重
  4. Greedy Early Stop：某 case 成功后跳过剩余 combo
===============================================================================
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

_log = logging.getLogger(__name__)


class TargetArchitecture(Enum):
    """目标架构类型（来自侦察阶段）。"""
    LLM_BASIC = "llm_basic"        # 基础 LLM API
    RAG = "rag"                     # RAG 检索增强
    AGENT = "agent"                 # Agent 代理架构
    MCP = "mcp"                     # MCP 协议
    A2A = "a2a"                     # Agent-to-Agent
    MULTIMODAL = "multimodal"       # 多模态
    CHAIN = "chain"                 # 链式调用
    UNKNOWN = "unknown"


class AttackCategory(Enum):
    """攻击类别。"""
    JAILBREAK = "jailbreak"
    INJECTION = "injection"
    BYPASS = "bypass"
    RAG_POISON = "rag_poison"
    AGENT_HIJACK = "agent_hijack"
    EMBEDDING = "embedding"
    MULTIMODAL = "multimodal"
    ENCODING = "encoding"


@dataclass
class ReconResult:
    """侦察阶段输出结果。"""
    target_type: TargetArchitecture = TargetArchitecture.UNKNOWN
    target_vendor: str = ""          # openai/anthropic/google/deepseek/qwen/zhipu
    confidence: float = 0.0          # 可信度 0.0-1.0
    context_size: int = 4096         # 上下文窗口大小（tokens）
    recommended_categories: list[str] = field(default_factory=list)
    model_name: str = ""
    features: dict = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════
# 架构 → 攻击策略映射
# ═══════════════════════════════════════════════════════════════

_ARCHITECTURE_STRATEGIES = {
    TargetArchitecture.AGENT: {
        "priority": [
            "agent_hijack", "injection", "jailbreak",
            "encoding", "bypass",
        ],
        "skip": ["rag_poison", "embedding", "multimodal"],
        "description": "Agent 架构 → 优先 agent_hijack + 注入 + 越狱",
        "tactics": [
            # Tool use manipulation
            "JSONStructuredOutputHijackConverter",
            "IndirectPromptInjectionConverter",
            "MultiTurnStateManipulationConverter",
            # Agent-specific
            "SuffixAppendConverter",
            "LLMGuidedJailbreakConverter",
        ],
    },
    TargetArchitecture.RAG: {
        "priority": [
            "rag_poison", "embedding", "injection",
            "jailbreak", "bypass",
        ],
        "skip": ["agent_hijack", "multimodal"],
        "description": "RAG 架构 → 优先 RAG 投毒 + Embedding 对抗 + 注入",
        "tactics": [
            "RAGPoisoningConverter",
            "EmbeddingAdversarialConverter",
            "IndirectPromptInjectionConverter",
            "CodeNestingBypassConverter",
        ],
    },
    TargetArchitecture.MCP: {
        "priority": [
            "injection", "agent_hijack", "jailbreak",
            "encoding", "bypass",
        ],
        "skip": ["rag_poison", "multimodal"],
        "description": "MCP 协议 → 优先注入 + agent_hijack + 越狱",
    },
    TargetArchitecture.A2A: {
        "priority": [
            "agent_hijack", "injection", "jailbreak",
            "bypass",
        ],
        "skip": ["rag_poison", "embedding", "multimodal"],
        "description": "A2A Agent → 优先 agent_hijack + 注入",
    },
    TargetArchitecture.MULTIMODAL: {
        "priority": [
            "multimodal", "jailbreak", "injection",
            "encoding",
        ],
        "skip": ["rag_poison", "embedding"],
        "description": "多模态架构 → 优先多模态攻击 + 越狱",
    },
    TargetArchitecture.LLM_BASIC: {
        "priority": [
            "jailbreak", "encoding", "bypass",
            "injection", "reasoning",
        ],
        "skip": ["rag_poison", "embedding", "multimodal", "agent_hijack"],
        "description": "基础 LLM → 优先越狱 + 编码 + 绕过",
    },
    TargetArchitecture.UNKNOWN: {
        "priority": [
            "jailbreak", "encoding", "injection",
            "bypass", "reasoning", "embedding",
        ],
        "skip": [],
        "description": "未知架构 → 通用全量覆盖",
    },
}


# ═══════════════════════════════════════════════════════════════
# Bandit 算法调度器
# ═══════════════════════════════════════════════════════════════

class BanditScheduler:
    """Epsilon-Greedy Bandit 调度器。

    在多臂老虎机框架下，每个 combo 是一个"臂"，
    每次选择一个 combo 执行并获得奖励（成功=1, 失败=0）。
    算法平衡探索（尝试新组合）和利用（使用已知高成功率组合）。

    使用指数移动平均追踪每个臂的成功率。
    """

    def __init__(self, epsilon: float = 0.15):
        """
        Args:
            epsilon: 探索概率 (0.0-1.0)
                     0.15 = 15% 概率随机探索，85% 利用最优
        """
        self._epsilon = epsilon
        self._successes: dict[str, int] = defaultdict(int)
        self._trials: dict[str, int] = defaultdict(int)
        self._ema_scores: dict[str, float] = {}  # 指数移动平均
        self._alpha = 0.2  # EMA 平滑因子

    def select(self, combo_names: list[str]) -> str:
        """选择下一个要执行的 combo。

        Args:
            combo_names: 可选 combo 名称列表

        Returns:
            选中的 combo 名称
        """
        if not combo_names:
            return ""

        # Epsilon-greedy
        if random.random() < self._epsilon:
            # 探索: 随机选择
            return random.choice(combo_names)

        # 利用: 选 EMA 得分最高的
        # 未试过的 combo 给一个乐观初始值 (optimistic initialization)
        best = max(
            combo_names,
            key=lambda n: self._ema_scores.get(n, 0.6)
        )
        return best

    def update(self, combo_name: str, success: bool):
        """更新 combo 的奖励。

        Args:
            combo_name: combo 名称
            success: 是否成功
        """
        self._trials[combo_name] += 1
        if success:
            self._successes[combo_name] += 1

        # EMA 更新
        reward = 1.0 if success else 0.0
        old = self._ema_scores.get(combo_name, 0.5)
        self._ema_scores[combo_name] = old * (1 - self._alpha) + reward * self._alpha

    def get_stats(self, combo_name: str) -> dict:
        """获取 combo 统计信息。"""
        trials = self._trials.get(combo_name, 0)
        successes = self._successes.get(combo_name, 0)
        ema = self._ema_scores.get(combo_name, 0.5)

        return {
            "trials": trials,
            "successes": successes,
            "success_rate": successes / trials if trials > 0 else 0.0,
            "ema_score": round(ema, 3),
        }

    def get_top_combos(self, n: int = 10) -> list[tuple[str, float]]:
        """获取 EMA 得分最高的 N 个 combo。"""
        scored = sorted(
            self._ema_scores.items(),
            key=lambda x: x[1],
            reverse=True,
        )
        return [(name, round(score, 3)) for name, score in scored[:n]]


# ═══════════════════════════════════════════════════════════════
# 自适应策略选择器
# ═══════════════════════════════════════════════════════════════

import random  # noqa: E402 (must be after BanditScheduler which uses it via closure)


class AdaptiveComboSelector:
    """侦察驱动的自适应攻击组合选择器。

    核心功能:
      1. 根据侦察结果过滤和排序 combo
      2. 跨用例策略共享（成功组合自动推广）
      3. Bandit 算法实时调度
      4. Greedy Early Stop 管理

    Usage:
        selector = AdaptiveComboSelector(recon_result=recon_result)

        # 获取排序后的 combo 列表
        ranked_combos = selector.rank_combos(all_combos)

        # 带 bandit 调度的选择
        next_combo = selector.select_next(available_combos)

        # 反馈结果
        selector.report_result("PAIR + Base64", success=True)

        # 跨用例推广
        selector.propagate_success("PAIR + Base64", ["case_2", "case_3"])
    """

    def __init__(
        self,
        recon_result: Optional[ReconResult] = None,
        enable_bandit: bool = True,
        enable_early_stop: bool = True,
        enable_cross_case_share: bool = True,
        epsilon: float = 0.15,
    ):
        """
        Args:
            recon_result: 侦察阶段输出
            enable_bandit: 是否启用 Bandit 调度
            enable_early_stop: 是否启用 Greedy Early Stop
            enable_cross_case_share: 是否启用跨用例策略共享
            epsilon: Bandit 探索率
        """
        self._recon = recon_result or ReconResult()
        self._enable_bandit = enable_bandit
        self._enable_early_stop = enable_early_stop
        self._enable_cross_case = enable_cross_case_share
        self._bandit = BanditScheduler(epsilon=epsilon)

        # 早停追踪
        self._case_success: dict[str, bool] = {}
        self._case_tested_combos: dict[str, set[str]] = defaultdict(set)
        self._case_remaining_combos: dict[str, list[str]] = {}

        # 跨用例共享
        self._global_success_combos: list[str] = []

        # 统计
        self._total_attacks = 0
        self._total_successes = 0
        self._saved_by_early_stop = 0

    # ── 策略排序 ──

    def rank_combos(self, combos: list[dict]) -> list[dict]:
        """根据侦察结果对组合进行优先级排序。

        Args:
            combos: 原始组合列表

        Returns:
            排序后的组合列表
        """
        architecture = self._recon.target_type
        strategy = _ARCHITECTURE_STRATEGIES.get(
            architecture,
            _ARCHITECTURE_STRATEGIES[TargetArchitecture.UNKNOWN],
        )

        priority_cats = set(strategy["priority"])
        skip_cats = set(strategy["skip"])

        scored_combos = []
        for combo in combos:
            score = 1.0

            # 优先级类别加分
            for cat in combo.get("categories", []):
                if cat in priority_cats:
                    score *= 1.5
                elif cat in skip_cats:
                    score *= 0.3

            # 厂商适配加分（复用 vendor_score）
            score *= combo.get("vendor_score", 1.0)

            # 推荐 tactics 加分
            if "converters" in combo:
                for conv_name in combo["converters"]:
                    if conv_name in strategy.get("tactics", []):
                        score *= 1.3

            combo["adaptive_score"] = round(score, 3)
            scored_combos.append(combo)

        # 按得分降序排列
        scored_combos.sort(key=lambda c: c.get("adaptive_score", 1.0), reverse=True)
        return scored_combos

    def filter_by_architecture(self, combos: list[dict]) -> list[dict]:
        """根据架构类型过滤组合。"""
        architecture = self._recon.target_type
        strategy = _ARCHITECTURE_STRATEGIES.get(
            architecture,
            _ARCHITECTURE_STRATEGIES[TargetArchitecture.UNKNOWN],
        )

        skip_cats = set(strategy["skip"])

        filtered = []
        for combo in combos:
            combo_cats = set(combo.get("categories", []))
            # 如果 combo 的所有类别都在 skip 中，跳过
            if combo_cats and combo_cats.issubset(skip_cats):
                continue
            filtered.append(combo)

        return filtered

    # ── Bandit 选择 ──

    def select_next(self, available_combos: list[dict], case_id: str = "") -> dict | None:
        """选择下一个要执行的攻击组合。

        Args:
            available_combos: 可用组合列表
            case_id: 用例 ID（用于早停追踪）

        Returns:
            选中的 combo 字典，或 None（所有 combo 已完成）
        """
        if not available_combos:
            return None

        # 初始化用例追踪
        if case_id and case_id not in self._case_tested_combos:
            self._case_tested_combos[case_id] = set()
            self._case_remaining_combos[case_id] = [
                c["name"] for c in available_combos
            ]

        # 早停检查
        if self._enable_early_stop and case_id:
            already_tested = self._case_tested_combos.get(case_id, set())
            untested = [c for c in available_combos if c["name"] not in already_tested]

            if not untested:
                return None
            available_combos = untested

        if not self._enable_bandit:
            return available_combos[0]

        combo_names = [c["name"] for c in available_combos]
        selected_name = self._bandit.select(combo_names)

        for combo in available_combos:
            if combo["name"] == selected_name:
                return combo

        return available_combos[0]  # fallback

    # ── 反馈与学习 ──

    def report_result(self, combo_name: str, success: bool, case_id: str = ""):
        """报告攻击结果，更新内部状态。

        Args:
            combo_name: combo 名称
            success: 是否成功
            case_id: 用例 ID
        """
        self._total_attacks += 1
        if success:
            self._total_successes += 1

        # Bandit 更新
        if self._enable_bandit:
            self._bandit.update(combo_name, success)

        # 用例追踪
        if case_id:
            self._case_tested_combos[case_id].add(combo_name)

            if success:
                self._case_success[case_id] = True

        # 跨用例共享
        if success and self._enable_cross_case:
            if combo_name not in self._global_success_combos:
                self._global_success_combos.append(combo_name)

    def propagate_success(self, combo_name: str, target_case_ids: list[str]):
        """跨用例推广成功的攻击策略。

        当 combo 在某个 case 成功后，将其标记为其他 case 的优先组合。

        Args:
            combo_name: 成功的 combo 名称
            target_case_ids: 要推广到的目标 case ID 列表
        """
        if not self._enable_cross_case:
            return

        for case_id in target_case_ids:
            self._case_tested_combos[case_id] = self._case_tested_combos.get(
                case_id, set()
            )
            # 不标记为已测试，而是提升优先级
            # 在实际使用中，由 rank_combos 处理优先级

    def should_early_stop(self, case_id: str) -> bool:
        """判断是否应该对该 case 进行早停。

        当该 case 已有 combo 成功时，可以早停以节省资源。

        Args:
            case_id: 用例 ID

        Returns:
            是否应该停止对该 case 的后续攻击
        """
        if not self._enable_early_stop:
            return False

        return self._case_success.get(case_id, False)

    def should_skip_case(self, case_id: str, threshold: float = 0.05) -> bool:
        """判断是否应跳过该 case（全部 combo 尝试多次仍失败）。

        Args:
            case_id: 用例 ID
            threshold: 最低成功率阈值

        Returns:
            是否应跳过
        """
        tested = self._case_tested_combos.get(case_id, set())
        if len(tested) < 10:  # 至少尝试过 10 个 combo
            return False

        successes = sum(
            1 for name in tested
            if self._bandit.get_stats(name)["successes"] > 0
        )
        if successes == 0 and len(tested) >= 15:
            return True  # 15 个 combo 全部失败 → 跳过

        return False

    # ── 统计 ──

    def get_stats(self) -> dict:
        """获取选择器统计信息。"""
        return {
            "total_attacks": self._total_attacks,
            "total_successes": self._total_successes,
            "overall_success_rate": (
                self._total_successes / self._total_attacks
                if self._total_attacks > 0 else 0.0
            ),
            "bandit_epsilon": self._bandit._epsilon if self._enable_bandit else None,
            "top_combos": self._bandit.get_top_combos(5) if self._enable_bandit else [],
            "early_stop_saved": self._saved_by_early_stop,
            "cases_completed": len(self._case_success),
            "cases_successful": sum(1 for v in self._case_success.values() if v),
            "global_success_combos": len(self._global_success_combos),
        }

    def get_case_status(self, case_id: str) -> dict:
        """获取特定用例状态。"""
        return {
            "case_id": case_id,
            "success": self._case_success.get(case_id, False),
            "tested_combos": list(self._case_tested_combos.get(case_id, set())),
            "remaining_combos": [
                c for c in self._case_remaining_combos.get(case_id, [])
                if c not in self._case_tested_combos.get(case_id, set())
            ],
        }


# ═══════════════════════════════════════════════════════════════
# 辅助: 从侦察输出创建选择器
# ═══════════════════════════════════════════════════════════════

def create_selector_from_probe(
    target_type_str: str = "unknown",
    target_vendor: str = "",
    confidence: float = 0.0,
    context_size: int = 4096,
    **kwargs,
) -> AdaptiveComboSelector:
    """从侦察输出快速创建自适应选择器。

    Args:
        target_type_str: 目标类型字符串
        target_vendor: 目标厂商
        confidence: 可信度
        context_size: 上下文窗口大小
        **kwargs: 其他参数传递给 AdaptiveComboSelector

    Returns:
        配置好的 AdaptiveComboSelector
    """
    # 字符串 → TargetArchitecture 映射
    type_map = {
        "llm": TargetArchitecture.LLM_BASIC,
        "rag": TargetArchitecture.RAG,
        "agent": TargetArchitecture.AGENT,
        "mcp": TargetArchitecture.MCP,
        "a2a": TargetArchitecture.A2A,
        "multimodal": TargetArchitecture.MULTIMODAL,
        "chain": TargetArchitecture.CHAIN,
    }

    arch = TargetArchitecture.UNKNOWN
    for key, val in type_map.items():
        if key in target_type_str.lower():
            arch = val
            break

    recon = ReconResult(
        target_type=arch,
        target_vendor=target_vendor,
        confidence=confidence,
        context_size=context_size,
    )

    return AdaptiveComboSelector(recon_result=recon, **kwargs)
