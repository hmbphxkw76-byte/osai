# -*- coding: utf-8 -*-
"""
AI-300 Framework - Smart Matcher v3.0
智能匹配引擎：PayloadProfile → PyRIT Native Attack Strategy Selector

核心改进（v3.0）：
1. 两层策略选择：快速规则筛选 → 精确模型匹配（借鉴 Promptfoo 分层思想）
2. 攻击探针族：将相似攻击编组，按载荷类别自动选择（借鉴 garak 探针族概念）
3. ASI 感知策略：OWASP/ASI 分类作为策略约束（借鉴 DeepTeam 框架映射）
4. 动态参数计算：基于 payload 特征自适应调整攻击参数
5. 策略链 Fallback：支持多策略渐进升级
6. PAIR/RedTeaming 激活：完整利用 PyRIT 全部攻击类型
7. 转换器预设影响：converter_presets 参与策略决策

设计原则（v3.0）：
- SmartMatcher = 策略选择器（不负责执行，只选择 PyRIT 攻击类）
- AttackOrchestrator = PyRIT 攻击构建器 + 结果收集器
- 执行全部交给 PyRIT 原生攻击（继承重试/升级/回退/剪枝/早停）

PyRIT 0.14.0 兼容
"""

import sys
import os
import logging
from typing import Any, Dict, List, Optional, Set

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# PyRIT 攻击策略常量
# ──────────────────────────────────────────────────────────────────────────────

class PyRITAttack:
    """PyRIT 原生攻击策略常量"""
    PROMPT_SENDING = "pyrit.executor.attack.single_turn.prompt_sending.PromptSendingAttack"
    CRESCENDO = "pyrit.executor.attack.multi_turn.crescendo.CrescendoAttack"
    TREE_OF_ATTACKS = "pyrit.executor.attack.multi_turn.tree_of_attacks.TreeOfAttacksWithPruningAttack"
    PAIR = "pyrit.executor.attack.multi_turn.pair.PAIRAttack"
    RED_TEAMING = "pyrit.executor.attack.multi_turn.red_teaming.RedTeamingAttack"
    SEQUENTIAL = "pyrit.executor.attack.compound.sequential_attack.SequentialAttack"


# ──────────────────────────────────────────────────────────────────────────────
# 攻击探针族（借鉴 garak 探针族概念）
# ──────────────────────────────────────────────────────────────────────────────

class AttackProbeFamily:
    """攻击探针族：将相似攻击编组"""
    # 单轮直接攻击族
    DIRECT_SINGLE = "direct_single"           # PromptSendingAttack
    # 渐进升级攻击族
    PROGRESSIVE = "progressive"               # CrescendoAttack
    # 树搜索攻击族
    TREE_SEARCH = "tree_search"               # TreeOfAttacksWithPruningAttack
    # 迭代优化攻击族
    ITERATIVE = "iterative"                   # PAIRAttack
    # 开放式探索攻击族
    EXPLORATORY = "exploratory"               # RedTeamingAttack
    # 多 preset 早停族
    MULTI_PRESET = "multi_preset"             # SequentialAttack


# 载荷类别 → 攻击探针族映射
CATEGORY_PROBE_FAMILY_MAP: Dict[str, str] = {
    "direct_short": AttackProbeFamily.DIRECT_SINGLE,
    "role_play": AttackProbeFamily.PROGRESSIVE,
    "multilingual": AttackProbeFamily.DIRECT_SINGLE,
    "encoded": AttackProbeFamily.DIRECT_SINGLE,
    "long_context": AttackProbeFamily.TREE_SEARCH,
    "prompt_leaking": AttackProbeFamily.DIRECT_SINGLE,
    "adversarial": AttackProbeFamily.TREE_SEARCH,
    "markdown_injection": AttackProbeFamily.DIRECT_SINGLE,
    "indirect_injection": AttackProbeFamily.PROGRESSIVE,
    "context_splitting": AttackProbeFamily.PROGRESSIVE,
    "multi_encoding": AttackProbeFamily.DIRECT_SINGLE,
    "instruction_override": AttackProbeFamily.PROGRESSIVE,
    "payload_splitting": AttackProbeFamily.PROGRESSIVE,
    # v3.1 新增类别
    "data_exfiltration": AttackProbeFamily.PROGRESSIVE,
    "cross_context_contamination": AttackProbeFamily.TREE_SEARCH,
    "context_manipulation": AttackProbeFamily.PROGRESSIVE,
}

# 攻击探针族 → PyRIT 攻击类映射
FAMILY_ATTACK_CLASS_MAP: Dict[str, str] = {
    AttackProbeFamily.DIRECT_SINGLE: PyRITAttack.PROMPT_SENDING,
    AttackProbeFamily.PROGRESSIVE: PyRITAttack.CRESCENDO,
    AttackProbeFamily.TREE_SEARCH: PyRITAttack.TREE_OF_ATTACKS,
    AttackProbeFamily.ITERATIVE: PyRITAttack.PAIR,
    AttackProbeFamily.EXPLORATORY: PyRITAttack.RED_TEAMING,
    AttackProbeFamily.MULTI_PRESET: PyRITAttack.SEQUENTIAL,
}


# ──────────────────────────────────────────────────────────────────────────────
# ASI 类别感知策略映射（借鉴 DeepTeam 框架映射）
# ──────────────────────────────────────────────────────────────────────────────

ASI_STRATEGY_HINTS: Dict[str, Dict[str, Any]] = {
    "ASI01": {  # Agent Goal Hijack
        "preferred_families": [AttackProbeFamily.PROGRESSIVE, AttackProbeFamily.ITERATIVE],
        "reason": "目标劫持需要渐进偏移，Crescendo/PAIR 最适合",
    },
    "ASI02": {  # Tool Misuse & Exploitation
        "preferred_families": [AttackProbeFamily.PROGRESSIVE, AttackProbeFamily.TREE_SEARCH],
        "reason": "工具滥用需要多轮试探，渐进升级+树搜索",
    },
    "ASI03": {  # Agent Identity & Privilege Abuse
        "preferred_families": [AttackProbeFamily.PROGRESSIVE, AttackProbeFamily.EXPLORATORY],
        "reason": "身份滥用需要角色扮演+开放式探索",
    },
    "ASI04": {  # Agentic Supply Chain Vulnerabilities
        "preferred_families": [AttackProbeFamily.DIRECT_SINGLE, AttackProbeFamily.TREE_SEARCH],
        "reason": "供应链攻击需要直接注入+路径探索",
    },
    "ASI05": {  # Unexpected Code Execution
        "preferred_families": [AttackProbeFamily.TREE_SEARCH, AttackProbeFamily.ITERATIVE],
        "reason": "代码执行需要系统性探索，TAP/PAIR",
    },
    "ASI06": {  # Memory & Context Poisoning
        "preferred_families": [AttackProbeFamily.PROGRESSIVE, AttackProbeFamily.TREE_SEARCH],
        "reason": "记忆污染需要多轮渐进注入",
    },
    "ASI07": {  # Insecure Inter-Agent Communication
        "preferred_families": [AttackProbeFamily.PROGRESSIVE, AttackProbeFamily.EXPLORATORY],
        "reason": "代理间通信需要模拟多轮对话",
    },
    "ASI08": {  # Cascading Failures
        "preferred_families": [AttackProbeFamily.TREE_SEARCH, AttackProbeFamily.ITERATIVE],
        "reason": "级联失败需要树搜索探索路径",
    },
    "ASI09": {  # Human-Agent Trust Exploitation
        "preferred_families": [AttackProbeFamily.PROGRESSIVE, AttackProbeFamily.EXPLORATORY],
        "reason": "信任利用需要渐进式社会工程",
    },
    "ASI10": {  # Rogue Agents
        "preferred_families": [AttackProbeFamily.EXPLORATORY, AttackProbeFamily.TREE_SEARCH],
        "reason": "自主Agent需要开放式探索+树搜索",
    },
}


# ──────────────────────────────────────────────────────────────────────────────
# 攻击记忆系统（v3.1 新增 - 借鉴 AutoRedTeamer arXiv:2503.15754）
# ──────────────────────────────────────────────────────────────────────────────

class AttackMemory:
    """
    攻击记忆系统：记录历史攻击效果，指导未来选择
    
    借鉴 AutoRedTeamer 的记忆引导攻击选择机制：
    - 记录每次攻击的结果（成功/失败、成本）
    - 基于历史成功率推荐最优攻击
    - 终身学习：持续积累经验
    """
    
    def __init__(self):
        self._history: List[Dict[str, Any]] = []
        self._category_stats: Dict[str, Dict[str, Dict[str, int]]] = {}
        # {payload_category: {attack_family: {"successes": N, "total": N}}}
    
    def record_result(
        self,
        payload_category: str,
        attack_family: str,
        success: bool,
        cost: float = 1.0,
    ):
        """
        记录攻击结果
        
        Args:
            payload_category: 载荷类别
            attack_family: 攻击探针族
            success: 是否成功
            cost: 攻击成本（请求次数/时间）
        """
        if payload_category not in self._category_stats:
            self._category_stats[payload_category] = {}
        if attack_family not in self._category_stats[payload_category]:
            self._category_stats[payload_category][attack_family] = {
                "successes": 0, "total": 0, "total_cost": 0.0
            }
        
        stats = self._category_stats[payload_category][attack_family]
        stats["total"] += 1
        stats["total_cost"] += cost
        if success:
            stats["successes"] += 1
        
        self._history.append({
            "category": payload_category,
            "family": attack_family,
            "success": success,
            "cost": cost,
        })
    
    def get_best_family(self, payload_category: str) -> Optional[str]:
        """
        获取某载荷类别下历史最佳攻击族
        
        Returns:
            最佳攻击族名称，或 None（无足够数据）
        """
        if payload_category not in self._category_stats:
            return None
        
        best_family = None
        best_rate = -1.0
        
        for family, stats in self._category_stats[payload_category].items():
            if stats["total"] < 2:  # 至少需要 2 次记录
                continue
            rate = stats["successes"] / stats["total"]
            if rate > best_rate:
                best_rate = rate
                best_family = family
        
        return best_family if best_rate > 0.3 else None
    
    def get_success_rate(self, payload_category: str, attack_family: str) -> Optional[float]:
        """获取某类别+攻击族的成功率"""
        stats = self._category_stats.get(payload_category, {}).get(attack_family)
        if stats and stats["total"] > 0:
            return stats["successes"] / stats["total"]
        return None
    
    @property
    def total_records(self) -> int:
        return len(self._history)
    
    def get_summary(self) -> Dict[str, Any]:
        """获取记忆摘要"""
        return {
            "total_records": len(self._history),
            "categories": {
                cat: {
                    fam: {
                        "rate": s["successes"] / max(s["total"], 1),
                        "total": s["total"],
                    }
                    for fam, s in fams.items()
                }
                for cat, fams in self._category_stats.items()
            },
        }


# ──────────────────────────────────────────────────────────────────────────────
# 自适应探索管理器（v3.1 新增 - 借鉴 Active Attacks arXiv:2509.21947）
# ──────────────────────────────────────────────────────────────────────────────

class AdaptiveExplorationManager:
    """
    自适应探索管理器：防止攻击策略过早收敛
    
    借鉴 Active Attacks 的自适应环境思想：
    - 已探索区域的奖励自然衰减
    - 鼓励攻击者探索未充分测试的策略组合
    - 自然形成从易到难的课程学习
    """
    
    def __init__(self, decay_factor: float = 0.7, exploration_bonus: float = 1.5):
        self._exploited_regions: Set[str] = set()
        self._region_decay: Dict[str, float] = {}
        self._decay_factor = decay_factor
        self._exploration_bonus = exploration_bonus
    
    def compute_exploration_bonus(self, technique: str, complexity: str) -> float:
        """
        计算探索奖励
        
        Args:
            technique: 攻击技术类别
            complexity: 复杂度
            
        Returns:
            探索奖励乘数
        """
        region_key = f"{technique}_{complexity}"
        
        if region_key in self._exploited_regions:
            # 已探索区域给予衰减奖励
            decay = self._region_decay.get(region_key, 1.0)
            return 0.3 * decay
        else:
            # 未探索区域给予探索奖励
            return self._exploration_bonus
    
    def mark_exploited(self, technique: str, complexity: str, success: bool):
        """
        标记区域为已探索
        
        Args:
            technique: 攻击技术类别
            complexity: 复杂度
            success: 是否成功
        """
        region_key = f"{technique}_{complexity}"
        if success:
            self._exploited_regions.add(region_key)
            # 成功后衰减该区域未来奖励
            self._region_decay[region_key] = self._region_decay.get(region_key, 1.0) * self._decay_factor
    
    @property
    def exploited_count(self) -> int:
        return len(self._exploited_regions)
    
    def get_summary(self) -> Dict[str, Any]:
        """获取探索摘要"""
        return {
            "exploited_regions": list(self._exploited_regions),
            "region_decay": dict(self._region_decay),
        }


# ──────────────────────────────────────────────────────────────────────────────
# 第一层：快速规则筛选
# ──────────────────────────────────────────────────────────────────────────────

def _fast_rule_filter(profile: Any) -> Dict[str, Any]:
    """
    第一层：基于规则的快速筛选

    根据载荷特征快速确定攻击策略类别，不做复杂计算。
    返回初步策略建议，供第二层精确匹配使用。
    """
    technique = profile.technique
    encoding = profile.encoding_state
    length = profile.length_class
    complexity = profile.complexity

    # 规则 1: 已编码载荷 → 直接投递，不需要多轮
    if encoding in ("encoded", "multi_encoded"):
        if technique == "prompt_leaking":
            return {"family": AttackProbeFamily.DIRECT_SINGLE, "max_attempts": 0, "reason": "已编码+提示泄露，直接投递"}
        return {"family": AttackProbeFamily.DIRECT_SINGLE, "max_attempts": 2, "reason": "已编码载荷，直接投递"}

    # 规则 2: 对抗性后缀 → 保持原样，树搜索
    if technique == "adversarial":
        return {"family": AttackProbeFamily.TREE_SEARCH, "max_attempts": 0, "reason": "对抗性后缀，树搜索探索"}

    # 规则 3: Prompt Leaking → 单轮，无重试
    if technique == "prompt_leaking":
        return {"family": AttackProbeFamily.DIRECT_SINGLE, "max_attempts": 0, "reason": "提示泄露，单轮无重试"}

    # 规则 4: 超长文本 → 树搜索
    if length == "context_overflow":
        return {"family": AttackProbeFamily.TREE_SEARCH, "max_attempts": 0, "reason": "超长文本，树搜索分段"}

    # 规则 5: 角色扮演 → 渐进升级
    if technique == "role_play":
        return {"family": AttackProbeFamily.PROGRESSIVE, "max_attempts": 0, "reason": "角色扮演，渐进升级"}

    # 规则 6: 间接注入 → 渐进升级
    if technique == "indirect_injection":
        return {"family": AttackProbeFamily.PROGRESSIVE, "max_attempts": 0, "reason": "间接注入，渐进升级"}

    # 规则 7: 上下文拆分 → 渐进升级
    if technique in ("context_splitting", "payload_splitting"):
        return {"family": AttackProbeFamily.PROGRESSIVE, "max_attempts": 0, "reason": "拆分载荷，渐进重组"}

    # 规则 8: 指令覆盖 → 渐进升级
    if technique == "instruction_override":
        return {"family": AttackProbeFamily.PROGRESSIVE, "max_attempts": 0, "reason": "指令覆盖，渐进替换"}

    # 规则 9: 复杂载荷 → 渐进升级
    if complexity == "complex":
        return {"family": AttackProbeFamily.PROGRESSIVE, "max_attempts": 0, "reason": "复杂载荷，渐进试探"}

    # 规则 10: Markdown 注入 → 单轮
    if technique == "markdown_injection":
        return {"family": AttackProbeFamily.DIRECT_SINGLE, "max_attempts": 1, "reason": "Markdown注入，单轮"}

    # 规则 11: 数据渗出 → 渐进升级（需要多轮诱导）
    if technique == "data_exfiltration":
        return {"family": AttackProbeFamily.PROGRESSIVE, "max_attempts": 0, "reason": "数据渗出，渐进诱导"}

    # 规则 12: 跨上下文污染 → 树搜索（需要系统性探索）
    if technique == "cross_context_contamination":
        return {"family": AttackProbeFamily.TREE_SEARCH, "max_attempts": 0, "reason": "跨上下文污染，树搜索探索"}

    # 规则 13: 上下文操纵 → 渐进升级（需要多轮注入）
    if technique == "context_manipulation":
        return {"family": AttackProbeFamily.PROGRESSIVE, "max_attempts": 0, "reason": "上下文操纵，渐进注入"}

    # 默认：单轮 + 重试
    return {"family": AttackProbeFamily.DIRECT_SINGLE, "max_attempts": 2, "reason": "标准载荷，单轮+重试"}


# ──────────────────────────────────────────────────────────────────────────────
# 第二层：精确模型匹配
# ──────────────────────────────────────────────────────────────────────────────

def _precise_model_match(
    profile: Any,
    rule_result: Dict[str, Any],
    has_adversarial: bool = False,
    asi_category: str = "",
    converter_presets: Optional[Dict[str, List[str]]] = None,
    preferred_probe_families: Optional[List[str]] = None,
    aggression_level: str = "medium",
) -> Dict[str, Any]:
    """
    第二层：基于载荷特征的精确策略匹配

    在第一层快速筛选基础上，结合 ASI 类别、转换器预设、
    目标模型信息、侦察推荐等精细调整策略参数。
    """
    family = rule_result["family"]
    confidence = profile.avg_confidence

    # ── 侦察推荐约束（来自 TargetProfile 的漏洞发现）──
    if preferred_probe_families:
        # 如果当前族不在侦察推荐列表中，优先使用侦察推荐的族
        if family not in preferred_probe_families:
            if has_adversarial:
                # 有对抗 LLM，使用侦察推荐的首选族
                family = preferred_probe_families[0]
                rule_result["reason"] += " | 侦察推荐: 基于漏洞发现"
            elif not has_adversarial and preferred_probe_families[0] == AttackProbeFamily.DIRECT_SINGLE:
                # 无对抗 LLM 时，如果侦察推荐是单轮则切换
                family = AttackProbeFamily.DIRECT_SINGLE
                rule_result["reason"] += " | 侦察推荐: 基于漏洞发现"

    # ── ASI 类别约束（借鉴 DeepTeam 框架映射）──
    if asi_category and asi_category in ASI_STRATEGY_HINTS:
        asi_hint = ASI_STRATEGY_HINTS[asi_category]
        preferred = asi_hint["preferred_families"]
        # 如果当前族不在 ASI 推荐列表中，优先使用 ASI 推荐的族
        if family not in preferred:
            # 如果有对抗 LLM，使用 ASI 推荐的首选族
            if has_adversarial and preferred:
                family = preferred[0]
                rule_result["reason"] += f" | ASI约束: {asi_hint['reason']}"
            # 无对抗 LLM 时，如果推荐族是 DIRECT_SINGLE 则切换
            elif not has_adversarial and preferred and preferred[0] == AttackProbeFamily.DIRECT_SINGLE:
                family = AttackProbeFamily.DIRECT_SINGLE
                rule_result["reason"] += f" | ASI约束: {asi_hint['reason']}"

    # ── 无对抗 LLM 时的降级 ──
    if not has_adversarial:
        if family == AttackProbeFamily.PROGRESSIVE:
            family = AttackProbeFamily.DIRECT_SINGLE
            rule_result["reason"] += " | 无对抗LLM: 降级为单轮"
        elif family == AttackProbeFamily.TREE_SEARCH:
            family = AttackProbeFamily.DIRECT_SINGLE
            rule_result["reason"] += " | 无对抗LLM: 降级为单轮"
        elif family == AttackProbeFamily.ITERATIVE:
            family = AttackProbeFamily.DIRECT_SINGLE
            rule_result["reason"] += " | 无对抗LLM: 降级为单轮"
        elif family == AttackProbeFamily.EXPLORATORY:
            family = AttackProbeFamily.DIRECT_SINGLE
            rule_result["reason"] += " | 无对抗LLM: 降级为单轮"

    # ── 转换器预设影响 ──
    preset_complexity = _assess_preset_complexity(converter_presets)
    if preset_complexity == "high" and family == AttackProbeFamily.PROGRESSIVE:
        # 已有复杂转换器，可以简化攻击策略
        rule_result["reason"] += " | 转换器已复杂: 简化攻击"

    # ── 动态参数计算 ──
    params = _compute_dynamic_params(family, profile, rule_result)

    # ── 策略链 Fallback ──
    fallback_chain = _build_fallback_chain(family, has_adversarial, profile)

    attack_class = FAMILY_ATTACK_CLASS_MAP.get(family, PyRITAttack.PROMPT_SENDING)

    return {
        "class": attack_class,
        "family": family,
        "params": params,
        "fallback_chain": fallback_chain,
        "reason": rule_result["reason"],
        "confidence": confidence,
    }


def _assess_preset_complexity(converter_presets: Optional[Dict[str, List[str]]]) -> str:
    """评估转换器预设的复杂度"""
    if not converter_presets:
        return "none"

    total_converters = sum(len(v) for v in converter_presets.values())
    if total_converters >= 4:
        return "high"
    elif total_converters >= 2:
        return "medium"
    return "low"


def _compute_dynamic_params(
    family: str,
    profile: Any,
    rule_result: Dict[str, Any],
) -> Dict[str, Any]:
    """
    动态计算攻击参数（v3.0 核心改进）

    基于 payload 特征自适应调整攻击参数，而非静态硬编码。
    """
    complexity = profile.complexity
    token_count = profile.token_count
    context_window = profile.context_window
    length_ratio = token_count / max(context_window, 1)

    # 基础复杂度分数 (0-6)
    complexity_score = {"simple": 1, "moderate": 3, "complex": 5}.get(complexity, 1)

    if family == AttackProbeFamily.PROGRESSIVE:
        # Crescendo 参数动态计算
        base_turns = 5
        # 复杂度越高，需要越多轮次
        max_turns = base_turns + complexity_score
        # 长文本需要更多轮次建立上下文
        if length_ratio > 0.1:
            max_turns += 3
        max_turns = min(max_turns, 15)  # 上限

        base_backtracks = 3
        max_backtracks = base_backtracks + complexity_score // 2
        max_backtracks = min(max_backtracks, 10)

        return {
            "max_turns": max_turns,
            "max_backtracks": max_backtracks,
        }

    elif family == AttackProbeFamily.TREE_SEARCH:
        # TAP 参数动态计算
        base_width = 2
        tree_width = base_width + (1 if complexity == "complex" else 0)
        tree_width = min(tree_width, 5)

        base_depth = 3
        tree_depth = base_depth + complexity_score // 2
        tree_depth = min(tree_depth, 7)

        branching_factor = 2
        if complexity == "complex":
            branching_factor = 3

        return {
            "tree_width": tree_width,
            "tree_depth": tree_depth,
            "branching_factor": branching_factor,
        }

    elif family == AttackProbeFamily.ITERATIVE:
        # PAIR 参数动态计算
        base_iterations = 3
        max_iterations = base_iterations + complexity_score
        max_iterations = min(max_iterations, 10)

        return {
            "max_iterations": max_iterations,
        }

    elif family == AttackProbeFamily.EXPLORATORY:
        # RedTeaming 参数动态计算
        base_turns = 5
        max_turns = base_turns + complexity_score
        max_turns = min(max_turns, 12)

        return {
            "max_turns": max_turns,
        }

    elif family == AttackProbeFamily.DIRECT_SINGLE:
        # PromptSendingAttack 参数
        max_attempts = rule_result.get("max_attempts", 2)
        return {
            "max_attempts_on_failure": max_attempts,
        }

    return {}


def _build_fallback_chain(
    primary_family: str,
    has_adversarial: bool,
    profile: Any,
) -> List[Dict[str, Any]]:
    """
    构建策略链 Fallback（v3.0 新增）

    当主策略失败时，按优先级尝试备选策略。
    借鉴红队最佳实践：快速 → 渐进 → 深度搜索
    """
    chain = []

    if not has_adversarial:
        # 无对抗 LLM 时，只有单轮策略可用
        return chain

    if primary_family == AttackProbeFamily.PROGRESSIVE:
        # Crescendo 失败后尝试 TAP
        chain.append({
            "class": PyRITAttack.TREE_OF_ATTACKS,
            "family": AttackProbeFamily.TREE_SEARCH,
            "params": {"tree_width": 2, "tree_depth": 3, "branching_factor": 2},
            "reason": "Crescendo失败后备选TAP",
        })
    elif primary_family == AttackProbeFamily.TREE_SEARCH:
        # TAP 失败后尝试 PAIR
        chain.append({
            "class": PyRITAttack.PAIR,
            "family": AttackProbeFamily.ITERATIVE,
            "params": {"max_iterations": 3},
            "reason": "TAP失败后备选PAIR",
        })

    # 低置信度载荷增加更多备选
    if profile.needs_multi_strategy:
        if primary_family != AttackProbeFamily.DIRECT_SINGLE:
            chain.append({
                "class": PyRITAttack.PROMPT_SENDING,
                "family": AttackProbeFamily.DIRECT_SINGLE,
                "params": {"max_attempts_on_failure": 1},
                "reason": "低置信度备选: 单轮尝试",
            })

    return chain


# ──────────────────────────────────────────────────────────────────────────────
# 主策略选择接口
# ──────────────────────────────────────────────────────────────────────────────

def select_attack_strategy(
    profile: Any,
    target_model: str = "",
    has_adversarial: bool = False,
    converter_presets: Optional[Dict[str, List[str]]] = None,
    preferred_probe_families: Optional[List[str]] = None,
    aggression_level: str = "medium",
) -> Dict[str, Any]:
    """
    基于 PayloadProfile 选择最优 PyRIT 原生攻击策略（v3.0 两层选择）

    第一层：快速规则筛选 → 确定攻击探针族
    第二层：精确模型匹配 → 动态参数 + ASI 约束 + Fallback 链 + 侦察推荐

    Args:
        profile: PayloadProfile 实例
        target_model: 目标模型名称
        has_adversarial: 是否有可用的对抗性 LLM
        converter_presets: 转换器预设配置
        preferred_probe_families: 侦察推荐的攻击探针族列表
        aggression_level: 侦察推荐的攻击强度

    Returns:
        攻击配置字典：{
            "class": str,           # PyRIT 攻击类 FQN
            "family": str,          # 攻击探针族
            "params": dict,         # 动态构造参数
            "fallback_chain": list, # 备选策略链
            "reason": str,          # 选择原因
            "confidence": float,    # 置信度
        }
    """
    # 第一层：快速规则筛选
    rule_result = _fast_rule_filter(profile)

    # 第二层：精确模型匹配
    result = _precise_model_match(
        profile=profile,
        rule_result=rule_result,
        has_adversarial=has_adversarial,
        asi_category=profile.asi_category if hasattr(profile, 'asi_category') else "",
        converter_presets=converter_presets,
        preferred_probe_families=preferred_probe_families,
        aggression_level=aggression_level,
    )

    logger.debug(
        "Strategy selected: %s (family=%s, conf=%.2f, reason=%s)",
        result["class"].split(".")[-1],
        result["family"],
        result["confidence"],
        result["reason"],
    )

    return result


def select_preset_strategy(
    preset_count: int,
    has_adversarial: bool = False,
) -> Dict[str, Any]:
    """
    presets 模式下选择执行策略

    使用 SequentialAttack 实现 FIRST_SUCCESS 早停：
    - 每个 preset 作为一个 child attack
    - 第一个成功后立即停止

    Args:
        preset_count: preset 数量
        has_adversarial: 是否有对抗性 LLM

    Returns:
        执行策略配置
    """
    if preset_count > 1:
        return {
            "class": PyRITAttack.SEQUENTIAL,
            "family": AttackProbeFamily.MULTI_PRESET,
            "params": {
                "completion_policy": "FIRST_SUCCESS",
            },
            "fallback_chain": [],
            "reason": f"多 preset ({preset_count}) 顺序执行，FIRST_SUCCESS 早停",
            "confidence": 0.95,
        }
    return {
        "class": PyRITAttack.PROMPT_SENDING,
        "family": AttackProbeFamily.DIRECT_SINGLE,
        "params": {
            "max_attempts_on_failure": 1,
        },
        "fallback_chain": [],
        "reason": "单 preset 直接执行",
        "confidence": 0.95,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Smart Matcher v3.0 — 策略选择器
# ──────────────────────────────────────────────────────────────────────────────

class SmartMatcher:
    """
    智能匹配引擎 v3.1

    职责：PayloadProfile → PyRIT 攻击策略选择（两层选择 + 记忆引导 + 自适应探索）
    执行：由 AttackOrchestrator 调用 PyRIT 原生攻击完成

    v3.1 新增：
    - 攻击记忆系统（AttackMemory）：记录历史攻击效果，指导未来选择
    - 自适应探索管理器（AdaptiveExplorationManager）：防止策略过早收敛

    使用方式：
        matcher = SmartMatcher(target_model="gpt-4")
        strategy = matcher.select_strategy(payload_profile, has_adversarial=True)
        # orchestrator 使用 strategy 构建 PyRIT 攻击并执行
        # 执行后记录结果：matcher.record_attack_result(category, family, success)
    """

    def __init__(
        self,
        target_model: str = "",
        has_adversarial: bool = False,
        context_window: int = 8192,
        preferred_probe_families: Optional[List[str]] = None,
        aggression_level: str = "medium",
    ):
        """
        Args:
            target_model: 目标模型名称
            has_adversarial: 是否有可用的对抗性 LLM
            context_window: 目标模型上下文窗口大小
            preferred_probe_families: 侦察推荐的攻击探针族列表（来自 TargetProfile）
            aggression_level: 侦察推荐的攻击强度（low/medium/high）
        """
        self.target_model = target_model
        self.has_adversarial = has_adversarial
        self.context_window = context_window
        self.preferred_probe_families = preferred_probe_families or []
        self.aggression_level = aggression_level

        # v3.1 新增：攻击记忆系统
        self.attack_memory = AttackMemory()
        self.exploration_manager = AdaptiveExplorationManager()

        # 自动检测目标模型的上下文窗口
        if target_model:
            for model_name, window in _get_model_context_windows().items():
                if model_name in target_model.lower():
                    self.context_window = window
                    break

    def select_strategy(
        self,
        profile: Any,
        converter_presets: Optional[Dict[str, List[str]]] = None,
    ) -> Dict[str, Any]:
        """
        为单个 payload 选择最优 PyRIT 攻击策略（两层选择 + 记忆引导 + 自适应探索 + 侦察驱动）

        Args:
            profile: PayloadProfile 实例
            converter_presets: 转换器预设配置

        Returns:
            攻击配置字典
        """
        # 基础两层策略选择（含侦察推荐）
        strategy = select_attack_strategy(
            profile=profile,
            target_model=self.target_model,
            has_adversarial=self.has_adversarial,
            converter_presets=converter_presets,
            preferred_probe_families=self.preferred_probe_families,
            aggression_level=self.aggression_level,
        )
        
        # v3.1 新增：记忆引导优化
        category = profile.primary_category
        memory_best = self.attack_memory.get_best_family(category)
        if memory_best and memory_best != strategy["family"]:
            # 历史记忆推荐不同策略，且有足够数据支持
            rate = self.attack_memory.get_success_rate(category, memory_best)
            if rate and rate > 0.4:
                # 切换到历史最佳策略
                strategy["family"] = memory_best
                strategy["class"] = FAMILY_ATTACK_CLASS_MAP.get(memory_best, strategy["class"])
                strategy["reason"] += f" | 记忆引导: 历史成功率 {rate:.0%}"
        
        # v3.1 新增：自适应探索奖励
        exploration_bonus = self.exploration_manager.compute_exploration_bonus(
            profile.technique, profile.complexity
        )
        if exploration_bonus > 1.0:
            # 未探索区域，给予探索奖励（增加备选策略）
            strategy["reason"] += f" | 探索奖励: {exploration_bonus:.1f}x"
            # 低置信度时增加更多备选
            if profile.needs_multi_strategy:
                extra_fallback = self._build_exploration_fallback(profile)
                strategy.setdefault("fallback_chain", []).extend(extra_fallback)
        
        return strategy
    
    def _build_exploration_fallback(self, profile: Any) -> List[Dict[str, Any]]:
        """构建探索性备选策略"""
        fallbacks = []
        # 尝试未使用的攻击族
        all_families = [
            AttackProbeFamily.PROGRESSIVE,
            AttackProbeFamily.TREE_SEARCH,
            AttackProbeFamily.ITERATIVE,
        ]
        for family in all_families:
            if family != profile.technique:
                attack_class = FAMILY_ATTACK_CLASS_MAP.get(family)
                if attack_class:
                    fallbacks.append({
                        "class": attack_class,
                        "family": family,
                        "params": {},
                        "reason": f"探索备选: {family}",
                    })
                    if len(fallbacks) >= 2:
                        break
        return fallbacks
    
    def record_attack_result(
        self,
        payload_category: str,
        attack_family: str,
        success: bool,
        cost: float = 1.0,
    ):
        """
        记录攻击结果（v3.1 新增）
        
        在每次攻击执行后调用，更新记忆系统和探索状态。
        
        Args:
            payload_category: 载荷类别
            attack_family: 攻击探针族
            success: 是否成功
            cost: 攻击成本
        """
        self.attack_memory.record_result(payload_category, attack_family, success, cost)
        # 更新探索状态
        # 注意：technique 和 complexity 需要从 payload 获取，这里简化处理
        self.exploration_manager.mark_exploited(
            payload_category, "moderate", success
        )
    
    def get_memory_summary(self) -> Dict[str, Any]:
        """获取记忆摘要"""
        return self.attack_memory.get_summary()
    
    def get_exploration_summary(self) -> Dict[str, Any]:
        """获取探索摘要"""
        return self.exploration_manager.get_summary()

    def select_preset_strategy(
        self,
        preset_count: int,
    ) -> Dict[str, Any]:
        """presets 模式下选择执行策略"""
        return select_preset_strategy(preset_count, self.has_adversarial)

    def build_attack_plan(
        self,
        payloads: List[str],
        converter_presets: Dict[str, List[str]],
        custom_rules: Optional[List[Dict[str, Any]]] = None,
        asi_category: str = "",
    ) -> List[Dict[str, Any]]:
        """
        构建攻击计划（v3.0：两层策略选择 + ASI 感知）

        Args:
            payloads: 原始载荷列表
            converter_presets: {preset_name: [converter_names]}
            custom_rules: 自定义规则（可选）
            asi_category: ASI 类别（可选，如 "ASI01"）

        Returns:
            攻击计划列表，每项包含 payload + PyRIT 攻击配置
        """
        from ..payloads.payload_classifier import analyze_payload

        plan = []
        for payload in payloads:
            profile = analyze_payload(
                payload,
                context_window=self.context_window,
                asi_category=asi_category,
            )

            # 两层策略选择
            strategy = self.select_strategy(profile, converter_presets)

            plan.append({
                "payload": payload,
                "payload_profile": profile.to_dict(),
                "payload_category": profile.primary_category,
                "attack_class": strategy["class"],
                "attack_family": strategy["family"],
                "attack_params": strategy["params"],
                "attack_fallback_chain": strategy.get("fallback_chain", []),
                "attack_reason": strategy["reason"],
                "attack_confidence": strategy["confidence"],
                "converter_presets": converter_presets,
                "target_model": self.target_model,
            })

        logger.info(
            "Attack plan (v3.0): %d payloads → PyRIT native attacks "
            "(target=%s, adversarial=%s, context_window=%d)",
            len(plan), self.target_model or "unknown",
            self.has_adversarial, self.context_window,
        )

        return plan

    def get_plan_summary(self, plan: List[Dict[str, Any]]) -> Dict[str, Any]:
        """生成攻击计划摘要"""
        summary = {
            "total": len(plan),
            "by_attack_class": {},
            "by_attack_family": {},
            "by_category": {},
            "by_confidence": {"high": 0, "medium": 0, "low": 0},
            "with_fallback": 0,
        }

        for item in plan:
            attack_cls = item["attack_class"].split(".")[-1]
            family = item.get("attack_family", "unknown")
            cat = item["payload_category"]
            conf = item.get("attack_confidence", 1.0)

            summary["by_attack_class"][attack_cls] = summary["by_attack_class"].get(attack_cls, 0) + 1
            summary["by_attack_family"][family] = summary["by_attack_family"].get(family, 0) + 1
            summary["by_category"][cat] = summary["by_category"].get(cat, 0) + 1

            if conf >= 0.8:
                summary["by_confidence"]["high"] += 1
            elif conf >= 0.6:
                summary["by_confidence"]["medium"] += 1
            else:
                summary["by_confidence"]["low"] += 1

            if item.get("attack_fallback_chain"):
                summary["with_fallback"] += 1

        return summary


def _get_model_context_windows() -> Dict[str, int]:
    """获取模型上下文窗口配置"""
    from ..payloads.payload_classifier import MODEL_CONTEXT_WINDOWS
    return MODEL_CONTEXT_WINDOWS
