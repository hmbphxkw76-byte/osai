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
    # P0-2: 新增 PyRIT 原生攻击类型
    MANY_SHOT_JAILBREAK = "pyrit.executor.attack.single_turn.many_shot_jailbreak.ManyShotJailbreakAttack"
    SKELETON_KEY = "pyrit.executor.attack.single_turn.skeleton_key.SkeletonKeyAttack"
    ROLE_PLAY = "pyrit.executor.attack.single_turn.role_play.RolePlayAttack"
    FLIP = "pyrit.executor.attack.single_turn.flip_attack.FlipAttack"
    CONTEXT_COMPLIANCE = "pyrit.executor.attack.single_turn.context_compliance.ContextComplianceAttack"
    CHUNKED_REQUEST = "pyrit.executor.attack.multi_turn.chunked_request.ChunkedRequestAttack"


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
    # P0-2: 新增攻击探针族
    # 上下文注入攻击族（Skeleton Key / Many Shot）
    CONTEXT_INJECTION = "context_injection"   # SkeletonKeyAttack / ManyShotJailbreakAttack
    # 角色伪装攻击族（RolePlay / Flip）
    IDENTITY_DECEPTION = "identity_deception" # RolePlayAttack / FlipAttack
    # 上下文诱导攻击族（ContextCompliance / ChunkedRequest）
    CONTEXT_MANIPULATION = "context_manipulation" # ContextComplianceAttack / ChunkedRequestAttack


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
    # P0-2: 新增探针族映射
    AttackProbeFamily.CONTEXT_INJECTION: PyRITAttack.SKELETON_KEY,
    AttackProbeFamily.IDENTITY_DECEPTION: PyRITAttack.ROLE_PLAY,
    AttackProbeFamily.CONTEXT_MANIPULATION: PyRITAttack.CONTEXT_COMPLIANCE,
}

# P0-2: 新增攻击类需要对抗性 LLM 的标识
ATTACKS_NEEDING_ADVERSARIAL: Set[str] = {
    PyRITAttack.CRESCENDO,
    PyRITAttack.TREE_OF_ATTACKS,
    PyRITAttack.PAIR,
    PyRITAttack.RED_TEAMING,
    PyRITAttack.ROLE_PLAY,
    PyRITAttack.CONTEXT_COMPLIANCE,
}

# P0-2: 新增攻击类默认参数
NEW_ATTACK_DEFAULT_PARAMS: Dict[str, Dict[str, Any]] = {
    PyRITAttack.MANY_SHOT_JAILBREAK: {"example_count": 100},
    PyRITAttack.SKELETON_KEY: {},
    PyRITAttack.ROLE_PLAY: {},  # 需要 role_play_definition_path
    PyRITAttack.FLIP: {},
    PyRITAttack.CONTEXT_COMPLIANCE: {},  # 需要 AttackAdversarialConfig
    PyRITAttack.CHUNKED_REQUEST: {"chunk_size": 50, "total_length": 200},
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
        "preferred_families": [AttackProbeFamily.PROGRESSIVE, AttackProbeFamily.EXPLORATORY, AttackProbeFamily.IDENTITY_DECEPTION],
        "reason": "身份滥用需要角色扮演+开放式探索",
    },
    "ASI04": {  # Agentic Supply Chain Vulnerabilities
        "preferred_families": [AttackProbeFamily.DIRECT_SINGLE, AttackProbeFamily.TREE_SEARCH],
        "reason": "供应链攻击需要直接注入+路径探索",
    },
    "ASI05": {  # Unexpected Code Execution
        "preferred_families": [AttackProbeFamily.TREE_SEARCH, AttackProbeFamily.ITERATIVE, AttackProbeFamily.CONTEXT_INJECTION],
        "reason": "代码执行需要系统性探索，TAP/PAIR + 骨架密钥",
    },
    "ASI06": {  # Memory & Context Poisoning
        "preferred_families": [AttackProbeFamily.PROGRESSIVE, AttackProbeFamily.TREE_SEARCH, AttackProbeFamily.CONTEXT_INJECTION],
        "reason": "记忆污染需要多轮渐进注入 + 上下文注入",
    },
    "ASI07": {  # Insecure Inter-Agent Communication
        "preferred_families": [AttackProbeFamily.PROGRESSIVE, AttackProbeFamily.EXPLORATORY, AttackProbeFamily.CONTEXT_MANIPULATION],
        "reason": "代理间通信需要模拟多轮对话 + 上下文操纵",
    },
    "ASI08": {  # Cascading Failures
        "preferred_families": [AttackProbeFamily.TREE_SEARCH, AttackProbeFamily.ITERATIVE],
        "reason": "级联失败需要树搜索探索路径",
    },
    "ASI09": {  # Human-Agent Trust Exploitation
        "preferred_families": [AttackProbeFamily.PROGRESSIVE, AttackProbeFamily.EXPLORATORY, AttackProbeFamily.IDENTITY_DECEPTION],
        "reason": "信任利用需要渐进式社会工程 + 角色伪装",
    },
    "ASI10": {  # Rogue Agents
        "preferred_families": [AttackProbeFamily.EXPLORATORY, AttackProbeFamily.TREE_SEARCH, AttackProbeFamily.CONTEXT_INJECTION],
        "reason": "自主Agent需要开放式探索+树搜索 + 骨架密钥",
    },
}


# ──────────────────────────────────────────────────────────────────────────────
# 第一层：快速规则筛选
# ──────────────────────────────────────────────────────────────────────────────

def _fast_rule_filter(profile: Any, aggression_level: str = "medium") -> Dict[str, Any]:
    """
    第一层：基于规则的快速筛选

    根据载荷特征快速确定攻击策略类别，不做复杂计算。
    返回初步策略建议，供第二层精确匹配使用。

    aggression_level 影响默认重试次数：
    - low: 1, medium: 2, high: 3
    """
    _aggression_attempts = {"low": 1, "medium": 2, "high": 3}
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

    # P0-2: 新增规则 — 骨架密钥 / 上下文注入
    if technique in ("skeleton_key", "context_injection"):
        return {"family": AttackProbeFamily.CONTEXT_INJECTION, "max_attempts": 1, "reason": "骨架密钥注入，单轮直接投递"}

    # P0-2: 新增规则 — 角色伪装 / 身份欺骗
    if technique in ("role_play", "identity_deception", "flip"):
        return {"family": AttackProbeFamily.IDENTITY_DECEPTION, "max_attempts": 1, "reason": "角色伪装/身份欺骗，单轮直接投递"}

    # P0-2: 新增规则 — 上下文诱导 / 分块请求
    if technique in ("context_compliance", "chunked_delivery"):
        return {"family": AttackProbeFamily.CONTEXT_MANIPULATION, "max_attempts": 1, "reason": "上下文诱导/分块投递，渐进式"}

    # 默认：单轮 + 重试（受 aggression_level 影响）
    default_attempts = _aggression_attempts.get(aggression_level, 2)
    return {"family": AttackProbeFamily.DIRECT_SINGLE, "max_attempts": default_attempts, "reason": f"标准载荷，单轮+重试 (aggression={aggression_level})"}


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
                rule_result["reason"] += " | 侦察推荐: 基于 OWASP 漏洞发现"
            elif not has_adversarial and preferred_probe_families[0] == AttackProbeFamily.DIRECT_SINGLE:
                # 无对抗 LLM 时，如果侦察推荐是单轮则切换
                family = AttackProbeFamily.DIRECT_SINGLE
                rule_result["reason"] += " | 侦察推荐: 基于 OWASP 漏洞发现"

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
        # 已有复杂转换器，降级为单轮攻击（减少不必要的多轮开销）
        family = AttackProbeFamily.DIRECT_SINGLE
        rule_result["reason"] += " | 转换器已复杂: 降级为单轮"

    # ── 动态参数计算 ──
    params = _compute_dynamic_params(family, profile, rule_result)

    # ── 策略链 Fallback（支持冲突驱动）──
    fallback_chain = _build_fallback_chain(
        family, has_adversarial, profile,
        preferred_probe_families=preferred_probe_families,
    )

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
    preferred_probe_families: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    构建策略链 Fallback（v3.1：支持冲突驱动的多路径备选）

    当主策略失败时，按优先级尝试备选策略。
    借鉴红队最佳实践：快速 → 渐进 → 深度搜索

    冲突驱动：当存在工具间冲突时，增加更多备选策略，
    确保覆盖多种攻击路径。
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
    elif primary_family == AttackProbeFamily.EXPLORATORY:
        # RedTeaming 失败后尝试 Crescendo
        chain.append({
            "class": PyRITAttack.CRESCENDO,
            "family": AttackProbeFamily.PROGRESSIVE,
            "params": {"max_turns": 5, "max_backtracks": 3},
            "reason": "RedTeaming失败后备选Crescendo",
        })

    # 冲突驱动：存在冲突时，增加侦察推荐的备选探针族
    if preferred_probe_families:
        existing_families = {primary_family} | {c.get("family") for c in chain}
        for fam in preferred_probe_families:
            if fam not in existing_families:
                attack_class = FAMILY_ATTACK_CLASS_MAP.get(fam)
                if attack_class:
                    chain.append({
                        "class": attack_class,
                        "family": fam,
                        "params": _get_default_params_for_family(fam),
                        "reason": "冲突驱动: 多工具结论不一致，增加备选路径",
                    })

    # 低置信度载荷增加更多备选
    if profile.needs_multi_strategy:
        if primary_family != AttackProbeFamily.DIRECT_SINGLE:
            # 避免重复添加
            if not any(c.get("family") == AttackProbeFamily.DIRECT_SINGLE for c in chain):
                chain.append({
                    "class": PyRITAttack.PROMPT_SENDING,
                    "family": AttackProbeFamily.DIRECT_SINGLE,
                    "params": {"max_attempts_on_failure": 1},
                    "reason": "低置信度备选: 单轮尝试",
                })

    return chain


def _get_default_params_for_family(family: str) -> Dict[str, Any]:
    """获取探针族的默认参数"""
    defaults = {
        AttackProbeFamily.DIRECT_SINGLE: {"max_attempts_on_failure": 2},
        AttackProbeFamily.PROGRESSIVE: {"max_turns": 5, "max_backtracks": 3},
        AttackProbeFamily.TREE_SEARCH: {"tree_width": 2, "tree_depth": 3, "branching_factor": 2},
        AttackProbeFamily.ITERATIVE: {"max_iterations": 3},
        AttackProbeFamily.EXPLORATORY: {"max_turns": 5},
        # P0-2: 新增探针族默认参数
        AttackProbeFamily.CONTEXT_INJECTION: {"max_attempts_on_failure": 1},
        AttackProbeFamily.IDENTITY_DECEPTION: {"max_attempts_on_failure": 1},
        AttackProbeFamily.CONTEXT_MANIPULATION: {"max_attempts_on_failure": 1},
    }
    return defaults.get(family, {})


def _enrich_fallback_chain_with_converters(
    fallback_chain: List[Dict[str, Any]],
    converter_candidates: List[str],
) -> List[Dict[str, Any]]:
    """
    用转换器候选增强 Fallback 链（P0-B）

    当主攻击策略失败时，除了切换攻击类，还尝试不同的转换器组合。
    覆盖"编码被过滤"这一最常见的失败原因。
    """
    if not converter_candidates or len(converter_candidates) <= 1:
        return fallback_chain

    primary_converter = converter_candidates[0]
    for alt_converter in converter_candidates[1:3]:
        fallback_chain.append({
            "class": PyRITAttack.PROMPT_SENDING,
            "family": AttackProbeFamily.DIRECT_SINGLE,
            "params": {"max_attempts_on_failure": 1},
            "converter_override": [alt_converter],
            "reason": f"转换器降级: {primary_converter} -> {alt_converter}",
        })
    return fallback_chain


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
    # 第一层：快速规则筛选（传入 aggression_level）
    rule_result = _fast_rule_filter(profile, aggression_level)

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
    智能匹配引擎 v3.0

    职责：PayloadProfile → PyRIT 攻击策略选择（两层选择）
    执行：由 AttackOrchestrator 调用 PyRIT 原生攻击完成

    使用方式：
        matcher = SmartMatcher(target_model="gpt-4")
        strategy = matcher.select_strategy(payload_profile, has_adversarial=True)
        # orchestrator 使用 strategy 构建 PyRIT 攻击并执行
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
        为单个 payload 选择最优 PyRIT 攻击策略（两层选择 + 侦察驱动）

        Args:
            profile: PayloadProfile 实例
            converter_presets: 转换器预设配置

        Returns:
            攻击配置字典
        """
        # 两层策略选择（含侦察推荐）
        strategy = select_attack_strategy(
            profile=profile,
            target_model=self.target_model,
            has_adversarial=self.has_adversarial,
            converter_presets=converter_presets,
            preferred_probe_families=self.preferred_probe_families,
            aggression_level=self.aggression_level,
        )

        return strategy

    def select_converters_for_payload(
        self,
        profile: Any,
        owasp_id: str = "",
        converter_presets: Optional[Dict[str, List[str]]] = None,
        max_converters: int = 5,
    ) -> List[str]:
        """
        逐载荷选择最优转换器（P0-A）

        基于 PayloadProfile 的语言、技术类别、OWASP 类别，
        从 encoding_selector 获取兼容的转换器候选，
        并按技术特征调整优先级。
        """
        from .encoding_selector import get_converter_candidates, filter_converters_by_language
        from .component_registry import CONVERTER_MAP

        registered = set(CONVERTER_MAP.keys())
        language = getattr(profile, "language", "en")
        technique = getattr(profile, "technique", "direct")

        if owasp_id:
            candidates = get_converter_candidates(
                owasp_id=owasp_id.upper(),
                language=language,
                registered_converters=registered,
            )
        else:
            candidates = filter_converters_by_language(list(registered), language)

        if not candidates:
            if converter_presets:
                first_preset = list(converter_presets.values())[0]
                return first_preset[:max_converters]
            return ["base64"]

        # 技术特征调整优先级
        if technique == "encoded":
            re_encode = {"base64", "rot13", "atbash", "caesar", "binary", "morse", "braille"}
            candidates = [c for c in candidates if c not in re_encode]
        elif technique == "role_play":
            priority = [c for c in ("persuasion", "text_jailbreak") if c in candidates]
            candidates = priority + [c for c in candidates if c not in priority]
        elif technique == "prompt_leaking":
            no_encode = {"base64", "rot13", "atbash", "caesar", "binary", "morse"}
            candidates = [c for c in candidates if c not in no_encode]
        elif technique == "adversarial":
            candidates = []

        if converter_presets:
            for preset_converters in converter_presets.values():
                for c in preset_converters:
                    if c not in candidates and c in registered:
                        candidates.append(c)

        if not candidates:
            if converter_presets:
                first_preset = list(converter_presets.values())[0]
                return first_preset[:max_converters]
            return ["base64"]

        return candidates[:max_converters]

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
        owasp_id: str = "",
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

            # 逐载荷选择最优转换器（P0-A）
            selected_converters = self.select_converters_for_payload(
                profile=profile,
                owasp_id=owasp_id,
                converter_presets=converter_presets,
            )

            # 两层策略选择
            strategy = self.select_strategy(profile, converter_presets)

            # 用转换器候选增强 Fallback 链（P0-B）
            fallback_chain = _enrich_fallback_chain_with_converters(
                strategy.get("fallback_chain", []),
                selected_converters,
            )

            plan.append({
                "payload": payload,
                "payload_profile": profile.to_dict(),
                "payload_category": profile.primary_category,
                "attack_class": strategy["class"],
                "attack_family": strategy["family"],
                "attack_params": strategy["params"],
                "attack_fallback_chain": fallback_chain,
                "attack_reason": strategy["reason"],
                "attack_confidence": strategy["confidence"],
                "converter_presets": converter_presets,
                "selected_converters": selected_converters,
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
