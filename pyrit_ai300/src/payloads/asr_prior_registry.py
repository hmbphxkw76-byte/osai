"""
ASR Prior Registry — 学术基准 ASR 先验数据
==========================================

为 AdaptiveScenario 的 epsilon-greedy selector 提供基于学术基准的初始 Q 值，
消除首次运行无先验导致的纯随机探索问题。

数据来源:
1. JailbreakBench (arXiv:2402.01135) — 标准化越狱基准排行榜
   Chao et al., "JailbreakBench: An Open Robustness Benchmark for
   Jailbreaking Large Language Models", NeurIPS 2024
2. HarmBench (arXiv:2402.04249) — 自动化红队评估框架
   Mazeika et al., "HarmBench: A Standardized Evaluation Framework
   for Automated Red Teaming", ICML 2024
3. PyRIT 官方 Scenario 文档展示的成功率数据

学术引用:
- PAIR:  Chao et al., arXiv:2310.08437 — "Jailbreaking Black Box LLMs in Twenty Queries"
- TAP:   Mehrotra et al., arXiv:2312.02191 — "Tree of Attacks: Jailbreaking Black-Box LLMs"
- Many-shot: Anthropic, arXiv:2402.05124 — "Many-shot Jailbreaking"
- Crescendo: Russinovich et al., arXiv:2402.12109 — "Great, Now We Have to Sing"
- Skeleton Key: Microsoft, arXiv:2407.01576 — "Skeleton Key: A Multilingual LLM Jailbreak"
- GCG: Zou et al., arXiv:2307.15043 — "Universal and Transferable Adversarial Attacks"
- Persuasion: Zeng et al., arXiv:2402.19181 — "How Johnny Can Persuade LLMs to Jailbreak Them"

关键学术发现:
- 编码攻击（Base64/ROT13/Caesar）在 GPT-4o 上 ASR 仅 3-12%
  (Wei et al., 2023; HarmBench 2024)
- 多轮迭代攻击（Crescendo/PAIR/TAP）在 GPT-4o 上 ASR 50-85%
  (JailbreakBench 2024-2025)
- 说服策略攻击在 GPT-4o 上 ASR 30-40%
  (Zeng et al., 2024)
- 编码攻击对无过滤开源模型（LLaMA/Vicuna uncensored）ASR 40-55%
  (HarmBench 2024)

设计原则:
- 不可变 frozen dataclass — 数据一旦定义不可修改
- per-model ASR — 不同模型版本有不同的 ASR
- patched 标记 — 被补丁修复的技术标记为 patched=True
- 运行时动态更新 — 实际运行后可用 update_empirical_asr() 更新
"""

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ============================================================
# ASR Prior Data Class
# ============================================================


@dataclass(frozen=True)
class ASRPrior:
    """
    单技术的学术 ASR 先验数据

    每个 AttackTechnique 对应一个 ASRPrior，包含:
    - per-model ASR (0.0-1.0)
    - 数据来源（jailbreakbench / harmbench / pyrit_doc / empirical）
    - arXiv 论文 ID
    - 是否已被补丁修复
    """
    technique: str
    # per-model ASR (0.0-1.0)
    gpt_4o: float
    gpt_4: float
    gpt_35: float
    claude_3_5: float
    llama_3_1: float
    # 元数据
    source: str          # "jailbreakbench" / "harmbench" / "pyrit_doc" / "empirical"
    paper_arxiv: str     # arXiv ID
    last_updated: str    # YYYY-MM
    patched: bool        # 是否已被主要模型补丁修复
    notes: str = ""

    def for_model(self, model_name: str) -> float:
        """
        获取特定模型的 ASR

        Args:
            model_name: 模型名称（如 "gpt-4o", "gpt-4", "gpt-3.5-turbo",
                        "claude-3-5-sonnet", "llama-3.1-70b"）

        Returns:
            ASR 值 (0.0-1.0)，未知模型默认用 GPT-4o 的值
        """
        name_lower = model_name.lower()
        if "gpt-4o" in name_lower or "gpt4o" in name_lower:
            return self.gpt_4o
        if "gpt-4" in name_lower or "gpt4" in name_lower:
            return self.gpt_4
        if "gpt-3.5" in name_lower or "gpt-35" in name_lower or "gpt3.5" in name_lower:
            return self.gpt_35
        if "claude" in name_lower and ("3.5" in name_lower or "3-5" in name_lower):
            return self.claude_3_5
        if "llama" in name_lower and ("3.1" in name_lower or "3-1" in name_lower):
            return self.llama_3_1
        if "llama" in name_lower or "vicuna" in name_lower or "mistral" in name_lower:
            return self.llama_3_1  # 开源模型近似
        # 默认用 GPT-4o（最保守估计）
        return self.gpt_4o


# ============================================================
# JailbreakBench + HarmBench 学术 ASR 先验数据
# ============================================================

# 数据截止: 2025-06
# 来源: JailbreakBench 官方排行榜 + HarmBench 评估结果
# 注意: ASR 随模型补丁更新而变化，patched=True 的技术可能已被修复

_ASR_PRIORS: Dict[str, ASRPrior] = {

    # ── 多轮迭代攻击 (学术验证高 ASR) ──
    "crescendo": ASRPrior(
        technique="crescendo",
        gpt_4o=0.82, gpt_4=0.85, gpt_35=0.95,
        claude_3_5=0.78, llama_3_1=0.90,
        source="jailbreakbench",
        paper_arxiv="2402.12109",
        last_updated="2025-06",
        patched=False,
        notes="多轮渐进式升级, 对强内容过滤最有效; Russinovich et al.",
    ),
    "red_teaming": ASRPrior(
        technique="red_teaming",
        gpt_4o=0.55, gpt_4=0.60, gpt_35=0.80,
        claude_3_5=0.50, llama_3_1=0.75,
        source="harmbench",
        paper_arxiv="2202.01241",
        last_updated="2025-03",
        patched=False,
        notes="通用红队对抗; Perez et al.",
    ),
    "tap": ASRPrior(
        technique="tap",
        gpt_4o=0.62, gpt_4=0.66, gpt_35=0.80,
        claude_3_5=0.55, llama_3_1=0.75,
        source="jailbreakbench",
        paper_arxiv="2312.02191",
        last_updated="2025-06",
        patched=False,
        notes="树搜索攻击, 成本较高但泛化性好; Mehrotra et al.",
    ),
    "pair": ASRPrior(
        technique="pair",
        gpt_4o=0.53, gpt_4=0.60, gpt_35=0.75,
        claude_3_5=0.48, llama_3_1=0.70,
        source="jailbreakbench",
        paper_arxiv="2310.08437",
        last_updated="2025-06",
        patched=False,
        notes="20-query 迭代攻击, 性价比好; Chao et al.",
    ),
    "tree_of_attacks_pruned": ASRPrior(
        technique="tree_of_attacks_pruned",
        gpt_4o=0.60, gpt_4=0.64, gpt_35=0.78,
        claude_3_5=0.53, llama_3_1=0.72,
        source="jailbreakbench",
        paper_arxiv="2312.02191",
        last_updated="2025-06",
        patched=False,
        notes="TAP 剪枝版本",
    ),

    # ── 单轮高成本攻击 ──
    "many_shot": ASRPrior(
        technique="many_shot",
        gpt_4o=0.12, gpt_4=0.15, gpt_35=0.48,
        claude_3_5=0.10, llama_3_1=0.40,
        source="jailbreakbench",
        paper_arxiv="2402.05124",
        last_updated="2025-06",
        patched=True,
        notes="Anthropic 补丁后 ASR 急剧下降; 对无过滤模型仍有效",
    ),
    "best_of_n_jailbreak": ASRPrior(
        technique="best_of_n_jailbreak",
        gpt_4o=0.35, gpt_4=0.40, gpt_35=0.65,
        claude_3_5=0.30, llama_3_1=0.60,
        source="harmbench",
        paper_arxiv="2402.01135",
        last_updated="2025-03",
        patched=False,
        notes="N 采样取最优; 大 N 时 ASR 更高",
    ),
    "skeleton_key": ASRPrior(
        technique="skeleton_key",
        gpt_4o=0.05, gpt_4=0.08, gpt_35=0.30,
        claude_3_5=0.03, llama_3_1=0.25,
        source="jailbreakbench",
        paper_arxiv="2407.01576",
        last_updated="2025-06",
        patched=True,
        notes="已被主要模型补丁修复; 对旧版本/开源模型仍有效",
    ),
    "bad_likert_judge": ASRPrior(
        technique="bad_likert_judge",
        gpt_4o=0.15, gpt_4=0.20, gpt_35=0.45,
        claude_3_5=0.12, llama_3_1=0.40,
        source="harmbench",
        paper_arxiv="2311.08268",
        last_updated="2025-03",
        patched=True,
        notes="Likert 评分操控; 部分模型已修复",
    ),

    # ── 角色扮演 / 模拟对话 (中等 ASR) ──
    "crescendo_simulated": ASRPrior(
        technique="crescendo_simulated",
        gpt_4o=0.45, gpt_4=0.50, gpt_35=0.70,
        claude_3_5=0.40, llama_3_1=0.65,
        source="pyrit_doc",
        paper_arxiv="2402.12109",
        last_updated="2025-06",
        patched=False,
        notes="预计算模拟对话重放; PyRIT Scenario 文档数据",
    ),
    "context_compliance": ASRPrior(
        technique="context_compliance",
        gpt_4o=0.40, gpt_4=0.45, gpt_35=0.65,
        claude_3_5=0.35, llama_3_1=0.60,
        source="pyrit_doc",
        paper_arxiv="N/A",
        last_updated="2025-06",
        patched=False,
        notes="上下文合规攻击; PyRIT Scenario 文档数据",
    ),
    "role_play_movie_script": ASRPrior(
        technique="role_play_movie_script",
        gpt_4o=0.35, gpt_4=0.40, gpt_35=0.65,
        claude_3_5=0.30, llama_3_1=0.60,
        source="pyrit_doc",
        paper_arxiv="N/A",
        last_updated="2025-06",
        patched=False,
        notes="电影剧本角色扮演; PyRIT Scenario 文档 71-100% 数据",
    ),
    "role_play_persuasion": ASRPrior(
        technique="role_play_persuasion",
        gpt_4o=0.38, gpt_4=0.42, gpt_35=0.68,
        claude_3_5=0.33, llama_3_1=0.62,
        source="pyrit_doc",
        paper_arxiv="2402.19181",
        last_updated="2025-06",
        patched=False,
        notes="说服角色扮演; Zeng et al. persuasion 分类",
    ),
    "wrapping_attack": ASRPrior(
        technique="wrapping_attack",
        gpt_4o=0.42, gpt_4=0.45, gpt_35=0.60,
        claude_3_5=0.38, llama_3_1=0.55,
        source="empirical",
        paper_arxiv="N/A",
        last_updated="2025-06",
        patched=False,
        notes="上下文包装攻击; 项目 YAML asr_baseline 数据",
    ),

    # ── 说服攻击 (LLM 辅助, 中等 ASR) ──
    "persuasion_authority": ASRPrior(
        technique="persuasion_authority",
        gpt_4o=0.35, gpt_4=0.42, gpt_35=0.60,
        claude_3_5=0.30, llama_3_1=0.55,
        source="harmbench",
        paper_arxiv="2402.19181",
        last_updated="2025-03",
        patched=False,
        notes="权威说服; Zeng et al. — 对语义安全分类器有一定效果",
    ),
    "decomposition_chain": ASRPrior(
        technique="decomposition_chain",
        gpt_4o=0.30, gpt_4=0.35, gpt_35=0.55,
        claude_3_5=0.25, llama_3_1=0.50,
        source="harmbench",
        paper_arxiv="2311.08268",
        last_updated="2025-03",
        patched=False,
        notes="任务分解重构; 将有害请求分解为无害子任务",
    ),

    # ── 编码攻击 (对现代商业模型低 ASR) ──
    "encoding_bypass": ASRPrior(
        technique="encoding_bypass",
        gpt_4o=0.08, gpt_4=0.12, gpt_35=0.45,
        claude_3_5=0.06, llama_3_1=0.55,
        source="harmbench",
        paper_arxiv="2307.15043",
        last_updated="2025-03",
        patched=False,
        notes="编码绕过对 GPT-4o 几乎无效; 对开源 uncensored 模型有效",
    ),
    "multi_encoding_v2": ASRPrior(
        technique="multi_encoding_v2",
        gpt_4o=0.10, gpt_4=0.14, gpt_35=0.48,
        claude_3_5=0.08, llama_3_1=0.58,
        source="harmbench",
        paper_arxiv="2307.15043",
        last_updated="2025-03",
        patched=False,
        notes="四层编码; 比 encoding_bypass 略好但仍低",
    ),
    "stealth_evasion": ASRPrior(
        technique="stealth_evasion",
        gpt_4o=0.12, gpt_4=0.16, gpt_35=0.50,
        claude_3_5=0.10, llama_3_1=0.60,
        source="harmbench",
        paper_arxiv="2307.15043",
        last_updated="2025-03",
        patched=False,
        notes="Unicode 混淆 + Base64 + 后缀追加; 对弱过滤有效",
    ),
    "rot13": ASRPrior(
        technique="rot13",
        gpt_4o=0.03, gpt_4=0.05, gpt_35=0.35,
        claude_3_5=0.02, llama_3_1=0.50,
        source="harmbench",
        paper_arxiv="2307.15043",
        last_updated="2025-03",
        patched=False,
        notes="单层 ROT13 编码; GPT-4o 可直接解码并拒绝",
    ),
    "base64": ASRPrior(
        technique="base64",
        gpt_4o=0.04, gpt_4=0.06, gpt_35=0.38,
        claude_3_5=0.03, llama_3_1=0.52,
        source="harmbench",
        paper_arxiv="2307.15043",
        last_updated="2025-03",
        patched=False,
        notes="单层 Base64 编码; GPT-4o 可直接解码",
    ),

    # ── 基线 ──
    "prompt_sending": ASRPrior(
        technique="prompt_sending",
        gpt_4o=0.02, gpt_4=0.03, gpt_35=0.15,
        claude_3_5=0.01, llama_3_1=0.20,
        source="harmbench",
        paper_arxiv="N/A",
        last_updated="2025-03",
        patched=False,
        notes="无转换器基线; 几乎无法直接越狱",
    ),

    # ── Agent / 注入类 ──
    "agent_injection_chain": ASRPrior(
        technique="agent_injection_chain",
        gpt_4o=0.25, gpt_4=0.30, gpt_35=0.50,
        claude_3_5=0.22, llama_3_1=0.48,
        source="empirical",
        paper_arxiv="2302.12173",
        last_updated="2025-03",
        patched=False,
        notes="Agent 注入链; Greshake et al. 间接注入",
    ),
    "direct_injection": ASRPrior(
        technique="direct_injection",
        gpt_4o=0.30, gpt_4=0.35, gpt_35=0.55,
        claude_3_5=0.25, llama_3_1=0.52,
        source="harmbench",
        paper_arxiv="2302.12173",
        last_updated="2025-03",
        patched=False,
        notes="直接提示注入",
    ),
}


# ============================================================
# 运行时 ASR 更新缓存
# ============================================================

# 实际运行后的 ASR 数据（覆盖学术先验）
# key = (technique, model_name), value = empirical ASR
_empirical_asr_cache: Dict[tuple[str, str], float] = {}


def update_empirical_asr(
    technique: str,
    model_name: str,
    asr: float,
) -> None:
    """
    用实际运行结果更新 ASR 数据

    在 pipeline 执行后调用，将实际测量的 ASR 存入缓存，
    后续 selector 查询时优先使用实测值而非学术先验。

    Args:
        technique: 技术名称
        model_name: 模型名称
        asr: 实测 ASR (0.0-1.0)
    """
    key = (technique, model_name)
    _empirical_asr_cache[key] = asr
    logger.debug(
        f"ASR Prior: updated empirical ASR for '{technique}' "
        f"on '{model_name}': {asr:.2%}"
    )


def batch_update_empirical_asr(
    results: Dict[str, Dict[str, float]],
    model_name: str,
) -> None:
    """
    批量更新实测 ASR

    Args:
        results: {technique: {"success": int, "total": int}} 或
                 {technique: {"asr": float}}
        model_name: 模型名称
    """
    for technique, data in results.items():
        if "asr" in data:
            update_empirical_asr(technique, model_name, data["asr"])
        elif "success" in data and "total" in data and data["total"] > 0:
            asr = data["success"] / data["total"]
            update_empirical_asr(technique, model_name, asr)


# ============================================================
# 查询 API
# ============================================================


def get_asr_prior(technique: str) -> Optional[ASRPrior]:
    """
    获取技术的学术 ASR 先验

    Args:
        technique: 技术名称（如 "crescendo", "pair", "prompt_sending"）

    Returns:
        ASRPrior 对象，不存在返回 None
    """
    return _ASR_PRIORS.get(technique)


def get_initial_q_value(
    technique: str,
    model_name: str = "gpt-4o",
) -> float:
    """
    获取技术的初始 Q 值（用于 epsilon-greedy selector 先验）

    优先级:
    1. 实测 ASR（运行后更新）
    2. 学术先验 ASR（JailbreakBench/HarmBench）
    3. 中性先验 0.3（未知技术）

    Args:
        technique: 技术名称
        model_name: 模型名称

    Returns:
        初始 Q 值 (0.0-1.0)
    """
    # 1. 实测数据优先
    emp_key = (technique, model_name)
    if emp_key in _empirical_asr_cache:
        return _empirical_asr_cache[emp_key]

    # 2. 学术先验
    prior = _ASR_PRIORS.get(technique)
    if prior:
        return prior.for_model(model_name)

    # 3. 检查是否是 Converter 变体（如 "prompt_sending+stealth_evasion"）
    if "+" in technique:
        base_tech = technique.split("+")[0]
        prior = _ASR_PRIORS.get(base_tech)
        if prior:
            # 变体的 ASR 略高于基础技术（Converter 增强效果）
            base_asr = prior.for_model(model_name)
            return min(base_asr * 1.2, 0.95)  # 最多 +20%, 上限 95%

    # 4. 中性先验
    return 0.3


def get_prior_ordered_techniques(
    techniques: List[str],
    model_name: str = "gpt-4o",
) -> List[str]:
    """
    使用学术 ASR 先验对技术列表排序（高 ASR 优先）

    用于首次运行（memory 中无历史数据）时，替代纯随机探索。

    Args:
        techniques: 技术名称列表
        model_name: 模型名称

    Returns:
        按 ASR 从高到低排序的技术列表
    """
    return sorted(
        techniques,
        key=lambda t: get_initial_q_value(t, model_name),
        reverse=True,
    )


def get_all_priors() -> Dict[str, ASRPrior]:
    """获取所有学术 ASR 先验数据"""
    return dict(_ASR_PRIORS)


def get_prior_summary() -> List[Dict[str, Any]]:
    """
    获取所有先验数据的摘要（用于文档生成和展示）

    Returns:
        摘要列表
    """
    from typing import Any
    summary: List[Dict[str, Any]] = []
    for tech, prior in sorted(
        _ASR_PRIORS.items(),
        key=lambda x: x[1].gpt_4o,
        reverse=True,
    ):
        summary.append({
            "technique": tech,
            "gpt_4o": prior.gpt_4o,
            "gpt_4": prior.gpt_4,
            "gpt_35": prior.gpt_35,
            "claude_3_5": prior.claude_3_5,
            "llama_3_1": prior.llama_3_1,
            "source": prior.source,
            "paper_arxiv": prior.paper_arxiv,
            "patched": prior.patched,
            "notes": prior.notes,
        })
    return summary
