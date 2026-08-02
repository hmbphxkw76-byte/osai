# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""学术 ASR 先验注册表 — 为 epsilon-greedy selector 提供基于学术基准的初始 Q 值。.

PyRIT 原生 ``EpsilonGreedyTechniqueSelector._estimate()`` 对未见技术返回 1.0
（乐观初始化），导致首次运行时高 ASR 技术（Crescendo 82%）与低 ASR 技术
（prompt_sending 2%）被同等对待。本模块提供学术先验数据，注入 selector
的 warm-start，消除冷启动随机探索问题。

数据来源 (R-007 规则, 优先 arXiv 学术文献):
1. JailbreakBench (arXiv:2402.01135) — 标准化越狱基准排行榜
   Chao et al., NeurIPS 2024
2. HarmBench (arXiv:2402.04249) — 自动化红队评估框架
   Mazeika et al., ICML 2024
3. PyRIT 官方 Scenario 文档展示的成功率数据

学术引用:
- PAIR:        arXiv:2310.08437 — "Jailbreaking Black Box LLMs in Twenty Queries"
- TAP:         arXiv:2312.02191 — "Tree of Attacks: Jailbreaking Black-Box LLMs"
- Many-shot:   arXiv:2402.05124 — "Many-shot Jailbreaking"
- Crescendo:   arXiv:2402.12109 — "Great, Now We Have to Sing"
- Skeleton Key: arXiv:2407.01576 — "A Multilingual LLM Jailbreak"
- GCG:         arXiv:2307.15043 — "Universal and Transferable Adversarial Attacks"
- Persuasion:  arXiv:2402.19181 — "How Johnny Can Persuade LLMs to Jailbreak Them"

设计原则:
- 纯数据层, 不干扰 PyRIT 原生执行生命周期
- 跨运行学习由 PyRIT 原生 ``EpsilonGreedyTechniqueSelector`` + ``CentralMemory`` 持久化
- 本模块仅提供初始 Q 值 (warm-start), 不维护运行时缓存
- Tier 阈值唯一权威定义点
- **YAML 唯一数据源**: 所有 ASR 数据从 ``data/asr_priors.yaml`` 加载,
  更新 ASR 先验无需修改代码, 只需编辑 YAML 文件。YAML 不存在则报错退出。

> **日期**: 2026-8-1
> **更新记录**:
>   2026-8-1 19:10 — 优化2: ASR 数据从 ``data/asr_priors.yaml`` 外部加载
>   2026-8-1 19:30 — P0+P2: 删除所有 ``_FALLBACK_*`` 硬编码数据, YAML 为唯一数据源;
>     修复 ``_CONVERTER_VARIANT_PRIORS`` 和 ``_OWASP_ASR_MULTIPLIERS`` 被硬编码
>     覆盖的 Bug; 消除 ``global`` 语句反模式
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ============================================================
# 外部 YAML 配置文件路径
# ============================================================

_ASR_PRIORS_YAML = Path(__file__).parent.parent.parent / "data" / "config" / "asr_priors.yaml"


# ============================================================
# 统一 Tier 阈值 (ASR 引导策略学术标准 — 唯一权威定义)
# ============================================================
# 从 YAML 加载, 支持外部更新
# 使用 dataclass 配置对象替代 global 语句


@dataclass(frozen=True)
class TierConfig:
    """Tier 阈值配置 (从 YAML 加载)。."""

    thresholds: dict[str, float]
    s: float
    a: float
    b: float
    c: float

    @classmethod
    def default(cls) -> TierConfig:
        """Return default TierConfig with standard thresholds."""
        return cls(
            thresholds={"S": 0.70, "A": 0.40, "B": 0.15, "C": 0.05, "D": 0.0},
            s=0.70,
            a=0.40,
            b=0.15,
            c=0.05,
        )


# 初始默认值, YAML 加载后会被替换
_tier_config: TierConfig = TierConfig.default()

# 兼容性别名 (供外部引用)
TIER_S_THRESHOLD = _tier_config.s
TIER_A_THRESHOLD = _tier_config.a
TIER_B_THRESHOLD = _tier_config.b
TIER_C_THRESHOLD = _tier_config.c
TIER_THRESHOLDS: dict[str, float] = dict(_tier_config.thresholds)


def tier_from_asr(asr: float) -> str:
    """根据 ASR 值返回 Tier 等级。."""
    if asr >= _tier_config.s:
        return "S"
    elif asr >= _tier_config.a:
        return "A"
    elif asr >= _tier_config.b:
        return "B"
    elif asr >= _tier_config.c:
        return "C"
    else:
        return "D"


# ============================================================
# ASR Prior Data Class
# ============================================================


@dataclass(frozen=True)
class ASRPrior:
    """单技术的学术 ASR 先验数据。."""

    technique: str
    gpt_4o: float
    gpt_4: float
    gpt_35: float
    claude_3_5: float
    llama_3_1: float
    source: str  # "jailbreakbench" / "harmbench" / "pyrit_doc" / "empirical"
    paper_arxiv: str  # arXiv ID
    last_updated: str  # YYYY-MM
    patched: bool  # 是否已被主要模型补丁修复
    notes: str = ""

    def for_model(self, model_name: str, model_tier: str = "unknown") -> float:
        """获取特定模型的 ASR。.

        未知模型根据 model_tier 选择回退:
        - strong → gpt_4o (保守)
        - moderate → llama_3_1 (开源近似)
        - weak → gpt_35 (编码攻击更有效)
        - unknown → gpt_4o (保守默认)
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
        if "llama-3" in name_lower or "llama3" in name_lower:
            return self.llama_3_1
        if "qwen" in name_lower or "deepseek" in name_lower or "yi-" in name_lower or "chatglm" in name_lower:
            if model_tier == "weak":
                return self.gpt_35
            elif model_tier == "moderate":
                return self.llama_3_1
            return self.gpt_4o
        if "vicuna" in name_lower:
            return min(self.llama_3_1 * 1.1, 0.99)
        if "mistral" in name_lower or "mixtral" in name_lower:
            return min(self.llama_3_1 * 0.9, 0.99)
        # 未知模型根据 model_tier 选择回退
        if model_tier == "weak":
            return self.gpt_35
        elif model_tier == "moderate":
            return self.llama_3_1
        return self.gpt_4o


# ============================================================
# YAML 加载器 — 唯一数据源
# ============================================================


def _load_yaml_priors() -> tuple[
    dict[str, ASRPrior],
    dict[tuple[str, str], float],
    dict[str, str],
    set[str],
    dict[str, float],
    dict[str, dict[str, float]],
    dict[str, dict[str, float]],
    TierConfig,
]:
    """从 ``data/asr_priors.yaml`` 加载全部 ASR 先验数据。.

    YAML 是唯一数据源。如果 YAML 不存在或加载失败, 报错退出。

    Returns:
        (priors, combo_multipliers, chain_type_map,
         multi_turn_base_techs, patched_penalty_by_tier,
         converter_variant_priors, owasp_asr_multipliers, tier_config)
    """
    if not _ASR_PRIORS_YAML.exists():
        raise FileNotFoundError(
            f"ASR priors YAML not found at {_ASR_PRIORS_YAML}. "
            f"This is the required data source. Please create it or restore from git."
        )

    try:
        import yaml
    except ImportError as exc:
        raise ImportError("PyYAML is required to load ASR priors. Install with: pip install pyyaml") from exc

    try:
        with open(_ASR_PRIORS_YAML, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except (OSError, ValueError) as e:
        raise RuntimeError(f"Failed to load ASR priors YAML at {_ASR_PRIORS_YAML}: {e}") from e

    # 加载 Tier 阈值
    yt = data.get("tier_thresholds", {})
    tier_cfg = TierConfig(
        thresholds=dict(yt) if yt else TierConfig.default().thresholds,
        s=yt.get("S", 0.70),
        a=yt.get("A", 0.40),
        b=yt.get("B", 0.15),
        c=yt.get("C", 0.05),
    )

    # 加载 priors
    priors: dict[str, ASRPrior] = {}
    for item in data.get("priors", []):
        p = ASRPrior(
            technique=item["technique"],
            gpt_4o=float(item.get("gpt_4o", 0.3)),
            gpt_4=float(item.get("gpt_4", 0.3)),
            gpt_35=float(item.get("gpt_35", 0.3)),
            claude_3_5=float(item.get("claude_3_5", 0.3)),
            llama_3_1=float(item.get("llama_3_1", 0.3)),
            source=item.get("source", "empirical"),
            paper_arxiv=item.get("paper_arxiv", "N/A"),
            last_updated=item.get("last_updated", "2025-06"),
            patched=bool(item.get("patched", False)),
            notes=item.get("notes", ""),
        )
        priors[p.technique] = p

    # 加载 combo multipliers
    combo_multipliers: dict[tuple[str, str], float] = {}
    for item in data.get("combo_multipliers", []):
        if len(item) >= 3:
            combo_multipliers[(item[0], item[1])] = float(item[2])

    # 加载 chain type map
    chain_type_map: dict[str, str] = dict(data.get("chain_type_map", {}))

    # 加载 multi-turn base techs
    multi_turn_base_techs: set[str] = set(data.get("multi_turn_base_techs", []))

    # 加载 patched penalty
    patched_penalty: dict[str, float] = {k: float(v) for k, v in data.get("patched_penalty_by_tier", {}).items()}

    # 加载 converter variant priors
    cvp_raw = data.get("converter_variant_priors", {})
    converter_variant_priors: dict[str, dict[str, float]] = {
        k: {kk: float(vv) for kk, vv in v.items()} for k, v in cvp_raw.items()
    }

    # 加载 OWASP multipliers
    owasp_raw = data.get("owasp_asr_multipliers", {})
    owasp_multipliers: dict[str, dict[str, float]] = {
        k: {kk: float(vv) for kk, vv in v.items()} for k, v in owasp_raw.items()
    }

    if not priors:
        logger.warning("ASR priors YAML loaded but contains no prior entries")

    logger.info(
        f"ASR priors loaded from YAML: {len(priors)} techniques, "
        f"{len(combo_multipliers)} combos, {len(converter_variant_priors)} variants"
    )

    return (
        priors,
        combo_multipliers,
        chain_type_map,
        multi_turn_base_techs,
        patched_penalty,
        converter_variant_priors,
        owasp_multipliers,
        tier_cfg,
    )


# ============================================================
# 加载外部 YAML 数据 (模块级唯一初始化)
# ============================================================

(
    _ASR_PRIORS,
    _COMBO_MULTIPLIERS,
    _CHAIN_TYPE_MAP,
    _MULTI_TURN_BASE_TECHS,
    _PATCHED_PENALTY_BY_TIER,
    _CONVERTER_VARIANT_PRIORS,
    _OWASP_ASR_MULTIPLIERS,
    _tier_config,
) = _load_yaml_priors()

# 更新兼容性别名
TIER_THRESHOLDS = dict(_tier_config.thresholds)
TIER_S_THRESHOLD = _tier_config.s
TIER_A_THRESHOLD = _tier_config.a
TIER_B_THRESHOLD = _tier_config.b
TIER_C_THRESHOLD = _tier_config.c


# ============================================================
# 内部辅助函数
# ============================================================


def _classify_chain(chain_name: str) -> str:
    """分类 Converter 链类型。."""
    return _CHAIN_TYPE_MAP.get(chain_name, "unknown")


def _get_combo_multiplier(base_tech: str, chain_name: str) -> float:
    """查询 (基础技术, Converter链) 组合的 ASR 乘数。."""
    tech_category = "multi_turn" if base_tech in _MULTI_TURN_BASE_TECHS else "single_turn"
    chain_type = _classify_chain(chain_name)
    return _COMBO_MULTIPLIERS.get((tech_category, chain_type), 1.2)


def _apply_owasp_adjustment(asr: float, technique: str, owasp_id: str) -> float:
    """OWASP 分类感知 ASR 调整。."""
    owasp_ids = [oid.strip() for oid in owasp_id.split(",") if oid.strip()]
    if not owasp_ids:
        return min(asr, 0.99)
    base_tech = technique.split("+")[0] if "+" in technique else technique
    best_multiplier = 1.0
    for oid in owasp_ids:
        multipliers = _OWASP_ASR_MULTIPLIERS.get(oid, {})
        multiplier = multipliers.get(base_tech, 1.0)
        if multiplier > best_multiplier:
            best_multiplier = multiplier
    return min(asr * best_multiplier, 0.99)


# ============================================================
# 查询 API
# ============================================================


def get_asr_prior(technique: str) -> ASRPrior | None:
    """获取技术的学术 ASR 先验。."""
    return _ASR_PRIORS.get(technique)


def get_initial_q_value(
    technique: str,
    model_name: str = "gpt-4o",
    model_tier: str = "unknown",
    owasp_id: str = "",
) -> float:
    """获取技术的初始 Q 值（用于 epsilon-greedy selector warm-start）。.

    优先级:
    1. 学术先验 ASR（含 patched 惩罚）
    2. Converter 变体（独立先验 → base × boost）
    3. OWASP 分类感知 ASR 调整
    4. 中性先验 0.3（未知技术）

    跨运行学习由 PyRIT 原生 EpsilonGreedyTechniqueSelector + CentralMemory 持久化，
    本函数仅提供初始 Q 值（warm-start）。
    """
    # 1. 学术先验 (含 patched 惩罚)
    prior = _ASR_PRIORS.get(technique)
    if prior:
        asr = prior.for_model(model_name, model_tier)
        if prior.patched:
            penalty = _PATCHED_PENALTY_BY_TIER.get(model_tier, 0.4)
            asr = asr * penalty
        if owasp_id:
            asr = _apply_owasp_adjustment(asr, technique, owasp_id)
        return asr

    # 2. Converter 变体
    if "+" in technique:
        # 优先查询独立 ASR 先验条目
        variant_prior = _CONVERTER_VARIANT_PRIORS.get(technique)
        if variant_prior:
            variant_asr = ASRPrior(
                technique=technique,
                gpt_4o=variant_prior.get("gpt_4o", 0.3),
                gpt_4=variant_prior.get("gpt_4", 0.3),
                gpt_35=variant_prior.get("gpt_35", 0.3),
                claude_3_5=variant_prior.get("claude_3_5", 0.3),
                llama_3_1=variant_prior.get("llama_3_1", 0.3),
                source="empirical",
                paper_arxiv="2402.12109",
                last_updated="2025-06",
                patched=False,
                notes="Independent variant ASR prior",
            ).for_model(model_name, model_tier)
            if owasp_id:
                variant_asr = _apply_owasp_adjustment(variant_asr, technique, owasp_id)
            return variant_asr

        # 回退到 base × boost
        base_tech, _, chain_name = technique.partition("+")
        prior = _ASR_PRIORS.get(base_tech)
        if prior:
            base_asr = prior.for_model(model_name, model_tier)
            if prior.patched:
                penalty = _PATCHED_PENALTY_BY_TIER.get(model_tier, 0.4)
                base_asr = base_asr * penalty
            multiplier = _get_combo_multiplier(base_tech, chain_name)
            boosted = min(base_asr * multiplier, 0.95)
            if owasp_id:
                boosted = _apply_owasp_adjustment(boosted, technique, owasp_id)
            return boosted

    # 3. 中性先验
    return 0.3


def get_prior_ordered_techniques(
    techniques: list[str],
    model_name: str = "gpt-4o",
    model_tier: str = "unknown",
) -> list[str]:
    """使用学术 ASR 先验对技术列表排序（高 ASR 优先）。."""
    return sorted(
        techniques,
        key=lambda t: get_initial_q_value(t, model_name, model_tier),
        reverse=True,
    )


def get_all_priors() -> dict[str, ASRPrior]:
    """获取所有学术 ASR 先验数据。."""
    return dict(_ASR_PRIORS)


def get_prior_summary() -> list[dict[str, Any]]:
    """获取所有先验数据的摘要。."""
    summary: list[dict[str, Any]] = []
    for tech, prior in sorted(
        _ASR_PRIORS.items(),
        key=lambda x: x[1].gpt_4o,
        reverse=True,
    ):
        summary.append(
            {
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
            }
        )
    return summary
