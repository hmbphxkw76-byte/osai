# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""ASR 排序构建器 — 按 ASR 对技术组排序 + 加权种子采样 + 组级降级链。.

PyRIT 原生 ``EpsilonGreedyTechniqueSelector`` 使用 Memory 中的历史数据排序技术，
但无 Tier 分层、无 ASR 加权种子采样、无组级降级链。本模块在纯数据层提供:
  1. 按 technique_group 聚合种子，计算 max/avg ASR
  2. Tier 分层 (S/A/B/C/D/UNKNOWN) — 引用 asr_prior_registry 唯一权威定义
  3. ASR 加权种子采样 (S:50%, A:30%, B:20%, C:10%, D:5%)
  4. Tier-based fallback chain (S → A → B → C → D)
  5. 组级 ASR 降级链报告 (优化7: 合并原 group_fallback_executor.py)

设计原则:
- 纯分析层, 不修改任何 SeedGroup 对象
- ASR 数据三级查询: 学术先验 → Memory 历史 → 启发式代理
- 使用 PyRIT 原生 ``DatasetAttackConfiguration(seed_groups=...)`` 注入采样结果
- Tier 定义引用 ``asr_prior_registry.tier_from_asr()`` 唯一权威定义 (优化7)

学术依据:
- JailbreakBench (arXiv:2402.01135): Tier 阈值学术标准
- HarmBench (arXiv:2402.04249): ASR 加权采样防止执行爆炸

> **日期**: 2026-8-1
> **更新记录**:
>   2026-8-1 19:50 — 优化7: 合并 group_fallback_executor.py 的 Tier/排序逻辑,
>     GroupFallbackExecutor + FallbackRecord + GroupFallbackResult 合并到本模块,
>     消除 Tier 定义重复。P3-12: 这部分逻辑在概念上是独立的「降级计划器」,
>     保留在本模块中以复用 ASRRankBuilder 的 Tier 定义, 但通过明确的
>     区段分隔符标识其职责边界。
>   2026-8-1 20:00 — P3-13: 拆分 sample_seed_groups_by_tier 为
>     _sample_group() + _trim_lowest_tier() 两个子方法
"""

from __future__ import annotations

import logging
import random
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pipeline.asr.prior_registry import get_initial_q_value, tier_from_asr

logger = logging.getLogger(__name__)


# ============================================================
# ASR Tier 枚举
# ============================================================


class ASRTier(str, Enum):
    """ASR-based technique tier classification."""

    S = "S"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    UNKNOWN = "UNKNOWN"

    @property
    def priority(self) -> int:
        priorities = {
            "S": 100,
            "A": 80,
            "B": 60,
            "C": 40,
            "D": 20,
            "UNKNOWN": 50,
        }
        return priorities.get(self.value, 0)

    @classmethod
    def from_asr(cls, max_asr: float) -> ASRTier:
        from pipeline.asr.prior_registry import tier_from_asr

        return cls(tier_from_asr(max_asr))


# ============================================================
# Technique Group Info
# ============================================================


@dataclass
class TechniqueGroupInfo:
    """单个技术组的元数据和 ASR 指标。."""

    technique_group: str
    owasp_id: str
    seed_count: int
    max_asr: float
    avg_asr: float
    has_asr_data: bool
    tier: ASRTier
    heuristic_score: float
    attack_modes: list[str]
    difficulties: list[str]
    severities: list[str]
    evasion_levels: list[str]
    dataset_name: str
    source_seed_groups: list[Any] = field(default_factory=list)

    @property
    def effective_score(self) -> float:
        if self.has_asr_data:
            return self.max_asr * 100
        return self.heuristic_score


# ============================================================
# ASR Rank Builder
# ============================================================

_DIFFICULTY_WEIGHTS = {"easy": 3, "medium": 2, "hard": 1, "unknown": 1.5}
_EVASION_WEIGHTS = {"high": 3, "medium": 2, "low": 1, "unknown": 1.5}
_MODE_WEIGHTS = {
    "single_turn": 3,
    "converter_enhanced": 2.5,
    "sequential": 2,
    "multi_turn": 1.5,
    "unknown": 1.5,
}


class ASRRankBuilder:
    """构建 ASR 排序的技术组列表。."""

    _TIER_SAMPLE_RATIOS: dict[ASRTier, float] = {
        ASRTier.S: 0.50,
        ASRTier.A: 0.30,
        ASRTier.B: 0.20,
        ASRTier.C: 0.10,
        ASRTier.D: 0.05,
        ASRTier.UNKNOWN: 0.15,
    }

    _TIER_MIN_SAMPLES: dict[ASRTier, int] = {
        ASRTier.S: 3,
        ASRTier.A: 2,
        ASRTier.B: 2,
        ASRTier.C: 1,
        ASRTier.D: 1,
        ASRTier.UNKNOWN: 1,
    }

    @classmethod
    def build_ranked_groups(
        cls,
        seed_groups: Sequence[Any],
        model_name: str = "gpt-4o",
    ) -> list[TechniqueGroupInfo]:
        """从 SeedGroup 构建按 ASR 排序的技术组信息。.

        三级 ASR 查询:
        1. 种子元数据 asr_baseline (实测优先)
        2. 学术先验 (通过 asr_prior_registry)
        3. 启发式代理 (最后兜底)
        """
        cluster: dict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "seeds": [],
                "seed_groups": [],
                "owasp_id": "",
                "dataset_name": "",
            }
        )

        for sg in seed_groups:
            for seed in getattr(sg, "seeds", []):
                meta = getattr(seed, "metadata", None) or {}
                tg = meta.get("technique_group", meta.get("technique", "ungrouped"))
                owasp_id = meta.get("owasp_id", "")
                dataset_name = getattr(seed, "dataset_name", "") or ""

                cluster[tg]["seeds"].append(seed)
                cluster[tg]["seed_groups"].append(sg)
                if owasp_id and not cluster[tg]["owasp_id"]:
                    cluster[tg]["owasp_id"] = owasp_id
                if dataset_name and not cluster[tg]["dataset_name"]:
                    cluster[tg]["dataset_name"] = dataset_name

        groups: list[TechniqueGroupInfo] = []
        for tg_name, data in cluster.items():
            info = cls._build_group_info(tg_name, data, model_name=model_name)
            groups.append(info)

        groups.sort(key=lambda g: -g.effective_score)
        return groups

    @classmethod
    def _build_group_info(
        cls,
        technique_group: str,
        data: dict[str, Any],
        model_name: str = "gpt-4o",
    ) -> TechniqueGroupInfo:
        seeds = data["seeds"]
        _seen_ids: set[int] = set()
        seed_groups: list[Any] = []
        for sg in data["seed_groups"]:
            if id(sg) not in _seen_ids:
                _seen_ids.add(id(sg))
                seed_groups.append(sg)

        asr_values: list[float] = []
        attack_modes: set = set()
        difficulties: set = set()
        severities: set = set()
        evasion_levels: set = set()

        for seed in seeds:
            meta = getattr(seed, "metadata", None) or {}
            asr = meta.get("asr_baseline", {})
            if asr and isinstance(asr, dict):
                asr_values.append(max(asr.values()))
            attack_modes.add(meta.get("attack_mode", "single_turn"))
            d = meta.get("difficulty", "unknown")
            difficulties.add(d)
            s = meta.get("severity", "")
            if s:
                severities.add(s)
            evasion_levels.add(meta.get("evasion_level", "unknown"))

        has_asr = bool(asr_values)
        max_asr = max(asr_values) if asr_values else 0.0
        avg_asr = sum(asr_values) / len(asr_values) if asr_values else 0.0
        tier = ASRTier.from_asr(max_asr) if has_asr else ASRTier.UNKNOWN

        # 无 YAML ASR 时回退到学术先验
        if not has_asr:
            try:
                from pipeline.asr.prior_registry import get_asr_prior

                prior = get_asr_prior(technique_group)
                if prior is not None:
                    academic_asr = prior.for_model(model_name, "unknown")
                    max_asr = academic_asr
                    avg_asr = academic_asr
                    has_asr = True
                    tier = ASRTier.from_asr(max_asr)
            except (RuntimeError, OSError, ValueError):
                pass

        heuristic = (
            cls._heuristic_score(
                difficulties,
                evasion_levels,
                attack_modes,
            )
            if not has_asr
            else max_asr * 100
        )

        return TechniqueGroupInfo(
            technique_group=technique_group,
            owasp_id=data["owasp_id"],
            seed_count=len(seeds),
            max_asr=max_asr,
            avg_asr=avg_asr,
            has_asr_data=has_asr,
            tier=tier,
            heuristic_score=heuristic,
            attack_modes=sorted(attack_modes),
            difficulties=sorted(difficulties),
            severities=sorted(severities),
            evasion_levels=sorted(evasion_levels),
            dataset_name=data["dataset_name"],
            source_seed_groups=seed_groups,
        )

    @staticmethod
    def _heuristic_score(
        difficulties: set[str],
        evasion_levels: set[str],
        attack_modes: set[str],
    ) -> float:
        def avg_weight(values: set[str], weights: dict[str, float]) -> float:
            if not values:
                return 1.5
            total = sum(weights.get(v, 1.5) for v in values)
            return total / len(values)

        d_score = avg_weight(difficulties, _DIFFICULTY_WEIGHTS)
        e_score = avg_weight(evasion_levels, _EVASION_WEIGHTS)
        m_score = avg_weight(attack_modes, _MODE_WEIGHTS)
        return (d_score * 10) + (e_score * 10) + (m_score * 10)

    @classmethod
    def build_fallback_chain(
        cls,
        ranked_groups: list[TechniqueGroupInfo],
    ) -> list[list[TechniqueGroupInfo]]:
        """构建 Tier-based fallback chain (S → A → B → C → D → UNKNOWN)。."""
        tiers_order = [
            ASRTier.S,
            ASRTier.A,
            ASRTier.B,
            ASRTier.C,
            ASRTier.D,
            ASRTier.UNKNOWN,
        ]
        chain: list[list[TechniqueGroupInfo]] = []
        for tier in tiers_order:
            tier_groups = [g for g in ranked_groups if g.tier == tier]
            if tier_groups:
                tier_groups.sort(key=lambda g: -g.effective_score)
                chain.append(tier_groups)
        return chain

    @classmethod
    def get_top_n(
        cls,
        ranked_groups: list[TechniqueGroupInfo],
        n: int = 5,
        min_tier: ASRTier | None = None,
    ) -> list[TechniqueGroupInfo]:
        """获取 Top-N 组，可选最低 Tier 过滤。."""
        min_priority = min_tier.priority if min_tier else 0
        filtered = [g for g in ranked_groups if g.tier.priority >= min_priority]
        return filtered[:n]

    @classmethod
    def sample_seed_groups_by_tier(
        cls,
        ranked_groups: list[TechniqueGroupInfo],
        *,
        max_total: int = 100,
    ) -> list[TechniqueGroupInfo]:
        """ASR 加权种子采样 — 按 Tier 比例从每个技术组采样种子。.

        P3-13: 拆分为 ``_sample_group()`` 和 ``_trim_lowest_tier()`` 两个子方法,
        每个方法职责单一, 易于测试和维护。

        高 ASR 技术组保留更多种子（Tier S: 50%）
        低 ASR 技术组保留少量种子（Tier D: 5%，但至少 1 个）
        """
        total_seeds = sum(g.seed_count for g in ranked_groups)
        if total_seeds <= max_total:
            return list(ranked_groups)

        # P3-13: 采样阶段委托给 _sample_group
        sampled_groups = [cls._sample_group(g) for g in ranked_groups]

        # P3-13: 裁剪阶段委托给 _trim_lowest_tier
        return cls._trim_lowest_tier(sampled_groups, max_total=max_total)

    @classmethod
    def _sample_group(
        cls,
        group: TechniqueGroupInfo,
    ) -> TechniqueGroupInfo:
        """P3-13: 对单个技术组进行 Tier 比例采样。.

        高 Tier 组保留更多种子, 低 Tier 组保留少量种子。
        采样策略: severity 排序的确定性采样 + 随机采样。
        """
        ratio = cls._TIER_SAMPLE_RATIOS.get(group.tier, 0.10)
        min_count = cls._TIER_MIN_SAMPLES.get(group.tier, 1)
        sample_count = max(min_count, int(group.seed_count * ratio))

        source_groups = group.source_seed_groups
        if len(source_groups) <= sample_count:
            return group

        # 按 severity 排序
        def _severity_key(sg: Any) -> tuple:
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            best_sev = "unknown"
            for seed in getattr(sg, "seeds", []):
                meta = getattr(seed, "metadata", None) or {}
                sev = meta.get("severity", "")
                if sev in severity_order and severity_order.get(sev, 99) < severity_order.get(best_sev, 99):
                    best_sev = sev
            return (severity_order.get(best_sev, 99),)

        sorted_sources = sorted(source_groups, key=_severity_key)
        deterministic = sorted_sources[: min(sample_count, len(sorted_sources))]
        remaining = sorted_sources[min(sample_count, len(sorted_sources)) :]
        random_needed = sample_count - len(deterministic)
        if random_needed > 0 and remaining:
            random_sample = random.sample(
                remaining,
                min(random_needed, len(remaining)),
            )
            sampled_sources = deterministic + random_sample
        else:
            sampled_sources = deterministic

        return TechniqueGroupInfo(
            technique_group=group.technique_group,
            owasp_id=group.owasp_id,
            seed_count=sum(len(getattr(sg, "seeds", [])) for sg in sampled_sources),
            max_asr=group.max_asr,
            avg_asr=group.avg_asr,
            has_asr_data=group.has_asr_data,
            tier=group.tier,
            heuristic_score=group.heuristic_score,
            attack_modes=group.attack_modes,
            difficulties=group.difficulties,
            severities=group.severities,
            evasion_levels=group.evasion_levels,
            dataset_name=group.dataset_name,
            source_seed_groups=sampled_sources,
        )

    @classmethod
    def _trim_lowest_tier(
        cls,
        sampled_groups: list[TechniqueGroupInfo],
        *,
        max_total: int,
    ) -> list[TechniqueGroupInfo]:
        """P3-13: 从最低 Tier 开始裁剪, 直到总数不超过 max_total。.

        保留高 Tier 组的种子, 优先裁剪 D/UNKNOWN/C Tier 组。
        """
        total_sampled = sum(g.seed_count for g in sampled_groups)
        if total_sampled <= max_total:
            return sampled_groups

        tier_priority = {
            ASRTier.D: 0,
            ASRTier.UNKNOWN: 1,
            ASRTier.C: 2,
            ASRTier.B: 3,
            ASRTier.A: 4,
            ASRTier.S: 5,
        }
        sorted_by_priority = sorted(
            sampled_groups,
            key=lambda g: tier_priority.get(g.tier, 0),
        )
        while total_sampled > max_total and sorted_by_priority:
            lowest = sorted_by_priority[0]
            if lowest.seed_count > 1:
                keep = max(1, lowest.seed_count // 2)
                new_group = TechniqueGroupInfo(
                    technique_group=lowest.technique_group,
                    owasp_id=lowest.owasp_id,
                    seed_count=keep,
                    max_asr=lowest.max_asr,
                    avg_asr=lowest.avg_asr,
                    has_asr_data=lowest.has_asr_data,
                    tier=lowest.tier,
                    heuristic_score=lowest.heuristic_score,
                    attack_modes=lowest.attack_modes,
                    difficulties=lowest.difficulties,
                    severities=lowest.severities,
                    evasion_levels=lowest.evasion_levels,
                    dataset_name=lowest.dataset_name,
                    source_seed_groups=lowest.source_seed_groups[:keep],
                )
                idx = next(
                    (i for i, g in enumerate(sampled_groups) if g is lowest),
                    None,
                )
                if idx is not None:
                    sampled_groups[idx] = new_group
                sorted_by_priority[0] = new_group
                sorted_by_priority.sort(
                    key=lambda g: tier_priority.get(g.tier, 0),
                )
                total_sampled = sum(g.seed_count for g in sampled_groups)
            else:
                sorted_by_priority.pop(0)

        return sampled_groups

    @classmethod
    def get_tier_summary(
        cls,
        ranked_groups: list[TechniqueGroupInfo],
    ) -> dict[str, dict[str, int]]:
        """获取按 Tier 的汇总统计。."""
        summary: dict[str, dict[str, int]] = {}
        for tier in ASRTier:
            tier_groups = [g for g in ranked_groups if g.tier == tier]
            if tier_groups:
                summary[tier.value] = {
                    "groups": len(tier_groups),
                    "seeds": sum(g.seed_count for g in tier_groups),
                }
        return summary


# ============================================================
# 组级 ASR 降级链 (优化7: 合并原 group_fallback_executor.py)
# ============================================================


@dataclass
class FallbackRecord:
    """单次降级记录。."""

    from_group: str
    to_group: str
    from_tier: str
    to_tier: str
    reason: str
    from_asr: float
    to_asr: float


@dataclass
class GroupFallbackResult:
    """组级降级执行结果。."""

    execution_order: list[str] = field(default_factory=list)
    fallback_records: list[FallbackRecord] = field(default_factory=list)
    successful_groups: list[str] = field(default_factory=list)
    failed_groups: list[str] = field(default_factory=list)
    total_groups: int = 0

    @property
    def fallback_count(self) -> int:
        return len(self.fallback_records)

    @property
    def success_rate(self) -> float:
        if self.total_groups == 0:
            return 0.0
        return len(self.successful_groups) / self.total_groups


class GroupFallbackExecutor:
    """组级 ASR 降级链执行器 (优化7: 合并到 asr_rank_builder, 消除 Tier 定义重复)。.

    按 ASR Tier 对技术组排序，高 ASR 组优先执行。
    如果高 ASR 组失败，自动降级到下一 Tier 组。

    Tier 定义引用 ``asr_prior_registry.tier_from_asr()`` 唯一权威定义,
    不重复维护 Tier 阈值常量。

    使用方式:
        executor = GroupFallbackExecutor(
            model_name="gpt-4o",
            model_tier="strong",
        )
        result = executor.build_fallback_plan(
            technique_names=["crescendo", "tap", "many_shot", "prompt_sending"],
            owasp_id="LLM01",
        )
    """

    # Tier 优先级排序 (引用 ASRTier.priority, 不重复定义阈值)
    _TIER_PRIORITY: dict[str, int] = {
        "S": 100,
        "A": 80,
        "B": 60,
        "C": 40,
        "D": 20,
        "UNKNOWN": 50,
    }

    def __init__(
        self,
        *,
        model_name: str = "gpt-4o",
        model_tier: str = "unknown",
        owasp_id: str = "",
    ) -> None:
        self._model_name = model_name
        self._model_tier = model_tier
        self._owasp_id = owasp_id

    def build_fallback_plan(
        self,
        technique_names: Sequence[str],
        *,
        historical_asr: dict[str, float] | None = None,
    ) -> GroupFallbackResult:
        """构建组级 ASR 降级执行计划。.

        1. 为每个技术计算 ASR (历史优先 → 学术先验)
        2. 按 Tier 分层 (引用 asr_prior_registry.tier_from_asr)
        3. Tier 内按 ASR 降序
        4. Tier 间按 S→A→B→C→D→UNKNOWN 降级
        """
        if not technique_names:
            return GroupFallbackResult()

        tech_asr_map: dict[str, tuple[float, str]] = {}
        for tech in technique_names:
            asr = self._compute_asr(tech, historical_asr)
            tier = tier_from_asr(asr)
            tech_asr_map[tech] = (asr, tier)

        tier_groups: dict[str, list[str]] = defaultdict(list)
        for tech, (_, tier) in tech_asr_map.items():
            tier_groups[tier].append(tech)

        for tier in tier_groups:
            tier_groups[tier].sort(
                key=lambda t: tech_asr_map[t][0],
                reverse=True,
            )

        tier_order = sorted(
            tier_groups.keys(),
            key=lambda t: self._TIER_PRIORITY.get(t, 0),
            reverse=True,
        )

        execution_order: list[str] = []
        fallback_records: list[FallbackRecord] = []

        prev_tier: str | None = None
        prev_tech: str | None = None
        prev_asr: float = 0.0

        for tier in tier_order:
            tier_techs = tier_groups[tier]
            for tech in tier_techs:
                execution_order.append(tech)

                if prev_tier is not None and tier != prev_tier:
                    fallback_records.append(
                        FallbackRecord(
                            from_group=prev_tech or "",
                            to_group=tech,
                            from_tier=prev_tier,
                            to_tier=tier,
                            reason=f"Tier {prev_tier} → {tier} 降级",
                            from_asr=prev_asr,
                            to_asr=tech_asr_map[tech][0],
                        )
                    )

                prev_tier = tier
                prev_tech = tech
                prev_asr = tech_asr_map[tech][0]

        result = GroupFallbackResult(
            execution_order=execution_order,
            fallback_records=fallback_records,
            total_groups=len(technique_names),
        )

        logger.info(
            f"GroupFallbackExecutor: {len(execution_order)} techniques, "
            f"{len(fallback_records)} fallback points, "
            f"tier chain: {' → '.join(tier_order)}"
        )

        return result

    def record_execution_outcome(
        self,
        plan: GroupFallbackResult,
        successful_techniques: Sequence[str],
        failed_techniques: Sequence[str],
    ) -> GroupFallbackResult:
        """记录执行结果，更新降级记录。."""
        plan.successful_groups = list(successful_techniques)
        plan.failed_groups = list(failed_techniques)

        actual_fallbacks: list[FallbackRecord] = []
        for record in plan.fallback_records:
            if record.from_group in failed_techniques:
                actual_fallbacks.append(record)

        plan.fallback_records = actual_fallbacks
        return plan

    def get_fallback_summary(self, result: GroupFallbackResult) -> str:
        """生成降级执行摘要文本 (用于报告)。."""
        lines: list[str] = ["--- 组级 ASR 降级链 ---"]
        lines.append(f"  执行顺序 ({len(result.execution_order)} 组):")
        for i, tech in enumerate(result.execution_order, 1):
            status = "✓" if tech in result.successful_groups else ("✗" if tech in result.failed_groups else "—")
            lines.append(f"    {i}. {tech} [{status}]")

        if result.fallback_records:
            lines.append(f"\n  降级记录 ({result.fallback_count} 次):")
            for rec in result.fallback_records:
                lines.append(f"    {rec.from_group} ({rec.from_tier}) → {rec.to_group} ({rec.to_tier}) [{rec.reason}]")

        lines.append(f"\n  成功: {len(result.successful_groups)}/{result.total_groups}")
        lines.append(f"  成功率: {result.success_rate * 100:.1f}%")

        return "\n".join(lines)

    def _compute_asr(
        self,
        technique: str,
        historical_asr: dict[str, float] | None = None,
    ) -> float:
        """计算技术的 ASR (历史优先 → 学术先验 → 中性先验 0.3)。."""
        if historical_asr and technique in historical_asr:
            return historical_asr[technique]

        base_tech = technique.split("+")[0] if "+" in technique else technique
        if historical_asr and base_tech in historical_asr:
            return historical_asr[base_tech]

        return get_initial_q_value(
            technique,
            model_name=self._model_name,
            model_tier=self._model_tier,
            owasp_id=self._owasp_id,
        )
