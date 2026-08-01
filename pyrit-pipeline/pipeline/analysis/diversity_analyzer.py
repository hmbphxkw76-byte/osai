# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""攻击多样性分析器 — 量化评估红队攻击的覆盖广度和策略多样性。.

PyRIT 原生输出 ASR (Attack Success Rate) 作为核心指标，但 ASR 仅衡量
"攻击是否成功"，不衡量 "攻击是否全面"。本模块补充以下多样性指标:

  1. Shannon 熵 — 攻击技术分布的熵值 (越高=越多样化)
  2. 覆盖度 — 使用的技术占可用技术的比例
  3. 范式覆盖 — multi_turn / persuasion / encoding 三大范式的覆盖情况
  4. OWASP 覆盖 — OWASP LLM/Agentic Top 10 分类的覆盖情况
  5. Converter 链覆盖 — 使用的 Converter 链类型分布

这些指标帮助红队评估:
  - 是否存在 "只测试了一种攻击范式" 的盲区
  - 是否有高 ASR 但未测试的技术
  - 报告的可信度 (高多样性 = 评估更全面)

学术依据:
  - Shannon entropy (Shannon, 1948): 信息论多样性度量
  - HarmBench (arXiv:2402.04249): 标准化红队评估框架
  - JailbreakBench (arXiv:2402.01135): 技术覆盖率分析

> **日期**: 2026-8-1
"""

from __future__ import annotations

import logging
import math
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ============================================================
# 数据结构
# ============================================================


@dataclass
class DiversityMetrics:
    """多样性指标集合。."""

    # 技术多样性
    technique_entropy: float = 0.0
    technique_coverage: float = 0.0
    unique_techniques: int = 0
    total_attacks: int = 0

    # 范式覆盖
    paradigm_coverage: float = 0.0
    paradigms_used: list[str] = field(default_factory=list)
    paradigms_available: list[str] = field(default_factory=list)

    # OWASP 覆盖
    owasp_coverage: float = 0.0
    owasp_categories_used: list[str] = field(default_factory=list)

    # Converter 链覆盖
    converter_chain_entropy: float = 0.0
    converter_chains_used: list[str] = field(default_factory=list)

    # 攻击模式分布
    attack_mode_distribution: dict[str, int] = field(default_factory=dict)

    # L5 对齐: 失败模式集中度 — 最大失败原因占比 (越高越集中, 越低越分散)
    failure_concentration: float = 0.0
    failure_type_distribution: dict[str, int] = field(default_factory=dict)

    # 整体评分
    overall_diversity_score: float = 0.0
    diversity_grade: str = "F"

    def to_dict(self) -> dict[str, Any]:
        """转换为字典 (用于报告序列化)。."""
        return {
            "technique_entropy": round(self.technique_entropy, 4),
            "technique_coverage": round(self.technique_coverage, 4),
            "unique_techniques": self.unique_techniques,
            "total_attacks": self.total_attacks,
            "paradigm_coverage": round(self.paradigm_coverage, 4),
            "paradigms_used": self.paradigms_used,
            "paradigms_available": self.paradigms_available,
            "owasp_coverage": round(self.owasp_coverage, 4),
            "owasp_categories_used": self.owasp_categories_used,
            "converter_chain_entropy": round(self.converter_chain_entropy, 4),
            "converter_chains_used": self.converter_chains_used,
            "attack_mode_distribution": self.attack_mode_distribution,
            "failure_concentration": round(self.failure_concentration, 4),
            "failure_type_distribution": self.failure_type_distribution,
            "overall_diversity_score": round(self.overall_diversity_score, 2),
            "diversity_grade": self.diversity_grade,
        }


# ============================================================
# 攻击范式分类 — P2-9: 统一使用 failure_type_selector._infer_paradigm
# ============================================================
# 范式分类逻辑已统一到 pipeline.asr.failure_type_selector._infer_paradigm
# 消除跨模块硬编码集合不一致问题

_ALL_PARADIGMS = ["multi_turn", "persuasion", "encoding"]


def _classify_paradigm(technique: str) -> str:
    """分类技术的攻击范式 (委托给统一推断函数)。."""
    from pipeline.asr.failure_type_selector import _infer_paradigm

    return _infer_paradigm(technique)


# ============================================================
# DiversityAnalyzer
# ============================================================


class DiversityAnalyzer:
    """攻击多样性分析器。.

    分析 ScenarioResult 中的攻击结果，计算多样性指标。

    使用方式:
        analyzer = DiversityAnalyzer()
        metrics = analyzer.analyze(
            attack_results=result.attack_results,
            available_techniques=["crescendo", "tap", "many_shot", ...],
        )
        print(analyzer.format_report(metrics))
    """

    def analyze(
        self,
        attack_results: dict[str, list[Any]],
        available_techniques: Sequence[str] | None = None,
        owasp_mapping: dict[str, str] | None = None,
    ) -> DiversityMetrics:
        """分析攻击结果，计算多样性指标。.

        Args:
            attack_results: ScenarioResult.attack_results 字典
                           {attack_id: [AttackResult, ...]}
            available_techniques: 可用技术列表 (用于计算覆盖率)
            owasp_mapping: 技术名 → OWASP ID 映射

        Returns:
            DiversityMetrics: 多样性指标集合
        """
        metrics = DiversityMetrics()

        # 收集所有技术名
        all_techniques: list[str] = []
        all_owasp: list[str] = []
        all_chains: list[str] = []
        all_modes: list[str] = []

        for _attack_id, results in attack_results.items():
            for ar in results:
                tech_name = self._extract_technique_name(ar)
                all_techniques.append(tech_name)

                # 子结果 (SequentialAttack)
                child_results = getattr(ar, "child_attack_results", None) or []
                for child in child_results:
                    if child is not None:
                        child_tech = self._extract_technique_name(child)
                        all_techniques.append(child_tech)

                # OWASP 分类
                if owasp_mapping and tech_name in owasp_mapping:
                    all_owasp.append(owasp_mapping[tech_name])

                # Converter 链
                if "+" in tech_name:
                    chain = tech_name.split("+")[1]
                    all_chains.append(chain)

                # 攻击模式
                paradigm = _classify_paradigm(tech_name)
                all_modes.append(paradigm)

        metrics.total_attacks = len(all_techniques)

        if metrics.total_attacks == 0:
            return metrics

        # ── 技术多样性 ──
        tech_counter = Counter(all_techniques)
        metrics.unique_techniques = len(tech_counter)

        if available_techniques:
            metrics.technique_coverage = len(tech_counter) / len(available_techniques)
        else:
            metrics.technique_coverage = 1.0

        # Shannon 熵
        metrics.technique_entropy = self._shannon_entropy(tech_counter)

        # ── 范式覆盖 ──
        paradigm_counter = Counter(_classify_paradigm(t) for t in all_techniques)
        metrics.paradigms_used = sorted(p for p in paradigm_counter if p != "unknown")
        metrics.paradigms_available = _ALL_PARADIGMS
        metrics.paradigm_coverage = len(metrics.paradigms_used) / len(_ALL_PARADIGMS)

        # ── OWASP 覆盖 ──
        if all_owasp:
            # P1: 使用外部常量替代硬编码
            from pipeline.analysis.attack_result_analyzer import OWASP_LLM_CATEGORY_COUNT

            owasp_counter = Counter(all_owasp)
            metrics.owasp_categories_used = sorted(owasp_counter.keys())
            metrics.owasp_coverage = len(metrics.owasp_categories_used) / OWASP_LLM_CATEGORY_COUNT

        # ── Converter 链覆盖 ──
        if all_chains:
            chain_counter = Counter(all_chains)
            metrics.converter_chain_entropy = self._shannon_entropy(chain_counter)
            metrics.converter_chains_used = sorted(chain_counter.keys())

        # ── 攻击模式分布 ──
        metrics.attack_mode_distribution = dict(paradigm_counter.most_common())

        # ── L5 对齐: 失败模式集中度 ──
        metrics.failure_concentration, metrics.failure_type_distribution = (
            self._compute_failure_concentration(attack_results)
        )

        # ── 整体评分 ──
        metrics.overall_diversity_score = self._compute_overall_score(metrics)
        metrics.diversity_grade = self._compute_grade(metrics.overall_diversity_score)

        return metrics

    def format_report(self, metrics: DiversityMetrics) -> str:
        """生成多样性分析报告文本。."""
        from pipeline.analysis.attack_result_analyzer import OWASP_LLM_CATEGORY_COUNT

        lines: list[str] = ["--- 攻击多样性分析 ---"]

        # 技术多样性
        lines.append("\n  技术多样性:")
        lines.append(
            f"    Shannon 熵: {metrics.technique_entropy:.4f} (最大={math.log2(max(metrics.unique_techniques, 1)):.4f})"
        )
        lines.append(f"    技术覆盖: {metrics.technique_coverage:.1%} ({metrics.unique_techniques} 个唯一技术)")
        lines.append(f"    总攻击数: {metrics.total_attacks}")

        # 范式覆盖
        lines.append("\n  范式覆盖:")
        lines.append(
            f"    覆盖度: {metrics.paradigm_coverage:.1%} "
            f"({len(metrics.paradigms_used)}/{len(metrics.paradigms_available)})"
        )
        lines.append(f"    已覆盖范式: {', '.join(metrics.paradigms_used)}")
        missing_paradigms = set(metrics.paradigms_available) - set(metrics.paradigms_used)
        if missing_paradigms:
            lines.append(f"    [!] 缺失范式: {', '.join(missing_paradigms)}")

        # OWASP 覆盖
        if metrics.owasp_categories_used:
            lines.append("\n  OWASP 覆盖:")
            lines.append(
                f"    覆盖度: {metrics.owasp_coverage:.1%} "
                f"({len(metrics.owasp_categories_used)}/{OWASP_LLM_CATEGORY_COUNT})"
            )
            lines.append(f"    已覆盖分类: {', '.join(metrics.owasp_categories_used)}")

        # Converter 链覆盖
        if metrics.converter_chains_used:
            lines.append("\n  Converter 链覆盖:")
            lines.append(f"    Shannon 熵: {metrics.converter_chain_entropy:.4f}")
            lines.append(f"    使用链数: {len(metrics.converter_chains_used)}")
            lines.append(f"    链列表: {', '.join(metrics.converter_chains_used)}")

        # 攻击模式分布
        if metrics.attack_mode_distribution:
            lines.append("\n  攻击模式分布:")
            for mode, count in metrics.attack_mode_distribution.items():
                pct = count / metrics.total_attacks * 100
                bar = "█" * int(pct / 5)
                lines.append(f"    {mode:<20} {count:>5} ({pct:>5.1f}%) {bar}")

        # L5 对齐: 失败模式集中度
        if metrics.failure_type_distribution:
            lines.append("\n  失败模式集中度:")
            lines.append(f"    集中度: {metrics.failure_concentration:.1%} (越高越集中)")
            total_f = sum(metrics.failure_type_distribution.values())
            for ftype, count in metrics.failure_type_distribution.items():
                pct = count / total_f * 100 if total_f > 0 else 0
                bar = "█" * int(pct / 5)
                lines.append(f"    {ftype:<20} {count:>5} ({pct:>5.1f}%) {bar}")

        # 整体评分
        lines.append(f"\n  整体多样性评分: {metrics.overall_diversity_score:.2f}/100 ({metrics.diversity_grade})")

        return "\n".join(lines)

    def _shannon_entropy(self, counter: Counter) -> float:
        """计算 Shannon 熵。."""
        total = sum(counter.values())
        if total == 0:
            return 0.0
        entropy = 0.0
        for count in counter.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return entropy

    def _compute_failure_concentration(
        self,
        attack_results: dict[str, list[Any]],
    ) -> tuple[float, dict[str, int]]:
        """L5 对齐: 计算失败模式集中度。

        失败集中度 = 最大失败类型次数 / 总失败次数。
        - 值越高 → 失败原因越集中 (可能存在系统性盲区)
        - 值越低 → 失败原因越分散 (攻击多样化失败)

        Returns:
            (concentration, failure_type_distribution)
        """
        failure_types: Counter = Counter()

        for _attack_id, results in attack_results.items():
            for ar in results:
                outcome = getattr(ar, "outcome", None)
                outcome_str = (
                    str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()
                ) if outcome else "UNKNOWN"

                if outcome_str != "SUCCESS":
                    try:
                        from pipeline.asr.failure_type_selector import extract_failure_type_from_result
                        ftype = extract_failure_type_from_result(ar)
                    except Exception:
                        ftype = "unknown"
                    failure_types[ftype] += 1

                # 子结果
                child_results = getattr(ar, "child_attack_results", None) or []
                for child in child_results:
                    if child is None:
                        continue
                    child_outcome = getattr(child, "outcome", None)
                    child_outcome_str = (
                        str(child_outcome.value).upper() if hasattr(child_outcome, "value")
                        else str(child_outcome).upper()
                    ) if child_outcome else "UNKNOWN"
                    if child_outcome_str != "SUCCESS":
                        try:
                            from pipeline.asr.failure_type_selector import extract_failure_type_from_result
                            ftype = extract_failure_type_from_result(child)
                        except Exception:
                            ftype = "unknown"
                        failure_types[ftype] += 1

        total_failures = sum(failure_types.values())
        if total_failures == 0:
            return 0.0, {}

        max_count = max(failure_types.values())
        concentration = max_count / total_failures
        return concentration, dict(failure_types.most_common())

    def _compute_overall_score(self, metrics: DiversityMetrics) -> float:
        """计算整体多样性评分 (0-100)。.

        权重:
        - 技术熵 (30%): 技术分布均匀度
        - 技术覆盖 (25%): 使用了多少可用技术
        - 范式覆盖 (25%): 攻击范式多样性
        - OWASP 覆盖 (10%): OWASP 分类覆盖
        - Converter 链熵 (10%): Converter 多样性
        """
        max_entropy = math.log2(max(metrics.unique_techniques, 1)) if metrics.unique_techniques > 1 else 1.0
        normalized_entropy = metrics.technique_entropy / max_entropy if max_entropy > 0 else 0.0

        score = (
            normalized_entropy * 30
            + metrics.technique_coverage * 25
            + metrics.paradigm_coverage * 25
            + metrics.owasp_coverage * 10
            + min(metrics.converter_chain_entropy / 3.0, 1.0) * 10
        )
        return min(score * 100, 100.0)

    def _compute_grade(self, score: float) -> str:
        """将分数转换为等级。."""
        if score >= 90:
            return "A+"
        if score >= 80:
            return "A"
        if score >= 70:
            return "B+"
        if score >= 60:
            return "B"
        if score >= 50:
            return "C+"
        if score >= 40:
            return "C"
        if score >= 30:
            return "D"
        return "F"

    def _extract_technique_name(self, attack_result: Any) -> str:
        """从 AttackResult 提取技术名 (委托给 AttackResultAnalyzer)。."""
        from pipeline.analysis.attack_result_analyzer import AttackResultAnalyzer

        return AttackResultAnalyzer.extract_technique_name(attack_result)
