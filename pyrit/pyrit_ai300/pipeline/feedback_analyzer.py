# -*- coding: utf-8 -*-
"""
AI-300 Framework - Feedback Analyzer v1.0
攻击结果反馈分析器：闭环优化引擎

职责：
- 分析攻击执行结果，提取成功率、策略效果等关键指标
- 识别最优攻击策略和编码组合
- 生成优化建议（调整 aggression_level、推荐 probe families 等）
- 将分析结果反馈到 TargetProfile，优化下次策略选择

设计原则：
- 只读分析器，不修改原始结果
- 输出结构化建议，可供 ProfileLoader / SmartMatcher 使用
- 支持增量分析（单次攻击）和聚合分析（多次攻击）

使用方式：
    analyzer = FeedbackAnalyzer()
    report = analyzer.analyze(attack_results)
    suggestions = analyzer.generate_suggestions(report)
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class FeedbackReport:
    """
    反馈分析报告

    Attributes:
        total_attacks: 总攻击次数
        total_payloads: 总载荷数
        success_count: 成功数
        failure_count: 失败数
        success_rate: 成功率 (0.0-1.0)
        strategy_stats: 按攻击策略统计 {attack_class: {success, failure, rate}}
        category_stats: 按载荷类别统计 {category: {success, failure, rate}}
        encoding_stats: 按编码变体统计 {encoding: {success, failure, rate}}
        best_strategies: 成功率最高的策略列表
        worst_strategies: 成功率最低的策略列表
        recommended_families: 推荐的攻击探针族
        recommended_aggression: 推荐的攻击强度
        optimization_notes: 优化建议列表
    """
    total_attacks: int = 0
    total_payloads: int = 0
    success_count: int = 0
    failure_count: int = 0
    success_rate: float = 0.0
    strategy_stats: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    category_stats: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    encoding_stats: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    best_strategies: List[Dict[str, Any]] = field(default_factory=list)
    worst_strategies: List[Dict[str, Any]] = field(default_factory=list)
    recommended_families: List[str] = field(default_factory=list)
    recommended_aggression: str = "medium"
    optimization_notes: List[str] = field(default_factory=list)
    # P0-C: 组合统计
    best_combinations: List[Dict[str, Any]] = field(default_factory=list)
    combo_stats: Dict[str, Dict[str, Any]] = field(default_factory=dict)


class FeedbackAnalyzer:
    """
    攻击结果反馈分析器

    分析攻击执行结果，生成优化建议，形成闭环反馈。

    闭环流程：
        攻击执行 → 结果收集 → FeedbackAnalyzer 分析
        → 生成优化建议 → 更新 TargetProfile 参数
        → 下次 SmartMatcher 使用优化后的参数

    使用方式：
        analyzer = FeedbackAnalyzer()
        report = analyzer.analyze(scope_results)
        suggestions = analyzer.generate_suggestions(report)

        # 将建议应用到下次执行
        if report.recommended_families:
            profile_params["preferred_probe_families"] = report.recommended_families
        if report.recommended_aggression:
            profile_params["aggression_level"] = report.recommended_aggression
    """

    # 攻击探针族映射（攻击类名 → 探针族名）
    _ATTACK_CLASS_FAMILY_MAP = {
        "PromptSendingAttack": "DIRECT_SINGLE",
        "CrescendoAttack": "PROGRESSIVE",
        "TreeOfAttacksWithPruningAttack": "TREE_SEARCH",
        "PAIRAttack": "ITERATIVE",
        "RedTeamingAttack": "EXPLORATORY",
        "SequentialAttack": "MULTI_PRESET",
    }

    def analyze(self, results: List[Dict[str, Any]]) -> FeedbackReport:
        """
        分析攻击结果，生成反馈报告

        Args:
            results: 攻击结果列表（scope_results 格式）

        Returns:
            FeedbackReport 分析报告
        """
        report = FeedbackReport()

        for scope_result in results:
            if not isinstance(scope_result, dict):
                continue

            attacks = scope_result.get("attacks", [])
            for attack in attacks:
                report.total_attacks += 1
                self._analyze_attack(attack, report)

        # 计算总体成功率
        report.total_payloads = report.success_count + report.failure_count
        report.success_rate = (
            report.success_count / report.total_payloads
            if report.total_payloads > 0
            else 0.0
        )

        # 生成策略排名
        self._rank_strategies(report)

        # 生成推荐
        self._generate_recommendations(report)

        logger.info(
            "Feedback analysis: %d attacks, %d payloads, %.1f%% success rate",
            report.total_attacks,
            report.total_payloads,
            report.success_rate * 100,
        )

        return report

    def _analyze_attack(self, attack: Dict[str, Any], report: FeedbackReport) -> None:
        """分析单个攻击结果"""
        attack_results = attack.get("results", [])
        mode = attack.get("mode", "chain")

        for r in attack_results:
            is_success = r.get("status") == "success"
            if is_success:
                report.success_count += 1
            else:
                report.failure_count += 1

            # 按攻击策略统计
            attack_class = r.get("attack_class", "PromptSendingAttack")
            self._update_stats(report.strategy_stats, attack_class, is_success)

            # 按载荷类别统计
            category = r.get("payload_category", "unknown")
            self._update_stats(report.category_stats, category, is_success)

            # 按编码变体统计（presets 模式）
            preset = r.get("preset", "default")
            if preset != "default" and preset != "error" and preset != "all_failed":
                self._update_stats(report.encoding_stats, preset, is_success)

            # P0-C: 追踪 payload_category x attack_family 组合
            attack_family = r.get("attack_family", "unknown")
            combo_key = f"{category}|{attack_family}"
            self._update_stats(report.combo_stats, combo_key, is_success)

    def _update_stats(
        self,
        stats: Dict[str, Dict[str, Any]],
        key: str,
        is_success: bool,
    ) -> None:
        """更新统计数据"""
        if key not in stats:
            stats[key] = {"success": 0, "failure": 0, "total": 0, "rate": 0.0}
        if is_success:
            stats[key]["success"] += 1
        else:
            stats[key]["failure"] += 1
        stats[key]["total"] += 1
        stats[key]["rate"] = stats[key]["success"] / stats[key]["total"]

    def _rank_strategies(self, report: FeedbackReport) -> None:
        """生成策略排名"""
        # 按成功率排序
        sorted_strategies = sorted(
            report.strategy_stats.items(),
            key=lambda x: x[1]["rate"],
            reverse=True,
        )

        for class_name, stats in sorted_strategies:
            entry = {
                "attack_class": class_name,
                "family": self._ATTACK_CLASS_FAMILY_MAP.get(class_name, "UNKNOWN"),
                "success": stats["success"],
                "total": stats["total"],
                "rate": stats["rate"],
            }
            if stats["rate"] >= 0.5:
                report.best_strategies.append(entry)
            elif stats["rate"] < 0.2:
                report.worst_strategies.append(entry)

        # P0-C: 计算高成功率组合
        sorted_combos = sorted(
            report.combo_stats.items(),
            key=lambda x: x[1]["rate"],
            reverse=True,
        )
        for combo_key, stats in sorted_combos[:10]:
            parts = combo_key.split("|")
            report.best_combinations.append({
                "category": parts[0] if len(parts) > 0 else "unknown",
                "attack_family": parts[1] if len(parts) > 1 else "unknown",
                "success": stats["success"],
                "total": stats["total"],
                "rate": stats["rate"],
            })

    def _generate_recommendations(self, report: FeedbackReport) -> None:
        """生成推荐和优化建议"""

        # 推荐攻击探针族（基于成功率最高的策略）
        if report.best_strategies:
            seen = set()
            for s in report.best_strategies:
                family = s["family"]
                if family not in seen and family != "UNKNOWN":
                    report.recommended_families.append(family)
                    seen.add(family)

        # 推荐攻击强度
        if report.success_rate >= 0.7:
            report.recommended_aggression = "low"
            report.optimization_notes.append(
                f"成功率 {report.success_rate:.0%} 较高，建议降低攻击强度到 'low'，"
                "减少不必要的多轮攻击，节省资源"
            )
        elif report.success_rate >= 0.3:
            report.recommended_aggression = "medium"
            report.optimization_notes.append(
                f"成功率 {report.success_rate:.0%} 中等，保持攻击强度 'medium'"
            )
        elif report.success_rate > 0:
            report.recommended_aggression = "high"
            report.optimization_notes.append(
                f"成功率 {report.success_rate:.0%} 较低，建议提升攻击强度到 'high'，"
                "增加多轮攻击和 Fallback 尝试"
            )
        else:
            report.recommended_aggression = "high"
            report.optimization_notes.append(
                "成功率为 0，建议：1) 检查目标是否在线 2) 尝试更多编码变体 "
                "3) 使用更强的攻击策略（TAP/PAIR）"
            )

        # 编码变体建议
        if report.encoding_stats:
            best_encoding = max(
                report.encoding_stats.items(),
                key=lambda x: x[1]["rate"],
            )
            if best_encoding[1]["rate"] > 0 and best_encoding[1]["total"] >= 2:
                report.optimization_notes.append(
                    f"编码变体 '{best_encoding[0]}' 成功率最高 ({best_encoding[1]['rate']:.0%})，"
                    "建议在后续攻击中优先使用"
                )

            worst_encoding = min(
                report.encoding_stats.items(),
                key=lambda x: x[1]["rate"],
            )
            if worst_encoding[1]["rate"] == 0 and worst_encoding[1]["total"] >= 3:
                report.optimization_notes.append(
                    f"编码变体 '{worst_encoding[0]}' 连续 {worst_encoding[1]['total']} 次失败，"
                    "建议在后续攻击中跳过此编码"
                )

        # 策略降级建议
        if report.worst_strategies:
            for s in report.worst_strategies[:3]:
                report.optimization_notes.append(
                    f"策略 {s['attack_class']} 成功率仅 {s['rate']:.0%} ({s['success']}/{s['total']})，"
                    "建议降级为更简单的策略或增加 Fallback"
                )

    def generate_suggestions(self, report: FeedbackReport) -> Dict[str, Any]:
        """
        生成结构化优化建议（可供 ProfileLoader / SmartMatcher 直接使用）

        Returns:
            优化建议字典，包含：
            - preferred_probe_families: 推荐的攻击探针族列表
            - aggression_level: 推荐的攻击强度
            - notes: 优化建议文本列表
            - success_rate: 总体成功率
        """
        return {
            "preferred_probe_families": report.recommended_families,
            "aggression_level": report.recommended_aggression,
            "notes": report.optimization_notes,
            "success_rate": report.success_rate,
            "best_strategies": report.best_strategies,
            "worst_strategies": report.worst_strategies,
            "best_combinations": report.best_combinations,
        }

    def generate_mutations(
        self,
        results: List[Dict[str, Any]],
        strategies: Optional[List[str]] = None,
        max_payloads: int = 10,
    ) -> Optional[Any]:
        """
        P1-F: 从成功载荷生成变异体

        接入 PayloadMutator，自动从攻击结果中提取成功载荷并生成变异体。
        使用纯规则变异（无需 LLM），可在离线环境运行。

        Args:
            results: 攻击结果列表
            strategies: 变异策略列表（默认 paraphrase + tone_shift）
            max_payloads: 最大处理载荷数

        Returns:
            MutationResult 或 None（如果无成功载荷）
        """
        try:
            from ..payloads.payload_mutator import PayloadMutator
            mutator = PayloadMutator()  # 纯规则变异，无需 LLM
            if strategies is None:
                strategies = ["paraphrase", "tone_shift"]
            return mutator.mutate_from_results(
                results, strategies=strategies,
                max_payloads=max_payloads, analyze=False,
            )
        except Exception as e:
            logger.warning("Mutation generation failed: %s", e)
            return None

    def apply_to_profile_params(
        self,
        report: FeedbackReport,
        profile_params: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        将反馈建议应用到 ProfileParams 字典

        创建更新后的参数字典，用于下次 SmartMatcher 调用。

        Args:
            report: 反馈分析报告
            profile_params: 原始 ProfileParams 字典

        Returns:
            更新后的 ProfileParams 字典
        """
        updated = dict(profile_params)

        if report.recommended_families:
            # 合并原有推荐和新推荐（去重）
            existing = set(updated.get("preferred_probe_families", []))
            merged = list(existing) + [
                f for f in report.recommended_families if f not in existing
            ]
            updated["preferred_probe_families"] = merged

        if report.recommended_aggression:
            updated["aggression_level"] = report.recommended_aggression

        # 添加反馈元数据
        updated["_feedback"] = {
            "success_rate": report.success_rate,
            "total_payloads": report.total_payloads,
            "notes_count": len(report.optimization_notes),
        }

        return updated
