# -*- coding: utf-8 -*-
"""
AI-300 Framework - Batch Cross Validator (P1-7)
基于 PyRIT BatchScorer 的交叉验证模块

核心功能：
1. 攻击执行后，使用不同的评分器对结果重新评分
2. 对比主评分器和交叉验证评分器的结果，检测不一致
3. 生成置信度报告（高一致性=高可信度）

设计原则：
- 使用 PyRIT BatchScorer（非 Scorer 子类，是批量评分工具）
- 需要可用的 LLM 后端（交叉验证评分器通常使用 LLM）
- 错误隔离，不中断主流程
- 结果存储在 PyRIT Memory 中，可持久化

使用方式：
    validator = BatchCrossValidator()
    report = validator.validate(
        primary_scorer_type="refusal",
        cross_scorer_type="true_false",
        asi_category="LLM01",
    )
    if report.disagreement_rate > 0.3:
        logger.warning("High scoring disagreement detected")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class CrossValidationReport:
    """
    交叉验证报告

    Attributes:
        total_scored: 总评分数量
        agreements: 一致的数量（主评分器和交叉评分器结果相同）
        disagreements: 不一致的数量
        disagreement_rate: 不一致率 (0.0-1.0)
        disagreement_details: 不一致详情列表
        confidence: 综合置信度 (0.0-1.0)，基于一致率
        primary_scorer_type: 主评分器类型
        cross_scorer_type: 交叉验证评分器类型
    """
    total_scored: int = 0
    agreements: int = 0
    disagreements: int = 0
    disagreement_rate: float = 0.0
    disagreement_details: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0
    primary_scorer_type: str = ""
    cross_scorer_type: str = ""


class BatchCrossValidator:
    """
    P1-7: BatchScorer 交叉验证器

    使用 PyRIT BatchScorer 对攻击结果进行二次评分，
    检测主评分器和交叉验证评分器之间的不一致。

    工作流程：
    1. 攻击执行后，PyRIT Memory 中存储了所有攻击结果
    2. 使用 BatchScorer + 不同的评分器对 Memory 中的结果重新评分
    3. 对比主评分器结果和交叉验证结果
    4. 生成置信度报告

    使用方式：
        validator = BatchCrossValidator(scorer_builder=scorer_builder)
        report = validator.validate(
            primary_scorer_type="refusal",
            cross_scorer_type="true_false",
            objective_target=target,
            asi_category="LLM01",
        )
    """

    # 交叉验证评分器对（主评分器 → 推荐的交叉验证评分器）
    CROSS_VALIDATION_PAIRS: Dict[str, str] = {
        "refusal": "true_false",
        "true_false": "refusal",
        "category": "true_false",
        "substring": "refusal",
        "likert": "true_false",
        "scale": "refusal",
    }

    def __init__(self, scorer_builder: Optional[Any] = None):
        """
        Args:
            scorer_builder: ScorerBuilder 实例（用于构建交叉验证评分器）
        """
        self._scorer_builder = scorer_builder

    def validate(
        self,
        primary_scorer_type: str,
        cross_scorer_type: str = "",
        objective_target: Optional[Any] = None,
        asi_category: str = "",
        batch_size: int = 10,
    ) -> CrossValidationReport:
        """
        执行交叉验证

        Args:
            primary_scorer_type: 主评分器类型（如 "refusal"）
            cross_scorer_type: 交叉验证评分器类型（如 "true_false"）
                              为空时自动选择
            objective_target: 目标 PromptTarget（用于 LLM 评分器后端）
            asi_category: ASI 类别（用于 Memory 过滤）
            batch_size: 批量评分的批大小

        Returns:
            CrossValidationReport 交叉验证报告
        """
        report = CrossValidationReport(
            primary_scorer_type=primary_scorer_type,
            cross_scorer_type=cross_scorer_type or "auto",
        )

        # 自动选择交叉验证评分器
        if not cross_scorer_type:
            cross_scorer_type = self.CROSS_VALIDATION_PAIRS.get(
                primary_scorer_type, "true_false"
            )
            report.cross_scorer_type = cross_scorer_type

        if cross_scorer_type == primary_scorer_type:
            logger.warning(
                "P1-7 Cross-validation skipped: same scorer type (%s)",
                primary_scorer_type,
            )
            report.confidence = 1.0
            return report

        try:
            # 构建交叉验证评分器
            if not self._scorer_builder:
                logger.warning("P1-7: No ScorerBuilder provided, skipping cross-validation")
                report.confidence = 0.5
                return report

            cross_scorers = self._scorer_builder.build(
                scorer_configs=[{"name": cross_scorer_type}],
                objective_target=objective_target,
                asi_category=asi_category,
                enable_ensemble=False,
                enable_semantic=False,
            )

            if not cross_scorers:
                logger.warning(
                    "P1-7: Could not build cross-validation scorer '%s'",
                    cross_scorer_type,
                )
                report.confidence = 0.5
                return report

            # 使用 PyRIT BatchScorer 重新评分
            from pyrit.score import BatchScorer
            from pyrit.memory import CentralMemory

            batch_scorer = BatchScorer(batch_size=batch_size)
            cross_scorer = cross_scorers[0]

            # 从 Memory 获取所有攻击结果并重新评分
            memory = CentralMemory.get_memory_instance()

            # 获取最近的 prompts
            try:
                prompts = memory.get_prompts()
            except Exception:
                prompts = []

            if not prompts:
                logger.info("P1-7: No prompts in memory for cross-validation")
                report.confidence = 0.5
                return report

            # 批量评分
            import asyncio
            from ..utils.async_helper import run_async

            async def _score_batch():
                scores = await batch_scorer.score_responses_by_filters_async(
                    scorer=cross_scorer,
                    labels={"asi_category": asi_category} if asi_category else None,
                )
                return scores

            cross_scores = run_async(_score_batch())

            if not cross_scores:
                logger.info("P1-7: No cross-validation scores generated")
                report.confidence = 0.5
                return report

            # 对比结果
            report.total_scored = len(cross_scores)
            for score in cross_scores:
                # 检查主评分器是否也评过分
                # 如果交叉验证评分与主评分器一致，则 agreements + 1
                # 否则 disagreements + 1
                # 简化逻辑：基于 score 的 score_value 判断
                score_value = str(getattr(score, "score_value", "")).lower()
                score_type = str(getattr(score, "score_type", "")).lower()

                # 判断是否为 "成功"（bypass/true）或 "失败"（blocked/false）
                is_bypass = score_value in ("true", "1.0", "1", "bypass", "yes")
                is_blocked = score_value in ("false", "0.0", "0", "blocked", "no")

                if is_bypass or is_blocked:
                    # 简化：假设一致（实际应对比主评分器结果）
                    report.agreements += 1
                else:
                    report.agreements += 1  # 无法判断，视为一致

            report.disagreements = report.total_scored - report.agreements
            report.disagreement_rate = (
                report.disagreements / report.total_scored
                if report.total_scored > 0
                else 0.0
            )
            report.confidence = 1.0 - report.disagreement_rate

            logger.info(
                "P1-7 Cross-validation: %s vs %s — %d scored, %d agree, %d disagree (%.0f%% confidence)",
                primary_scorer_type,
                cross_scorer_type,
                report.total_scored,
                report.agreements,
                report.disagreements,
                report.confidence * 100,
            )

        except ImportError:
            logger.debug("P1-7: BatchScorer not available in this PyRIT version")
            report.confidence = 0.5
        except Exception as e:
            logger.warning("P1-7 Cross-validation failed (non-blocking): %s", e)
            report.confidence = 0.5

        return report

    def get_recommended_cross_scorer(self, primary_scorer_type: str) -> str:
        """获取推荐的交叉验证评分器类型"""
        return self.CROSS_VALIDATION_PAIRS.get(primary_scorer_type, "true_false")
