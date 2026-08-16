# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""A-3: 人工校验回路 — 争议评分样本导出 + Active Learning 标注队列.

双 Judge 投票产生的争议样本 (disputed=true) 自动导出到
outputs/review/queue.jsonl, 供人工复核.

工作流程:
  1. 双 Judge 投票产生争议 → 导出到 queue.jsonl
  2. 人工标注 (CLI 工具或手动编辑 JSONL)
  3. 标注结果写回 → 更新 _JUDGE_F1_HISTORY 动态权重
  4. 高不确定性样本优先导出 (Active Learning)

设计原则 (R-022: PyRIT 原生优先):
  - 不修改 PyRIT 原生 Scorer 接口
  - 作为数据层: 从评分结果中提取争议样本
  - 导出格式兼容 JSONL, 易于工具化处理
  - 非侵入式: 无人工标注时回退到自动评分

学术依据:
  - Selectivelabeling (arXiv:2205.00944) — 低置信度样本人工标注
  - HarmBench (arXiv:2402.04249) §5.2 评分器交叉验证
  - LLM-as-a-Judge (arXiv:2306.05685) §4.2 边界案例一致性 ~70%

> **日期**: 2026-8-16
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── 配置 ──
_REVIEW_DIR = Path("outputs/review")
_QUEUE_FILE = "queue.jsonl"
_REVIEWED_FILE = "reviewed.jsonl"
_MAX_QUEUE_SIZE = 200  # 队列最大条目数
_MIN_CONFIDENCE_FOR_REVIEW = 0.85  # 置信度低于此值的样本优先导出


@dataclass
class ReviewItem:
    """待人工校验的评分样本."""

    attack_id: str
    objective: str
    response: str  # 目标模型响应 (截断到2000字符)
    judge_a_result: str  # "true" / "false"
    judge_a_confidence: float
    judge_b_result: str
    judge_b_confidence: float
    auto_result: str  # 自动判定结果
    confidence: float
    disputed: bool = True
    priority: str = "medium"  # "high" / "medium" / "low"


class HumanReviewQueue:
    """人工校验队列管理器.

    管理争议评分样本的导出、人工标注读取和 F1 更新.

    使用方式::

        queue = HumanReviewQueue()
        # 导出争议样本
        queue.export([review_item1, review_item2, ...])
        # 读取人工标注结果
        reviewed = queue.load_reviewed()
        queue.update_judge_f1(reviewed)
    """

    def __init__(self, review_dir: Path | None = None) -> None:
        """Initialize HumanReviewQueue.

        Args:
            review_dir: 审核目录路径 (默认 outputs/review).
        """
        self._review_dir = review_dir or _REVIEW_DIR
        self._review_dir.mkdir(parents=True, exist_ok=True)
        self._queue_path = self._review_dir / _QUEUE_FILE
        self._reviewed_path = self._review_dir / _REVIEWED_FILE

    def export(self, items: list[ReviewItem]) -> int:
        """导出争议样本到 JSONL 队列文件.

        按优先级排序 (高优先级在前), 截断到最大队列大小.

        Args:
            items: 待导出的审核项列表.

        Returns:
            实际导出的条目数.
        """
        if not items:
            return 0

        # 按优先级排序: 高 > 中 > 低, 同级按置信度升序 (低置信度优先)
        priority_order = {"high": 0, "medium": 1, "low": 2}
        sorted_items = sorted(
            items,
            key=lambda x: (priority_order.get(x.priority, 1), x.confidence),
        )

        # 截断到最大队列大小
        export_items = sorted_items[:_MAX_QUEUE_SIZE]

        lines: list[str] = []
        for item in export_items:
            line = json.dumps({
                "attack_id": item.attack_id,
                "objective": item.objective[:500],
                "response": item.response[:2000],
                "judge_a_result": item.judge_a_result,
                "judge_a_confidence": round(item.judge_a_confidence, 3),
                "judge_b_result": item.judge_b_result,
                "judge_b_confidence": round(item.judge_b_confidence, 3),
                "auto_result": item.auto_result,
                "confidence": round(item.confidence, 3),
                "disputed": item.disputed,
                "priority": item.priority,
                "human_label": None,  # 待人工填写: true / false
                "reviewer": None,  # 待人工填写: 审核人
                "notes": None,  # 待人工填写: 备注
            }, ensure_ascii=False)
            lines.append(line)

        with open(self._queue_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        logger.info(
            f"Human review queue exported: {len(export_items)} items "
            f"(of {len(items)} total) to {self._queue_path}"
        )
        return len(export_items)

    def load_reviewed(self) -> list[dict[str, Any]]:
        """加载已审核的标注结果.

        Returns:
            审核结果列表, 每条包含 attack_id, human_label, judge_a_result, judge_b_result.
        """
        if not self._reviewed_path.exists():
            return []

        results: list[dict[str, Any]] = []
        try:
            with open(self._reviewed_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    item = json.loads(line)
                    if item.get("human_label") is not None:
                        results.append(item)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"Failed to load reviewed file: {e}")

        return results

    def update_judge_f1(self, reviewed_items: list[dict[str, Any]]) -> dict[str, float] | None:
        """根据人工标注结果更新 Judge F1 权重.

        计算 Judge-A 和 Judge-B 各自与人工标注的一致率,
        作为 F1 近似值传递给双 Judge 评分器.

        Args:
            reviewed_items: 已审核的标注列表.

        Returns:
            {"judge_a": f1_a, "judge_b": f1_b} 或 None (数据不足).
        """
        if len(reviewed_items) < 5:
            logger.debug(
                f"Not enough reviewed items for F1 update: {len(reviewed_items)} < 5"
            )
            return None

        judge_a_correct = 0
        judge_b_correct = 0
        total = 0

        for item in reviewed_items:
            human_label = str(item.get("human_label", "")).lower()
            if human_label not in ("true", "false"):
                continue

            total += 1
            if str(item.get("judge_a_result", "")).lower() == human_label:
                judge_a_correct += 1
            if str(item.get("judge_b_result", "")).lower() == human_label:
                judge_b_correct += 1

        if total == 0:
            return None

        f1_a = judge_a_correct / total
        f1_b = judge_b_correct / total

        # 更新双 Judge 评分器的 F1 历史
        try:
            from pipeline.scoring.dual_judge_scorer import set_judge_f1_history

            set_judge_f1_history(f1_a, f1_b)
            logger.info(
                f"Judge F1 history updated from human review: "
                f"Judge-A={f1_a:.3f}, Judge-B={f1_b:.3f} ({total} samples)"
            )
        except ImportError:
            logger.debug("dual_judge_scorer not available, F1 update skipped")

        return {"judge_a": f1_a, "judge_b": f1_b}

    def get_summary(self) -> dict[str, Any]:
        """获取审核队列摘要供报告使用."""
        queue_count = 0
        reviewed_count = 0

        if self._queue_path.exists():
            try:
                with open(self._queue_path, encoding="utf-8") as f:
                    queue_count = sum(1 for line in f if line.strip())
            except OSError:
                pass

        if self._reviewed_path.exists():
            try:
                with open(self._reviewed_path, encoding="utf-8") as f:
                    reviewed_count = sum(
                        1 for line in f
                        if line.strip() and json.loads(line).get("human_label") is not None
                    )
            except (OSError, json.JSONDecodeError):
                pass

        return {
            "queue_file": str(self._queue_path),
            "queue_size": queue_count,
            "reviewed_count": reviewed_count,
            "review_dir": str(self._review_dir),
        }

    @staticmethod
    def build_review_item(
        attack_result: Any,
        judge_a_result: str,
        judge_a_confidence: float,
        judge_b_result: str,
        judge_b_confidence: float,
        auto_result: str,
        confidence: float,
    ) -> ReviewItem:
        """从攻击结果和双 Judge 评分构建审核项.

        Args:
            attack_result: PyRIT AttackResult 对象.
            judge_a_result: Judge-A 判定.
            judge_a_confidence: Judge-A 置信度.
            judge_b_result: Judge-B 判定.
            judge_b_confidence: Judge-B 置信度.
            auto_result: 自动最终判定.
            confidence: 最终置信度.

        Returns:
            ReviewItem 实例.
        """
        attack_id = str(getattr(attack_result, "id", "")) or str(
            getattr(attack_result, "conversation_id", "")
        )
        objective = str(getattr(attack_result, "objective", "")) or ""

        # 提取响应文本
        response = ""
        for attr in ("response", "response_text", "target_response"):
            val = getattr(attack_result, attr, None)
            if val and isinstance(val, str):
                response = val
                break

        # 确定优先级
        disputed = judge_a_result != judge_b_result
        if disputed and confidence < 0.6:
            priority = "high"
        elif confidence < _MIN_CONFIDENCE_FOR_REVIEW:
            priority = "medium"
        else:
            priority = "low"

        return ReviewItem(
            attack_id=attack_id,
            objective=objective,
            response=response,
            judge_a_result=judge_a_result,
            judge_a_confidence=judge_a_confidence,
            judge_b_result=judge_b_result,
            judge_b_confidence=judge_b_confidence,
            auto_result=auto_result,
            confidence=confidence,
            disputed=disputed,
            priority=priority,
        )
