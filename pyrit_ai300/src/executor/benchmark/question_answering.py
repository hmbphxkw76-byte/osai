"""
Question Answering Benchmark (Layer 5: Benchmarks)
===================================================

问答准确性基准测试封装 — 对齐 pyrit.executor.benchmark.question_answering

Layer 5: 标准测试层
"预定义测试集 + 预定义评分 → 一键出成绩单"

功能：评估目标模型在多选题上的准确性
流程：格式化问题 → 发送到目标 → 评分 → 统计正确率
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class QuestionAnsweringWrapper:
    """
    问答准确性基准测试封装

    对齐 PyRIT: pyrit.executor.benchmark.question_answering.QuestionAnsweringBenchmark

    功能：
    - 评估目标模型在多选题上的准确性
    - 标准化评估流程
    - 统计正确率

    使用场景：
    - 模型能力评估
    - 知识准确性测试
    - 基准对比

    用法示例：
        wrapper = QuestionAnsweringWrapper()
        result = await wrapper.run_async(
            qa_entry=qa_entry,
            target=objective_target,
            scorer=qa_scorer,
        )
    """

    def __init__(self):
        """初始化问答准确性基准测试封装"""

    async def run_async(
        self,
        qa_entry: Any,
        target: Any,
        scorer: Any = None,
        memory_labels: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        执行问答准确性基准测试

        Args:
            qa_entry: 问答条目（QuestionAnsweringEntry），包含问题和选项
            target: 目标 PromptTarget
            scorer: 问答评分器
            memory_labels: 可选的 memory 标签

        Returns:
            测试结果字典，包含 question / answer / correct / score
        """
        logger.info(f"QA 测试开始: question={getattr(qa_entry, 'question', 'N/A')[:50]}...")

        from pyrit.executor.benchmark.question_answering import (
            QuestionAnsweringBenchmark,
            QuestionAnsweringBenchmarkContext,
        )

        context = QuestionAnsweringBenchmarkContext(
            question_answering_entry=qa_entry,
            memory_labels=memory_labels or {},
        )

        # 创建 benchmark 实例
        benchmark = QuestionAnsweringBenchmark(objective_target=target)

        # 执行
        result = await benchmark.execute_async(context=context)

        # 提取结果
        is_correct = getattr(result, "is_correct", None)
        score = getattr(result, "score", None)

        logger.info(f"QA 测试完成: correct={is_correct}")
        return {
            "question": getattr(qa_entry, "question", ""),
            "correct_answer": getattr(qa_entry, "correct_answer", ""),
            "given_answer": getattr(result, "given_answer", ""),
            "is_correct": is_correct,
            "score": score,
        }

    async def run_batch_async(
        self,
        qa_entries: List[Any],
        target: Any,
        scorer: Any = None,
        memory_labels: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        批量执行问答准确性基准测试

        Args:
            qa_entries: 问答条目列表
            target: 目标 PromptTarget
            scorer: 问答评分器
            memory_labels: 可选的 memory 标签

        Returns:
            批量测试结果，包含 results / summary / accuracy
        """
        results = []
        correct_count = 0

        for i, qa_entry in enumerate(qa_entries):
            step_labels = dict(memory_labels or {})
            step_labels["qa_batch_index"] = str(i)
            step_labels["qa_batch_total"] = str(len(qa_entries))

            result = await self.run_async(
                qa_entry=qa_entry,
                target=target,
                scorer=scorer,
                memory_labels=step_labels,
            )
            results.append(result)

            if result.get("is_correct"):
                correct_count += 1

        total = len(qa_entries)
        accuracy = correct_count / total if total > 0 else 0.0

        logger.info(f"QA 批量测试完成: {correct_count}/{total} 正确 ({accuracy*100:.1f}%)")
        return {
            "results": results,
            "summary": {
                "total": total,
                "correct": correct_count,
                "incorrect": total - correct_count,
                "accuracy": accuracy,
            },
            "accuracy": accuracy,
        }
