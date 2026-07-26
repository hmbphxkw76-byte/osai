"""
Fairness Bias Benchmark (Layer 5: Benchmarks)
==============================================

公平性偏差基准测试封装 — 对齐 pyrit.executor.benchmark.fairness_bias

Layer 5: 标准测试层
"预定义测试集 + 预定义评分 → 一键出成绩单"

功能：评估目标模型在特定主题/角色上的公平性偏差
流程：生成故事提示 → 发送到目标 → 评分 → 统计偏差分布

L5 对齐改进（2026-07-26）：
1. run_async 返回原生 AttackResult（不再仅返回 dict）
2. 新增 run_native_async 方法直接返回 AttackResult
3. 批量方法返回原生结果 + 统计摘要
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class FairnessBiasWrapper:
    """
    公平性偏差基准测试封装

    对齐 PyRIT: pyrit.executor.benchmark.fairness_bias.FairnessBiasBenchmark

    功能：
    - 评估目标模型对不同主题/角色的公平性
    - 生成标准化故事提示
    - 统计偏差分布

    使用场景：
    - AI 系统公平性评估
    - 合规性测试
    - 偏见检测

    用法示例：
        wrapper = FairnessBiasWrapper()
        # 返回原生 AttackResult
        result = await wrapper.run_native_async(
            subject="software engineer",
            story_type="professional profile",
            target=objective_target,
        )
        # 返回 dict（向后兼容）
        result_dict = await wrapper.run_async(
            subject="software engineer",
            story_type="professional profile",
            target=objective_target,
        )
    """

    def __init__(self):
        """初始化公平性偏差基准测试封装"""
        self._default_num_experiments = 1

    async def run_native_async(
        self,
        subject: str,
        story_type: str,
        target: Any,
        num_experiments: int = 1,
        memory_labels: Optional[Dict[str, str]] = None,
    ) -> Any:
        """
        执行公平性偏差基准测试 — 返回原生 AttackResult

        对齐 PyRIT: FairnessBiasBenchmark.execute_async → AttackResult

        Args:
            subject: 评估主题（如职业、角色、特征）
            story_type: 故事类型（如 "professional profile", "personal story"）
            target: 目标 PromptTarget
            num_experiments: 实验次数
            memory_labels: 可选的 memory 标签

        Returns:
            原生 AttackResult 实例
        """
        logger.info(
            f"FairnessBias 测试开始: subject={subject}, story_type={story_type}, "
            f"experiments={num_experiments}"
        )

        from pyrit.executor.benchmark.fairness_bias import (
            FairnessBiasBenchmark,
            FairnessBiasBenchmarkContext,
        )

        context = FairnessBiasBenchmarkContext(
            subject=subject,
            story_type=story_type,
            num_experiments=num_experiments,
            memory_labels=memory_labels or {},
        )

        benchmark = FairnessBiasBenchmark(objective_target=target)
        result = await benchmark.execute_async(context=context)

        logger.info(
            f"FairnessBias 测试完成: conversation_id={getattr(result, 'conversation_id', 'N/A')}"
        )
        return result

    async def run_async(
        self,
        subject: str,
        story_type: str,
        target: Any,
        scorer: Any = None,
        num_experiments: int = 1,
        memory_labels: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        执行公平性偏差基准测试 — 返回 dict（向后兼容）

        Args:
            subject: 评估主题（如职业、角色、特征）
            story_type: 故事类型（如 "professional profile", "personal story"）
            target: 目标 PromptTarget
            scorer: 公平性评分器（已废弃，原生 Benchmark 内置评分）
            num_experiments: 实验次数
            memory_labels: 可选的 memory 标签

        Returns:
            测试结果字典，包含 experiments / summary / bias_distribution / native_result
        """
        result = await self.run_native_async(
            subject=subject,
            story_type=story_type,
            target=target,
            num_experiments=num_experiments,
            memory_labels=memory_labels,
        )

        experiment_results = getattr(result, "experiment_results", [])
        summary = {
            "subject": subject,
            "story_type": story_type,
            "num_experiments": num_experiments,
            "completed": len(experiment_results),
        }

        logger.info(f"FairnessBias 测试完成: {len(experiment_results)}/{num_experiments} 实验")
        return {
            "experiments": experiment_results,
            "summary": summary,
            "bias_distribution": self._compute_bias_distribution(experiment_results),
            "native_result": result,  # 附带原生 AttackResult
        }

    async def run_batch_native_async(
        self,
        subjects: List[str],
        story_type: str,
        target: Any,
        num_experiments_per_subject: int = 1,
        memory_labels: Optional[Dict[str, str]] = None,
    ) -> Tuple[List[Any], Dict[str, Any]]:
        """
        批量执行公平性偏差基准测试 — 返回原生 AttackResult 列表

        Args:
            subjects: 评估主题列表
            story_type: 故事类型
            target: 目标 PromptTarget
            num_experiments_per_subject: 每个主题的实验次数
            memory_labels: 可选的 memory 标签

        Returns:
            (AttackResult 列表, 统计摘要字典)
        """
        results = []
        for i, subject in enumerate(subjects):
            step_labels = dict(memory_labels or {})
            step_labels["fairness_batch_index"] = str(i)
            step_labels["fairness_batch_total"] = str(len(subjects))

            result = await self.run_native_async(
                subject=subject,
                story_type=story_type,
                target=target,
                num_experiments=num_experiments_per_subject,
                memory_labels=step_labels,
            )
            results.append(result)

        return results, {"total_subjects": len(subjects)}

    async def run_batch_async(
        self,
        subjects: List[str],
        story_type: str,
        target: Any,
        scorer: Any = None,
        num_experiments_per_subject: int = 1,
        memory_labels: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        批量执行公平性偏差基准测试 — 返回 dict 列表（向后兼容）

        Args:
            subjects: 评估主题列表
            story_type: 故事类型
            target: 目标 PromptTarget
            scorer: 公平性评分器（已废弃）
            num_experiments_per_subject: 每个主题的实验次数
            memory_labels: 可选的 memory 标签

        Returns:
            每个主题的测试结果列表
        """
        results = []
        for i, subject in enumerate(subjects):
            step_labels = dict(memory_labels or {})
            step_labels["fairness_batch_index"] = str(i)
            step_labels["fairness_batch_total"] = str(len(subjects))

            result = await self.run_async(
                subject=subject,
                story_type=story_type,
                target=target,
                scorer=scorer,
                num_experiments=num_experiments_per_subject,
                memory_labels=step_labels,
            )
            results.append(result)

        return results

    @staticmethod
    def _compute_bias_distribution(experiments: List) -> Dict[str, int]:
        """计算偏差分布统计"""
        distribution: Dict[str, int] = {}
        for exp in experiments:
            if isinstance(exp, dict):
                bias = exp.get("bias_type", "unknown")
            else:
                bias = getattr(exp, "bias_type", "unknown")
            distribution[bias] = distribution.get(bias, 0) + 1
        return distribution
