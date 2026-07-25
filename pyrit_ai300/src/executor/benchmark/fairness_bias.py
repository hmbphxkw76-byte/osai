"""
Fairness Bias Benchmark (Layer 5: Benchmarks)
==============================================

公平性偏差基准测试封装 — 对齐 pyrit.executor.benchmark.fairness_bias

Layer 5: 标准测试层
"预定义测试集 + 预定义评分 → 一键出成绩单"

功能：评估目标模型在特定主题/角色上的公平性偏差
流程：生成故事提示 → 发送到目标 → 评分 → 统计偏差分布
"""

import logging
from typing import Any, Dict, List, Optional

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
        result = await wrapper.run_async(
            subject="software engineer",
            story_type="professional profile",
            num_experiments=10,
            target=objective_target,
            scorer=fairness_scorer,
        )
    """

    def __init__(self):
        """初始化公平性偏差基准测试封装"""
        self._default_num_experiments = 1

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
        执行公平性偏差基准测试

        Args:
            subject: 评估主题（如职业、角色、特征）
            story_type: 故事类型（如 "professional profile", "personal story"）
            target: 目标 PromptTarget
            scorer: 公平性评分器
            num_experiments: 实验次数
            memory_labels: 可选的 memory 标签

        Returns:
            测试结果字典，包含 experiments / summary / bias_distribution
        """
        logger.info(
            f"FairnessBias 测试开始: subject={subject}, story_type={story_type}, "
            f"experiments={num_experiments}"
        )

        from pyrit.executor.benchmark.fairness_bias import (
            FairnessBiasBenchmark,
            FairnessBiasBenchmarkContext,
        )
        from pyrit.models import QuestionAnsweringEntry

        context = FairnessBiasBenchmarkContext(
            subject=subject,
            story_type=story_type,
            num_experiments=num_experiments,
            memory_labels=memory_labels or {},
        )

        # 创建 benchmark 实例
        benchmark = FairnessBiasBenchmark(objective_target=target)

        # 执行
        result = await benchmark.execute_async(context=context)

        # 提取结果
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
        }

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
        批量执行公平性偏差基准测试

        Args:
            subjects: 评估主题列表
            story_type: 故事类型
            target: 目标 PromptTarget
            scorer: 公平性评分器
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
