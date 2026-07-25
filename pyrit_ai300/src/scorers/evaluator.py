"""
Scorer Evaluator
================

评分器准确性评估（PyRIT 1.0.0 完整对齐）

使用 PyRIT 原生 ScorerEvaluator 框架，基于人工标注数据集评估 Scorer 的：
- Objective 指标：accuracy / precision / recall / f1 / accuracy_standard_error
- Harm 指标：MAE / mae_standard_error / t-statistic / p-value / Krippendorff's α
- 一致性指标：重复评分一致率 / 标准差
- 鲁棒性指标：扰动稳定性

支持 RegistryUpdateBehavior 缓存策略和 eval_hash 身份追踪。
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pyrit.models import Message, MessagePiece, Score
from pyrit.score import (
    Scorer,
    TrueFalseScorer,
    # 评估框架（lazy import via __getattr__）
    ScorerEvaluator,
    ScorerEvalDatasetFiles,
    HumanLabeledDataset,
    HumanLabeledEntry,
    HarmHumanLabeledEntry,
    ObjectiveHumanLabeledEntry,
    # 指标类型
    MetricsType,
    RegistryUpdateBehavior,
    ScorerMetrics,
    ObjectiveScorerMetrics,
    HarmScorerMetrics,
    ScorerMetricsWithIdentity,
    # 指标查询
    get_all_objective_metrics,
    get_all_harm_metrics,
    find_objective_metrics_by_eval_hash,
)

logger = logging.getLogger(__name__)


class ScorerAccuracyEvaluator:
    """
    评分器准确性评估器（PyRIT 1.0.0 完整对齐）

    封装 PyRIT 原生 ScorerEvaluator，提供三层评估能力：

    Layer 1 — 完整流水线评估（run_full_evaluation）
        从 CSV 文件加载 HumanLabeledDataset → 执行评分 → 计算指标 → 写入注册表
        支持 RegistryUpdateBehavior 缓存策略（SKIP_IF_EXISTS / ALWAYS_UPDATE / NEVER_UPDATE）

    Layer 2 — 内存数据集评估（evaluate_with_dataset）
        接受内存中的 HumanLabeledDataset，仅计算指标，不写文件
        适合迭代调优场景

    Layer 3 — 快捷评估（evaluate_quick）
        从简单的 (text, label) 列表构建 OBJECTIVE 数据集并评估
        适合快速验证评分器行为

    指标类型：
    - ObjectiveScorerMetrics：accuracy / precision / recall / f1_score / accuracy_standard_error
    - HarmScorerMetrics：mean_absolute_error / mae_standard_error / t_statistic / p_value
      / krippendorff_alpha_combined / krippendorff_alpha_humans / krippendorff_alpha_model

    身份追踪：
    - 使用 ScorerIdentifier.eval_hash 作为评分器配置的唯一标识
    - 评估结果以 JSONL 格式持久化到 SCORER_EVALS_PATH
    - 通过 get_scorer_metrics() 按 eval_hash 查询已有评估结果

    一致性 & 鲁棒性：
    - evaluate_consistency：多次评分同一文本，计算一致率/标准差
    - evaluate_robustness：对扰动文本的评分稳定性
    """

    def __init__(self, chat_target: Any = None):
        """
        初始化评分器评估器

        Args:
            chat_target: 评审用 LLM Target（用于一致性/鲁棒性评估中的文本评分）
        """
        self.chat_target = chat_target

    # ------------------------------------------------------------------
    # Layer 1: 完整流水线评估（文件 → 评估 → 注册表）
    # ------------------------------------------------------------------

    async def run_full_evaluation(
        self,
        scorer: Scorer,
        dataset_files: ScorerEvalDatasetFiles,
        *,
        num_scorer_trials: int = 3,
        update_registry_behavior: RegistryUpdateBehavior = RegistryUpdateBehavior.SKIP_IF_EXISTS,
        max_concurrency: int = 10,
    ) -> Optional[ScorerMetrics]:
        """
        完整评估流水线（从 CSV 文件加载 → 评分 → 指标计算 → 注册表写入）

        使用 PyRIT 原生 ScorerEvaluator.run_evaluation_async() 方法：
        1. 通过 glob 模式匹配 CSV 文件
        2. 加载为 HumanLabeledDataset
        3. 执行 num_scorer_trials 次评分
        4. 计算评估指标（ObjectiveScorerMetrics 或 HarmScorerMetrics）
        5. 按 update_registry_behavior 策略写入 JSONL 注册表

        RegistryUpdateBehavior 策略：
        - SKIP_IF_EXISTS（默认）：检查注册表中是否已有相同 scorer_hash + dataset_version
          的结果，如有则直接返回缓存指标
        - ALWAYS_UPDATE：始终重新评估并覆盖已有结果
        - NEVER_UPDATE：始终重新评估但不写入注册表（调试用）

        Args:
            scorer: 要评估的 Scorer 实例
            dataset_files: ScorerEvalDatasetFiles 配置（glob 模式 + 结果文件名）
            num_scorer_trials: 每个响应的评分试验次数（默认 3，用于测量方差）
            update_registry_behavior: 注册表更新策略
            max_concurrency: 最大并发评分请求数

        Returns:
            ScorerMetrics 实例（ObjectiveScorerMetrics 或 HarmScorerMetrics），
            如果未找到匹配的 CSV 文件则返回 None
        """
        evaluator = ScorerEvaluator.from_scorer(scorer)
        return await evaluator.run_evaluation_async(
            dataset_files=dataset_files,
            num_scorer_trials=num_scorer_trials,
            update_registry_behavior=update_registry_behavior,
            max_concurrency=max_concurrency,
        )

    # ------------------------------------------------------------------
    # Layer 2: 内存数据集评估（纯计算，不写文件）
    # ------------------------------------------------------------------

    async def evaluate_with_dataset(
        self,
        scorer: Scorer,
        labeled_dataset: HumanLabeledDataset,
        *,
        num_scorer_trials: int = 3,
        max_concurrency: int = 10,
    ) -> ScorerMetrics:
        """
        基于内存 HumanLabeledDataset 的纯计算评估

        使用 PyRIT 原生 ScorerEvaluator.evaluate_dataset_async() 方法：
        1. 接受已构建的 HumanLabeledDataset（可从 CSV 加载或内存构建）
        2. 执行评分试验
        3. 计算指标
        4. 不写入注册表（纯计算，无副作用）

        适合迭代调优场景：修改评分器参数后快速重新评估，
        无需担心注册表缓存。

        Args:
            scorer: 要评估的 Scorer 实例
            labeled_dataset: 已构建的 HumanLabeledDataset
            num_scorer_trials: 评分试验次数
            max_concurrency: 最大并发数

        Returns:
            ScorerMetrics 实例
        """
        evaluator = ScorerEvaluator.from_scorer(scorer)
        return await evaluator.evaluate_dataset_async(
            labeled_dataset=labeled_dataset,
            num_scorer_trials=num_scorer_trials,
            max_concurrency=max_concurrency,
        )

    # ------------------------------------------------------------------
    # Layer 3: 快捷评估（从简单列表构建数据集）
    # ------------------------------------------------------------------

    async def evaluate_quick(
        self,
        scorer: Scorer,
        samples: List[Dict[str, Any]],
        *,
        metrics_type: Optional[MetricsType] = None,
        num_scorer_trials: int = 1,
    ) -> ScorerMetrics:
        """
        快捷评估（从简单的 (text, label) 列表构建数据集并评估）

        自动推断 MetricsType：
        - TrueFalseScorer 子类 → MetricsType.OBJECTIVE
        - 其他 Scorer → MetricsType.HARM

        samples 格式：
        - OBJECTIVE 类型：[{"text": "响应文本", "label": True/False, "objective": "攻击目标"}]
        - HARM 类型：[{"text": "响应文本", "label": 0.0-1.0, "harm_category": "hate_speech"}]

        注意：HARM 类型评估需要 harm_definition 和 harm_definition_version，
        因此对于 HARM 评估，建议使用 evaluate_with_dataset() 或 run_full_evaluation()。
        本方法仅支持 OBJECTIVE 类型的快捷评估。

        Args:
            scorer: 要评估的 Scorer 实例
            samples: 样本列表
            metrics_type: 强制指定指标类型（None 则自动推断）
            num_scorer_trials: 评分试验次数

        Returns:
            ScorerMetrics 实例
        """
        # 推断 metrics_type
        if metrics_type is None:
            metrics_type = (
                MetricsType.OBJECTIVE
                if isinstance(scorer, TrueFalseScorer)
                else MetricsType.HARM
            )

        # HARM 类型需要 harm_definition，快捷评估不支持
        if metrics_type == MetricsType.HARM:
            raise ValueError(
                "HARM 类型评估需要 harm_definition 和 harm_definition_version。"
                "请使用 evaluate_with_dataset() 或 run_full_evaluation() 代替。"
            )

        # 构建 HumanLabeledDataset
        entries: List[HumanLabeledEntry] = []
        for sample in samples:
            text = str(sample.get("text", ""))
            label = sample.get("label", False)
            objective = str(sample.get("objective", ""))

            # 创建 Message（模拟 assistant 响应）
            message = Message(
                message_pieces=[
                    MessagePiece(
                        role="assistant",
                        original_value=text,
                        conversation_id=str(uuid4()),
                    )
                ]
            )

            entry = ObjectiveHumanLabeledEntry(
                conversation=[message],
                human_scores=[bool(label)],
                objective=objective,
            )
            entries.append(entry)

        dataset = HumanLabeledDataset(
            name="quick_evaluation",
            entries=entries,
            metrics_type=metrics_type,
            version="1.0",
        )

        return await self.evaluate_with_dataset(
            scorer, dataset,
            num_scorer_trials=num_scorer_trials,
        )

    # ------------------------------------------------------------------
    # 指标查询（基于 eval_hash）
    # ------------------------------------------------------------------

    def get_scorer_metrics(self, scorer: Scorer) -> Optional[ScorerMetrics]:
        """
        从结果文件查找评分器的评估指标

        使用 scorer.get_scorer_metrics() 方法，基于 scorer 的 eval_hash
        从 JSONL 结果文件中查找已有评估结果。

        - TrueFalseScorer 子类 → 返回 ObjectiveScorerMetrics
        - FloatScaleScorer 子类 → 返回 HarmScorerMetrics

        Args:
            scorer: 要查询的 Scorer 实例

        Returns:
            ScorerMetrics 实例，如果未找到则返回 None
        """
        return scorer.get_scorer_metrics()

    def get_scorer_eval_hash(self, scorer: Scorer) -> Optional[str]:
        """
        获取评分器的 eval_hash（身份哈希）

        eval_hash 是评分器配置的唯一标识，用于：
        - 在注册表中区分不同配置的评分器
        - 避免重复评估
        - A/B 比较不同配置

        Args:
            scorer: 要查询的 Scorer 实例

        Returns:
            eval_hash 字符串，如果不可用则返回 None
        """
        identifier = scorer.get_identifier()
        return identifier.eval_hash

    def list_all_objective_metrics(
        self,
        result_file: Optional[Path] = None,
    ) -> List[ScorerMetricsWithIdentity[ObjectiveScorerMetrics]]:
        """
        列出注册表中所有 Objective 评分器的评估指标

        Args:
            result_file: JSONL 结果文件路径（None 使用默认路径）

        Returns:
            ScorerMetricsWithIdentity[ObjectiveScorerMetrics] 列表，
            包含评分器身份信息和指标
        """
        return get_all_objective_metrics(file_path=result_file)

    def list_all_harm_metrics(self) -> List[ScorerMetricsWithIdentity[HarmScorerMetrics]]:
        """
        列出注册表中所有 Harm 评分器的评估指标

        Returns:
            ScorerMetricsWithIdentity[HarmScorerMetrics] 列表
        """
        return get_all_harm_metrics()

    def find_metrics_by_eval_hash(
        self,
        scorer: Scorer,
        result_file: Optional[Path] = None,
    ) -> Optional[ObjectiveScorerMetrics]:
        """
        按 eval_hash 查找 Objective 评分器的评估指标

        Args:
            scorer: 要查询的 Scorer 实例
            result_file: JSONL 结果文件路径（None 使用默认路径）

        Returns:
            ObjectiveScorerMetrics 实例，如果未找到则返回 None
        """
        eval_hash = self.get_scorer_eval_hash(scorer)
        if eval_hash is None:
            return None

        if result_file is None:
            from pyrit.common.path import SCORER_EVALS_PATH
            result_file = SCORER_EVALS_PATH / "objective" / "objective_achieved_metrics.jsonl"

        return find_objective_metrics_by_eval_hash(
            eval_hash=eval_hash,
            file_path=result_file,
        )

    # ------------------------------------------------------------------
    # 一致性评估
    # ------------------------------------------------------------------

    async def evaluate_consistency(
        self,
        scorer: Scorer,
        consistency_dataset: List[str],
        num_repetitions: int = 3,
    ) -> Dict[str, float]:
        """
        评估评分器一致性（重复评分的一致性）

        多次评分同一文本，计算评分结果的一致性。

        - TrueFalseScorer：计算一致率（agreement_rate）
        - FloatScaleScorer：计算标准差（average_std_deviation）

        Args:
            scorer: 要评估的 Scorer 实例
            consistency_dataset: 一致性测试文本列表
            num_repetitions: 重复评分次数

        Returns:
            一致性指标字典：
            - {"agreement_rate": 0.9} (TrueFalseScorer)
            - {"average_std_deviation": 0.1} (FloatScaleScorer)
        """
        from collections import defaultdict
        from statistics import stdev

        results: Dict[str, list] = defaultdict(list)

        for text in consistency_dataset:
            for _ in range(num_repetitions):
                try:
                    message = Message(
                        message_pieces=[
                            MessagePiece(role="assistant", original_value=text)
                        ]
                    )
                    message.message_pieces[0].not_in_memory = True
                    scores = await scorer.score_async(message=message)
                    if scores:
                        results[text].append(scores[0].get_value())
                except Exception as e:
                    logger.debug(f"一致性评估失败: {text[:50]}... - {e}")

        agreements: List[float] = []
        std_devs: List[float] = []

        for values in results.values():
            if not values:
                continue
            if isinstance(values[0], bool):
                agreement = sum(v == values[0] for v in values) / len(values)
                agreements.append(agreement)
            elif isinstance(values[0], (int, float)):
                if len(values) > 1:
                    std_devs.append(stdev(values))

        metrics: Dict[str, float] = {}
        if agreements:
            metrics["agreement_rate"] = sum(agreements) / len(agreements)
        if std_devs:
            metrics["average_std_deviation"] = sum(std_devs) / len(std_devs)

        return metrics

    # ------------------------------------------------------------------
    # 鲁棒性评估
    # ------------------------------------------------------------------

    async def evaluate_robustness(
        self,
        scorer: Scorer,
        adversarial_dataset: List[Dict[str, Any]],
    ) -> Dict[str, float]:
        """
        评估评分器鲁棒性（对扰动的抵抗力）

        测试评分器在轻微扰动下（如大小写变化、空格等）的评分稳定性。

        Args:
            scorer: 要评估的 Scorer 实例
            adversarial_dataset: 对抗测试数据集
                [{"original": "原始文本", "perturbations": ["扰动后文本1", "扰动后文本2"]}]

        Returns:
            鲁棒性指标 {"robustness_score": 0.8}
        """
        if not adversarial_dataset:
            return {"robustness_score": 1.0}

        stability_scores: List[float] = []

        for item in adversarial_dataset:
            try:
                original_text = str(item.get("original", ""))

                # 原始文本评分
                orig_msg = Message(
                    message_pieces=[
                        MessagePiece(role="assistant", original_value=original_text)
                    ]
                )
                orig_msg.message_pieces[0].not_in_memory = True
                orig_scores = await scorer.score_async(message=orig_msg)
                if not orig_scores:
                    continue
                original_value = orig_scores[0].get_value()

                # 扰动文本评分
                perturbed_values: List[Any] = []
                for perturbed_text in item.get("perturbations", []):
                    pmsg = Message(
                        message_pieces=[
                            MessagePiece(role="assistant", original_value=str(perturbed_text))
                        ]
                    )
                    pmsg.message_pieces[0].not_in_memory = True
                    p_scores = await scorer.score_async(message=pmsg)
                    if p_scores:
                        perturbed_values.append(p_scores[0].get_value())

                # 计算稳定性
                if isinstance(original_value, bool) and perturbed_values:
                    agreement_rate = sum(
                        v == original_value for v in perturbed_values
                    ) / len(perturbed_values)
                    stability_scores.append(agreement_rate)
                elif perturbed_values and isinstance(original_value, (int, float)):
                    avg_relative_diff = sum(
                        abs(v - original_value) / max(abs(original_value), 1e-6)
                        for v in perturbed_values
                    ) / len(perturbed_values)
                    stability_scores.append(1.0 / (1.0 + avg_relative_diff))
            except Exception as e:
                logger.debug(f"鲁棒性评估失败: {str(item.get('original', ''))[:50]}... - {e}")
                continue

        robustness_score = (
            sum(stability_scores) / len(stability_scores)
            if stability_scores
            else 0.0
        )
        return {"robustness_score": robustness_score}

    # ------------------------------------------------------------------
    # 批量评估
    # ------------------------------------------------------------------

    async def evaluate_multiple_scorers(
        self,
        scorers: List[Scorer],
        dataset_files: ScorerEvalDatasetFiles,
        *,
        num_scorer_trials: int = 3,
        update_registry_behavior: RegistryUpdateBehavior = RegistryUpdateBehavior.SKIP_IF_EXISTS,
        max_concurrency: int = 10,
    ) -> Dict[str, Optional[ScorerMetrics]]:
        """
        批量评估多个评分器

        对每个评分器执行完整评估流水线，返回结果字典。

        Args:
            scorers: 要评估的 Scorer 实例列表
            dataset_files: 评估数据集配置
            num_scorer_trials: 评分试验次数
            update_registry_behavior: 注册表更新策略
            max_concurrency: 最大并发数

        Returns:
            {scorer_class_name: ScorerMetrics} 字典
        """
        results: Dict[str, Optional[ScorerMetrics]] = {}
        for scorer in scorers:
            scorer_name = scorer.__class__.__name__
            try:
                metrics = await self.run_full_evaluation(
                    scorer=scorer,
                    dataset_files=dataset_files,
                    num_scorer_trials=num_scorer_trials,
                    update_registry_behavior=update_registry_behavior,
                    max_concurrency=max_concurrency,
                )
                results[scorer_name] = metrics
                logger.info(f"评分器 {scorer_name} 评估完成")
            except Exception as e:
                logger.error(f"评分器 {scorer_name} 评估失败: {e}")
                results[scorer_name] = None
        return results

    # ------------------------------------------------------------------
    # A/B 比较
    # ------------------------------------------------------------------

    def compare_scorers(
        self,
        scorer_a: Scorer,
        scorer_b: Scorer,
    ) -> Dict[str, Any]:
        """
        比较两个评分器的评估指标

        从注册表中查找两个评分器的 eval_hash 对应的指标并进行比较。

        Args:
            scorer_a: 评分器 A
            scorer_b: 评分器 B

        Returns:
            比较结果字典：
            {
                "scorer_a": {"name": ..., "eval_hash": ..., "metrics": ...},
                "scorer_b": {"name": ..., "eval_hash": ..., "metrics": ...},
                "comparison": {"metric": (a_value, b_value, diff), ...},
            }
        """
        metrics_a = self.get_scorer_metrics(scorer_a)
        metrics_b = self.get_scorer_metrics(scorer_b)

        result: Dict[str, Any] = {
            "scorer_a": {
                "name": scorer_a.__class__.__name__,
                "eval_hash": self.get_scorer_eval_hash(scorer_a),
                "metrics": metrics_a,
            },
            "scorer_b": {
                "name": scorer_b.__class__.__name__,
                "eval_hash": self.get_scorer_eval_hash(scorer_b),
                "metrics": metrics_b,
            },
            "comparison": {},
        }

        # 比较 ObjectiveScorerMetrics
        if isinstance(metrics_a, ObjectiveScorerMetrics) and isinstance(metrics_b, ObjectiveScorerMetrics):
            for metric_name in ["accuracy", "precision", "recall", "f1_score"]:
                val_a = getattr(metrics_a, metric_name, None)
                val_b = getattr(metrics_b, metric_name, None)
                if val_a is not None and val_b is not None:
                    result["comparison"][metric_name] = (val_a, val_b, val_a - val_b)

        # 比较 HarmScorerMetrics
        elif isinstance(metrics_a, HarmScorerMetrics) and isinstance(metrics_b, HarmScorerMetrics):
            for metric_name in ["mean_absolute_error", "krippendorff_alpha_combined"]:
                val_a = getattr(metrics_a, metric_name, None)
                val_b = getattr(metrics_b, metric_name, None)
                if val_a is not None and val_b is not None:
                    result["comparison"][metric_name] = (val_a, val_b, val_a - val_b)

        return result


# ============================================================
# 工厂函数
# ============================================================

def create_scorer_evaluator(chat_target: Any = None) -> ScorerAccuracyEvaluator:
    """
    创建评分器评估器实例

    Args:
        chat_target: 评审用 LLM Target（用于一致性/鲁棒性评估）

    Returns:
        ScorerAccuracyEvaluator 实例
    """
    return ScorerAccuracyEvaluator(chat_target=chat_target)


async def evaluate_scorer_quick(
    scorer: Scorer,
    positive_samples: List[str],
    negative_samples: List[str],
    chat_target: Any = None,
    objective: str = "Does the response achieve the objective?",
) -> Dict[str, float]:
    """
    快速评估评分器性能（工厂函数）

    构建简单的 OBJECTIVE 数据集：positive_samples 应判定为 True，
    negative_samples 应判定为 False。

    Args:
        scorer: 要评估的 Scorer
        chat_target: 评审用 LLM Target（保留参数，评估器内部使用 scorer 自身的 target）
        positive_samples: 应判定为 True 的样本列表
        negative_samples: 应判定为 False 的样本列表
        objective: 评估目标描述

    Returns:
        性能指标字典 {"accuracy": ..., "precision": ..., "recall": ..., "f1_score": ...}
    """
    samples: List[Dict[str, Any]] = []
    for text in positive_samples:
        samples.append({"text": text, "label": True, "objective": objective})
    for text in negative_samples:
        samples.append({"text": text, "label": False, "objective": objective})

    evaluator = ScorerAccuracyEvaluator(chat_target=chat_target)
    metrics = await evaluator.evaluate_quick(scorer, samples)

    if isinstance(metrics, ObjectiveScorerMetrics):
        return {
            "accuracy": metrics.accuracy,
            "accuracy_standard_error": metrics.accuracy_standard_error,
            "precision": metrics.precision,
            "recall": metrics.recall,
            "f1_score": metrics.f1_score,
        }
    return {}


def format_metrics_report(metrics: ScorerMetrics) -> str:
    """
    格式化评估指标为可读报告

    Args:
        metrics: ScorerMetrics 实例

    Returns:
        格式化的指标报告字符串
    """
    lines = ["=== Scorer Evaluation Report ==="]
    lines.append(f"Dataset: {metrics.dataset_name} (v{metrics.dataset_version})")
    lines.append(f"Responses: {metrics.num_responses}")
    lines.append(f"Human Raters: {metrics.num_human_raters}")
    lines.append(f"Scorer Trials: {metrics.num_scorer_trials}")
    lines.append(f"Avg Score Time: {metrics.average_score_time_seconds:.3f}s")

    if isinstance(metrics, ObjectiveScorerMetrics):
        lines.append("")
        lines.append("--- Objective Metrics ---")
        lines.append(f"Accuracy:        {metrics.accuracy:.4f} +/- {metrics.accuracy_standard_error:.4f}")
        lines.append(f"Precision:       {metrics.precision:.4f}")
        lines.append(f"Recall:          {metrics.recall:.4f}")
        lines.append(f"F1 Score:        {metrics.f1_score:.4f}")
    elif isinstance(metrics, HarmScorerMetrics):
        lines.append("")
        lines.append("--- Harm Metrics ---")
        lines.append(f"MAE:             {metrics.mean_absolute_error:.4f} +/- {metrics.mae_standard_error:.4f}")
        lines.append(f"t-statistic:     {metrics.t_statistic:.4f}")
        lines.append(f"p-value:         {metrics.p_value:.4f}")
        lines.append(f"Krippendorff alpha (combined): {metrics.krippendorff_alpha_combined:.4f}")
        if metrics.krippendorff_alpha_humans is not None:
            lines.append(f"Krippendorff alpha (humans):  {metrics.krippendorff_alpha_humans:.4f}")
        if metrics.krippendorff_alpha_model is not None:
            lines.append(f"Krippendorff alpha (model):   {metrics.krippendorff_alpha_model:.4f}")
        if metrics.harm_category:
            lines.append(f"Harm Category:   {metrics.harm_category}")

    return "\n".join(lines)
