"""
Fuzzer Wrapper (Layer 1: Prompt Generators)
============================================

Fuzzer 变异生成器封装 — 对齐 pyrit.executor.promptgen.fuzzer

Layer 1: 种子生成层
"把 1 个 objective 扩展成 N 个攻击变体"

功能：对已有种子执行变异操作（扩展/缩短/改写/交叉/相似生成）
用途：从少量手写种子自动生成大量变体，增加攻击覆盖面
"""

import logging
from typing import Any, List, Optional

from pyrit.models import SeedPrompt

logger = logging.getLogger(__name__)


class FuzzerWrapper:
    """
    Fuzzer 变异生成器封装

    对齐 PyRIT: pyrit.executor.promptgen.fuzzer.FuzzerGenerator

    Fuzzer 是一种基于变异的种子扩展策略：
    - 输入：已有的攻击种子（SeedPrompt）
    - 输出：通过变异操作生成的种子变体
    - 变异操作：
      - Expand: 扩展种子内容
      - Shorten: 缩短种子内容
      - Rephrase: 改写种子表达
      - CrossOver: 交叉两个种子
      - Similar: 生成相似种子

    使用场景：
    - 从少量手写 YAML 种子自动生成大量变体
    - 增加 prompt injection 测试的覆盖面
    - 为 fuzzing 测试提供自动化种子扩展

    用法示例：
        wrapper = FuzzerWrapper(chat_target=judge_target)
        variants = await wrapper.mutate_async(
            seeds=existing_seeds,
            num_variants=10,
        )
    """

    # 变异操作类型映射
    MUTATION_TYPES = ["expand", "shorten", "rephrase", "similar"]

    def __init__(self, chat_target: Any = None):
        """
        Args:
            chat_target: 用于变异生成的 LLM Target（通常是 judge_target）
        """
        self._chat_target = chat_target
        self._generator = None

    def _ensure_generator(self):
        """延迟初始化 FuzzerGenerator"""
        if self._generator is None:
            if self._chat_target is None:
                raise ValueError("FuzzerWrapper 需要 chat_target 才能生成种子")
            from pyrit.executor.promptgen.fuzzer import FuzzerGenerator
            self._generator = FuzzerGenerator(chat_target=self._chat_target)
            logger.info("FuzzerGenerator 初始化完成")

    async def mutate_async(
        self,
        seeds: List[SeedPrompt],
        num_variants: int = 5,
        memory_labels: Optional[dict] = None,
    ) -> List[SeedPrompt]:
        """
        对已有种子执行变异生成

        Args:
            seeds: 原始种子列表
            num_variants: 每个种子生成的变体数量
            memory_labels: 可选的 memory 标签

        Returns:
            变异生成的 SeedPrompt 列表
        """
        self._ensure_generator()

        from pyrit.executor.promptgen.fuzzer import FuzzerContext
        from pyrit.executor.promptgen.fuzzer.fuzzer_converter_base import FuzzerConverter

        # 提取种子文本
        seed_texts = [s.value for s in seeds]

        # 创建变异上下文
        context = FuzzerContext(
            prompts=seed_texts,
            num_variants=num_variants,
            memory_labels=memory_labels or {},
        )

        result = await self._generator.execute_async(context=context)

        # 转换为 SeedPrompt 列表
        variants: List[SeedPrompt] = []
        if hasattr(result, "prompts") and result.prompts:
            for prompt_text in result.prompts:
                variants.append(SeedPrompt(
                    value=prompt_text if isinstance(prompt_text, str) else str(prompt_text),
                    dataset_name="fuzzer_generated",
                    harm_categories=["prompt_injection"],
                    metadata={
                        "source": "fuzzer",
                        "mutation_count": str(num_variants),
                    },
                ))

        logger.info(f"Fuzzer 从 {len(seeds)} 个种子生成 {len(variants)} 个变体")
        return variants

    async def crossover_async(
        self,
        seed_a: SeedPrompt,
        seed_b: SeedPrompt,
        memory_labels: Optional[dict] = None,
    ) -> List[SeedPrompt]:
        """
        交叉两个种子生成新变体

        Args:
            seed_a: 种子 A
            seed_b: 种子 B
            memory_labels: 可选的 memory 标签

        Returns:
            交叉生成的 SeedPrompt 列表
        """
        self._ensure_generator()

        from pyrit.executor.promptgen.fuzzer.fuzzer_crossover_converter import FuzzerCrossOverConverter
        from pyrit.prompt_normalizer import PromptNormalizer

        # 使用交叉 Converter
        normalizer = PromptNormalizer()
        crossover_converter = FuzzerCrossOverConverter(converter_target=self._chat_target)

        # 执行交叉
        result_text = await crossover_converter.convert_async(
            prompt=seed_a.value,
            labels=memory_labels or {},
        )

        variants: List[SeedPrompt] = []
        if result_text:
            variants.append(SeedPrompt(
                value=result_text.output_text if hasattr(result_text, "output_text") else str(result_text),
                dataset_name="fuzzer_crossover",
                harm_categories=["prompt_injection"],
                metadata={
                    "source": "fuzzer_crossover",
                    "parent_a": seed_a.value[:50],
                    "parent_b": seed_b.value[:50],
                },
            ))

        logger.info(f"Fuzzer 交叉生成 {len(variants)} 个变体")
        return variants
