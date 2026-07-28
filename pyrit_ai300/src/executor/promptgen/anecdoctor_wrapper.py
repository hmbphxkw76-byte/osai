"""
Anecdoctor Wrapper (Layer 1: Prompt Generators)
================================================

AnecDoctor 种子生成器封装 — 对齐 pyrit.executor.promptgen.anecdoctor

Layer 1: 种子生成层
"把 1 个 objective 扩展成 N 个攻击变体"

功能：从 ClaimsReview 格式文档自动生成攻击种子（虚假叙事/新闻文章/推文）
用途：在数据准备阶段自动扩展种子库，不依赖手写 YAML
"""

import logging
from typing import Any, List, Optional

from pyrit.models import SeedPrompt

logger = logging.getLogger(__name__)


class AnecdoctorWrapper:
    """
    AnecDoctor 种子生成器封装

    对齐 PyRIT: pyrit.executor.promptgen.anecdoctor.AnecdoctorGenerator

    AnecDoctor 是一种自动种子生成策略：
    - 输入：ClaimsReview 格式的评估数据（事实核查文档）
    - 输出：基于文档内容自动生成的攻击种子（SeedPrompt）
    - 支持：多种内容类型（推文、新闻文章、社交媒体帖子等）
    - 支持：多语言生成

    使用场景：
    - 从真实事实核查数据生成误导性内容种子
    - 扩展 YAML 手写种子库，增加攻击覆盖面
    - 为 misinformation (LLM09) 测试提供自动化种子

    用法示例：
        wrapper = AnecdoctorWrapper(chat_target=judge_target)
        seeds = await wrapper.generate_async(
            evaluation_data=["文档1内容", "文档2内容"],
            content_type="viral tweet",
            language="english",
        )
    """

    def __init__(self, chat_target: Any = None, processing_model: Any = None):
        """
        Args:
            chat_target: 用于生成种子的 LLM Target（通常是 judge_target）
            processing_model: 可选的处理模型（用于 AnecdoctorGenerator 的 processing_model 参数）
        """
        self._chat_target = chat_target
        self._processing_model = processing_model
        self._generator = None

    def _ensure_generator(self):
        """延迟初始化 AnecdoctorGenerator"""
        if self._generator is None:
            if self._chat_target is None:
                raise ValueError("AnecdoctorWrapper 需要 chat_target 才能生成种子")
            from pyrit.executor.promptgen.anecdoctor import AnecdoctorGenerator
            self._generator = AnecdoctorGenerator(
                objective_target=self._chat_target,
                processing_model=self._processing_model,
            )
            logger.info("AnecdoctorGenerator 初始化完成")

    async def generate_async(
        self,
        evaluation_data: List[str],
        content_type: str = "viral tweet",
        language: str = "english",
        memory_labels: Optional[dict] = None,
    ) -> List[SeedPrompt]:
        """
        从评估数据生成攻击种子

        Args:
            evaluation_data: ClaimsReview 格式的事实核查文档列表
            content_type: 生成内容类型（如 "viral tweet", "news article"）
            language: 生成语言（如 "english", "chinese"）
            memory_labels: 可选的 memory 标签

        Returns:
            生成的 SeedPrompt 列表
        """
        self._ensure_generator()

        from pyrit.executor.promptgen.anecdoctor import AnecdoctorContext

        context = AnecdoctorContext(
            evaluation_data=evaluation_data,
            content_type=content_type,
            language=language,
            memory_labels=memory_labels or {},
        )

        result = await self._generator.execute_async(context=context)

        # 转换为 SeedPrompt 列表
        seeds: List[SeedPrompt] = []
        if hasattr(result, "prompts") and result.prompts:
            for prompt_text in result.prompts:
                seeds.append(SeedPrompt(
                    value=prompt_text if isinstance(prompt_text, str) else str(prompt_text),
                    dataset_name="anecdoctor_generated",
                    harm_categories=["misinformation"],
                    metadata={
                        "source": "anecdoctor",
                        "content_type": content_type,
                        "language": language,
                    },
                ))

        logger.info(f"AnecDoctor 生成 {len(seeds)} 个种子 (content_type={content_type})")
        return seeds

    async def generate_to_memory_async(
        self,
        evaluation_data: List[str],
        content_type: str = "viral tweet",
        language: str = "english",
        memory_labels: Optional[dict] = None,
    ) -> int:
        """
        生成种子并存入 CentralMemory

        Returns:
            存入的种子数量
        """
        seeds = await self.generate_async(
            evaluation_data, content_type, language, memory_labels
        )

        if seeds:
            from pyrit.memory import CentralMemory
            memory = CentralMemory.get_memory_instance()
            for seed in seeds:
                # 通过 memory 持久化
                memory.add_seed_prompt_to_memory_async(
                    prompts=[seed],
                    added_by="anecdoctor_wrapper",
                )

        return len(seeds)
