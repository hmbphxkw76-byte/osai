"""
Project-Specific Remote Dataset Loaders
=======================================

自定义 _RemoteDatasetLoader 子类 — 为项目特定数据源创建远程加载器

对齐 PyRIT 1.0.0 远程数据集架构：
- 继承 _RemoteDatasetLoader（自动注册到 SeedDatasetProvider._registry）
- 实现 dataset_name 属性和 fetch_dataset_async() 方法
- 支持公共 URL / HuggingFace Hub / 自定义 API 端点
- 利用基类缓存机制（_fetch_from_url / _fetch_from_huggingface_async）

AI-300 考试知识点：
- PyRIT 1.0.0 支持 60+ 远程数据集（HarmBench, JailbreakBench 等）
- 项目可通过 _RemoteDatasetLoader 子类贡献特定数据集
- 自动注册：继承 _RemoteDatasetLoader 的子类自动加入 SeedDatasetProvider._registry
- fetch_datasets_async(dataset_names=["..."]) 可按名称加载

使用方式：
    from pyrit.datasets import SeedDatasetProvider

    # 自动注册后，可通过名称加载
    datasets = await SeedDatasetProvider.fetch_datasets_async(
        dataset_names=["ai300_owasp_custom", "ai300_agentic_threats"]
    )

    # 或直接实例化
    from src.payloads.remote_loaders import AI300OWASPCustomDataset
    loader = AI300OWASPCustomDataset()
    dataset = await loader.fetch_dataset_async()
"""

import logging
from typing import List

from typing_extensions import override

from pyrit.datasets.seed_datasets.remote.remote_dataset_loader import (
    _RemoteDatasetLoader,
)
from pyrit.models import (
    Modality,
    SeedDataset,
    SeedPrompt,
    SeedUnion,
)
from pyrit.models.harm_category import HarmCategory

logger = logging.getLogger(__name__)


# ============================================================
# 1. AI-300 OWASP 自定义远程数据集加载器
# ============================================================


class AI300OWASPCustomDataset(_RemoteDatasetLoader):
    """
    AI-300 OWASP 自定义远程数据集加载器

    从项目配置的远程 URL（如 GitHub raw / 内部 CDN）加载 OWASP 对齐的
    自定义攻击提示词数据集。

    数据格式：JSON 数组，每个元素包含：
    - value: 提示词文本
    - owasp_id: OWASP LLM/Agentic ID（如 "LLM01", "ASI01"）
    - technique: 攻击技术名称
    - attack_mode: "single_turn" / "multi_turn" / "converter_enhanced"
    - harm_categories: 危害类别列表
    - metadata: 额外元数据

    自动注册：继承 _RemoteDatasetLoader 后自动注册到
    SeedDatasetProvider._registry["AI300OWASPCustomDataset"]
    """

    # SeedDatasetMetadata 字段
    modalities: tuple[Modality, ...] = (Modality.TEXT,)
    size: str = "small"
    source_type: str = "remote"
    tags: set[str] = {"owasp", "ai300", "red_team", "prompt_injection"}

    _AUTHORS = ["pyrit_ai300"]
    _GROUPS = ["AI-300"]

    def __init__(
        self,
        *,
        source: str = "",
        cache: bool = True,
    ) -> None:
        """
        初始化 AI-300 OWASP 自定义数据集加载器

        Args:
            source: 远程数据源 URL（JSON 格式）。
                如果为空，尝试从配置文件读取。
            cache: 是否启用缓存
        """
        if not source:
            # 尝试从配置读取远程 URL
            try:
                from src.core.config_loader import get_config_loader
                config = get_config_loader()
                remote_config = config.get_payload_sources_config().get("remote_datasets", {})
                source = remote_config.get("ai300_owasp_custom_url", "")
            except Exception:
                source = ""

        if not source:
            # 使用示例数据源（GitHub raw URL 格式）
            source = "https://raw.githubusercontent.com/example/ai300-datasets/main/owasp_custom.json"

        self.source = source
        self._cache = cache

    @property
    @override
    def dataset_name(self) -> str:
        return "ai300_owasp_custom"

    @override
    async def fetch_dataset_async(self, *, cache: bool = True) -> SeedDataset:
        """
        从远程 URL 获取 AI-300 OWASP 自定义数据集

        Returns:
            SeedDataset: 包含 OWASP 对齐攻击提示词的种子数据集
        """
        try:
            logger.info(f"Loading AI-300 OWASP custom dataset from {self.source}")

            examples = self._fetch_from_url(
                source=self.source,
                source_type="public_url",
                cache=cache and self._cache,
            )

            seed_prompts: List[SeedUnion] = []
            for item in examples:
                value = item.get("value", "").strip()
                if not value:
                    continue

                owasp_id = item.get("owasp_id", "")
                technique = item.get("technique", "direct")
                attack_mode = item.get("attack_mode", "single_turn")
                harm_cats_raw = item.get("harm_categories", [])

                # 标准化危害类别
                standardized_cats = self._standardize_harm_categories(harm_cats_raw)

                metadata = {
                    "owasp_id": owasp_id,
                    "technique": technique,
                    "attack_mode": attack_mode,
                    **item.get("metadata", {}),
                }

                seed_prompt = SeedPrompt(
                    value=value,
                    data_type="text",
                    name="AI-300 OWASP Custom",
                    dataset_name=self.dataset_name,
                    harm_categories=standardized_cats,
                    description="AI-300 OWASP-aligned custom attack prompts",
                    authors=self._AUTHORS,
                    groups=self._GROUPS,
                    source=self.source,
                    metadata=metadata,
                )
                seed_prompts.append(seed_prompt)

            if not seed_prompts:
                logger.warning("AI-300 OWASP custom dataset is empty after processing")
                raise ValueError("SeedDataset cannot be empty.")

            logger.info(f"Successfully loaded {len(seed_prompts)} prompts from AI-300 OWASP custom dataset")

            return SeedDataset(
                seeds=seed_prompts,
                dataset_name=self.dataset_name,
                description="AI-300 OWASP-aligned custom attack prompts from remote source",
            )

        except Exception as e:
            logger.error(f"Failed to load AI-300 OWASP custom dataset: {e}")
            raise


# ============================================================
# 2. AI-300 Agentic 威胁数据集加载器
# ============================================================


class AI300AgenticThreatsDataset(_RemoteDatasetLoader):
    """
    AI-300 Agentic AI 威胁数据集加载器

    从 HuggingFace Hub 加载 Agentic AI 特定攻击场景数据集。
    覆盖 OWASP Agentic Security Issues (ASI01-ASI10) 威胁类别。

    数据格式：HuggingFace Dataset，包含：
    - prompt: 攻击提示词
    - threat_category: 威胁类别（goal_hijack, identity_abuse, code_execution 等）
    - owasp_asi_id: OWASP ASI ID
    - severity: 严重程度
    """

    # SeedDatasetMetadata 字段
    modalities: tuple[Modality, ...] = (Modality.TEXT,)
    size: str = "medium"
    source_type: str = "remote"
    tags: set[str] = {"agentic", "ai300", "owasp_asi", "agent_security"}

    _AUTHORS = ["pyrit_ai300"]
    _GROUPS = ["AI-300"]

    # 威胁类别 → HarmCategory 映射
    THREAT_CATEGORY_MAP: dict[str, list[HarmCategory]] = {
        "goal_hijack": [HarmCategory.DECEPTION],
        "identity_abuse": [HarmCategory.REPRESENTATIONAL],
        "tool_misuse": [HarmCategory.MALWARE],
        "code_execution": [HarmCategory.MALWARE],
        "memory_attack": [HarmCategory.PPI],
        "agent_comm": [HarmCategory.DECEPTION],
        "trust_exploit": [HarmCategory.DECEPTION],
        "rogue_agent": [HarmCategory.MALWARE],
    }

    def __init__(
        self,
        *,
        source: str = "ai300/agentic-threats",
        split: str = "train",
        cache: bool = True,
        token: str | None = None,
    ) -> None:
        """
        初始化 Agentic 威胁数据集加载器

        Args:
            source: HuggingFace 数据集标识符
            split: 数据集分割
            cache: 是否启用缓存
            token: HuggingFace 认证 token（用于私有数据集）
        """
        self.source = source
        self.split = split
        self._cache = cache
        self._token = token

    @property
    @override
    def dataset_name(self) -> str:
        return "ai300_agentic_threats"

    @override
    async def fetch_dataset_async(self, *, cache: bool = True) -> SeedDataset:
        """
        从 HuggingFace Hub 获取 Agentic 威胁数据集

        Returns:
            SeedDataset: 包含 Agentic AI 威胁场景的种子数据集
        """
        try:
            logger.info(f"Loading AI-300 Agentic threats dataset from HuggingFace: {self.source}")

            data = await self._fetch_from_huggingface_async(
                dataset_name=self.source,
                split=self.split,
                cache=cache and self._cache,
                token=self._token,
            )

            seed_prompts: List[SeedUnion] = []

            for item in data:
                prompt = item.get("prompt", "").strip() if hasattr(item, "get") else getattr(item, "prompt", "").strip()
                if not prompt:
                    continue

                threat_category = item.get("threat_category", "unknown") if hasattr(item, "get") else getattr(item, "threat_category", "unknown")
                owasp_asi_id = item.get("owasp_asi_id", "") if hasattr(item, "get") else getattr(item, "owasp_asi_id", "")
                severity = item.get("severity", "medium") if hasattr(item, "get") else getattr(item, "severity", "medium")

                # 映射到 HarmCategory
                harm_cats = self.THREAT_CATEGORY_MAP.get(threat_category, [HarmCategory.DECEPTION])
                standardized_cats = [c.name for c in harm_cats]

                metadata = {
                    "owasp_id": owasp_asi_id,
                    "technique": threat_category,
                    "attack_mode": "multi_turn" if "multi" in threat_category else "single_turn",
                    "severity": severity,
                    "threat_category": threat_category,
                }

                seed_prompt = SeedPrompt(
                    value=prompt,
                    data_type="text",
                    name="AI-300 Agentic Threat",
                    dataset_name=self.dataset_name,
                    harm_categories=standardized_cats,
                    description="AI-300 Agentic AI threat scenarios aligned with OWASP ASI",
                    authors=self._AUTHORS,
                    groups=self._GROUPS,
                    source=self.source,
                    metadata=metadata,
                )
                seed_prompts.append(seed_prompt)

            if not seed_prompts:
                logger.warning("AI-300 Agentic threats dataset is empty after processing")
                raise ValueError("SeedDataset cannot be empty.")

            logger.info(f"Successfully loaded {len(seed_prompts)} agentic threat prompts")

            return SeedDataset(
                seeds=seed_prompts,
                dataset_name=self.dataset_name,
                description="AI-300 Agentic AI threat scenarios from HuggingFace",
            )

        except Exception as e:
            logger.error(f"Failed to load AI-300 Agentic threats dataset: {e}")
            raise


# ============================================================
# 3. AI-300 考试模拟数据集加载器
# ============================================================


class AI300ExamSimDataset(_RemoteDatasetLoader):
    """
    AI-300 考试模拟数据集加载器

    从公共 URL 加载 AI-300 考试模拟题库，包含：
    - 单轮直接攻击场景
    - 多轮渐进攻击场景
    - Agent 安全测试场景
    - RAG 注入测试场景

    用于考前模拟练习和自测。
    """

    # SeedDatasetMetadata 字段
    modalities: tuple[Modality, ...] = (Modality.TEXT,)
    size: str = "small"
    source_type: str = "remote"
    tags: set[str] = {"ai300", "exam", "practice", "simulation"}

    _AUTHORS = ["pyrit_ai300"]
    _GROUPS = ["AI-300"]

    def __init__(
        self,
        *,
        source: str = "",
        cache: bool = True,
    ) -> None:
        if not source:
            source = "https://raw.githubusercontent.com/example/ai300-datasets/main/exam_simulation.json"
        self.source = source
        self._cache = cache

    @property
    @override
    def dataset_name(self) -> str:
        return "ai300_exam_sim"

    @override
    async def fetch_dataset_async(self, *, cache: bool = True) -> SeedDataset:
        """
        从远程 URL 获取 AI-300 考试模拟数据集
        """
        try:
            logger.info(f"Loading AI-300 exam simulation dataset from {self.source}")

            examples = self._fetch_from_url(
                source=self.source,
                source_type="public_url",
                cache=cache and self._cache,
            )

            seed_prompts: List[SeedUnion] = []
            for item in examples:
                value = item.get("value", "").strip()
                if not value:
                    continue

                metadata = {
                    "exam_topic": item.get("exam_topic", "general"),
                    "difficulty": item.get("difficulty", "medium"),
                    "attack_mode": item.get("attack_mode", "single_turn"),
                    "technique": item.get("technique", "direct"),
                    **item.get("metadata", {}),
                }

                seed_prompt = SeedPrompt(
                    value=value,
                    data_type="text",
                    name="AI-300 Exam Sim",
                    dataset_name=self.dataset_name,
                    harm_categories=item.get("harm_categories", []),
                    description="AI-300 exam simulation practice prompts",
                    authors=self._AUTHORS,
                    groups=self._GROUPS,
                    source=self.source,
                    metadata=metadata,
                )
                seed_prompts.append(seed_prompt)

            if not seed_prompts:
                raise ValueError("SeedDataset cannot be empty.")

            logger.info(f"Successfully loaded {len(seed_prompts)} exam simulation prompts")

            return SeedDataset(
                seeds=seed_prompts,
                dataset_name=self.dataset_name,
                description="AI-300 exam simulation practice dataset",
            )

        except Exception as e:
            logger.error(f"Failed to load AI-300 exam simulation dataset: {e}")
            raise


# ============================================================
# 工具函数：获取所有项目自定义加载器名称
# ============================================================


def get_project_dataset_names() -> List[str]:
    """
    获取所有项目自定义远程数据集加载器名称

    Returns:
        数据集名称列表
    """
    return [
        "ai300_owasp_custom",
        "ai300_agentic_threats",
        "ai300_exam_sim",
    ]


def is_project_dataset_registered(name: str) -> bool:
    """
    检查项目自定义数据集是否已注册到 SeedDatasetProvider

    Args:
        name: 数据集名称

    Returns:
        是否已注册
    """
    from pyrit.datasets import SeedDatasetProvider
    return name in SeedDatasetProvider._registry or any(
        cls().dataset_name == name
        for cls in SeedDatasetProvider._registry.values()
    )
