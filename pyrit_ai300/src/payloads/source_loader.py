"""
Payload Source Loader
=====================

① 数据准备层 - 从多种数据源加载 SeedDataset

对齐 PyRIT 1.0.0 五层架构：
  ① 数据准备层 → 本模块 (source_loader.py)
  ② 数据管理层 → DatasetManager / CentralMemory (dataset_manager.py)
  ③ 攻击准备层 → AttackPreparator (attack_preparator.py)
  ④ 攻击执行层 → AttackStrategy.execute_async()
  ⑤ 评估与追踪层 → Scorer + Memory

本模块提供两种使用模式：
  模式 A（推荐）: DatasetManager → CentralMemory → get_seed_groups() → AttackPreparator
  模式 B（兼容）: load_payloads_async() → PromptBatch → plan_attacks()

数据源（自由组合，非一次性打包）：
  - OWASP 本地 YAML → data/owasp/llm/ + data/owasp/agentic/
  - 自定义 YAML    → data/custom/
  - PyRIT 远程数据集 → 60+ Provider (HarmBench, JailbreakBench 等)
"""

import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

from src.payloads.models import (
    AttackMode,
    PromptBatch,
    PromptItem,
)


# ============================================================
# 数据源加载器（同步 - 返回 PromptBatch，兼容现有管道）
# ============================================================


class PayloadSourceLoader:
    """数据源加载器 - 从多目录结构批量加载提示词"""

    def __init__(self, base_data_dir: Optional[str] = None):
        if base_data_dir is None:
            project_root = Path(__file__).parent.parent.parent
            base_data_dir = str(project_root / "data")

        self.base_data_dir = Path(base_data_dir)
        self._registry_cache: Dict[str, Dict[str, Any]] = {}

    def load_from_owasp_directory(
        self,
        framework: str = "llm",
        owasp_ids: Optional[List[str]] = None,
        exclude_ids: Optional[List[str]] = None,
    ) -> List[PromptBatch]:
        """从 OWASP 目录结构加载提示词批次"""
        from pyrit.models import SeedDataset
        from src.payloads.seed_adapter import SeedPromptAdapter

        owasp_dir = self.base_data_dir / "owasp" / framework
        if not owasp_dir.exists():
            return []

        registry_categories = self._load_registry(framework)
        owasp_ids_upper = {oid.upper() for oid in owasp_ids} if owasp_ids else None
        exclude_set = {eid.upper() for eid in (exclude_ids or [])}
        batches: List[PromptBatch] = []

        for category_dir in sorted(owasp_dir.iterdir()):
            if not category_dir.is_dir():
                continue

            category_name = category_dir.name
            meta = registry_categories.get(category_name, {})
            if not meta:
                continue

            owasp_id = meta.get("owasp_id", "")
            if owasp_ids_upper and owasp_id.upper() not in owasp_ids_upper:
                continue
            if owasp_id.upper() in exclude_set:
                continue

            for yaml_file in sorted(category_dir.glob("*.yaml")):
                if yaml_file.name.startswith("_"):
                    continue

                try:
                    dataset = SeedDataset.from_yaml_file(yaml_file)
                except Exception as e:
                    logger.warning(f"Failed to load SeedDataset from {yaml_file}: {e}")
                    continue

                owasp_id_override = meta.get("owasp_id")
                file_batches = SeedPromptAdapter.dataset_to_batches(
                    dataset, owasp_id=owasp_id_override
                )

                for batch in file_batches:
                    if not batch.owasp_id:
                        batch.owasp_id = owasp_id_override
                    if not batch.source_id:
                        batch.source_id = dataset.dataset_name or yaml_file.stem
                    if not batch.description:
                        batch.description = dataset.description or ""
                    if batch.prompts:
                        batches.append(batch)

        return batches

    def load_from_custom(self, path: Optional[str] = None) -> List[PromptBatch]:
        """加载自定义载荷文件"""
        from pyrit.models import SeedDataset
        from src.payloads.seed_adapter import SeedPromptAdapter

        custom_dir = Path(path) if path else self.base_data_dir / "custom"
        if not custom_dir.exists():
            return []

        batches: List[PromptBatch] = []
        for yaml_file in sorted(custom_dir.glob("*.yaml")):
            if yaml_file.name.startswith("_"):
                continue
            try:
                dataset = SeedDataset.from_yaml_file(yaml_file)
                file_batches = SeedPromptAdapter.dataset_to_batches(dataset)
                for batch in file_batches:
                    if not batch.source_id:
                        batch.source_id = dataset.dataset_name or yaml_file.stem
                    if batch.prompts:
                        batches.append(batch)
            except Exception as e:
                logger.warning(f"Failed to load custom payload {yaml_file}: {e}")

        return batches

    def _load_registry(self, framework: str) -> Dict[str, Dict[str, Any]]:
        """从 _registry.yaml 加载该框架所有分类的元数据"""
        if framework in self._registry_cache:
            return self._registry_cache[framework]

        registry_file = self.base_data_dir / "owasp" / framework / "_registry.yaml"
        if not registry_file.exists():
            self._registry_cache[framework] = {}
            return {}

        with open(registry_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        categories = data.get("categories", {})
        self._registry_cache[framework] = categories
        return categories


# ============================================================
# 工厂函数 - 兼容现有管道（返回 PromptBatch）
# ============================================================


def load_payloads(
    owasp_ids: Optional[List[str]] = None,
    exclude_ids: Optional[List[str]] = None,
    include_custom: bool = True,
    frameworks: Optional[List[str]] = None,
) -> List[PromptBatch]:
    """加载所有数据源提示词（工厂函数）"""
    from src.core.config_loader import get_config_loader

    loader = PayloadSourceLoader()

    if frameworks is None:
        config_loader = get_config_loader()
        owasp_config = config_loader.get_owasp_source_config()
        frameworks = owasp_config.get("frameworks", ["llm"])

    batches: List[PromptBatch] = []
    for framework in frameworks:
        batches.extend(loader.load_from_owasp_directory(
            framework=framework,
            owasp_ids=owasp_ids,
            exclude_ids=exclude_ids,
        ))

    if include_custom:
        batches.extend(loader.load_from_custom())

    return batches


async def load_payloads_async(
    owasp_ids: Optional[List[str]] = None,
    exclude_ids: Optional[List[str]] = None,
    include_custom: bool = True,
    frameworks: Optional[List[str]] = None,
) -> List[PromptBatch]:
    """异步加载所有数据源提示词（工厂函数）"""
    return await asyncio.to_thread(
        load_payloads,
        owasp_ids=owasp_ids,
        exclude_ids=exclude_ids,
        include_custom=include_custom,
        frameworks=frameworks,
    )


async def load_remote_datasets_async(
    dataset_names: Optional[List[str]] = None,
    max_concurrency: int = 3,
    cache: bool = True,
) -> List[PromptBatch]:
    """
    异步加载 PyRIT 远程数据集并转换为 PromptBatch

    利用 PyRIT 1.0.0 的 SeedDatasetProvider.fetch_datasets_async()
    加载 60+ 远程数据集（HarmBench, JailbreakBench 等），
    并通过 SeedPromptAdapter 转换为项目 PromptBatch 格式。
    """
    from pyrit.datasets import SeedDatasetProvider
    from src.payloads.seed_adapter import SeedPromptAdapter

    datasets = await SeedDatasetProvider.fetch_datasets_async(
        dataset_names=dataset_names,
        cache=cache,
        max_concurrency=max_concurrency,
    )

    return SeedPromptAdapter.remote_datasets_to_batches(datasets)


async def load_all_payloads_async(
    owasp_ids: Optional[List[str]] = None,
    exclude_ids: Optional[List[str]] = None,
    include_custom: bool = True,
    include_remote: bool = False,
    remote_dataset_names: Optional[List[str]] = None,
    frameworks: Optional[List[str]] = None,
) -> List[PromptBatch]:
    """
    异步加载入口 - 自由组合数据源（兼容现有管道）

    各数据源独立选择，非一次性打包。

    Args:
        owasp_ids: 指定加载的 OWASP ID，None = 全部
        exclude_ids: 排除的 OWASP ID
        include_custom: 是否包含自定义载荷
        include_remote: 是否包含 PyRIT 远程数据集
        remote_dataset_names: 远程数据集名称列表
        frameworks: 框架列表

    Returns:
        PromptBatch 列表
    """
    tasks = [
        load_payloads_async(
            owasp_ids=owasp_ids,
            exclude_ids=exclude_ids,
            include_custom=include_custom,
            frameworks=frameworks,
        )
    ]

    if include_remote:
        tasks.append(load_remote_datasets_async(
            dataset_names=remote_dataset_names,
        ))

    results = await asyncio.gather(*tasks)
    all_batches: List[PromptBatch] = []
    for batches in results:
        all_batches.extend(batches)

    return all_batches
