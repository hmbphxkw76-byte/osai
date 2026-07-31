"""
Payload Source Loader  [DEPRECATED]
=====================================

① 数据准备层 - 从多种数据源加载 SeedDataset

.. deprecated::
    本模块提供 **Mode B**（兼容路径），将原生 ``SeedDataset`` 转换为自定义
    ``PromptBatch``/``PromptItem`` 中间模型，增加了一层不必要的适配。

    **推荐使用 Mode A**（原生路径）::

        from src.payloads import DatasetManager
        dm = DatasetManager()
        await dm.load_datasets(owasp=True, academic=True)
        groups = dm.get_seed_groups()

    Mode B 保留仅为向后兼容，所有新代码应使用 ``DatasetManager``。

对齐 PyRIT 1.0.0 五层架构：
  ① 数据准备层 → 本模块 (source_loader.py)  [DEPRECATED — 使用 DatasetManager]
  ② 数据管理层 → DatasetManager / CentralMemory (dataset_manager.py)
  ③ 攻击准备层 → AttackPreparator (attack_preparator.py)
  ④ 攻击执行层 → AttackStrategy.execute_async()
  ⑤ 评估与追踪层 → Scorer + Memory

数据源（自由组合，非一次性打包）：
  - OWASP 本地 YAML → data/owasp/llm/ + data/owasp/agentic/
  - 自定义 YAML    → data/custom/
  - PyRIT 远程数据集 → 60+ Provider (HarmBench, JailbreakBench 等)
"""

import asyncio
import logging
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from src.payloads.models import (
    PromptBatch,
)

logger = logging.getLogger(__name__)


_DEPRECATION_MSG = (
    "PayloadSourceLoader returns PromptBatch (bypassing CentralMemory). "
    "Use DatasetManager.load_datasets() for PyRIT-native data management. "
    "See 'database as source of truth' best practice in PyRIT docs."
)


# ============================================================
# 数据源加载器（同步 - 返回 PromptBatch，兼容现有管道） [DEPRECATED]
# ============================================================


class PayloadSourceLoader:
    """数据源加载器 - 从多目录结构批量加载提示词 [DEPRECATED]

    .. deprecated::
        使用 ``DatasetManager`` 替代。本类将原生 ``SeedDataset`` 转换为
        自定义 ``PromptBatch``/``PromptItem``，绕过了 CentralMemory。
    """

    def __init__(self, base_data_dir: Optional[str] = None):
        warnings.warn(_DEPRECATION_MSG, DeprecationWarning, stacklevel=2)
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

            # 同时支持 .prompt 扩展名（PyRIT 官方约定）
            for prompt_file in sorted(category_dir.glob("*.prompt")):
                if prompt_file.name.startswith("_"):
                    continue

                try:
                    dataset = SeedDataset.from_yaml_file(prompt_file)
                except Exception as e:
                    logger.warning(f"Failed to load SeedDataset from {prompt_file}: {e}")
                    continue

                owasp_id_override = meta.get("owasp_id")
                file_batches = SeedPromptAdapter.dataset_to_batches(
                    dataset, owasp_id=owasp_id_override
                )

                for batch in file_batches:
                    if not batch.owasp_id:
                        batch.owasp_id = owasp_id_override
                    if not batch.source_id:
                        batch.source_id = dataset.dataset_name or prompt_file.stem
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

        # 同时支持 .prompt 扩展名（PyRIT 官方约定）
        for prompt_file in sorted(custom_dir.glob("*.prompt")):
            if prompt_file.name.startswith("_"):
                continue
            try:
                dataset = SeedDataset.from_yaml_file(prompt_file)
                file_batches = SeedPromptAdapter.dataset_to_batches(dataset)
                for batch in file_batches:
                    if not batch.source_id:
                        batch.source_id = dataset.dataset_name or prompt_file.stem
                    if batch.prompts:
                        batches.append(batch)
            except Exception as e:
                logger.warning(f"Failed to load custom payload {prompt_file}: {e}")

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
    """加载所有数据源提示词（工厂函数）  [DEPRECATED]

    .. deprecated::
        此函数返回 ``PromptBatch``（绕过 CentralMemory），不符合 PyRIT 1.0.0
        "database as source of truth" 最佳实践。

        **迁移对照表**::

            旧 API (Mode B)                          → 新 API (Mode A)
            ─────────────────────────────────────────────────────────────
            load_payloads()                          → DatasetManager.load_datasets()
            load_payloads_async()                    → DatasetManager.load_datasets()
            load_all_payloads_async()                → DatasetManager.load_datasets()
            load_remote_datasets_async()             → DatasetManager.load_remote_datasets()
            PayloadSourceLoader.load_from_owasp()    → DatasetManager.load_owasp_datasets()
            PayloadSourceLoader.load_from_custom()   → DatasetManager.load_custom_datasets()
            SeedPromptAdapter.dataset_to_batches()   → DatasetManager.get_seed_groups()
            PromptBatch / PromptItem                 → SeedGroup / Seed
            plan_attacks(prompt_batches)             → AttackPreparator.prepare_batch(seed_groups)

        推荐使用 ``DatasetManager.load_datasets()`` 替代，它将数据加载到
        CentralMemory 中，支持多维查询和审计追踪。

    保留此函数仅为向后兼容。如需同步到 CentralMemory，
    请使用 ``sync_batches_to_memory_async()``。
    """
    warnings.warn(
        "load_payloads() returns PromptBatch bypassing CentralMemory. "
        "Use DatasetManager.load_datasets() for PyRIT-native data management. "
        "See 'database as source of truth' best practice in PyRIT docs.",
        DeprecationWarning,
        stacklevel=2,
    )

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
    """异步加载所有数据源提示词（工厂函数）

    .. deprecated::
        使用 ``DatasetManager.load_datasets()`` 替代以获得 CentralMemory 集成。
    """
    return await asyncio.to_thread(
        load_payloads,
        owasp_ids=owasp_ids,
        exclude_ids=exclude_ids,
        include_custom=include_custom,
        frameworks=frameworks,
    )


async def sync_batches_to_memory_async(
    batches: List[PromptBatch],
    *,
    added_by: str = "pyrit_ai300",
) -> None:
    """
    将 PromptBatch 数据同步到 CentralMemory（兼容管道桥接）

    PyRIT 1.0.0 最佳实践要求 "database as source of truth"。
    兼容管道（load_payloads_async → PromptBatch）绕过了 CentralMemory，
    此函数提供桥接：将已加载的 PromptBatch 转换为 SeedDataset 并存入 CentralMemory。

    使用场景：
    - 现有管道使用 load_payloads_async() 加载数据
    - 后续需要通过 CentralMemory 查询/审计这些数据
    - 混合使用兼容管道和原生管道时统一数据源

    Args:
        batches: PromptBatch 列表
        added_by: 数据添加者标识
    """
    from pyrit.memory import CentralMemory
    from src.payloads.seed_adapter import SeedPromptAdapter

    memory = CentralMemory.get_memory_instance()
    datasets: list = []

    for batch in batches:
        dataset = SeedPromptAdapter.items_to_dataset(
            items=batch.prompts,
            dataset_name=batch.source_id or "compat_pipeline",
            description=batch.description or "",
            harm_categories=[],
        )
        datasets.append(dataset)

    if datasets:
        await memory.add_seed_datasets_to_memory_async(
            datasets=datasets, added_by=added_by
        )
        logger.info(
            f"Synced {len(datasets)} datasets from compat pipeline to CentralMemory"
        )


async def load_remote_datasets_async(
    dataset_names: Optional[List[str]] = None,
    max_concurrency: int = 3,
    cache: bool = True,
) -> List[PromptBatch]:
    """
    异步加载 PyRIT 远程数据集并转换为 PromptBatch  [DEPRECATED]

    .. deprecated::
        使用 ``DatasetManager.load_remote_datasets()`` 替代以获得原生
        CentralMemory 集成（返回原生 ``SeedDataset``，无需 ``PromptBatch`` 适配）。

    利用 PyRIT 1.0.0 的 SeedDatasetProvider.fetch_datasets_async()
    加载 60+ 远程数据集（HarmBench, JailbreakBench 等），
    并通过 SeedPromptAdapter 转换为项目 PromptBatch 格式。
    """
    warnings.warn(
        "load_remote_datasets_async() returns PromptBatch. "
        "Use DatasetManager.load_remote_datasets() for native CentralMemory integration.",
        DeprecationWarning,
        stacklevel=2,
    )

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
    sync_to_memory: bool = False,
) -> List[PromptBatch]:
    """
    异步加载入口 - 自由组合数据源（兼容管道）

    .. deprecated::
        推荐使用 ``DatasetManager.load_datasets()`` 替代以获得原生 CentralMemory 集成。
        设置 ``sync_to_memory=True`` 可将数据同步到 CentralMemory（桥接模式）。

    各数据源独立选择，非一次性打包。

    Args:
        owasp_ids: 指定加载的 OWASP ID，None = 全部
        exclude_ids: 排除的 OWASP ID
        include_custom: 是否包含自定义载荷
        include_remote: 是否包含 PyRIT 远程数据集
        remote_dataset_names: 远程数据集名称列表
        frameworks: 框架列表
        sync_to_memory: 是否同步到 CentralMemory（桥接模式，对齐 "database as source of truth"）

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

    # 桥接模式：同步到 CentralMemory
    if sync_to_memory and all_batches:
        await sync_batches_to_memory_async(all_batches)

    return all_batches
