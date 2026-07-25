"""
Dataset Manager
===============

② 数据管理层 - CentralMemory 作为数据枢纽

对齐 PyRIT 1.0.0 五层架构：
  ① 数据准备层 → 内置数据集 / YAML 文件 / 编程创建种子
  ② 数据管理层 → CentralMemory (本模块)
  ③ 攻击准备层 → AttackSeedGroup (attack_preparator.py)
  ④ 攻击执行层 → AttackStrategy.execute_async()
  ⑤ 评估与追踪层 → Scorer + Memory 审计链

核心设计：
- 所有数据源（OWASP 本地 / 自定义 / PyRIT 远程）加载后统一存入 CentralMemory
- 从 CentralMemory 查询种子/种子组，支持多维度过滤
- 数据源可自由组合，非一次性打包

PyRIT 原生 API：
  memory.add_seed_datasets_to_memory_async(datasets, added_by)
  memory.get_seeds(harm_categories, data_types, added_by, ...)
  memory.get_seed_groups(harm_categories, dataset_name, added_by, ...)
"""

import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import yaml

from pyrit.memory import CentralMemory
from pyrit.models import SeedDataset, SeedGroup, Seed

logger = logging.getLogger(__name__)


# ============================================================
# 数据集管理器
# ============================================================


class DatasetManager:
    """
    CentralMemory 数据枢纽

    将多种数据源（OWASP 本地 / 自定义 / PyRIT 远程）统一加载到 CentralMemory，
    提供多维度的种子/种子组查询接口。

    用法示例：
        manager = DatasetManager()

        # ①→② 自由组合数据源
        await manager.load_owasp_datasets(frameworks=["llm", "agentic"])
        await manager.load_custom_datasets()
        await manager.load_remote_datasets(["harmbench", "jailbreakbench"])

        # ②→③ 从 CentralMemory 查询
        all_groups = manager.get_seed_groups()
        filtered = manager.get_seed_groups(harm_categories=["prompt_injection"])
        seeds = manager.get_seeds(dataset_name="owasp_llm01_prompt_injection")
    """

    def __init__(self, added_by: str = "pyrit_ai300"):
        """
        初始化数据集管理器

        Args:
            added_by: 数据添加者标识，用于 CentralMemory 审计追踪
        """
        self.memory = CentralMemory.get_memory_instance()
        self.added_by = added_by
        self._loaded_dataset_names: List[str] = []

    # ------------------------------------------------------------------
    # ①→② 数据源加载（存入 CentralMemory）
    # ------------------------------------------------------------------

    async def load_owasp_datasets(
        self,
        frameworks: Optional[List[str]] = None,
        owasp_ids: Optional[List[str]] = None,
        exclude_ids: Optional[List[str]] = None,
    ) -> List[SeedDataset]:
        """
        加载 OWASP 本地 YAML 数据集 → CentralMemory

        扫描 data/owasp/{framework}/ 目录，使用 PyRIT 原生
        SeedDataset.from_yaml_file() 加载每个 YAML 文件。

        Args:
            frameworks: 框架列表（如 ["llm", "agentic"]），默认全部
            owasp_ids: 指定加载的 OWASP ID（如 ["LLM01", "ASI05"]），None = 全部
            exclude_ids: 排除的 OWASP ID

        Returns:
            加载的 SeedDataset 列表
        """
        frameworks = frameworks or ["llm", "agentic"]
        project_root = Path(__file__).parent.parent.parent
        owasp_base = project_root / "data" / "owasp"

        owasp_ids_upper = {oid.upper() for oid in owasp_ids} if owasp_ids else None
        exclude_set = {eid.upper() for eid in (exclude_ids or [])}

        datasets: List[SeedDataset] = []

        for framework in frameworks:
            framework_dir = owasp_base / framework
            if not framework_dir.exists():
                continue

            # 加载 registry 获取 OWASP ID 映射
            registry = self._load_registry(framework_dir / "_registry.yaml")

            for category_dir in sorted(framework_dir.iterdir()):
                if not category_dir.is_dir():
                    continue

                meta = registry.get(category_dir.name, {})
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
                        datasets.append(dataset)
                        self._loaded_dataset_names.append(dataset.dataset_name or yaml_file.stem)
                    except Exception as e:
                        logger.warning(f"Failed to load OWASP dataset {yaml_file}: {e}")

        if datasets:
            await self.memory.add_seed_datasets_to_memory_async(
                datasets=datasets, added_by=self.added_by
            )
            logger.info(f"Loaded {len(datasets)} OWASP datasets into CentralMemory")

        return datasets

    async def load_custom_datasets(self, path: Optional[str] = None) -> List[SeedDataset]:
        """
        加载自定义 YAML 数据集 → CentralMemory

        Args:
            path: 自定义数据集目录，默认 data/custom/

        Returns:
            加载的 SeedDataset 列表
        """
        project_root = Path(__file__).parent.parent.parent
        custom_dir = Path(path) if path else project_root / "data" / "custom"
        if not custom_dir.exists():
            return []

        datasets: List[SeedDataset] = []
        for yaml_file in sorted(custom_dir.glob("*.yaml")):
            if yaml_file.name.startswith("_"):
                continue
            try:
                dataset = SeedDataset.from_yaml_file(yaml_file)
                datasets.append(dataset)
                self._loaded_dataset_names.append(dataset.dataset_name or yaml_file.stem)
            except Exception as e:
                logger.warning(f"Failed to load custom dataset {yaml_file}: {e}")

        if datasets:
            await self.memory.add_seed_datasets_to_memory_async(
                datasets=datasets, added_by=self.added_by
            )
            logger.info(f"Loaded {len(datasets)} custom datasets into CentralMemory")

        return datasets

    async def load_remote_datasets(
        self,
        dataset_names: Optional[List[str]] = None,
        cache: bool = True,
        max_concurrency: int = 3,
    ) -> List[SeedDataset]:
        """
        加载 PyRIT 远程数据集 → CentralMemory

        使用 PyRIT 1.0.0 原生 SeedDatasetProvider.fetch_datasets_async()
        加载 60+ 远程数据集（HarmBench, JailbreakBench 等）。

        Args:
            dataset_names: 指定数据集名称列表，None = 全部
            cache: 是否使用缓存
            max_concurrency: 最大并发加载数

        Returns:
            加载的 SeedDataset 列表
        """
        from pyrit.datasets import SeedDatasetProvider

        datasets = await SeedDatasetProvider.fetch_datasets_async(
            dataset_names=dataset_names,
            cache=cache,
            max_concurrency=max_concurrency,
        )

        if datasets:
            await self.memory.add_seed_datasets_to_memory_async(
                datasets=datasets, added_by=self.added_by
            )
            for ds in datasets:
                self._loaded_dataset_names.append(ds.dataset_name or ds.name or "unknown")
            logger.info(f"Loaded {len(datasets)} remote datasets into CentralMemory")

        return datasets

    async def load_datasets(
        self,
        owasp: bool = True,
        owasp_frameworks: Optional[List[str]] = None,
        owasp_ids: Optional[List[str]] = None,
        exclude_ids: Optional[List[str]] = None,
        custom: bool = False,
        remote: bool = False,
        remote_dataset_names: Optional[List[str]] = None,
    ) -> List[SeedDataset]:
        """
        统一加载入口 - 自由组合数据源

        各数据源独立选择，非一次性打包。加载后统一存入 CentralMemory。

        Args:
            owasp: 是否加载 OWASP 本地数据集
            owasp_frameworks: OWASP 框架列表
            owasp_ids: 指定 OWASP ID
            exclude_ids: 排除的 OWASP ID
            custom: 是否加载自定义数据集
            remote: 是否加载远程数据集
            remote_dataset_names: 远程数据集名称列表

        Returns:
            所有加载的 SeedDataset 列表
        """
        all_datasets: List[SeedDataset] = []

        if owasp:
            ds = await self.load_owasp_datasets(
                frameworks=owasp_frameworks,
                owasp_ids=owasp_ids,
                exclude_ids=exclude_ids,
            )
            all_datasets.extend(ds)

        if custom:
            ds = await self.load_custom_datasets()
            all_datasets.extend(ds)

        if remote:
            ds = await self.load_remote_datasets(dataset_names=remote_dataset_names)
            all_datasets.extend(ds)

        logger.info(
            f"DatasetManager: loaded {len(all_datasets)} datasets total | "
            f"owasp={owasp}, custom={custom}, remote={remote}"
        )
        return all_datasets

    # ------------------------------------------------------------------
    # ②→③ 查询接口（从 CentralMemory）
    # ------------------------------------------------------------------

    def get_seed_groups(
        self,
        *,
        harm_categories: Optional[Sequence[str]] = None,
        dataset_name: Optional[str] = None,
        dataset_name_pattern: Optional[str] = None,
        added_by: Optional[str] = None,
        authors: Optional[Sequence[str]] = None,
        groups: Optional[Sequence[str]] = None,
        source: Optional[str] = None,
        seed_type: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        group_length: Optional[Sequence[int]] = None,
    ) -> Sequence[SeedGroup]:
        """
        从 CentralMemory 查询种子组

        支持多维度过滤，返回按 prompt_group_id 分组的 SeedGroup 列表。

        Args:
            harm_categories: 危害类别过滤（如 ["prompt_injection", "illegal"]）
            dataset_name: 数据集名称精确匹配
            dataset_name_pattern: 数据集名称模式匹配（SQL LIKE 语法）
            added_by: 添加者过滤
            authors: 作者列表过滤
            groups: 组列表过滤
            source: 来源过滤
            seed_type: 种子类型过滤（"prompt", "objective", "simulated_conversation"）
            metadata: 元数据字典过滤
            group_length: 按组内种子数量过滤

        Returns:
            SeedGroup 列表
        """
        return self.memory.get_seed_groups(
            harm_categories=harm_categories,
            dataset_name=dataset_name,
            dataset_name_pattern=dataset_name_pattern,
            added_by=added_by or self.added_by,
            authors=authors,
            groups=groups,
            source=source,
            seed_type=seed_type,
            metadata=metadata,
            group_length=group_length,
        )

    def get_seeds(
        self,
        *,
        harm_categories: Optional[Sequence[str]] = None,
        dataset_name: Optional[str] = None,
        dataset_name_pattern: Optional[str] = None,
        added_by: Optional[str] = None,
        authors: Optional[Sequence[str]] = None,
        groups: Optional[Sequence[str]] = None,
        source: Optional[str] = None,
        seed_type: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Sequence[Seed]:
        """
        从 CentralMemory 查询种子（扁平列表）

        Args:
            参见 get_seed_groups 的参数

        Returns:
            Seed 列表
        """
        return self.memory.get_seeds(
            harm_categories=harm_categories,
            dataset_name=dataset_name,
            dataset_name_pattern=dataset_name_pattern,
            added_by=added_by or self.added_by,
            authors=authors,
            groups=groups,
            source=source,
            seed_type=seed_type,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    def get_dataset_names(self) -> Sequence[str]:
        """获取 CentralMemory 中所有数据集名称"""
        return self.memory.get_seed_dataset_names()

    @property
    def loaded_dataset_names(self) -> List[str]:
        """本次加载的数据集名称列表"""
        return list(self._loaded_dataset_names)

    def describe(self) -> str:
        """返回数据集管理状态描述"""
        lines = [
            f"DatasetManager (added_by={self.added_by}):",
            f"  已加载数据集: {len(self._loaded_dataset_names)} 个",
        ]
        for name in self._loaded_dataset_names[:10]:
            lines.append(f"    - {name}")
        if len(self._loaded_dataset_names) > 10:
            lines.append(f"    ... 还有 {len(self._loaded_dataset_names) - 10} 个")
        return "\n".join(lines)

    @staticmethod
    def _load_registry(registry_file: Path) -> Dict[str, Dict[str, Any]]:
        """加载 OWASP registry YAML"""
        if not registry_file.exists():
            return {}
        try:
            with open(registry_file, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            return data.get("categories", {})
        except Exception:
            return {}
