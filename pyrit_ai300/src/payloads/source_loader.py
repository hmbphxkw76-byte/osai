"""
Payload Source Loader
=====================

本模块负责从 OWASP 目录结构批量加载提示词数据源。

支持从 data/owasp/llm/llm01-llm10/ 和 data/owasp/agentic/asi01-asi10/ 目录结构加载 YAML 提示词文件。

架构改进（三层分离）：
1. 数据层 YAML 只定义提示词内容（id, objective, turns, steps[].objective, metadata）
   不包含策略决策（attack_mode, converter_chains, attack_technique）
2. 元数据统一从 _registry.yaml 加载（不再逐目录维护 _meta.yaml）
3. 攻击技术、转换器链、评分器等策略由 PayloadStrategyMatcher 自动匹配
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from src.payloads.models import (
    AttackMode,
    PromptBatch,
    PromptItem,
    SequentialStep,
)


# ============================================================
# 数据源加载器
# ============================================================


class PayloadSourceLoader:
    """数据源加载器 - 从多目录结构批量加载提示词"""

    def __init__(self, base_data_dir: Optional[str] = None):
        """
        初始化数据源加载器

        Args:
            base_data_dir: 数据根目录，默认为项目根目录的 data/ 子目录
        """
        if base_data_dir is None:
            project_root = Path(__file__).parent.parent.parent
            base_data_dir = str(project_root / "data")

        self.base_data_dir = Path(base_data_dir)
        # 缓存：framework → registry categories 字典
        self._registry_cache: Dict[str, Dict[str, Any]] = {}

    def load_from_owasp_directory(
        self,
        framework: str = "llm",
        owasp_ids: Optional[List[str]] = None,
        exclude_ids: Optional[List[str]] = None,
    ) -> List[PromptBatch]:
        """
        从 OWASP 目录结构加载提示词批次

        Args:
            framework: OWASP 框架，"llm" 或 "agentic"
            owasp_ids: 指定加载的 OWASP ID 列表（如 ["LLM01", "LLM07"]），None = 全部
            exclude_ids: 排除的 OWASP ID 列表

        Returns:
            PromptBatch 列表
        """
        owasp_dir = self.base_data_dir / "owasp" / framework
        if not owasp_dir.exists():
            return []

        # 从 _registry.yaml 加载该框架所有分类的元数据
        registry_categories = self._load_registry(framework)

        # 统一转大写进行大小写不敏感匹配
        owasp_ids_upper = {oid.upper() for oid in owasp_ids} if owasp_ids else None
        exclude_set = {eid.upper() for eid in (exclude_ids or [])}
        batches: List[PromptBatch] = []

        # 遍历 llm01, llm02, ... 或 asi01, asi02, ... 目录
        for category_dir in sorted(owasp_dir.iterdir()):
            if not category_dir.is_dir():
                continue

            category_name = category_dir.name  # 如 "llm01" 或 "asi01"

            # 从 registry 获取该分类的元数据
            meta = registry_categories.get(category_name, {})
            if not meta:
                # registry 中没有该分类，尝试从目录名推断
                continue

            # 检查 OWASP ID 过滤（大小写不敏感）
            owasp_id = meta.get("owasp_id", "")
            if owasp_ids_upper and owasp_id.upper() not in owasp_ids_upper:
                continue
            if owasp_id.upper() in exclude_set:
                continue

            # 遍历该分类下的所有 YAML 文件（排除 _ 开头的文件）
            for yaml_file in sorted(category_dir.glob("*.yaml")):
                if yaml_file.name.startswith("_"):
                    continue

                batch = self._parse_prompt_file(yaml_file, meta)
                if batch and batch.prompts:
                    batches.append(batch)

        return batches

    def load_from_custom(self, path: Optional[str] = None) -> List[PromptBatch]:
        """
        加载自定义载荷文件

        Args:
            path: 自定义载荷目录，默认为 data/custom/

        Returns:
            PromptBatch 列表
        """
        custom_dir = Path(path) if path else self.base_data_dir / "custom"
        if not custom_dir.exists():
            return []

        batches: List[PromptBatch] = []
        for yaml_file in sorted(custom_dir.glob("*.yaml")):
            if yaml_file.name.startswith("_"):
                continue
            batch = self._parse_prompt_file(yaml_file, {})
            if batch and batch.prompts:
                batches.append(batch)

        return batches

    # -----------------------------------------------------------------
    # Registry 加载（替代逐目录 _meta.yaml）
    # -----------------------------------------------------------------

    def _load_registry(self, framework: str) -> Dict[str, Dict[str, Any]]:
        """
        从 _registry.yaml 加载该框架所有分类的元数据

        每个框架（llm / agentic）在 data/owasp/{framework}/_registry.yaml
        统一管理所有分类的 owasp_id 和 name，无需逐目录维护 _meta.yaml。

        Args:
            framework: 框架名称 "llm" 或 "agentic"

        Returns:
            分类名 → 元数据字典 的映射，如 {"llm01": {"owasp_id": "LLM01", "name": "..."}}
        """
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

    # -----------------------------------------------------------------
    # YAML 解析
    # -----------------------------------------------------------------

    def _parse_prompt_file(
        self,
        yaml_file: Path,
        meta: Dict[str, Any],
    ) -> Optional[PromptBatch]:
        """
        解析单个提示词 YAML 文件为 PromptBatch

        支持四种提示词格式（由 section 名称决定 attack_mode）：
        - prompts: 单轮直接攻击
        - multi_turn_prompts: 多轮渐进攻击
        - converter_enhanced_prompts: 编码转换增强
        - sequential_prompts: 顺序组合攻击

        三层分离：YAML 只包含数据，attack_mode 由 section 推断，
        converter_chains 和 attack_technique 由系统自动匹配。
        """
        with open(yaml_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data:
            return None

        source_id = data.get("source_id", yaml_file.stem)
        owasp_id = data.get("owasp_id", meta.get("owasp_id"))
        category = data.get("category", meta.get("category"))
        description = data.get("description", "")

        items: List[PromptItem] = []

        # 1. 单轮直接攻击（section 名称决定 attack_mode）
        for prompt_data in data.get("prompts", []):
            item = self._create_prompt_item(prompt_data, AttackMode.SINGLE_TURN)
            items.append(item)

        # 2. 多轮渐进攻击
        for prompt_data in data.get("multi_turn_prompts", []):
            item = self._create_prompt_item(prompt_data, AttackMode.MULTI_TURN)
            items.append(item)

        # 3. 编码转换增强
        for prompt_data in data.get("converter_enhanced_prompts", []):
            item = self._create_prompt_item(prompt_data, AttackMode.CONVERTER_ENHANCED)
            items.append(item)

        # 4. 顺序组合攻击
        for prompt_data in data.get("sequential_prompts", []):
            item = self._create_prompt_item(prompt_data, AttackMode.SEQUENTIAL)
            items.append(item)

        return PromptBatch(
            source_id=source_id,
            owasp_id=owasp_id,
            category=category,
            description=description,
            prompts=items,
        )

    def _create_prompt_item(
        self,
        data: Dict[str, Any],
        default_mode: AttackMode,
    ) -> PromptItem:
        """
        从字典创建 PromptItem

        三层分离架构：
        - attack_mode: 由 section 名称决定（default_mode），YAML 中不再声明
        - converter_chains: YAML 中不再声明，由 PayloadStrategyMatcher 自动匹配
        - attack_technique (sequential steps): 默认为空字符串，由 planner 自动匹配
        """

        # attack_mode 由 section 名称决定（向后兼容：仍支持 YAML 显式声明）
        mode_str = data.get("attack_mode", default_mode.value)
        try:
            attack_mode = AttackMode(mode_str)
        except ValueError:
            attack_mode = default_mode

        item = PromptItem(
            id=data.get("id", ""),
            objective=data.get("objective", ""),
            attack_mode=attack_mode,
            owasp_id=data.get("owasp_id"),
            source_id=data.get("source_id"),
            category=data.get("category"),
            converter_chains=data.get("converter_chains", []),
            multi_turn_steps=data.get("turns", []),
            metadata=data.get("metadata", {}),
        )

        # 顺序组合攻击：解析步骤（attack_technique 默认为空字符串，由 planner 自动匹配）
        if attack_mode == AttackMode.SEQUENTIAL:
            steps_data = data.get("steps", [])
            item.sequential_steps = [
                SequentialStep(
                    attack_technique=s.get("attack_technique", ""),
                    objective=s.get("objective", ""),
                    converter_chain=s.get("converter_chain"),
                )
                for s in steps_data
            ]

        return item


# ============================================================
# 工厂函数
# ============================================================


def load_payloads(
    owasp_ids: Optional[List[str]] = None,
    exclude_ids: Optional[List[str]] = None,
    include_custom: bool = True,
    frameworks: Optional[List[str]] = None,
) -> List[PromptBatch]:
    """
    加载所有数据源提示词（工厂函数）

    Args:
        owasp_ids: 指定加载的 OWASP ID，None = 全部
        exclude_ids: 排除的 OWASP ID
        include_custom: 是否包含自定义载荷
        frameworks: 框架列表（如 ["llm", "agentic"]），None = 从配置读取

    Returns:
        PromptBatch 列表
    """
    from src.core.config_loader import get_config_loader

    loader = PayloadSourceLoader()

    # 从配置读取框架列表
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
