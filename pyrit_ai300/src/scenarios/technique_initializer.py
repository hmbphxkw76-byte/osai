"""
AI-300 Technique Initializer — 对齐 pyrit.setup.initializers.techniques.TechniqueInitializer
================================================================================================

P1: Technique 注册与发现 — TechniqueInitializer 初始化器

封装技术注册流程，提供与 PyRIT 原生 TechniqueInitializer 兼容的接口。
支持通过 tags 参数控制注册范围。

对齐 PyRIT 1.0.0 的 set_params_from_args / initialize_async 模式。
"""

import logging
from typing import Any

from src.scenarios.technique_factories import register_ai300_techniques, AI300_TECHNIQUE_METADATA

logger = logging.getLogger(__name__)


class AI300TechniqueInitializer:
    """
    AI-300 Technique 初始化器

    对齐 PyRIT 1.0.0 TechniqueInitializer，封装技术注册流程。

    使用方式：
        initializer = AI300TechniqueInitializer()
        initializer.set_params_from_args(args={"tags": ["all"]})
        await initializer.initialize_async()

    或直接调用便捷函数：
        await initialize_techniques_async(tags=["all"])
    """

    def __init__(self) -> None:
        self._tags: list[str] = ["core"]
        self._registered_count: int = 0

    def set_params_from_args(self, *, args: dict[str, Any]) -> None:
        """
        从参数字典设置初始化器配置

        Args:
            args: 参数字典，支持：
                - tags (list[str]): 注册的组别 ["core"|"extra"|"all"|"encoding"]
        """
        if "tags" in args and args["tags"] is not None:
            self._tags = args["tags"]

    @property
    def supported_parameters(self) -> list[str]:
        """返回支持的参数名列表"""
        return ["tags"]

    @property
    def tags(self) -> list[str]:
        """当前注册的组别"""
        return self._tags

    @property
    def registered_count(self) -> int:
        """已注册的技术数量"""
        return self._registered_count

    async def initialize_async(self) -> None:
        """
        执行技术注册

        将选定组别的技术工厂注册到 PyRIT AttackTechniqueRegistry。
        注册是按名称幂等的。
        """
        self._registered_count = register_ai300_techniques(tags=self._tags)
        logger.info(
            f"AI300TechniqueInitializer: registered {self._registered_count} techniques "
            f"(tags={self._tags})"
        )


# ============================================================
# 便捷函数
# ============================================================

async def initialize_techniques_async(
    tags: list[str] | None = None,
    reset: bool = False,
) -> int:
    """
    初始化 AI-300 技术注册（便捷函数）

    Args:
        tags: 注册的组别，默认为 ["core"]
              ["core"] - 仅注册核心技术
              ["core", "extra"] - 注册核心 + 可选技术
              ["all"] - core + extra 简写
              ["encoding"] - 仅编码攻击技术
        reset: 是否重置注册表（主要用于测试）

    Returns:
        新注册的技术数量

    Usage:
        # 在管道初始化中
        await initialize_techniques_async(tags=["all"])

        # 仅编码攻击
        await initialize_techniques_async(tags=["encoding"])
    """
    return register_ai300_techniques(tags=tags, reset=reset)


# ============================================================
# 查询函数
# ============================================================

def get_registered_technique_names() -> list[str]:
    """获取已注册的技术名称列表"""
    from pyrit.registry import AttackTechniqueRegistry
    registry = AttackTechniqueRegistry.get_registry_singleton()
    return sorted(registry.get_factories().keys())


def get_technique_metadata(technique_name: str) -> dict[str, Any] | None:
    """获取技术元数据"""
    return AI300_TECHNIQUE_METADATA.get(technique_name)


def list_techniques_by_category(category: str) -> list[str]:
    """按类别列出技术名称"""
    return [
        name for name, meta in AI300_TECHNIQUE_METADATA.items()
        if meta.get("category") == category
    ]


def list_techniques_by_tag(tag: str) -> list[str]:
    """按标签列出技术名称"""
    return [
        name for name, meta in AI300_TECHNIQUE_METADATA.items()
        if tag in meta.get("tags", [])
    ]


def get_technique_summary() -> dict[str, Any]:
    """获取技术目录摘要"""
    categories: dict[str, list[str]] = {}
    for name, meta in AI300_TECHNIQUE_METADATA.items():
        cat = meta.get("category", "unknown")
        categories.setdefault(cat, []).append(name)

    tag_counts: dict[str, int] = {}
    for meta in AI300_TECHNIQUE_METADATA.values():
        for tag in meta.get("tags", []):
            tag_counts[tag] = tag_counts.get(tag, 0) + 1

    return {
        "total_techniques": len(AI300_TECHNIQUE_METADATA),
        "categories": {k: len(v) for k, v in sorted(categories.items())},
        "tags": dict(sorted(tag_counts.items())),
        "category_details": categories,
    }
