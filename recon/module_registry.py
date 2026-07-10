"""
===============================================================================
模块注册表 — 可插拔的侦察模块管理
===============================================================================
允许动态注册/注销侦察子模块。

功能:
  - 注册自定义探测模块
  - 按严重程度/类别筛选
  - 预算分配 (遵循多项分布)
  - 种子可重现性

设计原则:
  ✅ 零侵入 — 不改动现有模块即可接入
  ✅ 可组合 — 支持按需组合不同探测策略
  ✅ 可重现 — 固定种子确保结果一致
===============================================================================
"""
from __future__ import annotations

import numpy as np
from dataclasses import dataclass, field
from typing import Optional, Callable, Any


@dataclass
class ProbeModule:
    """单个探测模块定义。"""
    name: str
    category: str
    description: str
    severity: str = "medium"  # critical/high/medium/low/info
    execute_fn: Optional[Callable] = None
    enabled: bool = True
    max_probes: int = 3
    tags: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


class ModuleRegistry:
    """可插拔的侦察模块注册表。

    用法:
        registry = ModuleRegistry()
        registry.register(ProbeModule(name="system_prompt", ...))
        modules = registry.get_enabled()
        for module in modules:
            await module.execute_fn(...)
    """

    def __init__(self, seed: int = 42):
        self._modules: dict[str, ProbeModule] = {}
        self._seed = seed
        self._rng = np.random.default_rng(seed)

    @property
    def seed(self) -> int:
        return self._seed

    def register(self, module: ProbeModule) -> None:
        """注册一个探测模块。"""
        if module.name in self._modules:
            raise ValueError(f"模块 '{module.name}' 已注册")
        self._modules[module.name] = module

    def unregister(self, name: str) -> None:
        """注销一个探测模块。"""
        if name not in self._modules:
            raise ValueError(f"模块 '{name}' 未注册")
        del self._modules[name]

    def get(self, name: str) -> Optional[ProbeModule]:
        """获取指定模块。"""
        return self._modules.get(name)

    def get_enabled(self) -> list[ProbeModule]:
        """获取所有已启用的模块。"""
        return [m for m in self._modules.values() if m.enabled]

    def get_by_category(self, category: str) -> list[ProbeModule]:
        """按类别获取模块。"""
        return [m for m in self._modules.values()
                if m.category == category and m.enabled]

    def get_by_severity(self, min_severity: str = "low") -> list[ProbeModule]:
        """按最低严重程度获取模块。"""
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        min_level = severity_order.get(min_severity, 0)
        return [m for m in self._modules.values()
                if m.enabled and severity_order.get(m.severity, 0) >= min_level]

    def get_by_tag(self, tag: str) -> list[ProbeModule]:
        """按标签获取模块。"""
        return [m for m in self._modules.values()
                if tag in m.tags and m.enabled]

    def enable(self, name: str) -> None:
        """启用指定模块。"""
        if name in self._modules:
            self._modules[name].enabled = True

    def disable(self, name: str) -> None:
        """禁用指定模块。"""
        if name in self._modules:
            self._modules[name].enabled = False

    def list_all(self) -> list[dict]:
        """列出所有模块信息。"""
        return [
            {
                "name": m.name,
                "category": m.category,
                "description": m.description,
                "severity": m.severity,
                "enabled": m.enabled,
                "max_probes": m.max_probes,
                "tags": m.tags,
            }
            for m in self._modules.values()
        ]

    def allocate_budget(
        self,
        total_probes: int,
        categories: Optional[list[str]] = None,
    ) -> dict[str, int]:
        """使用多项分布分配探测预算。

        Args:
            total_probes: 总探测次数预算
            categories: 限制分配的类别列表 (None = 所有类别)

        Returns:
            dict[category_name, probe_count] — 每个类别的探测次数
        """
        enabled = self.get_enabled()
        if categories:
            enabled = [m for m in enabled if m.category in categories]

        if not enabled:
            return {}

        n = len(enabled)
        counts = self._rng.multinomial(total_probes, np.ones(n) / n)
        return {
            enabled[i].category: int(counts[i])
            for i in range(n)
        }

    def clear(self) -> None:
        """清空所有注册模块。"""
        self._modules.clear()

    def __len__(self) -> int:
        return len(self._modules)

    def __contains__(self, name: str) -> bool:
        return name in self._modules

    def __iter__(self):
        return iter(self._modules.values())


# ═══════════════════════════════════════════════════════════════
# 预构建的默认侦察模块注册表
# ═══════════════════════════════════════════════════════════════

def build_default_registry() -> ModuleRegistry:
    """构建包含所有标准侦察类别的默认注册表。"""
    return ModuleRegistry()
