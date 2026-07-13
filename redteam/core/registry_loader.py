"""注册表加载器 — 核心 + 本地分层注册表合并引擎。

实现 config/scenarios/_registry.core.yaml 和 config/payloads/_registry.core.yaml
的多层注册表合并逻辑，支持用户通过 _registry.local.yaml 扩展自定义场景/载荷。

设计原则:
  - 核心注册表 (_registry.core.yaml): 项目仓库管理，版本控制
  - 本地注册表 (_registry.local.yaml): 用户自建，.gitignore
  - 合并优先级: 本地 > 核心（同 ID 覆盖）
  - 本地文件可选：不存在时仅使用核心注册表
  - 可扩展: 支持额外注册表路径（如 team registry）

Library-First: 纯 Python 实现，无外部依赖。
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# ── 注册表文件名约定 ──────────────────────────────────────────────────
CORE_REGISTRY_NAME = "_registry.core.yaml"
LOCAL_REGISTRY_NAME = "_registry.local.yaml"


class RegistryLoader:
    """分层注册表加载器 — 核心 + 本地合并。

    使用方式:
        loader = RegistryLoader("config/scenarios")
        merged = loader.load()          # 返回合并后的 dict
        scenarios = merged["scenarios"] # 场景列表

    或用于载荷注册表:
        loader = RegistryLoader("config/payloads")
        merged = loader.load()
        categories = merged["categories"]  # OWASP 类别字典
    """

    def __init__(self, registry_dir: str):
        self._dir = Path(registry_dir)
        self._core_path = self._dir / CORE_REGISTRY_NAME
        self._local_path = self._dir / LOCAL_REGISTRY_NAME

    def load(self) -> dict[str, Any]:
        """加载并合并注册表。

        Returns:
            合并后的注册表字典。核心内容为基底，本地条目覆盖/追加。
            如果两者都不存在，返回空字典。
        """
        core = self._load_file(self._core_path)
        local = self._load_file(self._local_path)

        if not core and not local:
            logger.info("注册表目录 %s 中未找到注册表文件", self._dir)
            return {}

        if not local:
            logger.debug("未找到本地注册表，仅使用核心注册表: %s", self._core_path)
            return core

        if not core:
            logger.info("未找到核心注册表，仅使用本地注册表: %s", self._local_path)
            return local

        merged = self._merge(core, local)
        return merged

    def load_core_only(self) -> dict[str, Any]:
        """仅加载核心注册表（用于调试/对比）。"""
        return self._load_file(self._core_path)

    def load_local_only(self) -> dict[str, Any]:
        """仅加载本地注册表（用于调试）。"""
        return self._load_file(self._local_path)

    def get_local_path(self) -> Path:
        """获取本地注册表文件路径。"""
        return self._local_path

    def get_core_path(self) -> Path:
        """获取核心注册表文件路径。"""
        return self._core_path

    def has_local(self) -> bool:
        """检查是否存在本地注册表文件。"""
        return self._local_path.exists()

    def has_core(self) -> bool:
        """检查是否存在核心注册表文件。"""
        return self._core_path.exists()

    # ── private ──────────────────────────────────────────────────────

    @staticmethod
    def _load_file(path: Path) -> dict[str, Any]:
        """安全加载单个 YAML 注册表文件。"""
        if not path.exists():
            return {}

        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if isinstance(data, dict):
                return data
            logger.warning("注册表文件格式错误（非字典）: %s", path)
            return {}
        except yaml.YAMLError as e:
            logger.error("YAML 解析失败: %s, 错误: %s", path, e)
            return {}
        except Exception as e:
            logger.error("读取注册表失败: %s, 错误: %s", path, e)
            return {}

    def _merge(self, core: dict, local: dict) -> dict:
        """合并核心和本地注册表。

        合并策略取决于结构类型:
          - scenarios 列表: 按 id 字段去重，本地优先
          - categories 字典: 按 technique_group 去重，本地优先
          - 其他顶层字段 (version, summary 等): 核心优先，本地补充
        """
        merged: dict[str, Any] = {}

        # ── 处理 scenarios 列表（场景注册表） ──
        if "scenarios" in core or "scenarios" in local:
            core_list = core.get("scenarios", [])
            local_list = local.get("scenarios", [])
            merged["scenarios"] = self._merge_scenarios_list(core_list, local_list)

        # ── 处理 categories 字典（载荷注册表） ──
        if "categories" in core or "categories" in local:
            core_cats = core.get("categories", {})
            local_cats = local.get("categories", {})
            merged["categories"] = self._merge_categories_dict(core_cats, local_cats)

        # ── 处理其他顶层字段 ──
        for key, core_val in core.items():
            if key not in ("scenarios", "categories"):
                merged[key] = core_val

        for key, local_val in local.items():
            if key not in ("scenarios", "categories") and key not in merged:
                merged[key] = local_val

        # ── 合并 summary 统计 ──
        if "summary" in core or "summary" in local:
            merged["summary"] = self._merge_summary(
                core.get("summary", {}),
                local.get("summary", {}),
            )

        return merged

    def _merge_scenarios_list(
        self,
        core_list: list[dict],
        local_list: list[dict],
    ) -> list[dict]:
        """合并场景列表 — 按 id 去重，本地优先。"""
        merged: dict[str, dict] = {}

        # 先加载核心条目
        for item in core_list:
            if not isinstance(item, dict):
                continue
            item_id = item.get("id")
            if item_id:
                merged[item_id] = item

        # 本地条目覆盖同 ID 的核心条目
        for item in local_list:
            if not isinstance(item, dict):
                continue
            item_id = item.get("id")
            if not item_id:
                continue
            if item_id in merged:
                logger.info(
                    "本地注册表覆盖核心场景: id=%s (%s)",
                    item_id,
                    item.get("name", ""),
                )
            merged[item_id] = item

        return list(merged.values())

    def _merge_categories_dict(
        self,
        core_cats: dict,
        local_cats: dict,
    ) -> dict:
        """合并载荷 categories 字典 — 按类别 + technique_group 去重，本地优先。"""
        merged: dict = dict(core_cats)

        for cat_name, cat_data in local_cats.items():
            if not isinstance(cat_data, dict):
                continue

            if cat_name not in merged:
                # 新类别，直接添加
                merged[cat_name] = cat_data
                continue

            # 合并同类别下的 files 列表
            local_files = cat_data.get("files", [])
            if not local_files:
                continue

            core_files = merged[cat_name].get("files", [])
            merged_files = self._merge_payload_files_list(core_files, local_files)

            new_cat = dict(cat_data)
            new_cat["files"] = merged_files
            # 如果本地没有 name/description，保留核心的
            if "name" not in new_cat and "name" in merged[cat_name]:
                new_cat["name"] = merged[cat_name]["name"]
            if "description" not in new_cat and "description" in merged[cat_name]:
                new_cat["description"] = merged[cat_name]["description"]
            merged[cat_name] = new_cat

        return merged

    def _merge_payload_files_list(
        self,
        core_files: list[dict],
        local_files: list[dict],
    ) -> list[dict]:
        """合并载荷文件列表 — 按 technique_group 去重，本地优先。"""
        merged: dict[str, dict] = {}

        for item in core_files:
            if not isinstance(item, dict):
                continue
            key = item.get("file") or item.get("technique_group", "")
            if key:
                merged[key] = item

        for item in local_files:
            if not isinstance(item, dict):
                continue
            key = item.get("file") or item.get("technique_group", "")
            if not key:
                continue
            if key in merged:
                logger.info(
                    "本地注册表覆盖核心载荷: %s (%s)",
                    key,
                    item.get("technique_group", ""),
                )
            merged[key] = item

        return list(merged.values())

    @staticmethod
    def _merge_summary(core_summary: dict, local_summary: dict) -> dict:
        """合并统计摘要。"""
        merged = dict(core_summary)
        for k, v in local_summary.items():
            merged[k] = v
        return merged


class ScenarioRegistry:
    """场景注册表门面 — 加载并解析场景注册表。

    使用方式:
        reg = ScenarioRegistry()
        all_scenarios = reg.list_all()      # 核心 + 本地
        scenario = reg.get("agent_basic")   # 按 id 查找
        by_type = reg.get_by_type("agent")  # 按类型分组
    """

    def __init__(self, registry_dir: str = "config/scenarios"):
        self._loader = RegistryLoader(registry_dir)
        self._registry: dict[str, Any] | None = None

    def _ensure_loaded(self):
        """延迟加载注册表。"""
        if self._registry is None:
            self._registry = self._loader.load()

    def list_all(self) -> list[dict]:
        """列出所有已注册场景（核心 + 本地合并后）。"""
        self._ensure_loaded()
        return self._registry.get("scenarios", [])

    def get(self, scenario_id: str) -> dict | None:
        """按场景 ID 查找注册条目。"""
        for s in self.list_all():
            if s.get("id") == scenario_id:
                return s
        return None

    def get_by_type(self, target_type: str) -> list[dict]:
        """按目标类型筛选场景。"""
        return [s for s in self.list_all() if s.get("target_type") == target_type]

    def get_local_entries(self) -> list[dict]:
        """仅列出本地覆盖/新增的场景。"""
        local = self._loader.load_local_only()
        return local.get("scenarios", [])

    def get_core_entries(self) -> list[dict]:
        """仅列出核心场景。"""
        core = self._loader.load_core_only()
        return core.get("scenarios", [])

    def has_local_overrides(self) -> bool:
        """检查是否有本地覆盖。"""
        return self._loader.has_local()


class PayloadRegistry:
    """载荷注册表门面 — 加载并解析载荷注册表。

    使用方式:
        reg = PayloadRegistry()
        categories = reg.list_categories()     # 所有 OWASP 类别
        files = reg.get_category("llm01")      # 按类别获取载荷文件列表
    """

    def __init__(self, registry_dir: str = "config/payloads"):
        self._loader = RegistryLoader(registry_dir)
        self._registry: dict[str, Any] | None = None

    def _ensure_loaded(self):
        """延迟加载注册表。"""
        if self._registry is None:
            self._registry = self._loader.load()

    def list_categories(self) -> dict:
        """列出所有载荷类别（核心 + 本地合并后）。"""
        self._ensure_loaded()
        return self._registry.get("categories", {})

    def get_category(self, category: str) -> dict | None:
        """获取指定 OWASP 类别的文件列表。"""
        cats = self.list_categories()
        return cats.get(category)

    def list_files(self, category: str) -> list[dict]:
        """获取指定类别下的载荷文件列表。"""
        cat = self.get_category(category)
        return cat.get("files", []) if cat else []

    def get_summary(self) -> dict:
        """获取注册表统计摘要。"""
        self._ensure_loaded()
        return self._registry.get("summary", {})

    def has_local_overrides(self) -> bool:
        """检查是否有本地覆盖。"""
        return self._loader.has_local()


__all__ = [
    "RegistryLoader",
    "ScenarioRegistry",
    "PayloadRegistry",
    "CORE_REGISTRY_NAME",
    "LOCAL_REGISTRY_NAME",
]
