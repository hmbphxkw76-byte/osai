"""载荷加载器（AI-300 Ch3-Ch9 攻击载荷管理）。

基于 OWASP LLM Top 10 分类的 YAML 载荷库加载器：
  - 从 config/payloads/ 目录按 OWASP 分类加载 YAML 文件
  - 支持 payload（直接载荷）和 payload_template（模板载荷）两种格式
  - 提供 goal 占位符替换功能，生成可执行的攻击载荷

分层注册表集成 (v2.0):
  - 优先通过 PayloadRegistry (_registry.core.yaml + _registry.local.yaml) 发现文件
  - 回退到 glob 扫描（向后兼容未注册的载荷文件）
  - 支持 list_categories() / get_summary() / get_category_files() 等注册表层方法

Library-First: 载荷与执行解耦
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

import yaml

from redteam.core.registry_loader import PayloadRegistry

logger = logging.getLogger(__name__)


class PayloadLoader:
    """YAML 载荷库加载器 — AI-300 攻击载荷统一管理接口。

    使用方式：
        loader = PayloadLoader()

        # 按 OWASP 类别加载
        payloads = loader.load_by_category("llm01")

        # 按文件路径加载
        payloads = loader.load("config/payloads/llm01/direct_injection.yaml")

        # 转换为 Runner 输入格式（替换 {goal} 占位符）
        inputs = loader.to_runner_inputs(payloads, goal="leak system prompt")

        # 注册表感知方法 (v2.0)
        categories = loader.list_categories()      # 所有 OWASP 类别
        summary = loader.get_summary()             # 统计摘要
        files = loader.get_category_files("llm01") # 类别文件列表
    """

    def __init__(
        self,
        payload_dir: str = "config/payloads",
    ):
        self.payload_dir = Path(payload_dir)
        self._registry = PayloadRegistry(registry_dir=str(self.payload_dir))
        self._discoverable_files: list[Path] | None = None

    # ── 注册表感知方法 (v2.0) ───────────────────────────────────────

    def list_categories(self) -> dict:
        """列出所有载荷类别（核心 + 本地合并后）。

        优先使用注册表索引，回退到目录扫描。

        Returns:
            {category_name: {name, description, file_count}} 字典
        """
        cats = self._registry.list_categories()
        if cats:
            return cats

        # 回退：扫描子目录
        result: dict[str, dict] = {}
        for d in sorted(self.payload_dir.iterdir()):
            if d.is_dir() and d.name.startswith("llm"):
                yaml_files = list(d.glob("*.yaml"))
                result[d.name] = {
                    "name": d.name.upper(),
                    "description": "",
                    "file_count": len(yaml_files),
                }
        return result

    def get_summary(self) -> dict:
        """获取载荷库统计摘要。

        Returns:
            {total_categories, total_files, total_payloads, owasp_coverage} 字典
        """
        summary = self._registry.get_summary()
        if summary:
            return summary

        # 回退：遍历计算
        total_files = 0
        total_payloads = 0
        covered: list[str] = []
        for cat_name, cat_info in self.list_categories().items():
            covered.append(cat_name.upper())
            total_files += cat_info.get("file_count", 0)
            # 粗略估计载荷条目数（每个文件快速计行数）
            cat_dir = self.payload_dir / cat_name
            if cat_dir.exists():
                for yf in cat_dir.glob("*.yaml"):
                    payloads = self.load(str(yf))
                    total_payloads += len(payloads)
        return {
            "total_categories": len(covered),
            "total_files": total_files,
            "total_payloads": total_payloads,
            "owasp_coverage": {"covered": covered, "uncovered": []},
        }

    def get_category_files(self, category: str) -> list[dict]:
        """获取指定类别下的载荷文件元数据列表。

        优先使用注册表索引，回退到目录扫描。

        Args:
            category: OWASP 类别名

        Returns:
            文件元数据列表 [{technique_group, description, ai300_chapter, payload_count, status, file}]
        """
        files = self._registry.list_files(category)
        if files:
            return files

        # 回退：扫描目录
        category_dir = self.payload_dir / category
        if not category_dir.exists() or not category_dir.is_dir():
            return []
        result: list[dict] = []
        for yf in sorted(category_dir.glob("*.yaml")):
            payloads = self.load(str(yf))
            result.append({
                "technique_group": yf.stem,
                "description": "",
                "ai300_chapter": "",
                "payload_count": len(payloads),
                "status": "stable",
                "file": str(yf.relative_to(self.payload_dir)).replace("\\", "/"),
            })
        return result

    # ── 核心加载方法 ────────────────────────────────────────────────

    def load(self, yaml_path: str) -> list[dict[str, Any]]:
        """从指定 YAML 文件加载载荷列表。

        Args:
            yaml_path: YAML 文件路径（相对或绝对）

        Returns:
            载荷列表，每个载荷为 dict，包含 technique/name/payload 字段
        """
        path = Path(yaml_path)
        if not path.exists():
            logger.debug("载荷文件不存在: %s（使用内置回退载荷）", yaml_path)
            return []

        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not isinstance(data, dict) or "payloads" not in data:
                logger.warning("载荷文件格式错误，缺少 payloads 字段: %s", yaml_path)
                return []

            payloads = data["payloads"]
            # 规范化：确保每个条目同时有 payload 和 payload_template 键
            # YAML 文件使用 payload，fallback 常量使用 payload_template，
            # 统一规范化使得消费者可以用任意键名访问
            for item in payloads:
                if isinstance(item, dict):
                    py = item.get("payload", "")
                    pt = item.get("payload_template", "")
                    if py and not pt:
                        item["payload_template"] = py
                    elif pt and not py:
                        item["payload"] = pt
            return payloads

        except yaml.YAMLError as exc:
            logger.error("YAML 解析失败: %s, 错误: %s", yaml_path, exc)
            return []
        except Exception as exc:
            logger.error("加载载荷文件失败: %s, 错误: %s", yaml_path, exc)
            return []

    def load_by_category(self, category: str) -> list[dict[str, Any]]:
        """按 OWASP 类别加载该类别下所有载荷文件。

        优先通过注册表发现文件列表（O(1) 索引查找），回退到 glob 扫描。

        Args:
            category: OWASP 类别名（如 llm01, llm02）

        Returns:
            该类别下所有载荷合并后的列表
        """
        # ── Step 1: 通过注册表获取文件列表 ──
        reg_files = self._registry.list_files(category)
        if reg_files:
            all_payloads: list[dict[str, Any]] = []
            for entry in reg_files:
                file_rel = entry.get("file", "")
                if file_rel:
                    file_path = self.payload_dir / file_rel
                    if file_path.exists():
                        payloads = self.load(str(file_path))
                        all_payloads.extend(payloads)
                    else:
                        logger.debug("注册表引用载荷文件不存在: %s → %s", category, file_rel)
            if all_payloads:
                logger.info("从类别 %s 加载了 %d 条载荷（注册表）", category, len(all_payloads))
                return all_payloads

        # ── Step 2: 回退到 glob 扫描 ──
        category_dir = self.payload_dir / category
        if not category_dir.exists() or not category_dir.is_dir():
            logger.warning("类别目录不存在: %s", category_dir)
            return []

        all_payloads = []
        for yaml_file in sorted(self._get_discoverable_files(category)):
            payloads = self.load(str(yaml_file))
            all_payloads.extend(payloads)

        logger.info("从类别 %s 加载了 %d 条载荷（glob 扫描）", category, len(all_payloads))
        return all_payloads

    def to_runner_inputs(
        self,
        payloads: list[dict[str, Any]],
        goal: str = "",
        **kwargs: str,
    ) -> list[str]:
        """将载荷列表转换为 AttackRunner 可消费的字符串列表。

        支持两种载荷格式：
          - payload: 直接使用字符串值
          - payload_template: 使用 str.format() 替换占位符

        Args:
            payloads: 载荷列表
            goal: 攻击目标，用于替换 {goal} 占位符
            **kwargs: 额外的占位符键值对

        Returns:
            可直接传给 AttackRunner.run() 的字符串列表
        """
        inputs = []
        for payload in payloads:
            content = payload.get("payload", "") or payload.get("payload_template", "")
            if not content:
                continue

            if "{goal}" in content:
                content = content.replace("{goal}", goal)

            if kwargs:
                content = content.format(**kwargs)

            inputs.append(content)

        return inputs

    def get_payloads_by_technique(
        self,
        payloads: list[dict[str, Any]],
        technique: str,
    ) -> list[dict[str, Any]]:
        """按技术类型筛选载荷。

        Args:
            payloads: 原始载荷列表
            technique: 技术类型（如 instruction_override, roleplay）

        Returns:
            匹配的载荷列表
        """
        return [p for p in payloads if p.get("technique") == technique]

    def has_local_overrides(self) -> bool:
        """检查是否有本地载荷注册表覆盖。"""
        return self._registry.has_local_overrides()

    def reload_registry(self):
        """强制重新加载注册表（用于注册表文件变更后）。"""
        self._registry = PayloadRegistry(registry_dir=str(self.payload_dir))
        self._discoverable_files = None

    # ── private ──────────────────────────────────────────────────────

    def _get_discoverable_files(self, category: str = "") -> list[Path]:
        """获取可发现的载荷文件列表（排除注册表和模板文件）。

        Args:
            category: 限定子目录（如 llm01），为空时返回所有类别文件。

        Returns:
            载荷 YAML 文件路径列表
        """
        if category:
            category_dir = self.payload_dir / category
            if not category_dir.exists():
                return []
            files = []
            for yf in sorted(category_dir.glob("*.yaml")):
                if yf.stem.startswith(("_registry", "_template")):
                    continue
                files.append(yf)
            return files

        # 无类别限定：扫描全部子目录
        if self._discoverable_files is not None:
            return self._discoverable_files

        files: list[Path] = []
        skip_prefixes = ("_registry", "_template")
        for d in sorted(self.payload_dir.iterdir()):
            if not d.is_dir():
                continue
            for yf in sorted(d.glob("*.yaml")):
                if yf.stem.startswith(skip_prefixes):
                    continue
                files.append(yf)

        self._discoverable_files = files
        return files


__all__ = ["PayloadLoader"]
