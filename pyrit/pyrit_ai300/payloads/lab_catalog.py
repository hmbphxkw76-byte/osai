# -*- coding: utf-8 -*-
"""
AI-300 Framework - Lab/Challenge Catalog Loader
靶机 Lab/挑战目录加载器

从 YAML 配置文件加载靶机的 lab/challenge 目录，映射到 OWASP 分类。
支持 OWASP DonkAI（15 个挑战）和 AIVP（55 个 labs）两种靶机。

使用方式：
    catalog = LabCatalog.load("config/targets/aivp_labs.yaml")
    labs = catalog.get_labs_by_owasp("LLM01")
    lab = catalog.get_lab("PI_01")

    catalog = LabCatalog.load("config/targets/donkai_challenges.yaml")
    challenges = catalog.get_labs_by_owasp("LLM02")

PyRIT 0.14.0 兼容
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)


@dataclass
class LabInfo:
    """单个 Lab/挑战的信息"""
    lab_id: str
    phase: int = 0
    name: str = ""
    owasp: str = ""
    technique: str = ""
    description: str = ""
    secret_location: str = ""
    difficulty: str = "medium"
    requires_training: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LabCatalog:
    """
    Lab/挑战目录

    从 YAML 配置文件加载的完整 lab 目录，
    提供按 OWASP 分类、阶段、难度等维度的查询接口。
    """
    target_name: str = ""
    target_type: str = ""
    base_url: str = ""
    chat_endpoint: str = ""
    validate_endpoint: str = ""
    labs: Dict[str, LabInfo] = field(default_factory=dict)
    owasp_summary: Dict[str, List[str]] = field(default_factory=dict)
    sensitive_targets: List[Dict[str, Any]] = field(default_factory=list)

    @classmethod
    def load(cls, config_path: str) -> "LabCatalog":
        """
        从 YAML 文件加载 lab 目录

        Args:
            config_path: YAML 配置文件路径

        Returns:
            LabCatalog 实例
        """
        path = Path(config_path)
        if not path.exists():
            logger.warning("Lab catalog file not found: %s", config_path)
            return cls()

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        catalog = cls()

        # 解析 target 信息
        target = data.get("target", {})
        catalog.target_name = target.get("name", "")
        catalog.target_type = target.get("type", "")
        catalog.base_url = target.get("base_url", "")
        catalog.chat_endpoint = target.get("chat_endpoint", "")
        catalog.validate_endpoint = target.get("validate_endpoint", "")

        # 解析 labs（AIVP 格式：labs + owasp_summary）
        labs_data = data.get("labs", {})
        for lab_id, lab_info in labs_data.items():
            if not isinstance(lab_info, dict):
                continue
            catalog.labs[lab_id] = LabInfo(
                lab_id=lab_id,
                phase=lab_info.get("phase", 0),
                name=lab_info.get("name", ""),
                owasp=lab_info.get("owasp", ""),
                technique=lab_info.get("technique", ""),
                description=lab_info.get("description", ""),
                secret_location=lab_info.get("secret_location", ""),
                difficulty=lab_info.get("difficulty", "medium"),
                requires_training=lab_info.get("requires_training", False),
                extra={
                    k: v for k, v in lab_info.items()
                    if k not in ("phase", "name", "owasp", "technique",
                                 "description", "secret_location", "difficulty",
                                 "requires_training")
                },
            )

        # 解析 OWASP 汇总（AIVP 格式）
        owasp_data = data.get("owasp_summary", {})
        for owasp_id, info in owasp_data.items():
            if isinstance(info, dict):
                catalog.owasp_summary[owasp_id] = info.get("labs", [])
            elif isinstance(info, list):
                catalog.owasp_summary[owasp_id] = info

        # 解析 categories（DonkAI 格式：categories → 自动转换为 labs + owasp_summary）
        categories_data = data.get("categories", {})
        for owasp_id, cat_info in categories_data.items():
            if not isinstance(cat_info, dict):
                continue
            challenges = cat_info.get("challenges", [])
            lab_ids_for_category: list[str] = []
            for ch in challenges:
                if not isinstance(ch, dict):
                    continue
                ch_id = ch.get("id", f"{owasp_id}_{len(lab_ids_for_category)}")
                catalog.labs[ch_id] = LabInfo(
                    lab_id=ch_id,
                    phase=0,
                    name=ch.get("name", ""),
                    owasp=owasp_id,
                    technique=ch.get("attack_type", ""),
                    description=ch.get("hint", ""),
                    secret_location="",
                    difficulty="medium",
                    requires_training=False,
                    extra={
                        "category_id": owasp_id,
                        "defense": ch.get("defense", ""),
                        "vulnerability_type": cat_info.get("vulnerability_type", ""),
                    },
                )
                lab_ids_for_category.append(ch_id)
            # 自动生成 owasp_summary
            if lab_ids_for_category:
                catalog.owasp_summary[owasp_id] = lab_ids_for_category

        # 解析敏感信息目标（DonkAI 专用）
        catalog.sensitive_targets = data.get("sensitive_targets", [])

        logger.info(
            "Lab catalog loaded: %s (%s) — %d labs, %d OWASP categories",
            catalog.target_name, catalog.target_type,
            len(catalog.labs), len(catalog.owasp_summary),
        )

        return catalog

    def get_lab(self, lab_id: str) -> Optional[LabInfo]:
        """获取单个 lab 信息"""
        return self.labs.get(lab_id)

    def get_labs_by_owasp(self, owasp_id: str) -> List[LabInfo]:
        """按 OWASP 分类获取 labs"""
        owasp_upper = owasp_id.upper()
        result = []
        for lab in self.labs.values():
            if lab.owasp.upper() == owasp_upper:
                result.append(lab)
        return result

    def get_labs_by_phase(self, phase: int) -> List[LabInfo]:
        """按阶段获取 labs"""
        return [lab for lab in self.labs.values() if lab.phase == phase]

    def get_labs_by_difficulty(self, difficulty: str) -> List[LabInfo]:
        """按难度获取 labs"""
        difficulty_lower = difficulty.lower()
        return [lab for lab in self.labs.values() if lab.difficulty.lower() == difficulty_lower]

    def get_owasp_categories(self) -> List[str]:
        """获取所有 OWASP 分类"""
        return sorted(self.owasp_summary.keys())

    def get_lab_ids(self) -> List[str]:
        """获取所有 lab ID"""
        return sorted(self.labs.keys())

    def get_url_params_for_lab(self, lab_id: str) -> Dict[str, str]:
        """获取 lab 的 URL 参数（用于 API Target Builder）"""
        lab = self.get_lab(lab_id)
        if not lab:
            return {}
        params = {"lab_id": lab_id}
        # 如果是 DonkAI 挑战，添加 category_id
        if lab.extra.get("category_id"):
            params["category_id"] = lab.extra["category_id"]
        if lab.extra.get("challenge_id"):
            params["challenge_id"] = lab.extra["challenge_id"]
        return params

    def find_labs_for_scope(self, scope: str) -> List[LabInfo]:
        """
        根据 OWASP scope 查找匹配的 labs

        Args:
            scope: OWASP scope（如 "llm01", "asi01", "all", "llm", "agentic"）

        Returns:
            匹配的 LabInfo 列表
        """
        scope_lower = scope.lower()

        if scope_lower == "all":
            return list(self.labs.values())

        # 分组 scope
        if scope_lower == "llm":
            return [lab for lab in self.labs.values() if lab.owasp.upper().startswith("LLM")]
        if scope_lower in ("agentic", "asi"):
            return [lab for lab in self.labs.values() if lab.owasp.upper().startswith("ASI")]

        # 单个 OWASP ID
        scope_upper = scope.upper()
        return self.get_labs_by_owasp(scope_upper)

    def get_sensitive_patterns(self) -> List[Dict[str, Any]]:
        """获取敏感信息模式列表（用于评分器验证）"""
        return self.sensitive_targets


# ── 便捷函数 ──

_CATALOG_CACHE: Dict[str, LabCatalog] = {}


def load_catalog(config_path: str, use_cache: bool = True) -> LabCatalog:
    """
    加载 lab 目录（带缓存）

    Args:
        config_path: YAML 配置文件路径
        use_cache: 是否使用缓存

    Returns:
        LabCatalog 实例
    """
    if use_cache and config_path in _CATALOG_CACHE:
        return _CATALOG_CACHE[config_path]

    catalog = LabCatalog.load(config_path)
    if use_cache:
        _CATALOG_CACHE[config_path] = catalog
    return catalog


def detect_target_catalog(target_config: Dict[str, Any]) -> Optional[LabCatalog]:
    """
    从目标配置自动检测并加载对应的 lab 目录

    Args:
        target_config: 目标配置字典

    Returns:
        LabCatalog 实例或 None
    """
    target_type = target_config.get("type", "")
    target_name = target_config.get("name", "")

    # 通过 target type 匹配
    if target_type == "rest_api":
        return load_catalog("config/targets/donkai_challenges.yaml")
    elif target_type == "sse_chat":
        return load_catalog("config/targets/aivp_labs.yaml")

    # 通过 base_url 或 name 匹配
    base_url = target_config.get("base_url", target_config.get("connection", {}).get("base_url", ""))
    if "donkai" in (target_name + base_url).lower():
        return load_catalog("config/targets/donkai_challenges.yaml")
    if "aivp" in (target_name + base_url).lower():
        return load_catalog("config/targets/aivp_labs.yaml")

    return None
