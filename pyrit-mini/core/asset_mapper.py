"""core/asset_mapper.py — 测试资产映射器 (v2).

基于 MITRE ATLAS 框架的上下文感知资产映射.

迁移说明:
    v61 从 data/asset_mapper.py 迁来, 符合架构蓝图 D-13 要求:
    data/ 层只保留声明式资产, 代码迁至 core/ 或对应阶段层.

理论依据:
  - NIST SP 800-115: 基于威胁模型的测试用例选择
  - MITRE ATLAS v4.2: 攻击面→TTP映射
  - HarmBench (arXiv:2402.04249): 评分器选择标准化

设计原则:
  1. 静态映射优先, 统计增强为辅
  2. 向后兼容: 协同层作为可选增强
  3. 可验证: 每个决策点可独立测试
  4. 最小依赖: 仅依赖 YAML 配置

使用方式:
    from core.asset_mapper import AssetMapper
    mapper = AssetMapper()

    # Burp 文件 → 种子列表
    seeds = mapper.get_seeds_for_burp_profile("mcp05")

    # 攻击面类型 → 评分器
    scorer = mapper.get_scorer_for_attack_surface("mcp_server")
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class AssetMapper:
    """资产映射器 — 提供 Burp→Seed, Seed→Scorer 协同映射."""

    def __init__(self, asset_index: dict[str, Any] | None = None):
        """
        初始化资产映射器.

        Args:
            asset_index: 可选的资产索引字典. 默认从 data/asset_index.yaml 加载.
        """
        if asset_index is not None:
            self._index = asset_index
        else:
            self._index = self._load_default_index()

        self._seeds_cfg = self._index.get("assets", {}).get("seeds", {})
        self._scorers_cfg = self._index.get("assets", {}).get("scorers", {})
        self._surface_mapping = self._index.get("attack_surface_seed_mapping", {})
        self._burp_rules = self._index.get("burp_profile_rules", {}).get("patterns", [])

    @staticmethod
    def _load_default_index() -> dict[str, Any]:
        """加载默认 asset_index.yaml."""
        # v61: 迁移到 core/, 使用绝对路径加载
        import yaml
        from pathlib import Path
        index_path = Path(__file__).resolve().parent.parent / "data" / "asset_index.yaml"
        if not index_path.exists():
            logger.warning("asset_index.yaml not found at %s", index_path)
            return {}
        with open(index_path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    # ──────────────────────────────────────────────
    # Burp Profile → 攻击面类型
    # ──────────────────────────────────────────────
    def classify_attack_surface(self, burp_profile_name: str) -> str:
        """根据 Burp 配置文件名推断攻击面类型.

        匹配规则 (按优先级):
          1. 明确匹配 (精确文件名)
          2. 关键词匹配 (子串)
          3. 默认: standard_llm_api

        Args:
            burp_profile_name: Burp 配置文件名 (如 "mcp05", "mocka")

        Returns:
            攻击面类型字符串 (如 "mcp_server", "standard_llm_api")
        """
        profile_lower = burp_profile_name.lower()

        # 按规则顺序匹配
        for rule in self._burp_rules:
            patterns = rule.get("patterns", [])
            match_type = rule.get("match_type", "filename_contains")
            attack_surface = rule.get("attack_surface", "standard_llm_api")

            if match_type == "filename_contains":
                for pattern in patterns:
                    if pattern.lower() in profile_lower:
                        logger.debug(
                            "Burp profile '%s' matched rule '%s' via pattern '%s' → %s",
                            burp_profile_name, rule.get("name"), pattern, attack_surface,
                        )
                        return attack_surface

        # 默认回退
        logger.debug(
            "Burp profile '%s' did not match any rule, defaulting to standard_llm_api",
            burp_profile_name,
        )
        return "standard_llm_api"

    # ──────────────────────────────────────────────
    # 攻击面类型 → 种子列表
    # ──────────────────────────────────────────────
    def get_seeds_for_attack_surface(self, attack_surface: str) -> list[str]:
        """获取指定攻击面类型的推荐种子列表.

        Args:
            attack_surface: 攻击面类型 (如 "mcp_server", "rag_system")

        Returns:
            种子资源名称列表 (如 ["mcp_tool_enum", "mcp_server_injection"])
        """
        mapping = self._surface_mapping.get(attack_surface)
        if not mapping:
            logger.warning(
                "No seed mapping for attack_surface='%s', falling back to standard_llm_api",
                attack_surface,
            )
            mapping = self._surface_mapping.get("standard_llm_api")

        if not mapping:
            logger.error("No fallback seed mapping found!")
            return []

        seeds = mapping.get("seeds", [])
        logger.debug(
            "Attack surface '%s' mapped to %d seeds (priority=%s)",
            attack_surface, len(seeds), mapping.get("priority"),
        )
        return seeds

    def get_seeds_for_burp_profile(self, burp_profile_name: str) -> list[str]:
        """Burp 配置文件 → 种子列表 (便捷方法).

        Args:
            burp_profile_name: Burp 配置文件名 (如 "mcp05")

        Returns:
            种子资源名称列表
        """
        attack_surface = self.classify_attack_surface(burp_profile_name)
        return self.get_seeds_for_attack_surface(attack_surface)

    # ──────────────────────────────────────────────
    # 攻击面类型 → 评分器
    # ──────────────────────────────────────────────
    def get_scorer_for_attack_surface(self, attack_surface: str) -> str | None:
        """获取指定攻击面类型的推荐评分器.

        Args:
            attack_surface: 攻击面类型

        Returns:
            评分器资源名称 (如 "web_vuln_detected")
        """
        mapping = self._surface_mapping.get(attack_surface)
        if not mapping:
            return None
        return mapping.get("scorer")

    def get_scorer_path(self, scorer_name: str) -> str | None:
        """获取评分器配置文件路径.

        Args:
            scorer_name: 评分器名称 (如 "web_vuln_detected")

        Returns:
            评分器配置文件路径 (如 "scorers/web_vuln_detected.yaml")
        """
        scorer_cfg = self._scorers_cfg.get(scorer_name)
        if not scorer_cfg:
            logger.warning("Scorer '%s' not found in asset_index", scorer_name)
            return None
        return scorer_cfg.get("path")

    # ──────────────────────────────────────────────
    # 种子路径 → 实际文件路径
    # ──────────────────────────────────────────────
    def get_seed_file_path(self, seed_name: str) -> str | None:
        """获取种子文件的实际路径.

        Args:
            seed_name: 种子资源名称 (如 "mcp_tool_enum")

        Returns:
            种子文件相对路径 (如 "_attack_surface/T1_ASI02_mcp_full_surface/mcp_tool_enum")
        """
        seed_cfg = self._seeds_cfg.get(seed_name)
        if not seed_cfg:
            logger.warning("Seed '%s' not found in asset_index", seed_name)
            return None
        return seed_cfg.get("path")

    def get_seed_tier(self, seed_name: str) -> int | None:
        """获取种子的 tier 级别.

        Args:
            seed_name: 种子资源名称

        Returns:
            tier 级别 (1/2/3) 或 None
        """
        seed_cfg = self._seeds_cfg.get(seed_name)
        if not seed_cfg:
            return None
        return seed_cfg.get("tier")

    def get_seed_category(self, seed_name: str) -> str | None:
        """获取种子的攻击类别.

        Args:
            seed_name: 种子资源名称

        Returns:
            攻击类别字符串
        """
        seed_cfg = self._seeds_cfg.get(seed_name)
        if not seed_cfg:
            return None
        return seed_cfg.get("category")

    # ──────────────────────────────────────────────
    # 全链路协同
    # ──────────────────────────────────────────────
    def get_full_synergy_config(self, burp_profile_name: str) -> dict[str, Any]:
        """Burp 配置文件 → 完整协同配置 (便捷方法).

        Args:
            burp_profile_name: Burp 配置文件名

        Returns:
            完整配置字典:
            {
                "burp_profile": str,
                "attack_surface": str,
                "seeds": list[str],       # 种子名称列表
                "scorer": str,            # 评分器名称
                "scorer_path": str,       # 评分器文件路径
            }
        """
        attack_surface = self.classify_attack_surface(burp_profile_name)
        seeds = self.get_seeds_for_attack_surface(attack_surface)
        scorer = self.get_scorer_for_attack_surface(attack_surface)
        scorer_path = self.get_scorer_path(scorer) if scorer else None

        return {
            "burp_profile": burp_profile_name,
            "attack_surface": attack_surface,
            "seeds": seeds,
            "scorer": scorer,
            "scorer_path": scorer_path,
        }


# ──────────────────────────────────────────────
# 全局单例 (延迟加载)
# ──────────────────────────────────────────────
_default_mapper: AssetMapper | None = None


def get_default_mapper() -> AssetMapper:
    """获取全局默认 AssetMapper 实例."""
    global _default_mapper
    if _default_mapper is None:
        _default_mapper = AssetMapper()
    return _default_mapper


# 便捷函数 (直接使用全局单例)
def get_seeds_for_burp(burp_profile_name: str) -> list[str]:
    """便捷函数: Burp → 种子列表."""
    return get_default_mapper().get_seeds_for_burp_profile(burp_profile_name)


def get_scorer_for_burp(burp_profile_name: str) -> str | None:
    """便捷函数: Burp → 评分器."""
    mapper = get_default_mapper()
    surface = mapper.classify_attack_surface(burp_profile_name)
    return mapper.get_scorer_for_attack_surface(surface)


def get_synergy_config(burp_profile_name: str) -> dict[str, Any]:
    """便捷函数: 完整协同配置."""
    return get_default_mapper().get_full_synergy_config(burp_profile_name)
