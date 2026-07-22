# -*- coding: utf-8 -*-
"""
AI-300 Framework - Profile Loader
画像加载器：读取 TargetProfile JSON → SmartMatcher 参数

设计原则：
- 纯读取，不修改 TargetProfile
- 输出 SmartMatcher 可直接使用的参数字典
- 容错：Profile 缺失时使用默认值
"""

from __future__ import annotations

import sys
import os
import logging
from pathlib import Path
from typing import Any, Dict, List

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

logger = logging.getLogger(__name__)


def _get_alternative_families(owasp_id: str) -> List[str]:
    """
    获取 OWASP ID 的备选攻击探针族

    当存在冲突时，除了主探针族外还激活备选族，
    确保覆盖多种攻击路径。
    """
    ALTERNATIVE_MAP = {
        "LLM01": ["PROGRESSIVE"],       # Injection 备选渐进
        "LLM02": ["DIRECT_SINGLE"],     # Leakage 备选直接
        "LLM03": ["DIRECT_SINGLE"],     # Poisoning 备选直接
        "LLM04": ["PROGRESSIVE"],       # Insecure Output 备选渐进
        "LLM05": ["TREE_SEARCH"],       # Excessive Agency 备选树搜索
        "LLM06": ["DIRECT_SINGLE"],     # System Prompt 备选直接
        "LLM07": ["PROGRESSIVE"],       # RAG 备选渐进
        "LLM08": ["EXPLORATORY"],       # Bias 备选探索
        "LLM09": ["DIRECT_SINGLE"],     # Overreliance 备选直接
        "LLM10": ["EXPLORATORY"],       # Model Theft 备选探索
        "ASI01": ["TREE_SEARCH"],       # Goal Hijack 备选树搜索
        "ASI02": ["PROGRESSIVE"],       # Recursive Hijack 备选渐进
        "ASI03": ["TREE_SEARCH"],       # Tool Abuse 备选树搜索
        "ASI04": ["PROGRESSIVE"],       # Identity Abuse 备选渐进
    }
    return ALTERNATIVE_MAP.get(owasp_id, ["DIRECT_SINGLE"])


class ProfileLoader:
    """
    TargetProfile 加载器

    读取侦察引擎产出的 TargetProfile JSON，
    转换为 SmartMatcher 可用的参数字典。
    """

    @staticmethod
    def load(profile_path: str) -> Dict[str, Any]:
        """
        加载 TargetProfile 并转换为 SmartMatcher 参数

        Args:
            profile_path: TargetProfile JSON 文件路径

        Returns:
            SmartMatcher 参数字典
        """
        if not profile_path or not Path(profile_path).exists():
            logger.debug("No profile found at %s, using defaults", profile_path)
            return ProfileLoader._default_params()

        try:
            from pyrit_ai300.recon.target_profile import TargetProfile
            profile = TargetProfile.load(profile_path)
            return ProfileLoader._to_smartmatcher_params(profile)
        except Exception as e:
            logger.error("Failed to load profile: %s", str(e))
            return ProfileLoader._default_params()

    @staticmethod
    def _to_smartmatcher_params(profile) -> Dict[str, Any]:
        """将 TargetProfile 转换为 SmartMatcher 参数"""
        from pyrit_ai300.recon.owasp_taxonomy import OwaspTaxonomy

        params = {
            # 目标信息
            "target_model": profile.fingerprint.model_name,
            "target_family": profile.fingerprint.model_family,
            "target_provider": profile.fingerprint.provider,
            "target_endpoint": profile.target if profile.target.startswith("http") else None,
            "context_window": profile.fingerprint.context_window,

            # 攻击面
            "surfaces": profile.surfaces,

            # 已知漏洞（含 OWASP 对齐信息）
            "known_vulnerabilities": [
                {
                    "category": v.category,
                    "severity": v.severity,
                    "owasp_mapping": v.owasp_mapping,
                    "confidence": v.confidence,
                    "source_tools": v.source_tools,
                    "conflict": v.conflict,
                }
                for v in profile.vulnerabilities
            ],

            # 攻击建议
            "attack_recommendations": profile.attack_recommendations,

            # 风险等级
            "risk_level": profile.risk_level,

            # 能力信息
            "capabilities": profile.fingerprint.capabilities,
            "detected_filters": profile.fingerprint.detected_filters,
        }

        # 基于 OWASP ID 推荐攻击探针族
        params["preferred_probe_families"] = ProfileLoader._suggest_probe_families(profile)

        # 基于风险等级调整攻击强度
        params["aggression_level"] = ProfileLoader._risk_to_aggression(profile.risk_level)

        # 冲突信息：存在冲突时，SmartMatcher 应激活多个探针族
        params["has_conflicts"] = any(v.conflict for v in profile.vulnerabilities)
        params["conflict_owasp_ids"] = [
            v.owasp_mapping for v in profile.vulnerabilities if v.conflict
        ]

        return params

    @staticmethod
    def _suggest_probe_families(profile) -> List[str]:
        """基于 OWASP ID 推荐攻击探针族"""
        from pyrit_ai300.recon.owasp_taxonomy import OwaspTaxonomy

        families = set()

        # 基于 OWASP ID 映射探针族
        for v in profile.vulnerabilities:
            owasp_id = v.owasp_mapping
            # 兜底：如果没有 owasp_mapping，从 category 推导
            if not owasp_id and v.category:
                owasp_id = OwaspTaxonomy.normalize(v.category, tool=v.tool)

            if owasp_id:
                family = OwaspTaxonomy.get_probe_family(owasp_id)
                families.add(family)

                # 冲突漏洞：额外激活备选探针族
                if v.conflict:
                    families.update(_get_alternative_families(owasp_id))

        # 基于攻击面补充
        if "agent" in profile.surfaces:
            families.add("TREE_SEARCH")
        if "rag" in profile.surfaces:
            families.add("ITERATIVE")

        if not families:
            families.add("DIRECT_SINGLE")

        return list(families)

    @staticmethod
    def _risk_to_aggression(risk_level: str) -> str:
        """风险等级映射到攻击强度"""
        mapping = {
            "critical": "high",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "unknown": "medium",
        }
        return mapping.get(risk_level, "medium")

    @staticmethod
    def _default_params() -> Dict[str, Any]:
        """默认参数（无 Profile 时使用）"""
        return {
            "target_model": None,
            "target_family": None,
            "target_provider": None,
            "context_window": None,
            "surfaces": [],
            "known_vulnerabilities": [],
            "attack_recommendations": [],
            "risk_level": "unknown",
            "capabilities": [],
            "detected_filters": [],
            "preferred_probe_families": ["DIRECT_SINGLE"],
            "aggression_level": "medium",
        }
