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
            from pyrit_ai300.reconnaissance.target_profile import TargetProfile
            profile = TargetProfile.load(profile_path)
            return ProfileLoader._to_smartmatcher_params(profile)
        except Exception as e:
            logger.error("Failed to load profile: %s", str(e))
            return ProfileLoader._default_params()

    @staticmethod
    def _to_smartmatcher_params(profile) -> Dict[str, Any]:
        """将 TargetProfile 转换为 SmartMatcher 参数"""
        params = {
            # 目标信息
            "target_model": profile.fingerprint.model_name,
            "target_family": profile.fingerprint.model_family,
            "target_provider": profile.fingerprint.provider,
            "target_endpoint": profile.target if profile.target.startswith("http") else None,
            "context_window": profile.fingerprint.context_window,

            # 攻击面
            "surfaces": profile.surfaces,

            # 已知漏洞
            "known_vulnerabilities": [
                {
                    "category": v.category,
                    "severity": v.severity,
                    "owasp_mapping": v.owasp_mapping,
                    "confidence": v.confidence,
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

        # 基于漏洞类别推荐攻击探针族
        params["preferred_probe_families"] = ProfileLoader._suggest_probe_families(profile)

        # 基于风险等级调整攻击强度
        params["aggression_level"] = ProfileLoader._risk_to_aggression(profile.risk_level)

        return params

    @staticmethod
    def _suggest_probe_families(profile) -> List[str]:
        """基于漏洞类别推荐攻击探针族"""
        families = set()
        categories = {v.category for v in profile.vulnerabilities}

        if "prompt_injection" in categories:
            families.add("DIRECT_SINGLE")
        if "jailbreak" in categories:
            families.add("PROGRESSIVE")
        if "leakage" in categories:
            families.add("EXPLORATORY")
        if "context_overflow" in categories:
            families.add("TREE_SEARCH")

        # 基于攻击面
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
