# -*- coding: utf-8 -*-
"""
AI-300 Framework - Profile Merger
多工具结果合并器：将多个适配器的输出合并为统一的 TargetProfile

设计原则：
- 去重：相似发现合并
- 加权：不同工具置信度不同
- 归一化：统一输出格式
"""

from __future__ import annotations

import sys
import os
import logging
from typing import Any, Dict, List, Optional

from .target_profile import TargetProfile, FingerprintData, VulnerabilityFinding
from .adapters.base_adapter import AdapterResult

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

logger = logging.getLogger(__name__)


class ProfileMerger:
    """
    多工具结果合并器

    将多个 AdapterResult 合并为统一的 TargetProfile。
    支持置信度加权和去重。
    """

    # 默认置信度权重
    DEFAULT_WEIGHTS: Dict[str, float] = {
        "garak": 0.85,
        "deepteam": 0.85,
    }

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        """
        Args:
            weights: 自定义置信度权重
        """
        self.weights = weights or self.DEFAULT_WEIGHTS

    def merge(self, target: str, results: List[AdapterResult], depth: str = "standard") -> TargetProfile:
        """
        合并多个适配器结果为 TargetProfile

        Args:
            target: 目标 URL/endpoint
            results: 各适配器结果列表
            depth: 侦察深度

        Returns:
            合并后的 TargetProfile
        """
        profile = TargetProfile(target=target, recon_depth=depth)

        # 记录使用的工具
        profile.tools_used = [r.tool for r in results if r.success]

        # 合并原始结果
        for result in results:
            if result.success:
                profile.raw_results[result.tool] = result.to_dict()

        # 合并指纹信息
        self._merge_fingerprint(profile, results)

        # 合并漏洞发现
        self._merge_vulnerabilities(profile, results)

        # 合并攻击面
        self._merge_surfaces(profile, results)

        # 计算风险等级
        profile.risk_level = self._calculate_risk(profile)

        # 生成攻击建议
        profile.attack_recommendations = self._generate_recommendations(profile)

        return profile

    def _merge_fingerprint(self, profile: TargetProfile, results: List[AdapterResult]) -> None:
        """合并指纹信息"""
        for result in results:
            if not result.success:
                continue
            data = result.data

            # 从任意工具结果中提取指纹数据
            if not profile.fingerprint.model_name and data.get("model_name"):
                profile.fingerprint.model_name = data["model_name"]
            if not profile.fingerprint.model_family and data.get("model_family"):
                profile.fingerprint.model_family = data["model_family"]
            if not profile.fingerprint.provider and data.get("provider"):
                profile.fingerprint.provider = data["provider"]
            if not profile.fingerprint.context_window and data.get("context_window"):
                profile.fingerprint.context_window = data["context_window"]
            if not profile.fingerprint.system_prompt and data.get("system_prompt"):
                profile.fingerprint.system_prompt = data["system_prompt"]
            if data.get("capabilities"):
                profile.fingerprint.capabilities.extend(data["capabilities"])
            if data.get("detected_filters"):
                profile.fingerprint.detected_filters.extend(data["detected_filters"])
            if result.tool in self.weights:
                profile.fingerprint.confidence = self.weights[result.tool]

    def _merge_vulnerabilities(self, profile: TargetProfile, results: List[AdapterResult]) -> None:
        """合并漏洞发现（去重 + 加权）"""
        all_findings: List[VulnerabilityFinding] = []

        for result in results:
            if not result.success:
                continue
            weight = self.weights.get(result.tool, 0.5)

            for finding_data in result.findings:
                finding = VulnerabilityFinding(
                    tool=result.tool,
                    category=finding_data.get("category", "unknown"),
                    severity=finding_data.get("severity", "medium"),
                    description=finding_data.get("description", ""),
                    evidence=finding_data.get("evidence", ""),
                    owasp_mapping=finding_data.get("owasp_mapping", ""),
                    confidence=weight * finding_data.get("confidence", 0.5),
                )
                all_findings.append(finding)

        # 去重：相同 category + description 前缀视为重复
        profile.vulnerabilities = self._deduplicate_findings(all_findings)

    def _merge_surfaces(self, profile: TargetProfile, results: List[AdapterResult]) -> None:
        """合并攻击面信息"""
        surfaces_set = set()
        for result in results:
            if not result.success:
                continue
            for surface in result.data.get("surfaces", []):
                surfaces_set.add(surface)
        profile.surfaces = list(surfaces_set)

    def _deduplicate_findings(self, findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        """去重：相同 category + 相似描述合并"""
        if not findings:
            return []

        unique: List[VulnerabilityFinding] = []
        seen: set = set()

        for finding in findings:
            # 生成去重键（category + 描述前50字符）
            key = f"{finding.category}:{finding.description[:50].lower()}"
            if key not in seen:
                seen.add(key)
                unique.append(finding)
            else:
                # 合并：提升置信度
                for existing in unique:
                    key_existing = f"{existing.category}:{existing.description[:50].lower()}"
                    if key_existing == key:
                        existing.confidence = max(existing.confidence, finding.confidence)
                        if finding.evidence and not existing.evidence:
                            existing.evidence = finding.evidence
                        break

        return unique

    def _calculate_risk(self, profile: TargetProfile) -> str:
        """计算综合风险等级"""
        critical = profile.critical_count
        high = profile.high_count
        total = profile.vulnerability_count

        if critical >= 2 or (critical >= 1 and high >= 2):
            return "critical"
        elif critical >= 1 or high >= 2:
            return "high"
        elif high >= 1 or total >= 3:
            return "medium"
        elif total >= 1:
            return "low"
        else:
            return "unknown"

    def _generate_recommendations(self, profile: TargetProfile) -> List[str]:
        """基于发现生成攻击建议"""
        recommendations = []

        # 基于漏洞类别推荐攻击策略
        categories = {v.category for v in profile.vulnerabilities}

        if "prompt_injection" in categories:
            recommendations.append("优先使用直接注入攻击（DIRECT_SINGLE）")
        if "jailbreak" in categories:
            recommendations.append("使用多轮渐进攻击（PROGRESSIVE）")
        if "leakage" in categories:
            recommendations.append("尝试系统提示泄露攻击（EXPLORATORY）")
        if "rag" in categories:
            recommendations.append("针对 RAG 投毒攻击")
        if "mcp" in categories:
            recommendations.append("针对 MCP 协议的攻击")

        # 基于攻击面推荐
        if "agent" in profile.surfaces:
            recommendations.append("目标为 Agent，使用多轮树搜索攻击（TREE_SEARCH）")
        if "rag" in profile.surfaces:
            recommendations.append("目标包含 RAG，增加上下文溢出攻击")

        if not recommendations:
            recommendations.append("使用标准攻击链（Fallback Chain）")

        return recommendations
