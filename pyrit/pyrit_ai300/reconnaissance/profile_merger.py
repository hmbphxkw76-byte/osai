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
from typing import Dict, List, Optional

from .target_profile import TargetProfile, VulnerabilityFinding
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
        "protocol_fingerprint": 0.90,
        "spa_chat_recon": 0.90,
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

    def merge_incremental(
        self,
        target: str,
        existing_profile: Optional[TargetProfile],
        new_result: AdapterResult,
        depth: str = "standard",
    ) -> TargetProfile:
        """
        增量合并：将新适配器结果合并到现有 TargetProfile

        用于流式侦察模式——每个适配器完成后立即更新画像，
        无需等待全部完成。

        Args:
            target: 目标 URL/endpoint
            existing_profile: 现有 TargetProfile（首次为 None）
            new_result: 新完成的适配器结果
            depth: 侦察深度

        Returns:
            更新后的 TargetProfile
        """
        if existing_profile is None:
            # 首次：用单个结果创建基础画像
            existing_profile = TargetProfile(target=target, recon_depth=depth)

        if not new_result.success:
            return existing_profile

        # 记录工具
        if new_result.tool not in existing_profile.tools_used:
            existing_profile.tools_used.append(new_result.tool)

        # 保存原始结果
        existing_profile.raw_results[new_result.tool] = new_result.to_dict()

        # 增量合并指纹（仅更新空字段）
        self._merge_fingerprint_incremental(existing_profile, new_result)

        # 增量合并漏洞（追加 + 去重）
        self._merge_vulnerabilities_incremental(existing_profile, new_result)

        # 增量合并攻击面
        self._merge_surfaces_incremental(existing_profile, new_result)

        # 重新计算风险等级
        existing_profile.risk_level = self._calculate_risk(existing_profile)

        # 重新生成攻击建议
        existing_profile.attack_recommendations = self._generate_recommendations(existing_profile)

        return existing_profile

    def _merge_fingerprint_incremental(self, profile: TargetProfile, result: AdapterResult) -> None:
        """增量合并指纹信息（仅填充空字段）"""
        data = result.data
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
            for cap in data["capabilities"]:
                if cap not in profile.fingerprint.capabilities:
                    profile.fingerprint.capabilities.append(cap)
        if data.get("detected_filters"):
            for f in data["detected_filters"]:
                if f not in profile.fingerprint.detected_filters:
                    profile.fingerprint.detected_filters.append(f)
        # 置信度取最高
        if result.tool in self.weights:
            profile.fingerprint.confidence = max(
                profile.fingerprint.confidence,
                self.weights[result.tool],
            )

    def _merge_vulnerabilities_incremental(self, profile: TargetProfile, result: AdapterResult) -> None:
        """增量合并漏洞发现（OWASP ID 对齐 + 冲突检测）"""
        from .owasp_taxonomy import OwaspTaxonomy

        weight = self.weights.get(result.tool, 0.5)

        for finding_data in result.findings:
            confidence = weight * finding_data.get("confidence", 0.5)
            owasp_id = finding_data.get("owasp_mapping", "")

            # 如果没有 owasp_mapping，尝试从 category 推导
            if not owasp_id:
                owasp_id = OwaspTaxonomy.normalize(
                    finding_data.get("category", ""),
                    tool=result.tool,
                )

            # 查找是否已有相同 OWASP ID 的发现
            existing = None
            for v in profile.vulnerabilities:
                if v.owasp_mapping and v.owasp_mapping == owasp_id:
                    existing = v
                    break

            if existing:
                # 多工具发现同一 OWASP ID → 冲突解决
                findings_dict = [
                    {
                        "tool": existing.tool,
                        "severity": existing.severity,
                        "confidence": existing.confidence,
                        "description": existing.description,
                    },
                    {
                        "tool": result.tool,
                        "severity": finding_data.get("severity", "medium"),
                        "confidence": confidence,
                        "description": finding_data.get("description", ""),
                    },
                ]
                resolved_severity, resolved_confidence, is_conflict = (
                    OwaspTaxonomy.resolve_conflict(findings_dict)
                )

                existing.severity = resolved_severity
                existing.confidence = resolved_confidence
                existing.conflict = is_conflict
                if result.tool not in existing.source_tools:
                    existing.source_tools.append(result.tool)
                # 更新 evidence（取更详细的）
                new_evidence = finding_data.get("evidence", "")
                if new_evidence and len(new_evidence) > len(existing.evidence):
                    existing.evidence = new_evidence
            else:
                # 新发现
                profile.vulnerabilities.append(VulnerabilityFinding(
                    tool=result.tool,
                    category=finding_data.get("category", "unknown"),
                    severity=finding_data.get("severity", "medium"),
                    description=finding_data.get("description", ""),
                    evidence=finding_data.get("evidence", ""),
                    owasp_mapping=owasp_id,
                    confidence=confidence,
                    source_tools=[result.tool],
                    conflict=False,
                ))

    def _merge_surfaces_incremental(self, profile: TargetProfile, result: AdapterResult) -> None:
        """增量合并攻击面（追加去重）"""
        for surface in result.data.get("surfaces", []):
            if surface not in profile.surfaces:
                profile.surfaces.append(surface)

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
        """合并漏洞发现（OWASP ID 对齐 + 冲突检测 + 置信度融合）"""
        from .owasp_taxonomy import OwaspTaxonomy

        # 第一步：收集所有发现，映射到 OWASP ID
        owasp_findings: dict = {}  # owasp_id → [finding_dicts]
        unmapped_findings: List[VulnerabilityFinding] = []

        for result in results:
            if not result.success:
                continue
            weight = self.weights.get(result.tool, 0.5)

            for finding_data in result.findings:
                confidence = weight * finding_data.get("confidence", 0.5)
                owasp_id = finding_data.get("owasp_mapping", "")

                # 如果没有 owasp_mapping，尝试从 category 推导
                if not owasp_id:
                    owasp_id = OwaspTaxonomy.normalize(
                        finding_data.get("category", ""),
                        tool=result.tool,
                    )

                finding_dict = {
                    "tool": result.tool,
                    "category": finding_data.get("category", "unknown"),
                    "severity": finding_data.get("severity", "medium"),
                    "description": finding_data.get("description", ""),
                    "evidence": finding_data.get("evidence", ""),
                    "owasp_mapping": owasp_id,
                    "confidence": confidence,
                }

                if owasp_id:
                    if owasp_id not in owasp_findings:
                        owasp_findings[owasp_id] = []
                    owasp_findings[owasp_id].append(finding_dict)
                else:
                    # 无法映射到 OWASP ID 的发现，保留原样
                    unmapped_findings.append(VulnerabilityFinding(**finding_dict))

        # 第二步：按 OWASP ID 合并，检测冲突，融合置信度
        merged: List[VulnerabilityFinding] = []

        for owasp_id, findings in owasp_findings.items():
            if len(findings) == 1:
                f = findings[0]
                merged.append(VulnerabilityFinding(
                    tool=f["tool"],
                    category=f["category"],
                    severity=f["severity"],
                    description=f["description"],
                    evidence=f["evidence"],
                    owasp_mapping=owasp_id,
                    confidence=f["confidence"],
                    source_tools=[f["tool"]],
                    conflict=False,
                ))
            else:
                # 多工具发现同一 OWASP ID → 冲突解决
                resolved_severity, resolved_confidence, is_conflict = (
                    OwaspTaxonomy.resolve_conflict(findings)
                )

                # 合并 evidence（取最长的）
                best_evidence = max(
                    (f["evidence"] for f in findings if f["evidence"]),
                    key=len,
                    default="",
                )

                # 合并 description（取最详细的）
                best_description = max(
                    (f["description"] for f in findings if f["description"]),
                    key=len,
                    default="",
                )

                # 取最具代表性的 category（出现次数最多的）
                from collections import Counter
                category_counter = Counter(f["category"] for f in findings)
                representative_category = category_counter.most_common(1)[0][0]

                merged.append(VulnerabilityFinding(
                    tool=findings[0]["tool"],  # 主工具（最高置信度）
                    category=representative_category,
                    severity=resolved_severity,
                    description=best_description,
                    evidence=best_evidence,
                    owasp_mapping=owasp_id,
                    confidence=resolved_confidence,
                    source_tools=[f["tool"] for f in findings],
                    conflict=is_conflict,
                ))

        # 第三步：合并且非 OWASP 映射的发现（按 category + description 去重）
        merged.extend(self._deduplicate_findings(unmapped_findings))

        profile.vulnerabilities = merged

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
        """
        去重：相同 category + 相似描述合并（用于无 OWASP 映射的发现）

        OPT-M1 优化（2026-07-19）：使用 Jaccard 相似度进行语义去重，
        阈值 0.80（比載荷去重更宽松，因为漏洞描述更结构化）。
        保留原有的前缀匹配作为快速路径。
        """
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
                        if finding.tool not in existing.source_tools:
                            existing.source_tools.append(finding.tool)
                        break

        # OPT-M1: Jaccard 语义去重（二次去重，去除前缀不同但语义相同的发现）
        unique = self._jaccard_dedup(unique, threshold=0.80)

        return unique

    @staticmethod
    def _jaccard_dedup(
        findings: List[VulnerabilityFinding],
        threshold: float = 0.80,
    ) -> List[VulnerabilityFinding]:
        """
        Jaccard 语义去重（OPT-M1）

        对同一 category 的发现，使用 Jaccard 相似度检测语义重复。
        相似度 >= threshold 的发现合并为一个。
        """
        if len(findings) <= 1:
            return findings

        result: List[VulnerabilityFinding] = []

        for finding in findings:
            merged = False
            for existing in result:
                # 仅对相同 category 进行 Jaccard 比较
                if existing.category != finding.category:
                    continue

                # 计算 Jaccard 相似度
                sim = ProfileMerger._jaccard_similarity(
                    existing.description.lower(),
                    finding.description.lower(),
                )

                if sim >= threshold:
                    # 合并：取更高置信度 + 更长 evidence
                    existing.confidence = max(existing.confidence, finding.confidence)
                    if len(finding.evidence) > len(existing.evidence):
                        existing.evidence = finding.evidence
                    if finding.tool not in existing.source_tools:
                        existing.source_tools.append(finding.tool)
                    merged = True
                    break

            if not merged:
                result.append(finding)

        return result

    @staticmethod
    def _jaccard_similarity(s1: str, s2: str) -> float:
        """计算两个字符串的 Jaccard 相似度（基于词集）"""
        # 分词（按空格 + 标点）
        import re
        words1 = set(re.findall(r"[a-z0-9_]+", s1))
        words2 = set(re.findall(r"[a-z0-9_]+", s2))

        if not words1 and not words2:
            return 1.0
        if not words1 or not words2:
            return 0.0

        intersection = words1 & words2
        union = words1 | words2
        return len(intersection) / len(union) if union else 0.0

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
        """
        基于完整画像动态生成攻击建议（OPT-M2 优化）

        增强：
        - 基于 OWASP ID 推荐（原有）
        - 基于模型家族推荐（新增）
        - 基于模型能力推荐（新增）
        - 基于攻击面推荐（原有 + 增强）
        - 基于风险等级推荐（新增）
        - 冲突提醒（原有）
        """
        from .owasp_taxonomy import OwaspTaxonomy

        recommendations = []
        owasp_ids = {v.owasp_mapping for v in profile.vulnerabilities if v.owasp_mapping}

        # 基于 OWASP ID 推荐攻击策略
        owasp_recommendations = {
            "LLM01": "LLM01 Prompt Injection → 直接注入攻击（DIRECT_SINGLE）",
            "LLM02": "LLM02 Sensitive Info → 开放式探索（EXPLORATORY）",
            "LLM03": "LLM03 Poisoning → 迭代优化攻击（ITERATIVE）",
            "LLM04": "LLM04 Insecure Output → 直接注入攻击（DIRECT_SINGLE）",
            "LLM05": "LLM05 Excessive Agency → 渐进升级攻击（PROGRESSIVE）",
            "LLM06": "LLM06 System Prompt → 开放式探索（EXPLORATORY）",
            "LLM07": "LLM07 RAG → 树搜索攻击（TREE_SEARCH）",
            "LLM08": "LLM08 Bias → 渐进升级攻击（PROGRESSIVE）",
            "LLM09": "LLM09 Overreliance → 迭代优化攻击（ITERATIVE）",
            "LLM10": "LLM10 Model Theft → 树搜索攻击（TREE_SEARCH）",
            "ASI01": "ASI01 Goal Hijack → 渐进升级攻击（PROGRESSIVE）",
            "ASI02": "ASI02 Recursive Hijack → 树搜索攻击（TREE_SEARCH）",
            "ASI03": "ASI03 Tool Abuse → 渐进升级攻击（PROGRESSIVE）",
            "ASI04": "ASI04 Identity Abuse → 开放式探索（EXPLORATORY）",
        }

        for owasp_id in sorted(owasp_ids):
            if owasp_id in owasp_recommendations:
                recommendations.append(owasp_recommendations[owasp_id])

        # OPT-M2: 基于模型家族推荐
        model_family = (profile.fingerprint.model_family or "").lower()
        if model_family == "llama":
            recommendations.append("Llama 系列对 crescendo 攻击敏感，优先使用 CrescendoAttack")
        elif model_family == "gpt":
            recommendations.append("GPT 系列对 TAP/PAIR 攻击敏感，优先使用 TAP 策略")
        elif model_family == "claude":
            recommendations.append("Claude 系列对多轮渐进攻击敏感，优先使用 PROGRESSIVE 策略")
        elif model_family == "qwen":
            recommendations.append("Qwen 系列对中文越狱载荷敏感，优先使用中文载荷")

        # OPT-M2: 基于模型能力推荐
        capabilities = profile.fingerprint.capabilities or []
        if "function_calling" in capabilities:
            recommendations.append("支持 function calling，增加 ASI03 工具滥用攻击")
        if "vision" in capabilities:
            recommendations.append("支持多模态，增加图像注入攻击（multimodal_injection）")
        if "json_mode" in capabilities:
            recommendations.append("支持 JSON 模式，增加结构化字段注入攻击")
        if "streaming" in capabilities:
            recommendations.append("支持流式响应，增加流式注入检测")

        # 冲突提醒
        conflicts = [v for v in profile.vulnerabilities if v.conflict]
        if conflicts:
            conflict_ids = ", ".join(sorted(set(v.owasp_mapping for v in conflicts)))
            recommendations.append(
                f"⚠ 工具间冲突: {conflict_ids} — 已激活多路径备选策略"
            )

        # 基于攻击面推荐（增强）
        if "agent" in profile.surfaces:
            recommendations.append("目标为 Agent，使用多轮树搜索攻击（TREE_SEARCH）")
        if "rag" in profile.surfaces:
            recommendations.append("目标包含 RAG，增加上下文溢出攻击 + RAG 投毒")
        if "vector" in profile.surfaces:
            recommendations.append("目标包含向量 DB，增加嵌入反演攻击（embedding_inversion）")
        if "mcp" in profile.surfaces:
            recommendations.append("目标包含 MCP，增加 MCP 工具注入 + 能力混淆攻击")
        if "model_extraction" in profile.surfaces:
            recommendations.append("目标可提取模型，增加模型窃取攻击")

        # OPT-M2: 基于风险等级推荐
        if profile.risk_level == "critical":
            recommendations.append("⚠ 高风险目标，启用全量 Fallback 链 + 闭环变异")
        elif profile.risk_level == "high":
            recommendations.append("高风险目标，启用增强 Fallback 链")

        if not recommendations:
            recommendations.append("使用标准攻击链（Fallback Chain）")

        return recommendations
