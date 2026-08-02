# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""攻击推荐器 — 基于侦察结果推荐 PyRIT 攻击策略。.

将 ReconResult 中的发现映射到 PyRIT 原生攻击策略:
  - Agent 工具调用端点 → XPIAWorkflow (间接注入)
  - RAG API 端点 → XPIAWorkflow (知识库投毒)
  - 向量数据库端点 → 向量库未授权访问 + 知识库投毒 (指纹增强)
  - 文件上传表单 → XPIAWorkflow + AzureBlobStorageTarget
  - Model API 端点 → PromptSendingAttack / RedTeamingAttack
  - 多模态输入面 → MultimodalInjection (PyRIT 原生 Converter + Target)
  - Model API (提取) → ModelExtraction (HTTPTarget)
  - Agent 工具面板 → 过度代理探测 (ToolPermissionMatrix)

设计原则 (R-010: PyRIT 原生优先):
  所有推荐的攻击策略优先映射到 PyRIT 原生 Target/Workflow/Attack。
  仅当 PyRIT 原生无法覆盖时, 才推荐自研场景。

> **日期**: 2026-8-2
"""

from __future__ import annotations

import logging
from typing import Any

from core.probes.recon_result import (
    AttackRecommendation,
    DiscoveredEndpoint,
    EndpointType,
    InjectionSurface,
    InjectionSurfaceType,
    ReconResult,
)

logger = logging.getLogger(__name__)


class AttackRecommender:
    """攻击推荐器。.

    根据 ReconResult 中的端点和注入面发现,
    生成按优先级排序的攻击推荐列表。

    用法::
        recommender = AttackRecommender()
        recommendations = recommender.recommend(recon_result)
    """

    def recommend(self, recon_result: ReconResult) -> list[AttackRecommendation]:
        """生成攻击推荐。.

        Args:
            recon_result: 完整侦察结果。

        Returns:
            按优先级排序的 AttackRecommendation 列表。
        """
        recommendations: list[AttackRecommendation] = []

        # 按端点类型生成推荐
        for endpoint in recon_result.endpoints:
            rec = self._recommend_from_endpoint(endpoint)
            if rec and rec not in recommendations:
                recommendations.append(rec)

        # 按注入面类型生成推荐
        for surface in recon_result.injection_surfaces:
            rec = self._recommend_from_surface(surface)
            if rec and rec not in recommendations:
                recommendations.append(rec)

        # 向量数据库指纹识别增强
        # 对 RAG API 端点进行指纹识别, 生成针对性推荐
        from core.probes.vector_db_fingerprinter import VectorDBFingerprinter
        fingerprinter = VectorDBFingerprinter()
        fingerprints = fingerprinter.fingerprint(recon_result.endpoints)
        for fp in fingerprints:
            rec = self._recommend_from_vector_db(fp)
            if rec and rec not in recommendations:
                recommendations.append(rec)

        # 去重: 合并相同 (owasp_id, attack_strategy) 的推荐
        recommendations = self._merge_duplicates(recommendations)

        # 按优先级排序 (1=最高)
        recommendations.sort(key=lambda r: (r.priority, r.owasp_id))

        logger.info(
            f"AttackRecommender: generated {len(recommendations)} recommendations "
            f"from {len(recon_result.endpoints)} endpoints + "
            f"{len(recon_result.injection_surfaces)} surfaces + "
            f"{len(fingerprints)} vector DB fingerprints"
        )
        return recommendations

    def _recommend_from_vector_db(
        self, fingerprint: Any
    ) -> AttackRecommendation | None:
        """根据向量数据库指纹生成推荐。."""
        db_type_name = fingerprint.db_type.value if hasattr(fingerprint.db_type, "value") else str(fingerprint.db_type)

        if fingerprint.unauthorized_access_likely:
            return AttackRecommendation(
                owasp_id="LLM08",
                attack_strategy="unauthorized_vector_db_access",
                target_type="HTTPTarget",
                rationale=(
                    f"发现 {db_type_name} 向量数据库端点且可能存在未授权访问 — "
                    f"可直接查询/修改向量数据, 置入恶意文档触发 RAG 注入"
                ),
                priority=1,
                related_endpoints=[fingerprint.endpoint_url],
            )

        return AttackRecommendation(
            owasp_id="LLM08",
            attack_strategy="xpia_workflow",
            target_type="AzureBlobStorageTarget",
            converter="TextJailbreakConverter",
            rationale=(
                f"发现 {db_type_name} 向量数据库 — 可通过 XPIA 工作流投递恶意文档, "
                f"当 RAG 系统检索到该文档时触发间接注入"
            ),
            priority=2,
            related_endpoints=[fingerprint.endpoint_url],
        )

    def _recommend_from_endpoint(
        self, endpoint: DiscoveredEndpoint
    ) -> AttackRecommendation | None:
        """根据发现的端点生成推荐。."""
        if endpoint.endpoint_type == EndpointType.AGENT_TOOL_API:
            return AttackRecommendation(
                owasp_id="LLM01",
                attack_strategy="xpia_workflow",
                target_type="AzureBlobStorageTarget",
                converter="TextJailbreakConverter",
                rationale=(
                    "发现 Agent 工具调用端点 — 可通过 XPIA 工作流投递恶意内容, "
                    "当 Agent 调用工具获取内容时触发间接注入"
                ),
                priority=1,
                related_endpoints=[endpoint.url],
            )

        if endpoint.endpoint_type == EndpointType.RAG_API:
            # RAG API 端点同时推荐向量操纵策略
            return AttackRecommendation(
                owasp_id="LLM08",
                attack_strategy="xpia_workflow",
                target_type="AzureBlobStorageTarget",
                converter="TextJailbreakConverter",
                rationale=(
                    "发现 RAG API 端点 — 可通过 XPIA 工作流向知识库投毒, "
                    "当 RAG 系统检索到恶意文档时触发间接注入; "
                    "同时建议执行向量相似度操纵 (keyword stacking / GCG suffix) "
                    "劫持检索结果"
                ),
                priority=1,
                related_endpoints=[endpoint.url],
            )

        if endpoint.endpoint_type == EndpointType.MODEL_API:
            # Model API 产生两条推荐: 标准攻击 + 模型提取
            return AttackRecommendation(
                owasp_id="LLM01",
                attack_strategy="prompt_sending",
                target_type="HTTPTarget",
                rationale=(
                    "发现 Model API 端点 — 可直接发送攻击 prompt "
                    "(配合 Converter 路由增强)"
                ),
                priority=2,
                related_endpoints=[endpoint.url],
            )

        if endpoint.endpoint_type == EndpointType.FILE_UPLOAD:
            return AttackRecommendation(
                owasp_id="LLM04",
                attack_strategy="xpia_workflow",
                target_type="HTTPTarget",
                converter="TextJailbreakConverter",
                rationale=(
                    "发现文件上传端点 — 可上传含恶意指令的文档, "
                    "当 LLM 系统处理该文档时触发间接注入"
                ),
                priority=2,
                related_endpoints=[endpoint.url],
            )

        return None

    def _recommend_from_surface(
        self, surface: InjectionSurface
    ) -> AttackRecommendation | None:
        """根据发现的注入面生成推荐。."""
        if surface.surface_type == InjectionSurfaceType.FILE_UPLOAD_FORM:
            return AttackRecommendation(
                owasp_id="LLM04",
                attack_strategy="xpia_workflow",
                target_type="PlaywrightTarget",
                converter="TextJailbreakConverter",
                rationale=(
                    "发现文件上传表单 — 可通过浏览器上传含恶意指令的文档, "
                    "触发知识库投毒"
                ),
                priority=1,
                related_surfaces=[surface.selector],
            )

        if surface.surface_type == InjectionSurfaceType.MULTIMODAL_INPUT:
            return AttackRecommendation(
                owasp_id="LLM01",
                attack_strategy="multimodal_injection",
                target_type="PlaywrightTarget",
                converter="AddImageTextConverter",
                rationale=(
                    "发现多模态输入面 — 可通过图像中嵌入隐藏提示词, "
                    "绕过文本内容过滤器"
                ),
                priority=2,
                related_surfaces=[surface.selector],
            )

        if surface.surface_type == InjectionSurfaceType.AGENT_TOOL_PANEL:
            return AttackRecommendation(
                owasp_id="LLM06",
                attack_strategy="xpia_workflow",
                target_type="PlaywrightTarget",
                rationale=(
                    "发现 Agent 工具面板 — 可通过间接注入操控 Agent "
                    "执行未授权操作 (过度代理)"
                ),
                priority=1,
                related_surfaces=[surface.selector],
            )

        if surface.surface_type == InjectionSurfaceType.CHAT_INPUT:
            return AttackRecommendation(
                owasp_id="LLM01",
                attack_strategy="prompt_sending",
                target_type="PlaywrightTarget",
                rationale="发现聊天输入框 — 可直接发送攻击 prompt",
                priority=3,
                related_surfaces=[surface.selector],
            )

        return None

    def _merge_duplicates(
        self, recommendations: list[AttackRecommendation]
    ) -> list[AttackRecommendation]:
        """合并相同 (owasp_id, attack_strategy, target_type) 的推荐。."""
        merged: dict[str, AttackRecommendation] = {}
        for rec in recommendations:
            key = f"{rec.owasp_id}:{rec.attack_strategy}:{rec.target_type}"
            if key in merged:
                # 合并关联端点和注入面
                existing = merged[key]
                existing.related_endpoints = list(
                    set(existing.related_endpoints + rec.related_endpoints)
                )
                existing.related_surfaces = list(
                    set(existing.related_surfaces + rec.related_surfaces)
                )
                # 取最低优先级 (最高优先)
                existing.priority = min(existing.priority, rec.priority)
                # 合并理由
                if rec.rationale and rec.rationale not in existing.rationale:
                    existing.rationale = f"{existing.rationale}; {rec.rationale}"
            else:
                merged[key] = AttackRecommendation(
                    owasp_id=rec.owasp_id,
                    attack_strategy=rec.attack_strategy,
                    target_type=rec.target_type,
                    converter=rec.converter,
                    rationale=rec.rationale,
                    priority=rec.priority,
                    related_endpoints=list(rec.related_endpoints),
                    related_surfaces=list(rec.related_surfaces),
                )
        return list(merged.values())