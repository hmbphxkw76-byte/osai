# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Attack recommender — generates PyRIT attack strategies from recon results.

Maps ReconReport findings to PyRIT native attack strategies:
  - Agent tool endpoints -> XPIAWorkflow (indirect injection)
  - RAG API endpoints -> XPIAWorkflow (knowledge poisoning)
  - Vector DB endpoints -> unauthorized access + knowledge poisoning
  - File upload forms -> XPIAWorkflow + AzureBlobStorageTarget
  - Model API endpoints -> PromptSendingAttack / RedTeamingAttack
  - MCP Server endpoints -> MCP tool enumeration + tool shadowing
  - Embedding API -> embedding vector manipulation
  - LLM fingerprints -> model-specific jailbreak strategies
  - MCP tools -> tool-specific exploitation strategies

Design principle (R-010: PyRIT native first):
  All recommended attack strategies prefer PyRIT native Target/Workflow/Attack.
  Custom scenarios only when PyRIT native cannot cover.

Academic basis:
  - Auto Red Teaming (arXiv:2508.04451): recon results drive automated attack strategy selection
  - OWASP Top 10 for LLMs 2025
"""

from __future__ import annotations

import logging
from typing import Any

from core.models.recon_report import (
    AttackRecommendation,
    DiscoveredEndpoint,
    EndpointType,
    InjectionSurface,
    InjectionSurfaceType,
    LLMFingerprint,
    MCPToolInfo,
    ReconReport,
)

logger = logging.getLogger(__name__)


class AttackRecommender:
    """Attack recommender.

    Generates prioritized attack recommendations from ReconReport
    findings, consuming all available recon data types.

    Usage::
        recommender = AttackRecommender()
        recommendations = recommender.recommend(recon_report)
    """

    def recommend(self, recon_report: ReconReport) -> list[AttackRecommendation]:
        """Generate attack recommendations.

        Args:
            recon_report: Complete reconnaissance report.

        Returns:
            Priority-sorted list of AttackRecommendation.
        """
        recommendations: list[AttackRecommendation] = []

        # 1. From endpoints
        for endpoint in recon_report.endpoints:
            rec = self._recommend_from_endpoint(endpoint)
            if rec and rec not in recommendations:
                recommendations.append(rec)

        # 2. From injection surfaces
        for surface in recon_report.injection_surfaces:
            rec = self._recommend_from_surface(surface)
            if rec and rec not in recommendations:
                recommendations.append(rec)

        # 3. Vector DB fingerprint enhancement
        from core.probes.vector_db_fingerprinter import VectorDBFingerprinter
        fingerprinter = VectorDBFingerprinter()
        fingerprints = fingerprinter.fingerprint(recon_report.endpoints)
        for fp in fingerprints:
            rec = self._recommend_from_vector_db(fp)
            if rec and rec not in recommendations:
                recommendations.append(rec)

        # 4. From LLM fingerprints (NEW)
        for fp in recon_report.llm_fingerprints:
            rec = self._recommend_from_llm_fingerprint(fp)
            if rec and rec not in recommendations:
                recommendations.append(rec)

        # 5. From MCP tools (NEW)
        for tool in recon_report.mcp_tools:
            rec = self._recommend_from_mcp_tool(tool)
            if rec and rec not in recommendations:
                recommendations.append(rec)

        # 6. From embedding info (NEW)
        embedding_info = recon_report.probe_results.get("embedding_info", [])
        for info in embedding_info:
            rec = self._recommend_from_embedding_info(info)
            if rec and rec not in recommendations:
                recommendations.append(rec)

        # Deduplicate and sort
        recommendations = self._merge_duplicates(recommendations)
        recommendations.sort(key=lambda r: (r.priority, r.owasp_id))

        logger.info(
            "AttackRecommender: generated %d recommendations from "
            "%d endpoints + %d surfaces + %d vector DB fingerprints + "
            "%d LLM fingerprints + %d MCP tools + %d embedding infos",
            len(recommendations),
            len(recon_report.endpoints),
            len(recon_report.injection_surfaces),
            len(fingerprints),
            len(recon_report.llm_fingerprints),
            len(recon_report.mcp_tools),
            len(embedding_info),
        )
        return recommendations

    # ── Execution plan (P0-4-F) ──

    def to_execution_plan(
        self,
        recon_report: ReconReport,
        roe_excluded_hosts: list[str] | None = None,
        preferred_tool: str = "pyrit",
    ) -> list[dict[str, Any]]:
        """Convert recommendations into an executable plan (P0-4-F).

        Each entry carries: target, payload_ref, preferred_tool, owasp_id,
        attack_strategy, target_type, roe_gate (whether RoE permits execution).
        """
        from core.safety import RoE, enforce

        roe = RoE(excluded_hosts=roe_excluded_hosts or [])
        recommendations = self.recommend(recon_report)
        plan: list[dict[str, Any]] = []
        for rec in recommendations:
            target = rec.related_endpoints[0] if rec.related_endpoints else recon_report.target_url
            payload_ref = f"{rec.owasp_id}:{rec.attack_strategy}"
            allowed, reason = enforce(rec.owasp_id, target, roe)
            plan.append({
                "target": target,
                "payload_ref": payload_ref,
                "preferred_tool": preferred_tool,
                "owasp_id": rec.owasp_id,
                "attack_strategy": rec.attack_strategy,
                "target_type": rec.target_type,
                "roe_gate": {"allowed": allowed, "reason": reason},
            })
        return plan

    # ── Endpoint-based recommendations ──

    def _recommend_from_endpoint(
        self, endpoint: DiscoveredEndpoint
    ) -> AttackRecommendation | None:
        """Generate recommendation from discovered endpoint."""
        if endpoint.endpoint_type == EndpointType.AGENT_TOOL_API:
            return AttackRecommendation(
                owasp_id="LLM01",
                attack_strategy="xpia_workflow",
                target_type="AzureBlobStorageTarget",
                converter="TextJailbreakConverter",
                rationale=(
                    "发现 Agent 工具调用端点 — 可通过 XPIA 工作流投递恶意内容, "
                    "当 Agent 调用工具获取内容时触发间接注入; 同时建议评估工具权限矩阵与过度代理风险"
                ),
                priority=1,
                related_endpoints=[endpoint.url],
            )

        if endpoint.endpoint_type == EndpointType.RAG_API:
            return AttackRecommendation(
                owasp_id="LLM08",
                attack_strategy="xpia_workflow",
                target_type="AzureBlobStorageTarget",
                converter="TextJailbreakConverter",
                rationale=(
                    "发现 RAG API 端点 — 可通过 XPIA 工作流向知识库投毒, "
                    "当 RAG 系统检索到恶意文档时触发间接注入; "
                    "同时建议执行向量相似度操纵 (keyword stacking / GCG suffix) 劫持检索结果"
                ),
                priority=1,
                related_endpoints=[endpoint.url],
            )

        if endpoint.endpoint_type == EndpointType.MODEL_API:
            return AttackRecommendation(
                owasp_id="LLM01",
                attack_strategy="prompt_sending",
                target_type="HTTPTarget",
                rationale=(
                    "发现 Model API 端点 — 可直接发送攻击 prompt "
                    "(配合 Converter 路由增强); 若响应形状支持多个模型也可执行模型提取或角色切换测试"
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

        if endpoint.endpoint_type == EndpointType.MCP_SERVER:
            return AttackRecommendation(
                owasp_id="LLM06",
                attack_strategy="mcp_tool_enumeration",
                target_type="HTTPTarget",
                rationale=(
                    "发现 MCP Server 端点 — 可通过 JSON-RPC 枚举工具列表 "
                    "(tools/list), 检测 tool shadowing 漏洞 (LLM06/LLM07) 并评估注入面与工具注释矛盾"
                ),
                priority=1,
                related_endpoints=[endpoint.url],
            )

        if endpoint.endpoint_type == EndpointType.EMBEDDING_API:
            return AttackRecommendation(
                owasp_id="LLM08",
                attack_strategy="embedding_manipulation",
                target_type="HTTPTarget",
                rationale=(
                    "发现 Embedding API 端点 — 可通过操纵嵌入向量 "
                    "影响 RAG 检索结果, 或提取模型嵌入维度信息；同时建议与向量库端点做横向关联"
                ),
                priority=2,
                related_endpoints=[endpoint.url],
            )

        return None

    # ── Surface-based recommendations ──

    def _recommend_from_surface(
        self, surface: InjectionSurface
    ) -> AttackRecommendation | None:
        """Generate recommendation from injection surface."""
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

    # ── Vector DB recommendations ──

    def _recommend_from_vector_db(
        self, fingerprint: Any
    ) -> AttackRecommendation | None:
        """Generate recommendation from vector DB fingerprint."""
        db_type_name = (
            fingerprint.db_type.value
            if hasattr(fingerprint.db_type, "value")
            else str(fingerprint.db_type)
        )

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

    # ── LLM fingerprint recommendations (NEW) ──

    def _recommend_from_llm_fingerprint(
        self, fp: LLMFingerprint
    ) -> AttackRecommendation | None:
        """Generate recommendation from LLM fingerprint."""
        model_lower = fp.model_family.lower()

        if "gpt-4" in model_lower or "o1" in model_lower or "o3" in model_lower:
            return AttackRecommendation(
                owasp_id="LLM01",
                attack_strategy="dan_jailbreak",
                target_type="HTTPTarget",
                converter="TextJailbreakConverter",
                rationale=(
                    f"检测到 {fp.model_family} — 可尝试 DAN/角色扮演越狱攻击; "
                    f"若 guardrail={fp.guardrail_detected}, 需先绕过安全护栏"
                ),
                priority=1 if fp.guardrail_detected else 2,
                related_endpoints=[fp.endpoint],
            )

        if "claude" in model_lower:
            return AttackRecommendation(
                owasp_id="LLM01",
                attack_strategy="roleplay_jailbreak",
                target_type="HTTPTarget",
                converter="TextJailbreakConverter",
                rationale=(
                    f"检测到 {fp.model_family} — Claude 对角色扮演越狱较敏感, "
                    f"可尝试多轮对话绕过 / prefix injection / 长上下文溢出"
                ),
                priority=1 if fp.guardrail_detected else 2,
                related_endpoints=[fp.endpoint],
            )

        if "gemini" in model_lower:
            return AttackRecommendation(
                owasp_id="LLM01",
                attack_strategy="multilingual_jailbreak",
                target_type="HTTPTarget",
                converter="TextJailbreakConverter",
                rationale=(
                    f"检测到 {fp.model_family} — Gemini 对多语言越狱较敏感, "
                    f"可尝试非英语 / 混合语言注入绕过安全过滤器"
                ),
                priority=1 if fp.guardrail_detected else 2,
                related_endpoints=[fp.endpoint],
            )

        if fp.guardrail_detected:
            return AttackRecommendation(
                owasp_id="LLM01",
                attack_strategy="guardrail_bypass",
                target_type="HTTPTarget",
                converter="TextJailbreakConverter",
                rationale=(
                    f"检测到 {fp.model_family} 启用了安全护栏 — "
                    f"建议优先测试护栏绕过 (编码/混淆/角色扮演/多语言)"
                ),
                priority=1,
                related_endpoints=[fp.endpoint],
            )

        return None

    # ── MCP tool recommendations (NEW) ──

    def _recommend_from_mcp_tool(
        self, tool: MCPToolInfo
    ) -> AttackRecommendation | None:
        """Generate recommendation from MCP tool."""
        if tool.risk_level == "critical":
            return AttackRecommendation(
                owasp_id="LLM06",
                attack_strategy="excessive_agency",
                target_type="HTTPTarget",
                rationale=(
                    f"MCP 工具 '{tool.tool_name}' 被评为 critical 风险 — "
                    f"可尝试 excessive agency 攻击, 通过间接注入操控该工具执行未授权操作; "
                    f"描述: {tool.description[:100]}"
                ),
                priority=1,
                related_endpoints=[tool.server_url],
            )

        if tool.shadowing_detected:
            return AttackRecommendation(
                owasp_id="LLM07",
                attack_strategy="tool_shadowing",
                target_type="HTTPTarget",
                rationale=(
                    f"MCP 工具 '{tool.tool_name}' 存在 tool shadowing 风险 — "
                    f"多个 server 提供同名工具, 可尝试工具混淆攻击"
                ),
                priority=2,
                related_endpoints=[tool.server_url],
            )

        if tool.annotation_contradiction:
            return AttackRecommendation(
                owasp_id="LLM06",
                attack_strategy="annotation_bypass",
                target_type="HTTPTarget",
                rationale=(
                    f"MCP 工具 '{tool.tool_name}' 存在 annotation 矛盾 — "
                    f"readOnlyHint 但名称暗示 mutation, 可尝试绕过只读限制"
                ),
                priority=2,
                related_endpoints=[tool.server_url],
            )

        if tool.injection_surfaces:
            return AttackRecommendation(
                owasp_id="LLM01",
                attack_strategy="mcp_injection",
                target_type="HTTPTarget",
                rationale=(
                    f"MCP 工具 '{tool.tool_name}' 包含可注入参数: "
                    f"{', '.join(tool.injection_surfaces[:5])} — "
                    f"可通过间接注入操控工具参数执行非预期操作"
                ),
                priority=2,
                related_endpoints=[tool.server_url],
            )

        return None

    # ── Embedding info recommendations (NEW) ──

    def _recommend_from_embedding_info(
        self, info: dict[str, Any]
    ) -> AttackRecommendation | None:
        """Generate recommendation from embedding analysis."""
        dimension = info.get("dimension")
        model = info.get("model", "unknown")

        if dimension:
            return AttackRecommendation(
                owasp_id="LLM08",
                attack_strategy="vector_manipulation",
                target_type="HTTPTarget",
                rationale=(
                    f"检测到嵌入维度: {dimension} (model={model}) — "
                    f"可执行 keyword stacking / GCG suffix 向量操纵攻击, "
                    f"劫持 RAG 检索结果"
                ),
                priority=2,
                related_endpoints=[info.get("url", "")],
            )

        return None

    # ── Deduplication ──

    def _merge_duplicates(
        self, recommendations: list[AttackRecommendation]
    ) -> list[AttackRecommendation]:
        """Merge recommendations with same (owasp_id, attack_strategy, target_type)."""
        merged: dict[str, AttackRecommendation] = {}
        for rec in recommendations:
            key = f"{rec.owasp_id}:{rec.attack_strategy}:{rec.target_type}"
            if key in merged:
                existing = merged[key]
                existing.related_endpoints = list(
                    set(existing.related_endpoints + rec.related_endpoints)
                )
                existing.related_surfaces = list(
                    set(existing.related_surfaces + rec.related_surfaces)
                )
                existing.priority = min(existing.priority, rec.priority)
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
