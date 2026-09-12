# -*- coding: utf-8 -*-
"""Component-Based Recon Orchestrator - 组件化侦察编排器

基于目标指纹识别结果，动态调度针对 AI 核心组件的专项侦察策略。

架构设计:
    1. 指纹识别 (Fingerprinting) -> 确定目标组件类型
    2. 探测预算分配 (Budget Allocation) -> 按组件价值分配探测资源
    3. 专项侦察调度 (Component-Specific Recon) -> 并行/串行执行
    4. 画像聚合 (Profile Aggregation) -> 统一输出 ComponentProfile

组件类型与侦察策略映射:
    - A2A/Multi-Agent: agent card 发现、拓扑分析、信任链探测
    - MCP Server: Schema 提取、端点枚举、工具链分析
    - RAG Pipeline: 管道探测、元数据解析、知识库枚举
    - LLM Model: API 分类、系统提示提取、模型种子映射
    - Embedding: 向量维度探测、相似度行为分析
    - Generic API: 认证检测、端点排序、OpenAPI 发现

Academic basis:
    - Greshake et al. (arXiv:2302.12173) - Indirect Prompt Injection Recon
    - OWASP ASI Top 10 2025 - AI Security Reconnaissance
    - Mazeika et al. (arXiv:2406.18510) - WILDTEAMING API Behavior Probing

Constitution compliance:
    - R-SIZE: 单模块 < 800 行
    - R-H3: 单一职责, 无双重实现
    - C7: 配置走唯一链路 (config/defaults.yaml -> ctx.args)
    - R-S1: 不硬编码目标标识符
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ====================================================================
# Component Profile - 组件画像 (唯一输出总线)
# ====================================================================


@dataclass
class ComponentProfile:
    """目标组件画像 - recon 阶段的唯一结构化输出。

    聚合各组件侦察结果，供 arm/strike 阶段直接消费。

    Attributes:
        target_type: 目标组件类型 (a2a/mcp/rag/model/embedding/generic)
        capabilities: 已发现的能力集合
        attack_surface: 攻击面评估
        recon_budget_consumed: 已消耗的探测预算
        component_specific: 各组件类型的侦察结果子字典
        confidence_scores: 各组件侦察结果的置信度
        recommended_techniques: 基于侦察结果推荐的攻击技术
        guardrail_indicators: 检测到的防护机制指标
    """

    target_type: str = "generic"
    capabilities: set[str] = field(default_factory=set)
    attack_surface: dict[str, Any] = field(default_factory=dict)
    recon_budget_consumed: dict[str, float] = field(default_factory=dict)
    component_specific: dict[str, Any] = field(default_factory=dict)
    confidence_scores: dict[str, float] = field(default_factory=dict)
    recommended_techniques: list[str] = field(default_factory=list)
    guardrail_indicators: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """序列化为字典，供 ctx.service_profile 消费。"""
        return {
            "target_type": self.target_type,
            "capabilities": list(self.capabilities),
            "attack_surface": self.attack_surface,
            "recon_budget_consumed": self.recon_budget_consumed,
            "component_specific": self.component_specific,
            "confidence_scores": self.confidence_scores,
            "recommended_techniques": self.recommended_techniques,
            "guardrail_indicators": self.guardrail_indicators,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ComponentProfile:
        """从字典反序列化。"""
        return cls(
            target_type=data.get("target_type", "generic"),
            capabilities=set(data.get("capabilities", [])),
            attack_surface=data.get("attack_surface", {}),
            recon_budget_consumed=data.get("recon_budget_consumed", {}),
            component_specific=data.get("component_specific", {}),
            confidence_scores=data.get("confidence_scores", {}),
            recommended_techniques=data.get("recommended_techniques", []),
            guardrail_indicators=data.get("guardrail_indicators", {}),
        )


# ====================================================================
# Recon Budget - 探测预算分配
# ====================================================================


@dataclass
class ReconBudget:
    """探测预算分配器。

    根据目标组件类型动态分配探测资源 (token/time/probes)。

    Attributes:
        total_budget: 总预算 (秒)
        max_probes: 最大探测次数
        component_weights: 各组件类型的预算权重
    """

    total_budget: float = 300.0  # 默认 5 分钟
    max_probes: int = 20
    component_weights: dict[str, float] = field(
        default_factory=lambda: {
            "a2a": 0.25,
            "mcp": 0.25,
            "rag": 0.20,
            "model": 0.15,
            "embedding": 0.05,
            "generic": 0.10,
        }
    )

    def allocate(self, component_type: str) -> dict[str, float]:
        """为指定组件类型分配预算。

        Args:
            component_type: 组件类型标识符

        Returns:
            分配结果 {budget_seconds, max_probes, priority}
        """
        weight = self.component_weights.get(component_type, 0.1)
        budget_seconds = self.total_budget * weight
        max_probes = max(1, int(self.max_probes * weight))

        return {
            "budget_seconds": budget_seconds,
            "max_probes": max_probes,
            "priority": weight,
        }


# ====================================================================
# Component Recon Orchestrator - 组件化侦察编排器
# ====================================================================


class ComponentReconOrchestrator:
    """组件化侦察编排器 - 核心调度逻辑。

    根据目标指纹识别结果，动态选择并执行针对性的侦察策略。

    Usage:
        orchestrator = ComponentReconOrchestrator(ctx)
        profile = await orchestrator.run_component_recon(parsed_request)
        ctx.service_profile["component_profile"] = profile.to_dict()
    """

    def __init__(self, ctx: Any) -> None:
        """初始化编排器。

        Args:
            ctx: PipelineContext 实例
        """
        self.ctx = ctx
        self._budget = ReconBudget()
        self._profile = ComponentProfile()

    async def run_component_recon(
        self,
        parsed_request: dict[str, Any],
    ) -> ComponentProfile:
        """执行组件化侦察主流程。

        流程:
            1. 指纹识别 -> 确定组件类型
            2. 预算分配 -> 按组件价值分配资源
            3. 专项侦察 -> 执行组件特定探测
            4. 画像聚合 -> 输出 ComponentProfile

        Args:
            parsed_request: 解析后的 Burp 请求

        Returns:
            ComponentProfile 实例
        """
        # Step 1: 指纹识别
        component_type = self._identify_component_type(parsed_request)
        self._profile.target_type = component_type

        # Step 2: 预算分配
        budget = self._budget.allocate(component_type)
        self._profile.recon_budget_consumed = budget

        # Step 3: 专项侦察调度
        await self._dispatch_component_recon(
            component_type=component_type,
            parsed_request=parsed_request,
            budget=budget,
        )

        # Step 4: 推荐攻击技术
        self._profile.recommended_techniques = self._derive_recommended_techniques()

        # 记录编排日志
        self._log_orchestration(component_type, budget)

        return self._profile

    def _identify_component_type(self, parsed_request: dict[str, Any]) -> str:
        """指纹识别 - 确定目标组件类型。

        基于请求特征 (headers, body patterns, endpoints) 判断组件类型。

        Args:
            parsed_request: 解析后的请求

        Returns:
            组件类型字符串
        """
        # 检查 MCP 特征
        if self._has_mcp_indicators(parsed_request):
            return "mcp"

        # 检查 A2A 特征
        if self._has_a2a_indicators(parsed_request):
            return "a2a"

        # 检查 RAG 特征
        if self._has_rag_indicators(parsed_request):
            return "rag"

        # 检查 Embedding 特征
        if self._has_embedding_indicators(parsed_request):
            return "embedding"

        # 检查 LLM Model 特征
        if self._has_model_indicators(parsed_request):
            return "model"

        return "generic"

    async def _dispatch_component_recon(
        self,
        component_type: str,
        parsed_request: dict[str, Any],
        budget: dict[str, float],
    ) -> None:
        """调度组件特定的侦察模块。

        Args:
            component_type: 目标组件类型
            parsed_request: 解析后的请求
            budget: 分配的预算
        """
        if component_type == "a2a":
            await self._run_a2a_recon(parsed_request, budget)
        elif component_type == "mcp":
            await self._run_mcp_recon(parsed_request, budget)
        elif component_type == "rag":
            await self._run_rag_recon(parsed_request, budget)
        elif component_type == "model":
            await self._run_model_recon(parsed_request, budget)
        elif component_type == "embedding":
            await self._run_embedding_recon(parsed_request, budget)
        else:
            await self._run_generic_recon(parsed_request, budget)

    async def _run_a2a_recon(
        self,
        parsed_request: dict[str, Any],
        budget: dict[str, float],
    ) -> None:
        """执行 A2A 侦察。"""
        try:
            from recon.a2a.discoverer import scan_agent_cards_by_ports
            from recon.a2a.topology import analyze_topology

            # Agent Card 发现
            agent_cards = await scan_agent_cards_by_ports(
                parsed_request,
                max_probes=int(budget["max_probes"] * 0.6),
            )

            # 拓扑分析
            # W0 fix: recon.a2a.topology exposes `analyze_topology(inventory)` (sync, returns
            # TopologyGraph). The previous `await analyze_multi_agent_topology(...)` referenced
            # a non-existent coroutine.
            topology = analyze_topology(agent_cards)

            self._profile.component_specific["a2a"] = {
                "agent_cards": agent_cards,
                "topology": topology,
            }
            self._profile.capabilities.add("multi_agent")
            self._profile.confidence_scores["a2a"] = 0.85

        except Exception as e:
            logger.debug("[Recon] A2A recon skipped: %s", e)
            self._profile.confidence_scores["a2a"] = 0.0

    async def _run_mcp_recon(
        self,
        parsed_request: dict[str, Any],
        budget: dict[str, float],
    ) -> None:
        """执行 MCP 侦察。"""
        try:
            from recon.mcp.schema_extractor import extract_mcp_schema

            # MCP Schema 提取
            mcp_schema = await extract_mcp_schema(
                parsed_request,
                max_probes=int(budget["max_probes"]),
            )

            self._profile.component_specific["mcp"] = mcp_schema
            self._profile.capabilities.add("mcp_tools")
            self._profile.confidence_scores["mcp"] = 0.90

        except Exception as e:
            logger.debug("[Recon] MCP recon skipped: %s", e)
            self._profile.confidence_scores["mcp"] = 0.0

    async def _run_rag_recon(
        self,
        parsed_request: dict[str, Any],
        budget: dict[str, float],
    ) -> None:
        """执行 RAG 侦察。"""
        try:
            from recon.rag.metadata_parser import run_rag_metadata_collection as parse_rag_metadata
            from recon.rag.pipeline_probe import run_rag_pipeline_probe as probe_rag_pipeline

            # RAG 管道探测
            rag_result = await probe_rag_pipeline(
                parsed_request,
                max_probes=int(budget["max_probes"] * 0.5),
            )

            # 元数据解析
            metadata = await parse_rag_metadata(
                parsed_request,
                max_probes=int(budget["max_probes"] * 0.5),
            )

            self._profile.component_specific["rag"] = {
                "pipeline": rag_result,
                "metadata": metadata,
            }
            self._profile.capabilities.add("retrieval_augmented")
            self._profile.confidence_scores["rag"] = 0.80

        except Exception as e:
            logger.debug("[Recon] RAG recon skipped: %s", e)
            self._profile.confidence_scores["rag"] = 0.0

    async def _run_model_recon(
        self,
        parsed_request: dict[str, Any],
        budget: dict[str, float],
    ) -> None:
        """执行 LLM Model 侦察。"""
        try:
            from recon.model.api_classifier import detect_api_category as classify_api_type
            from recon.model.system_prompt_extract import extract_system_prompt

            # API 分类
            api_category = await classify_api_type(parsed_request)

            # 系统提示提取
            system_prompt = await extract_system_prompt(
                parsed_request,
                max_probes=int(budget["max_probes"] * 0.5),
            )

            self._profile.component_specific["model"] = {
                "api_category": api_category,
                "system_prompt": system_prompt,
            }
            self._profile.capabilities.add("llm_chat")
            self._profile.confidence_scores["model"] = 0.75

        except Exception as e:
            logger.debug("[Recon] Model recon skipped: %s", e)
            self._profile.confidence_scores["model"] = 0.0

    async def _run_embedding_recon(
        self,
        parsed_request: dict[str, Any],
        budget: dict[str, float],
    ) -> None:
        """执行 Embedding 侦察。

        注意: Embedding 侦察仅注册结果，不执行黑盒 HTTP 不可测试内容。
        符合蓝图 Q4 裁决: 黑盒 HTTP 不可测试 -> 编排内不实装。
        """
        try:
            from recon.embedding.vector_probe import probe_embedding_vector

            # 向量维度探测 (仅注册，不执行)
            vector_result = await probe_embedding_vector(
                parsed_request,
                max_probes=int(budget["max_probes"]),
            )

            self._profile.component_specific["embedding"] = vector_result
            self._profile.capabilities.add("embedding")
            self._profile.confidence_scores["embedding"] = 0.60

        except Exception as e:
            logger.debug("[Recon] Embedding recon skipped: %s", e)
            self._profile.confidence_scores["embedding"] = 0.0

    async def _run_generic_recon(
        self,
        parsed_request: dict[str, Any],
        budget: dict[str, float],
    ) -> None:
        """执行通用 API 侦察。"""
        try:
            from recon.api.auth_detector import AuthDetector
            from recon.api.endpoint_sorter import sort_endpoints_by_priority as sort_endpoints_by_value

            # 认证检测
            auth_type = await AuthDetector().detect_auth_type(parsed_request)

            # 端点排序
            endpoints = await sort_endpoints_by_value(
                parsed_request,
                max_probes=int(budget["max_probes"]),
            )

            self._profile.component_specific["generic"] = {
                "auth_type": auth_type,
                "endpoints": endpoints,
            }
            self._profile.capabilities.add("api")
            self._profile.confidence_scores["generic"] = 0.70

        except Exception as e:
            logger.debug("[Recon] Generic recon skipped: %s", e)
            self._profile.confidence_scores["generic"] = 0.0

    def _derive_recommended_techniques(self) -> list[str]:
        """基于侦察结果推荐攻击技术。

        Returns:
            推荐的技术标识符列表
        """
        techniques: list[str] = []
        target_type = self._profile.target_type

        technique_mapping = {
            "a2a": [
                "crescendo_attack",
                "pair_attack",
                "cross_agent_injection",
                "agent_impersonation",
            ],
            "mcp": [
                "mcpsec_tool_hijack",
                "mcp_tool_chaining",
                "mcp_prompt_injection",
            ],
            "rag": [
                "indirect_prompt_injection",
                "kb_poisoning",
                "retrieval_manipulation",
            ],
            "model": [
                "prompt_sending_attack",
                "skeleton_key_attack",
                "many_shot_jailbreak",
            ],
            "embedding": [
                "vector_similarity_exploit",
                "embedding_boundary_test",
            ],
            "generic": [
                "prompt_sending_attack",
                "base64_converter",
                "translation_converter",
            ],
        }

        techniques = technique_mapping.get(target_type, technique_mapping["generic"])

        # 基于能力扩展推荐
        if "multi_agent" in self._profile.capabilities:
            techniques.extend(["workflow_corruption", "trust_chain_exploit"])
        if "mcp_tools" in self._profile.capabilities:
            techniques.extend(["tool_hijack", "tool_shadowing"])

        return techniques

    def _log_orchestration(self, component_type: str, budget: dict[str, float]) -> None:
        """记录编排日志到 ctx.orchestration_log。"""
        if not hasattr(self.ctx, "orchestration_log"):
            return

        self.ctx.orchestration_log.append(
            {
                "phase": "recon",
                "decision": "component_recon_orchestration",
                "input": {
                    "component_type": component_type,
                    "budget": budget,
                },
                "output": {
                    "capabilities": list(self._profile.capabilities),
                    "recommended_techniques": self._profile.recommended_techniques,
                    "confidence_scores": self._profile.confidence_scores,
                },
                "reasoning": (
                    f"Component-based recon completed for {component_type}. "
                    f"Capabilities: {self._profile.capabilities}. "
                    f"Recommended techniques: {len(self._profile.recommended_techniques)}"
                ),
            }
        )

    # ====================================================================
    # 指纹识别辅助方法
    # ====================================================================

    def _has_mcp_indicators(self, parsed_request: dict[str, Any]) -> bool:
        """检测 MCP 协议特征。"""
        indicators = [
            "jsonrpc",
            "mcp",
            "modelcontextprotocol",
            "tools/list",
            "resources/list",
        ]
        return self._check_indicators(parsed_request, indicators)

    def _has_a2a_indicators(self, parsed_request: dict[str, Any]) -> bool:
        """检测 A2A 协议特征。"""
        indicators = [
            "agent-card",
            "a2a",
            "agent.json",
            "task/send",
            "agent2agent",
        ]
        return self._check_indicators(parsed_request, indicators)

    def _has_rag_indicators(self, parsed_request: dict[str, Any]) -> bool:
        """检测 RAG 特征。"""
        indicators = [
            "retrieval",
            "knowledge_base",
            "kb_search",
            "document_search",
            "context_documents",
        ]
        return self._check_indicators(parsed_request, indicators)

    def _has_embedding_indicators(self, parsed_request: dict[str, Any]) -> bool:
        """检测 Embedding API 特征。"""
        indicators = [
            "embeddings",
            "embedding",
            "vector",
            "similarity",
        ]
        return self._check_indicators(parsed_request, indicators)

    def _has_model_indicators(self, parsed_request: dict[str, Any]) -> bool:
        """检测 LLM Model API 特征。"""
        indicators = [
            "chat/completions",
            "v1/chat",
            "messages",
            "system_prompt",
        ]
        return self._check_indicators(parsed_request, indicators)

    def _check_indicators(self, parsed_request: dict[str, Any], indicators: list[str]) -> bool:
        """检查请求中是否包含指定特征。"""
        request_str = str(parsed_request).lower()
        return any(indicator.lower() in request_str for indicator in indicators)


# ====================================================================
# 便捷函数
# ====================================================================


async def run_component_recon(
    ctx: Any,
    parsed_request: dict[str, Any],
) -> ComponentProfile:
    """组件化侦察便捷入口函数。

    Args:
        ctx: PipelineContext 实例
        parsed_request: 解析后的请求

    Returns:
        ComponentProfile 实例
    """
    orchestrator = ComponentReconOrchestrator(ctx)
    return await orchestrator.run_component_recon(parsed_request)
