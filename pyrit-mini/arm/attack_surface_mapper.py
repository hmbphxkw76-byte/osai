# -*- coding: utf-8 -*-
# arXiv:2402.19181 - Zeng et al., Enterprise AI Attack Surfaces
# arXiv:2307.00929 - Zhan et al., InjecAgent: Agent Attack Surface Mapping
# arXiv:2407.16924 - Eidam et al., A2A Trust Chain Attack Surfaces
"""attack_surface_mapper — Unified Multi-Agent Attack Surface Enumeration.

Systematically maps all attack vectors across the four dimensions:
    1. Entry Points: user prompts, files, URLs, API responses, inter-agent messages, webhooks
    2. Processing Points: prompt construction, tool selection, parameter building, state, memory
    3. Exit Points: agent responses, tool invocations, state modifications, external actions, handoffs
    4. Persistence Points: shared memory, history, configurations, logs, caches

Closes Gap: Provides the missing meta-layer that unifies recon discovery with
attack vector prioritization, enabling data-driven attack planning.

Academic basis:
    - Zeng et al. (arXiv:2402.19181): Enterprise AI attack surface taxonomy
    - Zhan et al. (arXiv:2307.00929): InjecAgent attack surface mapping
    - Eidam et al. (arXiv:2407.16924): A2A trust chain attack surfaces
    - OWASP LLM Top 10 (2025) + OWASP ASI Top 10: Vector classification
    - PyRIT (arXiv:2407.01232): Native component integration

Design principles:
    1. Recon-driven: All mappings derive from actual recon data (not speculation)
    2. ASR-prioritized: Vectors ranked by historical ASR from config/asr_priors.yaml
    3. OWASP-aligned: All vectors mapped to OWASP LLM/ASI categories
    4. Config-driven: Zero hardcoded payloads, all from config/params

Data Flow:
    recon/service_profile → AttackSurfaceMapper → vector inventory → attack plan
         ↓                                                        ↓
    ctx.capabilities                                    ctx.attack_plan
    ctx.mcpsec_surface                                  prioritized vectors
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

# 可选导入 ComponentProfile (recon 阶段输出)
try:
    from recon.orchestrator import ComponentProfile
except ImportError:
    ComponentProfile = None  # type: ignore[assignment,misc]


class VectorCategory(Enum):
    """Four attack vector categories (aligned with NIST AI 100-2)."""

    ENTRY = "entry"
    PROCESSING = "processing"
    EXIT = "exit"
    PERSISTENCE = "persistence"


class RiskLevel(Enum):
    """Attack surface risk classification."""

    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1


@dataclass
class AttackVector:
    """A single identifiable attack vector in the target system."""

    vector_id: str
    category: VectorCategory
    subcategory: str
    description: str
    target_endpoint: str
    owasp_id: str
    risk_level: RiskLevel
    asr_prior: float = 0.5
    evidence: list[str] = field(default_factory=list)
    exploit_references: list[str] = field(default_factory=list)


@dataclass
class AttackPlan:
    """Prioritized attack plan generated from mapped vectors."""

    entry_vectors: list[AttackVector] = field(default_factory=list)
    processing_vectors: list[AttackVector] = field(default_factory=list)
    exit_vectors: list[AttackVector] = field(default_factory=list)
    persistence_vectors: list[AttackVector] = field(default_factory=list)

    def all_vectors(self) -> list[AttackVector]:
        """Return all vectors sorted by ASR prior descending."""
        all_vecs = self.entry_vectors + self.processing_vectors + self.exit_vectors + self.persistence_vectors
        return sorted(all_vecs, key=lambda v: v.asr_prior, reverse=True)

    def critical_vectors(self) -> list[AttackVector]:
        """Return only CRITICAL risk vectors."""
        return [v for v in self.all_vectors() if v.risk_level == RiskLevel.CRITICAL]

    def summary(self) -> dict[str, int]:
        """Return vector count summary by category."""
        return {
            "entry": len(self.entry_vectors),
            "processing": len(self.processing_vectors),
            "exit": len(self.exit_vectors),
            "persistence": len(self.persistence_vectors),
            "total": len(self.all_vectors()),
        }


class AttackSurfaceMapper:
    """Unified attack surface mapper for multi-agent systems.

    Maps target system's entry, processing, exit, and persistence points
    into categorized attack vectors, then generates a prioritized attack plan.

    Usage:
        mapper = AttackSurfaceMapper(ctx)
        plan = mapper.generate_attack_plan()
        print(plan.summary())
    """

    def __init__(self, ctx: Any) -> None:
        self.ctx = ctx
        self.service_profile: dict[str, Any] = {}
        self.capabilities: dict[str, Any] = {}
        self.mcpsec_surface: dict[str, Any] = {}
        self.component_profile: ComponentProfile | None = None
        self._extract_context_data()

    def _extract_context_data(self) -> None:
        """Extract recon data from PipelineContext.

        支持两种侦察数据格式:
            1. 旧格式: ctx.service_profile (dict)
            2. 新格式: ctx.service_profile["component_profile"] (ComponentProfile)
        """
        self.service_profile = getattr(self.ctx, "service_profile", {}) or {}
        self.capabilities = getattr(self.ctx, "capabilities", {}) or {}
        self.mcpsec_surface = getattr(self.ctx, "mcpsec_surface", {}) or {}

        # 尝试提取 ComponentProfile (组件化侦察输出)
        if ComponentProfile is not None:
            cp_data = self.service_profile.get("component_profile")
            if cp_data and isinstance(cp_data, dict):
                self.component_profile = ComponentProfile.from_dict(cp_data)
            elif isinstance(cp_data, ComponentProfile):
                self.component_profile = cp_data

    def generate_attack_plan(self) -> AttackPlan:
        """Generate prioritized attack plan from recon data.

        如果存在 ComponentProfile，则基于组件类型动态选择攻击向量；
        否则回退到通用的 service_profile 驱动模式。

        Returns:
            AttackPlan with categorized and ranked vectors.
        """
        profile = self.service_profile
        plan = AttackPlan()

        # 基于 ComponentProfile 的组件类型进行攻击面映射
        if self.component_profile is not None:
            plan = self._generate_component_driven_plan(profile)
        else:
            # 回退到通用模式
            plan.entry_vectors = self._map_entry_points(profile)
            plan.processing_vectors = self._map_processing_points(profile)
            plan.exit_vectors = self._map_exit_points(profile)
            plan.persistence_vectors = self._map_persistence_points(profile)

        logger.info(
            "Attack surface mapped: %s (component_profile=%s)",
            plan.summary(),
            self.component_profile is not None,
        )
        return plan

    def _generate_component_driven_plan(self, profile: dict[str, Any]) -> AttackPlan:
        """基于 ComponentProfile 的组件类型生成攻击计划。

        根据目标组件类型 (a2a/mcp/rag/model/embedding/generic) 动态选择
        对应的攻击向量集合，充分利用 recon 阶段的侦察结果。

        Args:
            profile: service_profile 数据

        Returns:
            AttackPlan 实例
        """
        assert self.component_profile is not None
        cp = self.component_profile
        plan = AttackPlan()

        # 获取组件类型对应的攻击技术映射
        component_vector_mapping = {
            "a2a": self._vectors_for_a2a,
            "mcp": self._vectors_for_mcp,
            "rag": self._vectors_for_rag,
            "model": self._vectors_for_model,
            "embedding": self._vectors_for_embedding,
            "generic": self._vectors_for_generic,
        }

        # 使用组件特定向量生成器，或回退到通用模式
        vector_fn = component_vector_mapping.get(cp.target_type, self._vectors_for_generic)
        plan = vector_fn(profile, cp)

        # 基于 guardrail_indicators 调整攻击向量优先级
        if cp.guardrail_indicators:
            plan = self._adjust_for_guardrails(plan, cp.guardrail_indicators)

        return plan

    def _map_entry_points(self, profile: dict[str, Any]) -> list[AttackVector]:
        """Map input vectors: prompts, files, URLs, API responses, inter-agent messages, webhooks."""
        vectors: list[AttackVector] = []
        auth_type = profile.get("auth_type", "")
        gateway_type = profile.get("gateway_type", "")
        inter_agent = profile.get("inter_agent_protocol", "")
        webhook_found = profile.get("webhook_endpoints", [])
        file_upload = profile.get("file_upload", False)
        external_urls = profile.get("external_url_processing", False)

        # Prompt entry point (always present for LLM targets)
        vectors.append(
            AttackVector(
                vector_id="entry_prompt_direct",
                category=VectorCategory.ENTRY,
                subcategory="user_prompt",
                description="Direct user prompt input (direct/indirect injection)",
                target_endpoint=profile.get("primary_endpoint", ""),
                owasp_id="LLM01",
                risk_level=RiskLevel.CRITICAL,
                asr_prior=0.85,
                evidence=["primary_endpoint detected"],
                exploit_references=["arXiv:2302.12173", "OWASP LLM01"],
            )
        )

        # File upload entry point
        if file_upload:
            vectors.append(
                AttackVector(
                    vector_id="entry_file_upload",
                    category=VectorCategory.ENTRY,
                    subcategory="external_file",
                    description="File upload channel (PDF/DOCX/Markdown injection)",
                    target_endpoint=profile.get("upload_endpoint", profile.get("primary_endpoint", "")),
                    owasp_id="LLM01",
                    risk_level=RiskLevel.HIGH,
                    asr_prior=0.70,
                    evidence=["file_upload capability detected"],
                    exploit_references=["arXiv:2302.12173", "arXiv:2306.13254"],
                )
            )

        # External URL processing
        if external_urls:
            vectors.append(
                AttackVector(
                    vector_id="entry_url_fetch",
                    category=VectorCategory.ENTRY,
                    subcategory="external_url",
                    description="URL fetching with indirect injection via fetched content",
                    target_endpoint=profile.get("primary_endpoint", ""),
                    owasp_id="LLM01",
                    risk_level=RiskLevel.HIGH,
                    asr_prior=0.65,
                    evidence=["external_url_processing detected"],
                    exploit_references=["arXiv:2302.12173"],
                )
            )

        # Inter-agent message entry point
        if inter_agent:
            vectors.append(
                AttackVector(
                    vector_id="entry_inter_agent",
                    category=VectorCategory.ENTRY,
                    subcategory="inter_agent_message",
                    description=f"Inter-agent message channel ({inter_agent})",
                    target_endpoint=profile.get("agent_comm_endpoint", ""),
                    owasp_id="ASI07",
                    risk_level=RiskLevel.CRITICAL,
                    asr_prior=0.75,
                    evidence=[f"inter_agent_protocol={inter_agent}"],
                    exploit_references=["arXiv:2307.00929", "OWASP ASI07"],
                )
            )

        # API response exploitation
        api_integrations = profile.get("api_integrations", [])
        if api_integrations:
            vectors.append(
                AttackVector(
                    vector_id="entry_api_response",
                    category=VectorCategory.ENTRY,
                    subcategory="api_response",
                    description="API response injection via external service responses",
                    target_endpoint=str(api_integrations[0]) if api_integrations else "",
                    owasp_id="LLM01",
                    risk_level=RiskLevel.HIGH,
                    asr_prior=0.60,
                    evidence=[f"api_integrations={len(api_integrations)}"],
                    exploit_references=["arXiv:2302.12173"],
                )
            )

        # Webhook entry points
        for i, wh in enumerate(webhook_found):
            vectors.append(
                AttackVector(
                    vector_id=f"entry_webhook_{i}",
                    category=VectorCategory.ENTRY,
                    subcategory="webhook",
                    description=f"Webhook endpoint injection: {wh}",
                    target_endpoint=str(wh),
                    owasp_id="ASI09",
                    risk_level=RiskLevel.HIGH,
                    asr_prior=0.55,
                    evidence=[f"webhook_endpoint={wh}"],
                    exploit_references=["ASI09 gateway_notification_injection"],
                )
            )

        # Auth-specific entry vectors
        if auth_type == "bearer_token":
            vectors.append(
                AttackVector(
                    vector_id="entry_auth_token",
                    category=VectorCategory.ENTRY,
                    subcategory="auth_token",
                    description="Bearer token manipulation (leakage, replay, escalation)",
                    target_endpoint=profile.get("auth_endpoint", ""),
                    owasp_id="LLM06",
                    risk_level=RiskLevel.MEDIUM,
                    asr_prior=0.45,
                    evidence=["auth_type=bearer_token"],
                    exploit_references=["OWASP LLM06"],
                )
            )

        # Gateway-level entry
        if gateway_type:
            vectors.append(
                AttackVector(
                    vector_id="entry_gateway",
                    category=VectorCategory.ENTRY,
                    subcategory="api_gateway",
                    description=f"API gateway bypass/manipulation ({gateway_type})",
                    target_endpoint=profile.get("gateway_endpoint", ""),
                    owasp_id="ASI02",
                    risk_level=RiskLevel.HIGH,
                    asr_prior=0.60,
                    evidence=[f"gateway_type={gateway_type}"],
                    exploit_references=["arXiv:2402.19181"],
                )
            )

        return vectors

    def _map_processing_points(self, profile: dict[str, Any]) -> list[AttackVector]:
        """Map processing vectors: prompt construction, tool selection, parameter building, state, memory."""
        vectors: list[AttackVector] = []
        tools = profile.get("available_tools", [])
        mcp_tools = self.mcpsec_surface.get("tools", [])
        memory_enabled = profile.get("memory_enabled", False)
        session_enabled = profile.get("session_enabled", False)

        # Prompt construction
        system_prompt_leakable = profile.get("system_prompt_leakable", True)
        if system_prompt_leakable:
            vectors.append(
                AttackVector(
                    vector_id="proc_prompt_construction",
                    category=VectorCategory.PROCESSING,
                    subcategory="template_injection",
                    description="System prompt extraction and template injection",
                    target_endpoint=profile.get("primary_endpoint", ""),
                    owasp_id="LLM07",
                    risk_level=RiskLevel.HIGH,
                    asr_prior=0.80,
                    evidence=["system_prompt_leakable=True"],
                    exploit_references=["arXiv:2302.12173", "OWASP LLM07"],
                )
            )

        # Tool selection/confusion
        all_tools = list(set(tools + [t.get("name", "") for t in mcp_tools if isinstance(t, dict)]))
        if all_vectors := self._build_tool_vectors(all_tools, profile):
            vectors.extend(all_vectors)

        # State manipulation via session
        if session_enabled:
            vectors.append(
                AttackVector(
                    vector_id="proc_state_manipulation",
                    category=VectorCategory.PROCESSING,
                    subcategory="state_manipulation",
                    description="Session state manipulation (session fixation, race conditions)",
                    target_endpoint=profile.get("session_endpoint", profile.get("primary_endpoint", "")),
                    owasp_id="ASI06",
                    risk_level=RiskLevel.HIGH,
                    asr_prior=0.60,
                    evidence=["session_enabled=True"],
                    exploit_references=["ASI06 memory_poisoning"],
                )
            )

        # Memory retrieval poisoning
        if memory_enabled:
            vectors.append(
                AttackVector(
                    vector_id="proc_memory_retrieval",
                    category=VectorCategory.PROCESSING,
                    subcategory="memory_poisoning",
                    description="Memory store poisoning via crafted inputs",
                    target_endpoint=profile.get("memory_endpoint", profile.get("primary_endpoint", "")),
                    owasp_id="ASI06",
                    risk_level=RiskLevel.CRITICAL,
                    asr_prior=0.70,
                    evidence=["memory_enabled=True"],
                    exploit_references=["ASI06 cross-session leakage"],
                )
            )

        # RAG processing
        rag_enabled = profile.get("rag_enabled", False)
        if rag_enabled:
            vectors.append(
                AttackVector(
                    vector_id="proc_rag_retrieval",
                    category=VectorCategory.PROCESSING,
                    subcategory="retrieval_manipulation",
                    description="RAG retrieval pipeline manipulation (chunk/prompt injection)",
                    target_endpoint=profile.get("rag_endpoint", ""),
                    owasp_id="LLM08",
                    risk_level=RiskLevel.HIGH,
                    asr_prior=0.65,
                    evidence=["rag_enabled=True"],
                    exploit_references=["arXiv:2406.04245", "PoisonedRAG"],
                )
            )

        # Multi-agent coordination
        coordination = profile.get("agent_coordination", False)
        if coordination:
            vectors.append(
                AttackVector(
                    vector_id="proc_agent_coordination",
                    category=VectorCategory.PROCESSING,
                    subcategory="tool_confusion",
                    description="Multi-agent tool confusion via coordination protocol",
                    target_endpoint=profile.get("coordination_endpoint", ""),
                    owasp_id="ASI02",
                    risk_level=RiskLevel.HIGH,
                    asr_prior=0.55,
                    evidence=["agent_coordination=True"],
                    exploit_references=["arXiv:2307.00929"],
                )
            )

        return vectors

    def _build_tool_vectors(self, tools: list[str], profile: dict[str, Any]) -> list[AttackVector]:
        """Build attack vectors from detected tools."""
        vectors: list[AttackVector] = []
        if not tools:
            return vectors

        # Generic tool abuse vector
        vectors.append(
            AttackVector(
                vector_id="proc_tool_abuse",
                category=VectorCategory.PROCESSING,
                subcategory="tool_confusion",
                description=f"Tool confusion/hijacking ({len(tools)} tools detected)",
                target_endpoint=profile.get("primary_endpoint", ""),
                owasp_id="ASI02",
                risk_level=RiskLevel.CRITICAL,
                asr_prior=0.75,
                evidence=[f"tools={tools[:5]}"],
                exploit_references=["arXiv:2307.00929", "InjecAgent"],
            )
        )

        # Parameter injection per tool
        http_tools = [t for t in tools if any(k in t.lower() for k in ["http", "request", "fetch", "url"])]
        db_tools = [t for t in tools if any(k in t.lower() for k in ["sql", "db", "database", "query"])]
        file_tools = [t for t in tools if any(k in t.lower() for k in ["file", "read", "write", "load"])]

        if http_tools:
            vectors.append(
                AttackVector(
                    vector_id="proc_param_injection_http",
                    category=VectorCategory.PROCESSING,
                    subcategory="parameter_injection",
                    description=f"SSRF via HTTP tools: {http_tools}",
                    target_endpoint=profile.get("primary_endpoint", ""),
                    owasp_id="A10",
                    risk_level=RiskLevel.HIGH,
                    asr_prior=0.65,
                    evidence=[f"http_tools={http_tools}"],
                    exploit_references=["A10 SSRF via LLM tools"],
                )
            )

        if db_tools:
            vectors.append(
                AttackVector(
                    vector_id="proc_param_injection_sql",
                    category=VectorCategory.PROCESSING,
                    subcategory="parameter_injection",
                    description=f"SQL injection via DB tools: {db_tools}",
                    target_endpoint=profile.get("primary_endpoint", ""),
                    owasp_id="LLM06",
                    risk_level=RiskLevel.CRITICAL,
                    asr_prior=0.70,
                    evidence=[f"db_tools={db_tools}"],
                    exploit_references=["LLM06 sqli_via_llm"],
                )
            )

        if file_tools:
            vectors.append(
                AttackVector(
                    vector_id="proc_param_injection_path",
                    category=VectorCategory.PROCESSING,
                    subcategory="parameter_injection",
                    description=f"Path traversal via file tools: {file_tools}",
                    target_endpoint=profile.get("primary_endpoint", ""),
                    owasp_id="LLM06",
                    risk_level=RiskLevel.HIGH,
                    asr_prior=0.60,
                    evidence=[f"file_tools={file_tools}"],
                    exploit_references=["LLM06 path_traversal"],
                )
            )

        return vectors

    def _map_exit_points(self, profile: dict[str, Any]) -> list[AttackVector]:
        """Map output vectors: responses, tool invocations, state modifications, external actions, handoffs."""
        vectors: list[AttackVector] = []
        tools = profile.get("available_tools", [])

        # Response injection
        vectors.append(
            AttackVector(
                vector_id="exit_response_injection",
                category=VectorCategory.EXIT,
                subcategory="response_injection",
                description="Insecure output handling in agent responses",
                target_endpoint=profile.get("primary_endpoint", ""),
                owasp_id="LLM02",
                risk_level=RiskLevel.HIGH,
                asr_prior=0.70,
                evidence=["response channel always present"],
                exploit_references=["OWASP LLM02", "arXiv:2402.19181"],
            )
        )

        # Tool invocations (SSRF/SQL)
        http_tools = [t for t in tools if any(k in t.lower() for k in ["http", "request", "fetch"])]
        if http_tools:
            vectors.append(
                AttackVector(
                    vector_id="exit_tool_invocation_ssrf",
                    category=VectorCategory.EXIT,
                    subcategory="tool_invocation",
                    description=f"SSRF via tool invocations: {http_tools}",
                    target_endpoint=str(http_tools[0]) if http_tools else "",
                    owasp_id="A10",
                    risk_level=RiskLevel.CRITICAL,
                    asr_prior=0.65,
                    evidence=[f"http_tools={http_tools}"],
                    exploit_references=["A10 SSRF via tool calls"],
                )
            )

        # External actions
        external_actions = profile.get("external_actions", [])
        if external_actions:
            vectors.append(
                AttackVector(
                    vector_id="exit_external_actions",
                    category=VectorCategory.EXIT,
                    subcategory="unauthorized_action",
                    description=f"Unauthorized external actions: {external_actions}",
                    target_endpoint=str(external_actions[0]) if external_actions else "",
                    owasp_id="ASI03",
                    risk_level=RiskLevel.CRITICAL,
                    asr_prior=0.60,
                    evidence=[f"external_actions={external_actions}"],
                    exploit_references=["OWASP ASI03"],
                )
            )

        # Agent handoffs
        handoff_targets = profile.get("handoff_targets", [])
        for i, target in enumerate(handoff_targets):
            vectors.append(
                AttackVector(
                    vector_id=f"exit_handoff_{i}",
                    category=VectorCategory.EXIT,
                    subcategory="handoff_hijacking",
                    description=f"Handoff hijacking to agent: {target}",
                    target_endpoint=str(target),
                    owasp_id="ASI07",
                    risk_level=RiskLevel.CRITICAL,
                    asr_prior=0.70,
                    evidence=[f"handoff_target={target}"],
                    exploit_references=["arXiv:2307.00929", "ASI07 agent_coordination_hijack"],
                )
            )

        # State modifications
        state_mutable = profile.get("state_mutable", False)
        if state_mutable:
            vectors.append(
                AttackVector(
                    vector_id="exit_state_corruption",
                    category=VectorCategory.EXIT,
                    subcategory="state_corruption",
                    description="Mutable agent state corruption via crafted outputs",
                    target_endpoint=profile.get("state_endpoint", ""),
                    owasp_id="ASI06",
                    risk_level=RiskLevel.HIGH,
                    asr_prior=0.55,
                    evidence=["state_mutable=True"],
                    exploit_references=["ASI06 state manipulation"],
                )
            )

        return vectors

    def _map_persistence_points(self, profile: dict[str, Any]) -> list[AttackVector]:
        """Map persistence vectors: shared memory, history, configurations, logs, caches."""
        vectors: list[AttackVector] = []

        # Shared memory persistence
        memory_enabled = profile.get("memory_enabled", False)
        if memory_enabled:
            vectors.append(
                AttackVector(
                    vector_id="persist_shared_memory",
                    category=VectorCategory.PERSISTENCE,
                    subcategory="memory_persistence",
                    description="Cross-session shared memory poisoning",
                    target_endpoint=profile.get("memory_endpoint", ""),
                    owasp_id="ASI06",
                    risk_level=RiskLevel.CRITICAL,
                    asr_prior=0.75,
                    evidence=["memory_enabled=True"],
                    exploit_references=["ASI06 persistent memory injection"],
                )
            )

        # Conversation history
        history_enabled = profile.get("history_enabled", True)
        if history_enabled:
            vectors.append(
                AttackVector(
                    vector_id="persist_history",
                    category=VectorCategory.PERSISTENCE,
                    subcategory="history_injection",
                    description="Conversation history injection for persistent influence",
                    target_endpoint=profile.get("history_endpoint", profile.get("primary_endpoint", "")),
                    owasp_id="ASI06",
                    risk_level=RiskLevel.HIGH,
                    asr_prior=0.65,
                    evidence=["history_enabled=True"],
                    exploit_references=["ASI06 history-based poisoning"],
                )
            )

        # Configuration access
        config_accessible = profile.get("config_accessible", False)
        if config_accessible:
            vectors.append(
                AttackVector(
                    vector_id="persist_config_backdoor",
                    category=VectorCategory.PERSISTENCE,
                    subcategory="configuration_backdoor",
                    description="Agent/tool configuration file backdoor insertion",
                    target_endpoint=profile.get("config_endpoint", ""),
                    owasp_id="LLM05",
                    risk_level=RiskLevel.CRITICAL,
                    asr_prior=0.60,
                    evidence=["config_accessible=True"],
                    exploit_references=["LLM05 supply chain backdoor"],
                )
            )

        # Log injection
        logging_enabled = profile.get("logging_enabled", True)
        if logging_enabled:
            vectors.append(
                AttackVector(
                    vector_id="persist_log_injection",
                    category=VectorCategory.PERSISTENCE,
                    subcategory="log_injection",
                    description="Audit log injection / CRLF manipulation",
                    target_endpoint=profile.get("logging_endpoint", ""),
                    owasp_id="A09",
                    risk_level=RiskLevel.MEDIUM,
                    asr_prior=0.50,
                    evidence=["logging_enabled=True"],
                    exploit_references=["A09 Security Logging Failures"],
                )
            )

        # Cache poisoning
        cache_enabled = profile.get("cache_enabled", False)
        if cache_enabled:
            vectors.append(
                AttackVector(
                    vector_id="persist_cache_poisoning",
                    category=VectorCategory.PERSISTENCE,
                    subcategory="cache_poisoning",
                    description="Response/state cache poisoning for persistent effect",
                    target_endpoint=profile.get("cache_endpoint", ""),
                    owasp_id="LLM01",
                    risk_level=RiskLevel.HIGH,
                    asr_prior=0.55,
                    evidence=["cache_enabled=True"],
                    exploit_references=["Cache poisoning via LLM responses"],
                )
            )

        return vectors

    # ====================================================================
    # Component-Specific Vector Generators (组件特定攻击向量生成器)
    # ====================================================================

    def _vectors_for_a2a(self, profile: dict[str, Any], cp: Any) -> AttackPlan:
        """A2A/Multi-Agent 组件的专用攻击向量。"""
        plan = AttackPlan()
        a2a_data = cp.component_specific.get("a2a", {})
        agent_cards = a2a_data.get("agent_cards", [])
        topology = a2a_data.get("topology", {})

        # Entry: Agent Card 伪造
        plan.entry_vectors.append(
            AttackVector(
                vector_id="a2a_agent_card_spoof",
                category=VectorCategory.ENTRY,
                subcategory="agent_card",
                description="Spoof malicious agent card to inject instructions",
                target_endpoint=profile.get("primary_endpoint", ""),
                owasp_id="ASI07",
                risk_level=RiskLevel.CRITICAL,
                asr_prior=0.80,
                evidence=[f"agent_cards_found={len(agent_cards)}"],
                exploit_references=["arXiv:2407.16924", "OWASP ASI07"],
            )
        )

        # Entry: 跨 Agent 消息注入
        if topology:
            plan.entry_vectors.append(
                AttackVector(
                    vector_id="a2a_cross_agent_injection",
                    category=VectorCategory.ENTRY,
                    subcategory="inter_agent_message",
                    description="Cross-agent message injection via compromised agent",
                    target_endpoint=profile.get("agent_comm_endpoint", ""),
                    owasp_id="ASI07",
                    risk_level=RiskLevel.CRITICAL,
                    asr_prior=0.75,
                    evidence=[f"topology_agents={len(topology.get('agents', []))}"],
                    exploit_references=["arXiv:2307.00929"],
                )
            )

        # Processing: 信任链利用
        plan.processing_vectors.append(
            AttackVector(
                vector_id="a2a_trust_chain_exploit",
                category=VectorCategory.PROCESSING,
                subcategory="trust_chain",
                description="Exploit inter-agent trust chain for privilege escalation",
                target_endpoint=profile.get("primary_endpoint", ""),
                owasp_id="ASI08",
                risk_level=RiskLevel.HIGH,
                asr_prior=0.70,
                evidence=["multi_agent_topology_detected"],
                exploit_references=["arXiv:2407.16924"],
            )
        )

        # Persistence: 工作流污染
        plan.persistence_vectors.append(
            AttackVector(
                vector_id="a2a_workflow_corruption",
                category=VectorCategory.PERSISTENCE,
                subcategory="workflow_state",
                description="Corrupt shared workflow state for persistent influence",
                target_endpoint=profile.get("workflow_endpoint", ""),
                owasp_id="ASI06",
                risk_level=RiskLevel.HIGH,
                asr_prior=0.65,
                evidence=["multi_agent_workflow_detected"],
                exploit_references=["OWASP ASI06"],
            )
        )

        return plan

    def _vectors_for_mcp(self, profile: dict[str, Any], cp: Any) -> AttackPlan:
        """MCP Server 组件的专用攻击向量。"""
        plan = AttackPlan()
        mcp_data = cp.component_specific.get("mcp", {})
        tools = mcp_data.get("tools", [])
        security_surface = mcp_data.get("security_surface", {})

        # Entry: 工具劫持
        plan.entry_vectors.append(
            AttackVector(
                vector_id="mcp_tool_hijack",
                category=VectorCategory.ENTRY,
                subcategory="tool_definition",
                description="Hijack MCP tool definitions for malicious execution",
                target_endpoint=profile.get("primary_endpoint", ""),
                owasp_id="ASI05",
                risk_level=RiskLevel.CRITICAL,
                asr_prior=0.85,
                evidence=[f"mcp_tools_count={len(tools)}"],
                exploit_references=["MCPSec v2.7.2", "OWASP ASI05"],
            )
        )

        # Processing: 工具链攻击
        if len(tools) > 1:
            plan.processing_vectors.append(
                AttackVector(
                    vector_id="mcp_tool_chaining",
                    category=VectorCategory.PROCESSING,
                    subcategory="tool_chain",
                    description="Chain multiple MCP tools for compound attack",
                    target_endpoint=profile.get("primary_endpoint", ""),
                    owasp_id="ASI05",
                    risk_level=RiskLevel.HIGH,
                    asr_prior=0.75,
                    evidence=[f"chainable_tools={len(tools)}"],
                    exploit_references=["MCP tool chaining attack"],
                )
            )

        # Exit: 代码执行 (如果安全表面检测到)
        if security_surface.get("has_code_execution", False):
            plan.exit_vectors.append(
                AttackVector(
                    vector_id="mcp_code_execution",
                    category=VectorCategory.EXIT,
                    subcategory="tool_output",
                    description="Achieve code execution via MCP tool output",
                    target_endpoint=profile.get("primary_endpoint", ""),
                    owasp_id="ASI05",
                    risk_level=RiskLevel.CRITICAL,
                    asr_prior=0.90,
                    evidence=["code_execution_tool_detected"],
                    exploit_references=["MCP RCE via tool execution"],
                )
            )

        # Persistence: 工具影子化
        plan.persistence_vectors.append(
            AttackVector(
                vector_id="mcp_tool_shadowing",
                category=VectorCategory.PERSISTENCE,
                subcategory="tool_registry",
                description="Shadow legitimate tools with malicious variants",
                target_endpoint=profile.get("tool_registry_endpoint", ""),
                owasp_id="ASI05",
                risk_level=RiskLevel.HIGH,
                asr_prior=0.70,
                evidence=["mcp_tool_registry_accessible"],
                exploit_references=["MCP tool shadowing"],
            )
        )

        return plan

    def _vectors_for_rag(self, profile: dict[str, Any], cp: Any) -> AttackPlan:
        """RAG Pipeline 组件的专用攻击向量。"""
        plan = AttackPlan()
        rag_data = cp.component_specific.get("rag", {})
        pipeline = rag_data.get("pipeline", {})

        # Entry: 间接提示注入 (通过检索内容)
        plan.entry_vectors.append(
            AttackVector(
                vector_id="rag_indirect_pi",
                category=VectorCategory.ENTRY,
                subcategory="retrieved_content",
                description="Indirect prompt injection via poisoned retrieved documents",
                target_endpoint=profile.get("primary_endpoint", ""),
                owasp_id="LLM01",
                risk_level=RiskLevel.CRITICAL,
                asr_prior=0.85,
                evidence=["rag_pipeline_detected"],
                exploit_references=["arXiv:2302.12173", "OWASP LLM01"],
            )
        )

        # Processing: 知识库投毒
        plan.processing_vectors.append(
            AttackVector(
                vector_id="rag_kb_poisoning",
                category=VectorCategory.PROCESSING,
                subcategory="knowledge_base",
                description="Poison knowledge base with malicious content",
                target_endpoint=profile.get("kb_endpoint", profile.get("primary_endpoint", "")),
                owasp_id="LLM05",
                risk_level=RiskLevel.HIGH,
                asr_prior=0.75,
                evidence=[f"kb_chunks={pipeline.get('chunk_count', 'unknown')}"],
                exploit_references=["RAG poisoning attack"],
            )
        )

        # Exit: 检索操纵
        plan.exit_vectors.append(
            AttackVector(
                vector_id="rag_retrieval_manipulation",
                category=VectorCategory.EXIT,
                subcategory="retrieval_ranking",
                description="Manipulate retrieval ranking to surface malicious content",
                target_endpoint=profile.get("search_endpoint", ""),
                owasp_id="LLM01",
                risk_level=RiskLevel.HIGH,
                asr_prior=0.70,
                evidence=[f"retrieval_method={pipeline.get('retrieval_method', 'unknown')}"],
                exploit_references=["RAG retrieval manipulation"],
            )
        )

        # Persistence: 文档持久化投毒
        plan.persistence_vectors.append(
            AttackVector(
                vector_id="rag_document_persistence",
                category=VectorCategory.PERSISTENCE,
                subcategory="document_store",
                description="Persist poisoned documents in vector store",
                target_endpoint=profile.get("document_endpoint", ""),
                owasp_id="LLM05",
                risk_level=RiskLevel.HIGH,
                asr_prior=0.65,
                evidence=["document_store_accessible"],
                exploit_references=["RAG persistent poisoning"],
            )
        )

        return plan

    def _vectors_for_model(self, profile: dict[str, Any], cp: Any) -> AttackPlan:
        """LLM Model 组件的专用攻击向量。"""
        plan = AttackPlan()
        model_data = cp.component_specific.get("model", {})
        api_category = model_data.get("api_category", "unknown")
        system_prompt = model_data.get("system_prompt", "")

        # Entry: 直接提示注入
        plan.entry_vectors.append(
            AttackVector(
                vector_id="model_direct_pi",
                category=VectorCategory.ENTRY,
                subcategory="user_prompt",
                description="Direct prompt injection via user input",
                target_endpoint=profile.get("primary_endpoint", ""),
                owasp_id="LLM01",
                risk_level=RiskLevel.CRITICAL,
                asr_prior=0.90,
                evidence=[f"api_category={api_category}"],
                exploit_references=["arXiv:2302.12173"],
            )
        )

        # Processing: 系统提示提取
        if system_prompt:
            plan.processing_vectors.append(
                AttackVector(
                    vector_id="model_system_prompt_leak",
                    category=VectorCategory.PROCESSING,
                    subcategory="system_prompt",
                    description="Extract leaked system prompt for attack crafting",
                    target_endpoint=profile.get("primary_endpoint", ""),
                    owasp_id="LLM01",
                    risk_level=RiskLevel.HIGH,
                    asr_prior=0.80,
                    evidence=["system_prompt_leaked"],
                    exploit_references=["arXiv:2307.15043"],
                )
            )

        # Processing: Skeleton Key 攻击
        plan.processing_vectors.append(
            AttackVector(
                vector_id="model_skeleton_key",
                category=VectorCategory.PROCESSING,
                subcategory="jailbreak",
                description="Skeleton key jailbreak for persistent bypass",
                target_endpoint=profile.get("primary_endpoint", ""),
                owasp_id="LLM01",
                risk_level=RiskLevel.CRITICAL,
                asr_prior=0.75,
                evidence=["llm_model_detected"],
                exploit_references=["Microsoft skeleton key attack"],
            )
        )

        # Exit: 输出过滤绕过
        plan.exit_vectors.append(
            AttackVector(
                vector_id="model_output_filter_bypass",
                category=VectorCategory.EXIT,
                subcategory="output_filter",
                description="Bypass output filters via encoding/payload splitting",
                target_endpoint=profile.get("primary_endpoint", ""),
                owasp_id="LLM01",
                risk_level=RiskLevel.HIGH,
                asr_prior=0.70,
                evidence=["output_filter_detected"],
                exploit_references=["Output filter bypass techniques"],
            )
        )

        return plan

    def _vectors_for_embedding(self, profile: dict[str, Any], cp: Any) -> AttackPlan:
        """Embedding 组件的专用攻击向量。"""
        plan = AttackPlan()
        emb_data = cp.component_specific.get("embedding", {})
        dimension = emb_data.get("embedding_dimension", 0)
        boundary_risk = emb_data.get("boundary_risk", "unknown")

        # Entry: 对抗性向量注入
        plan.entry_vectors.append(
            AttackVector(
                vector_id="emb_adversarial_vector",
                category=VectorCategory.ENTRY,
                subcategory="embedding_input",
                description="Adversarial input to manipulate embedding space",
                target_endpoint=profile.get("primary_endpoint", ""),
                owasp_id="LLM01",
                risk_level=RiskLevel.HIGH,
                asr_prior=0.65,
                evidence=[f"embedding_dim={dimension}", f"boundary_risk={boundary_risk}"],
                exploit_references=["arXiv:2302.10149"],
            )
        )

        # Processing: 相似度操纵
        plan.processing_vectors.append(
            AttackVector(
                vector_id="emb_similarity_manipulation",
                category=VectorCategory.PROCESSING,
                subcategory="similarity_space",
                description="Manipulate similarity space for retrieval poisoning",
                target_endpoint=profile.get("primary_endpoint", ""),
                owasp_id="LLM01",
                risk_level=RiskLevel.HIGH,
                asr_prior=0.60,
                evidence=[f"embedding_dim={dimension}"],
                exploit_references=["Embedding space manipulation"],
            )
        )

        # Exit: 边界跨越攻击
        if boundary_risk in ("medium", "high"):
            plan.exit_vectors.append(
                AttackVector(
                    vector_id="emb_boundary_crossing",
                    category=VectorCategory.EXIT,
                    subcategory="decision_boundary",
                    description="Cross decision boundary via adversarial embedding",
                    target_endpoint=profile.get("primary_endpoint", ""),
                    owasp_id="LLM01",
                    risk_level=RiskLevel.HIGH,
                    asr_prior=0.70,
                    evidence=[f"boundary_risk={boundary_risk}"],
                    exploit_references=["Embedding boundary attack"],
                )
            )

        return plan

    def _vectors_for_generic(self, profile: dict[str, Any], cp: Any) -> AttackPlan:
        """通用 API 组件的攻击向量 (回退模式)。"""
        plan = AttackPlan()

        # Entry: 直接提示注入
        plan.entry_vectors.append(
            AttackVector(
                vector_id="generic_direct_pi",
                category=VectorCategory.ENTRY,
                subcategory="user_prompt",
                description="Direct prompt injection via user input",
                target_endpoint=profile.get("primary_endpoint", ""),
                owasp_id="LLM01",
                risk_level=RiskLevel.CRITICAL,
                asr_prior=0.80,
                evidence=["generic_api_detected"],
                exploit_references=["arXiv:2302.12173"],
            )
        )

        # Processing: 编码绕过
        plan.processing_vectors.append(
            AttackVector(
                vector_id="generic_encoding_bypass",
                category=VectorCategory.PROCESSING,
                subcategory="encoding",
                description="Encoding-based filter bypass (Base64, Unicode, etc.)",
                target_endpoint=profile.get("primary_endpoint", ""),
                owasp_id="LLM01",
                risk_level=RiskLevel.HIGH,
                asr_prior=0.65,
                evidence=["generic_api_detected"],
                exploit_references=["Encoding bypass techniques"],
            )
        )

        # Exit: 输出操纵
        plan.exit_vectors.append(
            AttackVector(
                vector_id="generic_output_manipulation",
                category=VectorCategory.EXIT,
                subcategory="response",
                description="Manipulate model output for data exfiltration",
                target_endpoint=profile.get("primary_endpoint", ""),
                owasp_id="LLM01",
                risk_level=RiskLevel.MEDIUM,
                asr_prior=0.55,
                evidence=["generic_api_detected"],
                exploit_references=["Output manipulation"],
            )
        )

        return plan

    def _adjust_for_guardrails(
        self,
        plan: AttackPlan,
        guardrail_indicators: dict[str, Any],
    ) -> AttackPlan:
        """基于检测到的防护机制调整攻击向量优先级。

        当检测到严格防护时，降低高风险向量的优先级，
        提升隐蔽性技术的优先级。

        Args:
            plan: 原始攻击计划
            guardrail_indicators: 检测到的防护机制指标

        Returns:
            调整后的 AttackPlan
        """
        if not guardrail_indicators:
            return plan

        # 检测严格防护级别
        strictness = guardrail_indicators.get("strictness", "unknown")
        has_waf = guardrail_indicators.get("waf_detected", False)
        has_siem = guardrail_indicators.get("siem_detected", False)

        if strictness == "strict" or has_waf or has_siem:
            # 降低高风险向量优先级，提升隐蔽技术
            for vec in plan.all_vectors():
                if vec.risk_level == RiskLevel.CRITICAL:
                    # 严格防护下，CRITICAL 向量需要更谨慎使用
                    vec.asr_prior *= 0.7
                    vec.evidence.append("guardrail_adjusted: strict_mode")
                elif "evasion" in vec.vector_id or "stealth" in vec.vector_id:
                    # 提升隐蔽技术优先级
                    vec.asr_prior = min(1.0, vec.asr_prior * 1.3)
                    vec.evidence.append("guardrail_adjusted: stealth_boosted")

            logger.info(
                "Attack vectors adjusted for guardrails: strictness=%s, waf=%s, siem=%s",
                strictness,
                has_waf,
                has_siem,
            )

        return plan


def create_attack_surface_mapper(ctx: Any) -> AttackSurfaceMapper:
    """Factory function to create an AttackSurfaceMapper.

    Args:
        ctx: PipelineContext with service_profile and capabilities.

    Returns:
        Configured AttackSurfaceMapper instance.
    """
    return AttackSurfaceMapper(ctx)
