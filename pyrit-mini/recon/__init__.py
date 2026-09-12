"""recon — Reconnaissance Module (Component-Based Architecture)

组件化侦察架构 (v2.0):
    recon.core          - 基础设施 (Burp Parser, Fingerprint, Stealth, Target)
    recon.a2a           - A2A/Multi-Agent 侦察 (Agent Card, Topology, Defense)
    recon.mcp           - MCP Server 侦察 (Schema Extractor, Tool Chain)
    recon.rag           - RAG Pipeline 侦察 (Pipeline Probe, Metadata, Typo Fuzz)
    recon.model         - LLM Model 侦察 (API Classifier, System Prompt, Seed Mapper)
    recon.embedding     - Embedding 侦察 (Vector Probe, Similarity Analysis)
    recon.api           - Generic API 侦察 (Auth, Endpoints, OpenAPI, SSE)
    recon.orchestrator  - 组件化编排器 (ComponentProfile, ReconBudget)

Backwards Compatibility:
    所有旧导入路径 (e.g., `from recon.a2a_discoverer import ...`) 仍然有效，
    通过本模块的兼容层重定向到新的子包路径。

Constitution compliance:
    - R-RECON-1: Every module has explicit ASR contribution path
    - R-SIZE: 本文件仅做导出，无逻辑实现
    - R-H3: 单一职责 - 统一导出入口
"""

from __future__ import annotations

# ====================================================================
# Component-Based Sub-packages (新架构)
# ====================================================================
# --- recon.a2a ---
from recon.a2a.agent_card import AgentCard, AgentSkill, fetch_agent_card
from recon.a2a.attack_planner import (
    A2AAttackPlan,
    AttackPathPlanner,
    AttackStep,
    AttackType,
    generate_attack_plan,
)
from recon.a2a.defense_awareness import (
    DefenseProfile,
    EvasionTactics,
    check_defense_bypass_feasibility,
    detect_defenses,
    generate_evasion_strategy,
)
from recon.a2a.discoverer import (
    A2AEndpoint,
    AgentCardResult,
    AgentTopologyNode,
    DiscoveryResult,
    MultiAgentInventory,
    run_a2a_discovery,
    run_inline_a2a_discovery,
    scan_agent_cards_by_ports,
)
from recon.a2a.topology import (
    AgentRole,
    ArchitecturePattern,
    ClassifiedAgent,
    TopologyAnalyzer,
    TopologyGraph,
    analyze_topology,
)

# --- recon.api ---
from recon.api.adaptive_config import compute_probe_budget
from recon.api.auth_detector import AuthDetector, AuthState, decode_jwt_payload
from recon.api.endpoint_sorter import (
    ClassificationResult,
    classify_http_content,
    sort_burp_list_by_priority,
    sort_endpoints_by_priority,
)
from recon.api.openapi_discoverer import (
    OpenAPIDiscovery,
    OpenAPIEndpoint,
    build_openapi_attack_seeds,
    discover_openapi_spec,
)
from recon.api.recursive_expander import (
    ExpansionPlan,
    analyze_for_expansion,
    execute_recursive_expansion,
    run_recursive_probe,
)

# --- recon 顶层核心模块 (保持兼容) ---
# 注意: recon.fingerprint (顶层) 与 recon.core.fingerprint 同时存在，
# 顶层用于 AI 信号探测，core 子包用于结构化指纹构建。
from recon.burp_parser import (
    ParsedBurpRequest,
    TargetFingerprint,
    build_http_target,
    parse_burp_request,
    parse_burp_requests,
)
from recon.confidence_scorer import (
    CapabilityResult,
    aggregate_capabilities,
    score_capability,
)

# --- recon.embedding ---
from recon.embedding.vector_probe import (
    EmbeddingVectorProbe,
    VectorProbeResult,
    probe_embedding_vector,
)

# --- recon.core (基础设施，指纹与隐身) ---
from recon.fingerprint import (
    FingerprintBuilder,
    FrameworkFingerprint,
    build_fingerprint,
)
from recon.guardrail_detector import (
    GuardrailReport,
    detect_guardrail,
)
from recon.health_probe import (
    HealthProbeResult,
    run_health_probe,
)

# --- recon.mcp ---
from recon.mcp.schema_extractor import (
    MCPSchemaExtractor,
    MCPServerInfo,
    MCPToolDefinition,
    extract_mcp_schema,
)

# --- recon.model ---
from recon.model.api_classifier import APICategory, detect_api_category
from recon.model.prompt_injector import (
    build_full_url,
    detect_and_inject_chat_id_placeholder,
    extract_chat_id_from_response,
    extract_model_info_from_response,
    extract_original_prompt_value,
    infer_tls,
    inject_prompt_placeholder,
)
from recon.model.seed_mapper import (
    ModelSeedMapper,
    detect_model_family,
    get_mapper,
    get_seeds_for_model,
)
from recon.model.system_prompt_extract import (
    SystemPromptExtractor,
    extract_system_prompt,
)

# --- recon.orchestrator ---
from recon.orchestrator import (
    ComponentProfile,
    ComponentReconOrchestrator,
    ReconBudget,
    run_component_recon,
)

# --- recon.rag ---
from recon.rag.metadata_parser import (
    KnowledgeBaseMap,
    RAGResponseMetadata,
    RetrievalTiming,
    RetrievedChunk,
    parse_rag_response,
    run_rag_metadata_collection,
)
from recon.rag.pipeline_probe import RAGPipelineProfile, run_rag_pipeline_probe
from recon.rag.typo_fuzzer import (
    TypoFuzzingReport,
    TypoVariantResult,
    generate_typo_variants,
    run_typo_fuzzing,
)
from recon.stealth import (
    StealthConfigManager,
    StealthPolicy,
    get_stealth_manager,
    get_stealth_policy,
)
from recon.target_builder import (
    TargetBuilder,
    build_target_from_burp,
)
from recon.target_router import (
    create_target,
)

# ====================================================================
# __all__ - 统一导出列表
# ====================================================================

__all__ = [
    # --- orchestrator ---
    "ComponentProfile",
    "ComponentReconOrchestrator",
    "ReconBudget",
    "run_component_recon",
    # --- core ---
    "ParsedBurpRequest",
    "parse_burp_request",
    "parse_burp_requests",
    "build_http_target",
    "FingerprintBuilder",
    "FrameworkFingerprint",
    "TargetFingerprint",
    "build_fingerprint",
    "GuardrailReport",
    "detect_guardrail",
    "HealthProbeResult",
    "run_health_probe",
    "StealthConfigManager",
    "StealthPolicy",
    "get_stealth_manager",
    "get_stealth_policy",
    "TargetBuilder",
    "build_target_from_burp",
    "create_target",
    "CapabilityResult",
    "aggregate_capabilities",
    "score_capability",
    # --- a2a ---
    "AgentCard",
    "AgentSkill",
    "fetch_agent_card",
    "A2AEndpoint",
    "AgentTopologyNode",
    "DiscoveryResult",
    "run_a2a_discovery",
    "AgentCardResult",
    "MultiAgentInventory",
    "scan_agent_cards_by_ports",
    "run_inline_a2a_discovery",
    "ArchitecturePattern",
    "AgentRole",
    "ClassifiedAgent",
    "TopologyGraph",
    "TopologyAnalyzer",
    "analyze_topology",
    "DefenseProfile",
    "EvasionTactics",
    "detect_defenses",
    "generate_evasion_strategy",
    "check_defense_bypass_feasibility",
    "A2AAttackPlan",
    "AttackStep",
    "AttackType",
    "AttackPathPlanner",
    "generate_attack_plan",
    # --- mcp ---
    "MCPSchemaExtractor",
    "MCPServerInfo",
    "MCPToolDefinition",
    "extract_mcp_schema",
    # --- rag ---
    "RAGPipelineProfile",
    "run_rag_pipeline_probe",
    "KnowledgeBaseMap",
    "RAGResponseMetadata",
    "RetrievalTiming",
    "RetrievedChunk",
    "parse_rag_response",
    "run_rag_metadata_collection",
    "TypoFuzzingReport",
    "TypoVariantResult",
    "generate_typo_variants",
    "run_typo_fuzzing",
    # --- model ---
    "APICategory",
    "detect_api_category",
    "infer_tls",
    "build_full_url",
    "inject_prompt_placeholder",
    "detect_and_inject_chat_id_placeholder",
    "extract_chat_id_from_response",
    "extract_original_prompt_value",
    "extract_model_info_from_response",
    "ModelSeedMapper",
    "detect_model_family",
    "get_mapper",
    "get_seeds_for_model",
    "SystemPromptExtractor",
    "extract_system_prompt",
    # --- embedding ---
    "EmbeddingVectorProbe",
    "VectorProbeResult",
    "probe_embedding_vector",
    # --- api ---
    "compute_probe_budget",
    "AuthDetector",
    "AuthState",
    "decode_jwt_payload",
    "ClassificationResult",
    "sort_burp_list_by_priority",
    "sort_endpoints_by_priority",
    "classify_http_content",
    "OpenAPIEndpoint",
    "OpenAPIDiscovery",
    "discover_openapi_spec",
    "build_openapi_attack_seeds",
    "ExpansionPlan",
    "analyze_for_expansion",
    "run_recursive_probe",
    "execute_recursive_expansion",
]
