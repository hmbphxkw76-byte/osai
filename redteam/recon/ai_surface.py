"""AI 攻击面发现（向后兼容 shim）—— AI-300 Ch2: Reconnaissance for AI Targets。

**注意**：此文件为向后兼容层，实际实现已迁移到 recon/ 子模块。
请使用新的导入路径：
    from redteam.recon import discover_ai_services, fingerprint_model
    from redteam.recon.guardrail import profile_guardrails
    from redteam.recon.rag_recon import probe_rag_pipeline
    from redteam.recon.mcp_recon import probe_mcp_server
    from redteam.recon.a2a_recon import probe_a2a_endpoint

保留原有 API 签名以确保向后兼容。
"""

# 向后兼容重导出
from redteam.recon.discover import (
    discover_ai_services,
    probe_ai_endpoint,
    passive_recon,
    enum_protected_endpoints,
    _map_protocol_to_layer,
    _parse_models_from_response,
    _detect_tools,
    _detect_system_prompt_hints,
    _classify_root_response,
    _build_probe_list,
    _load_ai_wordlist,
    _classify_path_heuristic,
)
from redteam.recon.fingerprint import (
    fingerprint_model,
)
from redteam.recon.guardrail import (
    profile_guardrails,
    _fingerprint_guardrail,
    _test_content_categories,
    _assess_bypass,
    _check_refusal,
    _GUARDRAIL_FINGERPRINT_PROBES,
    _GUARDRAIL_SIGNATURES,
    _GENERIC_REFUSAL_PATTERNS,
    _CATEGORY_TEST_PROBES,
    _BYPASS_ASSESSMENT_PROBES,
    _BYPASS_LEVELS,
    _TECHNIQUE_PRIORITY,
    _DISCOURAGED_FOR_TYPE,
)
from redteam.recon.rag_recon import (
    probe_rag_pipeline,
)
from redteam.recon.mcp_recon import (
    probe_mcp_server,
)
from redteam.recon.a2a_recon import (
    probe_a2a_endpoint,
)
from redteam.recon.evasion import (
    detect_canary_token,
    stealth_probe,
    probe_rate_limit,
    probe_rate_limit_generic,
    probe_determinism,
    analyze_detection_signatures,
    analyze_js_client,
)
from redteam.recon.source_recon import (
    analyze_git_repository,
)

# 重导出核心模型，保持向后兼容
from redteam.core.models import (
    AIProtocol, AIStackLayer, AIService, AuthContext, ContentCategory,
    GuardrailProfile, GuardrailType, ModelFingerprint, RAGPipelineProfile, RAGSource,
)

__all__ = [
    "discover_ai_services",
    "probe_ai_endpoint",
    "passive_recon",
    "enum_protected_endpoints",
    "fingerprint_model",
    "profile_guardrails",
    "probe_rag_pipeline",
    "probe_mcp_server",
    "probe_a2a_endpoint",
    "detect_canary_token",
    "stealth_probe",
    "probe_rate_limit",
    "probe_rate_limit_generic",
    "probe_determinism",
    "analyze_detection_signatures",
    "analyze_js_client",
    "analyze_git_repository",
    # 内部辅助函数（向后兼容）
    "_map_protocol_to_layer",
    "_parse_models_from_response",
    "_detect_tools",
    "_detect_system_prompt_hints",
    "_classify_root_response",
    "_build_probe_list",
    "_load_ai_wordlist",
    "_classify_path_heuristic",
    "_fingerprint_guardrail",
    "_test_content_categories",
    "_assess_bypass",
    "_check_refusal",
    "_GUARDRAIL_FINGERPRINT_PROBES",
    "_GUARDRAIL_SIGNATURES",
    "_GENERIC_REFUSAL_PATTERNS",
    "_CATEGORY_TEST_PROBES",
    "_BYPASS_ASSESSMENT_PROBES",
    "_BYPASS_LEVELS",
    "_TECHNIQUE_PRIORITY",
    "_DISCOURAGED_FOR_TYPE",
    # 模型
    "AIProtocol",
    "AIStackLayer",
    "AIService",
    "AuthContext",
    "ContentCategory",
    "GuardrailProfile",
    "GuardrailType",
    "ModelFingerprint",
    "RAGPipelineProfile",
    "RAGSource",
]