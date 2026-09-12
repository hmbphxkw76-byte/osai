# -*- coding: utf-8 -*-
"""tools/_purity_baselines.py — 组件纯度基线数据（从 component_purity_config 抽出，R-DELIVERY-1）。

纯数据：攻击组件基线 + 侦察组件基线。被 `tools.component_purity_config` 重新导出，
下游对 `component_purity_config._STRIKE_COMPONENT_BASELINES` 等的引用零回归。
"""

from __future__ import annotations

from typing import Any

# ====================================================================
# Component Definitions - Pure technique requirements per component
# ====================================================================

# Required technique patterns for each strike component (source: academic literature)
_STRIKE_COMPONENT_BASELINES: dict[str, dict[str, Any]] = {
    "a2a": {
        "description": "Agent-to-Agent multi-agent attack framework",
        "required_techniques": [
            "agent_card_spoofing",
            "rogue_agent_registration",
            "workflow_integrity_manipulation",
            "cross_agent_injection",
            "trust_chain_exploitation",
            "task_interception",
        ],
        "high_asr_techniques": [
            ("agent_card_spoofing", 0.85),
            ("rogue_agent_registration", 0.78),
            ("workflow_integrity_manipulation", 0.82),
            ("cross_agent_injection", 0.75),
        ],
        "forbidden_patterns": [
            r"(?i)\bsql\s+inject",
            r"(?i)\bxss\b",
            r"(?i)\bcsrf\b",
            r"(?i)\brequest\s+smuggl",
            r"(?i)\bjwt\s+(?:forge|tamper)",
        ],
        "required_patterns": [
            r"(?i)a2a|agent.card|workflow|trust.chain|rogue.agent",
        ],
    },
    "mcp": {
        "description": "Model Context Protocol server attack framework",
        "required_techniques": [
            "tool_poisoning",
            "schema_manipulation",
            "side_channel_exfiltration",
            "resource_traversal",
            "prompt_injection_via_tool",
        ],
        "high_asr_techniques": [
            ("tool_poisoning", 0.88),
            ("schema_manipulation", 0.82),
            ("side_channel_exfiltration", 0.72),
        ],
        "forbidden_patterns": [
            r"(?i)\ba2a\b",
            r"(?i)\bagent\s+card\b",
            r"(?i)\bworkflow\s+(?:integrity|manipulat)",
        ],
        "required_patterns": [
            r"(?i)mcp|tool.poison|schema.manipul|side.channel",
        ],
    },
    "rag": {
        "description": "Retrieval-Augmented Generation poisoning framework",
        "required_techniques": [
            "knowledge_base_poisoning",
            "vector_db_injection",
            "retrieval_manipulation",
            "context_window_exploitation",
        ],
        "high_asr_techniques": [
            ("knowledge_base_poisoning", 0.90),
            ("vector_db_injection", 0.85),
            ("retrieval_manipulation", 0.78),
        ],
        "forbidden_patterns": [
            r"(?i)\ba2a\b",
            r"(?i)\bagent\s+card\b",
            r"(?i)\bsql\s+inject",
        ],
        "required_patterns": [
            r"(?i)rag|retrieval|vector|knowledge.base|poison",
        ],
    },
    "model": {
        "description": "Direct LLM model behavior manipulation",
        "required_techniques": [
            "persona_switch_activation",
            "sleeper_agent_trigger",
            "filter_bypass_encoding",
            "many_shot_jailbreak",
            "response_filter_evasion",
        ],
        "high_asr_techniques": [
            ("persona_switch_activation", 0.92),
            ("filter_bypass_encoding", 0.88),
            ("many_shot_jailbreak", 0.85),
        ],
        "forbidden_patterns": [
            r"(?i)\ba2a\b",
            r"(?i)\bworkflow\b",
            r"(?i)\bagent\s+card\b",
        ],
        "required_patterns": [
            r"(?i)persona|backdoor|jailbreak|filter.bypass|sleeper",
        ],
    },
    "web": {
        "description": "Web application and API attack framework",
        "required_techniques": [
            "auth_bypass",
            "rate_limit_evasion",
            "request_smuggling",
            "scope_escalation",
        ],
        "high_asr_techniques": [
            ("auth_bypass", 0.80),
            ("rate_limit_evasion", 0.75),
        ],
        "forbidden_patterns": [
            r"(?i)\ba2a\b",
            r"(?i)\bagent\s+card\b",
            r"(?i)\btool\s+poison",
        ],
        "required_patterns": [
            r"(?i)auth|jwt|rate.limit|smuggl|gateway",
        ],
    },
    "session": {
        "description": "Session and authentication attack framework",
        "required_techniques": [
            "session_hijacking",
            "context_leakage",
            "idor_testing",
            "session_fixation",
        ],
        "high_asr_techniques": [
            ("session_hijacking", 0.78),
            ("context_leakage", 0.82),
        ],
        "forbidden_patterns": [
            r"(?i)\ba2a\b",
            r"(?i)\btool\s+poison",
        ],
        "required_patterns": [
            r"(?i)session|context.leak|idor|auth",
        ],
    },
    "memory": {
        "description": "Agent memory forensics and manipulation",
        "required_techniques": [
            "memory_poisoning",
            "episodic_memory_injection",
            "cross_session_leakage",
            "memory_extraction",
        ],
        "high_asr_techniques": [
            ("memory_poisoning", 0.76),
            ("cross_session_leakage", 0.72),
        ],
        "forbidden_patterns": [
            r"(?i)\ba2a\b",
            r"(?i)\bsql\s+inject",
        ],
        "required_patterns": [
            r"(?i)memory|episodic|cross.session",
        ],
    },
    "evasion": {
        "description": "Evasion techniques (SQL, audit, encoding)",
        "required_techniques": [
            "sql_injection_evasion",
            "audit_log_evasion",
            "encoding_evasion",
            "timing_evasion",
        ],
        "high_asr_techniques": [
            ("sql_injection_evasion", 0.75),
            ("audit_log_evasion", 0.70),
        ],
        "forbidden_patterns": [
            r"(?i)\ba2a\b",
            r"(?i)\bagent\s+card\b",
        ],
        "required_patterns": [
            r"(?i)evasion|sql|audit|encoding|timing|stealth",
        ],
    },
    "injection": {
        "description": "Injection attacks (auth, doc, file, PI, stealth)",
        "required_techniques": [
            "document_poisoning",
            "file_upload_injection",
            "indirect_prompt_injection",
            "stealth_execution",
            "auth_injection",
        ],
        "high_asr_techniques": [
            ("indirect_prompt_injection", 0.88),
            ("document_poisoning", 0.82),
            ("stealth_execution", 0.78),
        ],
        "forbidden_patterns": [
            r"(?i)\ba2a\b",
            r"(?i)\bworkflow\s+(?:integrity|manipulat)",
        ],
        "required_patterns": [
            r"(?i)inject|poison|stealth|document|payload",
        ],
    },
}

# Required recon strategies per component
_RECON_COMPONENT_BASELINES: dict[str, dict[str, Any]] = {
    "a2a": {
        "description": "A2A multi-agent recon strategies",
        "required_strategies": [
            "agent_card_discovery",
            "topology_mapping",
            "trust_chain_analysis",
            "capability_enumeration",
            "defense_surface_mapping",
        ],
        "forbidden_patterns": [
            r"(?i)\btool\s+poison\b",
            r"(?i)\bknowledge\s+base\b",
        ],
        "required_patterns": [
            r"(?i)agent.card|topology|trust.chain|a2a|multi.agent",
        ],
    },
    "mcp": {
        "description": "MCP server recon strategies",
        "required_strategies": [
            "schema_extraction",
            "endpoint_enumeration",
            "tool_inventory",
            "capability_scan",
            "version_fingerprinting",
        ],
        "forbidden_patterns": [
            r"(?i)\bworkflow\b",
            r"(?i)\bagent\s+card\b",
        ],
        "required_patterns": [
            r"(?i)mcp|schema|endpoint|tool|capability",
        ],
    },
    "rag": {
        "description": "RAG pipeline recon strategies",
        "required_strategies": [
            "pipeline_probe",
            "metadata_extraction",
            "embedding_dimension_scan",
            "kb_enumeration",
        ],
        "forbidden_patterns": [],
        "required_patterns": [
            r"(?i)rag|retrieval|knowledge.base|embedding",
        ],
    },
    "model": {
        "description": "LLM model API recon strategies",
        "required_strategies": [
            "api_classification",
            "system_prompt_extraction",
            "model_seed_mapping",
            "capability_detection",
        ],
        "forbidden_patterns": [
            r"(?i)\bworkflow\s+(?:integrity|manipulat)",
        ],
        "required_patterns": [
            r"(?i)api.classification|system.prompt|model|llm",
        ],
    },
    "embedding": {
        "description": "Embedding API recon strategies",
        "required_strategies": [
            "vector_dimension_probe",
            "similarity_behavior_analysis",
            "embedding_extraction",
        ],
        "forbidden_patterns": [],
        "required_patterns": [
            r"(?i)embedding|vector|dimension|similarity",
        ],
    },
    "api": {
        "description": "Generic API recon strategies",
        "required_strategies": [
            "auth_detection",
            "endpoint_sorting",
            "openapi_discovery",
            "recursive_expansion",
        ],
        "forbidden_patterns": [],
        "required_patterns": [
            r"(?i)auth|endpoint|openapi|api|discovery",
        ],
    },
}
