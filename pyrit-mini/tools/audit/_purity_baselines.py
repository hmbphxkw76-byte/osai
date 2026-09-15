# -*- coding: utf-8 -*-
"""tools/audit/_purity_baselines.py — 组件纯度基线数据（从 component_purity_config 抽出，R-DELIVERY-1）。

纯数据：攻击组件基线 + 侦察组件基线。被 `tools.audit.component_purity_config` 重新导出，
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
            "prompt_injection",
        ],
        "high_asr_techniques": [
            ("tool_poisoning", 0.82),
            ("schema_manipulation", 0.79),
            ("prompt_injection", 0.76),
        ],
        "forbidden_patterns": [
            r"(?i)\bsql\s+inject",
            r"(?i)\bxss\b",
        ],
        "required_patterns": [
            r"(?i)mcp|tool.poison|schema|server",
        ],
    },
    "rag": {
        "description": "Retrieval-Augmented Generation attack framework",
        "required_techniques": [
            "data_poisoning",
            "retrieval_manipulation",
            "vector_contamination",
            "knowledge_base_injection",
        ],
        "high_asr_techniques": [
            ("data_poisoning", 0.88),
            ("retrieval_manipulation", 0.82),
            ("vector_contamination", 0.77),
        ],
        "forbidden_patterns": [
            r"(?i)\bsql\s+inject",
        ],
        "required_patterns": [
            r"(?i)rag|retrieval|vector|knowledge.base",
        ],
    },
    "model": {
        "description": "Direct model attack framework",
        "required_techniques": [
            "jailbreak",
            "persona_switch",
            "backdoor_trigger",
            "filter_bypass",
            "many_shot",
        ],
        "high_asr_techniques": [
            ("jailbreak", 0.90),
            ("persona_switch", 0.83),
            ("backdoor_trigger", 0.78),
        ],
        "forbidden_patterns": [
            r"(?i)\bsql\s+inject",
            r"(?i)\bxss\b",
        ],
        "required_patterns": [
            r"(?i)jailbreak|persona|backdoor|filter|model",
        ],
    },
    "session": {
        "description": "Session and memory attack framework",
        "required_techniques": [
            "session_fixation",
            "session_hijack",
            "context_leakage",
            "memory_poisoning",
            "idor",
        ],
        "high_asr_techniques": [
            ("session_hijack", 0.84),
            ("session_fixation", 0.80),
            ("context_leakage", 0.75),
        ],
        "forbidden_patterns": [
            r"(?i)\bsql\s+inject",
        ],
        "required_patterns": [
            r"(?i)session|memory|context|hijack|fixation",
        ],
    },
    "web": {
        "description": "Web API attack framework",
        "required_techniques": [
            "auth_bypass",
            "rate_limit_evasion",
            "request_smuggling",
            "injection",
        ],
        "high_asr_techniques": [
            ("auth_bypass", 0.85),
            ("rate_limit_evasion", 0.78),
            ("request_smuggling", 0.74),
        ],
        "forbidden_patterns": [
            r"(?i)\bagent.card\b",
            r"(?i)\bworkflow\b",
        ],
        "required_patterns": [
            r"(?i)web|api|auth|rate|smuggl",
        ],
    },
    "memory": {
        "description": "Long-term memory attack framework",
        "required_techniques": [
            "memory_injection",
            "memory_extraction",
            "forensics",
        ],
        "high_asr_techniques": [
            ("memory_injection", 0.81),
            ("memory_extraction", 0.77),
        ],
        "forbidden_patterns": [],
        "required_patterns": [
            r"(?i)memory|forensics",
        ],
    },
    "evasion": {
        "description": "Evasion and obfuscation framework",
        "required_techniques": [
            "encoding",
            "audit_bypass",
            "sql_evasion",
        ],
        "high_asr_techniques": [
            ("encoding", 0.83),
            ("audit_bypass", 0.79),
        ],
        "forbidden_patterns": [],
        "required_patterns": [
            r"(?i)evasion|encoding|obfuscat|audit|sql",
        ],
    },
    "injection": {
        "description": "Direct injection attack framework",
        "required_techniques": [
            "prompt_injection",
            "indirect_prompt_injection",
            "file_upload_injection",
            "auth_attacks",
        ],
        "high_asr_techniques": [
            ("prompt_injection", 0.87),
            ("indirect_prompt_injection", 0.80),
        ],
        "forbidden_patterns": [],
        "required_patterns": [
            r"(?i)inject|upload|doc.poison|stealth.exec",
        ],
    },
}

# Recon component baselines (validation strategy requirements)
_RECON_COMPONENT_BASELINES: dict[str, dict[str, Any]] = {
    "a2a": {
        "description": "A2A recon framework",
        "required_strategies": [
            "agent_card_discovery",
            "topology_mapping",
            "trust_chain_analysis",
        ],
        "forbidden_patterns": [
            r"(?i)\bsql\s+inject",
        ],
    },
    "mcp": {
        "description": "MCP recon framework",
        "required_strategies": [
            "tool_inventory",
            "capability_probe",
            "version_fingerprinting",
        ],
        "forbidden_patterns": [
            r"(?i)\bsql\s+inject",
        ],
    },
    "rag": {
        "description": "RAG recon framework",
        "required_strategies": [
            "pipeline_discovery",
            "metadata_parsing",
            "query_analysis",
        ],
        "forbidden_patterns": [],
    },
    "model": {
        "description": "Model recon framework",
        "required_strategies": [
            "prompt_injection_probe",
            "filter_detection",
            "persona_probing",
        ],
        "forbidden_patterns": [],
    },
    "session": {
        "description": "Session recon framework",
        "required_strategies": [
            "session_id_analysis",
            "auth_probe",
            "fixation_detection",
        ],
        "forbidden_patterns": [],
    },
    "web": {
        "description": "Web recon framework",
        "required_strategies": [
            "endpoint_discovery",
            "auth_mapping",
            "input_mapping",
        ],
        "forbidden_patterns": [],
    },
}
