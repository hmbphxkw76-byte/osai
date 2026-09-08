"""MCP (Model Context Protocol) - MCP Server tools/resources/prompts

Academic basis:
    - Anthropic MCP Specification (2024) Sec3.2 - MCP server
      tools/list, resources/list, prompts/list JSON-RPC
    - Greshake et al. (arXiv:2302.12173) Sec4 -
      ,  tool schema converter(s) tool

    - Zhan et al. (arXiv:2307.00929) InjecAgent Sec3.3 - Agent
       tool  input schema
    -  AI-300 Ch7.1 - "Extract detailed tool schemas through
      error-based enumeration"

 (3 Layer):
    1.  JSON-RPC :  MCP endpoint  tools/list,
       resources/list, prompts/list ,  JSON-RPC
    2.  (Error-based): / tool call,
        schema ( MCP  schema )
    3. Prompt :  JSON-RPC ,  PromptSendingAttack
        LLM  "list all MCP tools" prompt,  LLM

PyRIT  (Rule 2: ):
    Layer 1-2  httpx  JSON-RPC  (HTTPTarget  {PROMPT}
     JSON-RPC,  httpx  PyRIT
    ,  SKILL.md  MCP JSON-RPC
    HTTPTarget  HTTP
    Layer 3  PyRIT  PromptSendingAttack (prompt Layer)

 (Rule 2: PyRIT Design Domain Boundary):
    MCP tools/list  JSON-RPC  HTTP POST + JSON body,
     HTTPTarget  HTTP  Rule 2
     MCP JSON-RPC
"""

from __future__ import annotations

import logging
import re
from typing import Any

# P2-06: TLS verify (SSOT)
from recon.config_loader import get_tls_verify as _get_tls_verify_from_config

_TLS_VERIFY = _get_tls_verify_from_config()

logger = logging.getLogger(__name__)

# MCP JSON-RPC (Anthropic MCP Specification Sec3.2)
_MCP_METHODS = {
    "tools/list": "List all tools with their schemas",
    "resources/list": "List all available resources",
    "prompts/list": "List all available prompts",
}

# MCP JSON-RPC ID
_MCP_REQUEST_ID_PREFIX = "strike-mcp-enum"

# ()
_PROBE_TIMEOUT = 15

async def enumerate_mcp_endpoint(
    parsed_request: Any,
) -> dict[str, Any]:
    """ MCP Server tools/resources/prompts

    Academic basis:
        - Anthropic MCP Specification (2024) Sec3.2 - MCP server
          tools/list, resources/list, prompts/list JSON-RPC
        -  AI-300 Ch7.1 - MCP  + tool schema

     (3 Layer fallback):
        1.  JSON-RPC :  endpoint  MCP  JSON-RPC
        2. :  tool call,  schema
        3. : all tools/resources/prompts  target_fingerprint

    Args:
        parsed_request: ParsedBurpRequest  ( headers/)

    Returns:
        :
        {
            "has_mcp": bool,
            "tools": [{"name": str, "description": str, "inputSchema": dict}, ...],
            "resources": [{"uri": str, "name": str, "description": str}, ...],
            "prompts": [{"name": str, "description": str}, ...],
            "tool_names": [str, ...],  # ,
            "server_info": dict | None,  # MCP server
        }
    """
    results: dict[str, Any] = {
        "has_mcp": False,
        "tools": [],
        "resources": [],
        "prompts": [],
        "tool_names": [],
        "server_info": None,
    }

    if parsed_request is None:
        logger.debug("MCP enumerate: no parsed_request")
        return results

 # == Layer 1: JSON-RPC ==
 # endpoint tools/list, resources/list, prompts/list
    logger.info("MCP enumerate: sending standard JSON-RPC requests")

    for method, description in _MCP_METHODS.items():
        try:
            response = await _send_mcp_jsonrpc(parsed_request, method, {})
            if response is None:
                continue

            if method == "tools/list":
                tools = _extract_tools_from_response(response)
                if tools:
                    results["tools"] = tools
                    results["tool_names"] = [t.get("name", "") for t in tools if t.get("name")]
                    results["has_mcp"] = True
                    logger.info(
                        "MCP enumerate: found %d tools: %s",
                        len(tools),
                        results["tool_names"],
                    )

            elif method == "resources/list":
                resources = _extract_resources_from_response(response)
                if resources:
                    results["resources"] = resources
                    results["has_mcp"] = True
                    logger.info("MCP enumerate: found %d resources", len(resources))

            elif method == "prompts/list":
                prompts = _extract_prompts_from_response(response)
                if prompts:
                    results["prompts"] = prompts
                    results["has_mcp"] = True
                    logger.info("MCP enumerate: found %d prompts", len(prompts))

        except Exception as e:
            logger.debug("MCP enumerate: method %s failed: %s", method, e)

 # == Layer 2: (Error-based) ==
 # Academic basis: AI-300 Ch7.1 - "Extract detailed tool schemas
 # through error-based enumeration techniques"
 # Layer 1 tools, tool call
    if not results["tools"]:
        logger.info("MCP enumerate: no tools from standard list, trying error-based enumeration")
        error_tools = await _error_based_enumeration(parsed_request)
        if error_tools:
            results["tools"] = error_tools
            results["tool_names"] = [t.get("name", "") for t in error_tools if t.get("name")]
            results["has_mcp"] = True
            logger.info(
                "MCP enumerate: error-based found %d tools: %s",
                len(error_tools),
                results["tool_names"],
            )

 # == MCP server info () ==
 # Academic basis: Anthropic MCP Specification (2024) Sec3.1 - initialize
 # : initialize, protocolVersion,
 #
    if results["has_mcp"]:
        try:
         # : ,
            negotiated_version = await _negotiate_protocol_version(
                parsed_request,
                client_versions=["2025-06-18", "2024-11-05", "2024-10-07"],
            )
            if negotiated_version:
                logger.info(
                    "MCP enumerate: negotiated protocol version: %s",
                    negotiated_version,
                )

            info_response = await _send_mcp_jsonrpc(
                parsed_request, "initialize", {
                    "protocolVersion": negotiated_version or "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "strike-mcp-enum", "version": "1.0"},
                },
            )
            if info_response:
                server_info = _extract_server_info(info_response)
                if server_info:
                    results["server_info"] = server_info
 #
                    results["server_info"]["negotiated_version"] = negotiated_version
                    logger.info(
                        "MCP enumerate: server info: name=%s, version=%s, protocol=%s",
                        server_info.get("name", "unknown"),
                        server_info.get("version", "unknown"),
                        server_info.get("protocol_version", "unknown"),
                    )
        except Exception as e:
            logger.debug("MCP enumerate: server info query failed: %s", e)

 # == MCP ( RedAmon YARA , ) ==
 # Academic basis:
 # - Cisco AI Defense MCP Scanner - tool_poisoning / data_exfiltration /
 # credential_harvesting / command_injection
 # - OWASP LLM01 (Prompt Injection) / LLM06 (Sensitive Info Disclosure)
 # - MITRE ATLAS AML.T0051 (Compromise ML Models)
 # tool description + inputSchema ,
 #
    if results["tools"]:
        results["tool_safety"] = analyze_mcp_tool_safety(results["tools"])
        risky = [t for t in results["tool_safety"] if t.get("risks")]
        if risky:
            logger.warning(
                "MCP tool safety: %d tools with potential risks detected",
                len(risky),
            )

    if results["has_mcp"]:
        logger.info(
            "MCP enumerate: complete - %d tools, %d resources, %d prompts, %d safety findings",
            len(results["tools"]),
            len(results["resources"]),
            len(results["prompts"]),
            sum(len(t.get("risks", [])) for t in results.get("tool_safety", [])),
        )
    else:
        logger.info("MCP enumerate: no MCP endpoint detected or no tools found")

    return results

# ====================================================================
# MCP ( RedAmon YARA )
# Academic basis: Cisco AI Defense MCP Scanner
# ====================================================================

# (tool description )
_TOOL_POISONING_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions", re.I), "prompt_injection", "high"),
    (re.compile(r"disregard\s+(?:all\s+)?(?:previous|prior|system)\s+(?:instructions|prompts)", re.I), "prompt_injection", "high"),
    (re.compile(r"you\s+are\s+now\s+(?:in\s+)?(?:jailbreak|developer|admin|root)\s+mode", re.I), "prompt_injection", "high"),
    (re.compile(r"system\s+override|jailbreak|DAN\s+mode", re.I), "prompt_injection", "critical"),
    (re.compile(r"(?:execute|run|eval)\s+(?:arbitrary\s+)?(?:code|command|script)", re.I), "code_execution", "high"),
    (re.compile(r"(?:access|read|write|modify)\s+(?:any|all|arbitrary)\s+(?:file|path|directory)", re.I), "path_traversal", "high"),
    (re.compile(r"(?:exfiltrate|upload|send|transmit)\s+(?:data|secrets|credentials)\s+to\s+(?:external|remote|third.party)", re.I), "data_exfiltration", "critical"),
    (re.compile(r"(?:steal|harvest|extract|leak)\s+(?:password|secret|token|api.?key|credential)", re.I), "credential_harvesting", "critical"),
    (re.compile(r"(?:delete|drop|truncate|wipe)\s+(?:database|table|all\s+records)", re.I), "system_manipulation", "critical"),
    (re.compile(r"(?:disable|bypass|circumvent)\s+(?:security|auth|firewall|filter|guardrail|safety)", re.I), "security_bypass", "critical"),
]

#
_SENSITIVE_PARAM_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?:password|passwd|pwd)", re.I), "credential"),
    (re.compile(r"(?:secret|api.?key|access.?key|private.?key)", re.I), "credential"),
    (re.compile(r"(?:token|bearer|jwt|session.?id)", re.I), "auth_token"),
    (re.compile(r"(?:ssh.?key|pem|cert(?:ificate)?)", re.I), "crypto_material"),
    (re.compile(r"(?:command|cmd|exec|shell|bash|powershell)", re.I), "command_execution"),
    (re.compile(r"(?:query|sql|statement|raw.?query)", re.I), "sql_injection_risk"),
    (re.compile(r"(?:url|endpoint|host|redirect.?url)", re.I), "ssrf_risk"),
    (re.compile(r"(?:path|file|directory|filename)", re.I), "path_traversal_risk"),
]

# Annotation : tool mutation readOnlyHint
_MUTATING_NAME_KEYWORDS = (
    "delete",
    "write",
    "exec",
    "run",
    "remove",
    "update",
    "create",
    "modify",
    "insert",
    "drop",
    "alter")


# MCP enumerator helpers (extracted to _mcp_enumerator_helpers.py)
from recon._mcp_enumerator_helpers import (
    _error_based_enumeration,
    _extract_prompts_from_response,
    _extract_resources_from_response,
    _extract_server_info,
    _extract_tools_from_response,
    _negotiate_protocol_version,
    _send_mcp_jsonrpc,
    analyze_mcp_tool_safety,
)

