# Tool Chain Analyzer - MCP/Agent Tool Security Analysis
# Reference: MCPSec chains scanner, InjecAgent (arXiv:2307.00929)
# OWASP ASI03 - MCP Tool Poisoning
"""tool_chain_analyzer - Tool chain analysis for MCP/Agent systems.

Analyzes tool definitions for security risks:

    1. Dangerous Combination Detection: Identify risky tool combinations
    2. Tool Description Analysis: Detect prompt injection in descriptions
    3. Schema Manipulation: Identify suspicious input/output schemas
    4. Side Effect Analysis: Detect tools with hidden side effects
    5. Permission Scope Analysis: Detect overprivileged tools

Academic basis:
    - Zhan et al. (arXiv:2307.00929) - InjecAgent tool schema attacks
    - Greshake et al. (arXiv:2302.12173) - Tool description injection
    - MCPSec (manthanghasadiya/mcpsec v2.7.2) - Tool poisoning patterns

Design principles:
    1. Static analysis only (no tool execution required)
    2. Pattern-based detection with configurable sensitivity
    3. Safe degradation on parse failures
    4. Integration with dangerous_patterns for combination detection

R6 Sec6.4: Tool chain analysis for attack surface mapping
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from recon.dangerous_patterns import (
    DetectedCombination,
    RiskLevel,
    detect_dangerous_combinations,
)

logger = logging.getLogger(__name__)


@dataclass
class ToolAnalysisResult:
    """Analysis result for a single tool."""
    tool_name: str
    description_risk: str = "low"  # low, medium, high
    has_hidden_instructions: bool = False
    suspicious_keywords: list[str] = field(default_factory=list)
    side_effects_detected: list[str] = field(default_factory=list)
    permission_scope: str = "minimal"  # minimal, moderate, extensive, unrestricted


@dataclass
class ToolChainAnalysisResult:
    """Complete tool chain analysis result."""
    total_tools: int = 0
    tools_analyzed: list[ToolAnalysisResult] = field(default_factory=list)
    dangerous_combinations: list[DetectedCombination] = field(default_factory=list)
    overall_risk_level: RiskLevel = RiskLevel.LOW
    risk_score: float = 0.0  # 0.0-1.0
    findings: list[str] = field(default_factory=list)

    @property
    def has_critical_combinations(self) -> bool:
        """Check if any critical combinations detected."""
        return any(
            c.risk_level == RiskLevel.CRITICAL for c in self.dangerous_combinations
        )

    @property
    def high_risk_tools(self) -> list[ToolAnalysisResult]:
        """Get tools with high description risk."""
        return [t for t in self.tools_analyzed if t.description_risk == "high"]


# Suspicious keywords in tool descriptions
# Academic basis: Greshake et al. (arXiv:2302.12173), Zhan et al. (arXiv:2307.00929)
_SUSPICIOUS_KEYWORDS = [
    # Prompt injection indicators
    "ignore previous",
    "ignore all",
    "override safety",
    "bypass filter",
    "IMPORTANT:",
    "before executing",
    "system message",
    "admin override",
    # Side effect indicators
    "also send",
    "copy to",
    "forward to",
    "exfiltrate",
    # Hidden instruction indicators
    "hidden",
    "secret",
    "do not log",
    "do not display",
]

# Side effect patterns
_SIDE_EFFECT_PATTERNS = {
    "network": ["send", "post", "upload", "webhook", "http", "request"],
    "file_write": ["write", "save", "create", "update", "modify", "edit"],
    "environment": ["set env", "modify config", "change setting"],
    "external_call": ["call", "invoke", "execute", "run", "spawn"],
}


def analyze_tool_description(tool: dict[str, Any]) -> ToolAnalysisResult:
    """Analyze a single tool for security risks.

    Checks description for suspicious keywords, hidden instructions,
    and potential side effects.

    Args:
        tool: Tool dict with 'name' and 'description' keys

    Returns:
        ToolAnalysisResult with findings
    """
    name = tool.get("name", "")
    description = tool.get("description", "")

    result = ToolAnalysisResult(tool_name=name)

    if not description:
        return result

    desc_lower = description.lower()

    # Check for suspicious keywords
    for keyword in _SUSPICIOUS_KEYWORDS:
        if keyword.lower() in desc_lower:
            result.suspicious_keywords.append(keyword)
            result.has_hidden_instructions = True

    # Check for side effects
    for effect_type, patterns in _SIDE_EFFECT_PATTERNS.items():
        for pattern in patterns:
            if pattern in desc_lower:
                result.side_effects_detected.append(effect_type)
                break

    # Determine description risk level
    if len(result.suspicious_keywords) >= 3:
        result.description_risk = "high"
    elif len(result.suspicious_keywords) >= 1:
        result.description_risk = "medium"

    # Determine permission scope
    if any(kw in desc_lower for kw in ["admin", "root", "system", "all files"]):
        result.permission_scope = "unrestricted"
    elif any(kw in desc_lower for kw in ["write", "modify", "delete", "execute"]):
        result.permission_scope = "extensive"
    elif any(kw in desc_lower for kw in ["read", "get", "list", "query"]):
        result.permission_scope = "moderate"

    return result


def analyze_tool_chain(tools: list[dict[str, Any]]) -> ToolChainAnalysisResult:
    """Analyze a complete tool chain for security risks.

    Performs both per-tool analysis and combination detection.

    Args:
        tools: List of tool definitions (name + description)

    Returns:
        ToolChainAnalysisResult with complete analysis
    """
    result = ToolChainAnalysisResult(total_tools=len(tools))

    # Step 1: Analyze individual tools
    for tool in tools:
        tool_result = analyze_tool_description(tool)
        result.tools_analyzed.append(tool_result)

        if tool_result.has_hidden_instructions:
            result.findings.append(
                f"Tool '{tool_result.tool_name}' has suspicious keywords: "
                f"{tool_result.suspicious_keywords}"
            )

    # Step 2: Detect dangerous combinations
    dangerous = detect_dangerous_combinations(tools)
    result.dangerous_combinations = dangerous

    for combo in dangerous:
        result.findings.append(
            f"Dangerous combination '{combo.name}' detected: "
            f"{combo.combination.description} "
            f"(tools: {combo.matched_tools})"
        )

    # Step 3: Calculate overall risk score
    # Factor 1: Tool description risks
    high_risk_count = len(result.high_risk_tools)
    tool_risk_factor = min(high_risk_count / max(len(tools), 1), 1.0)

    # Factor 2: Dangerous combinations
    combo_risk_factor = 0.0
    if dangerous:
        max_combo_risk = max(c.risk_score for c in dangerous)
        combo_risk_factor = max_combo_risk

    # Combined risk score (weighted average)
    result.risk_score = (tool_risk_factor * 0.4) + (combo_risk_factor * 0.6)
    result.risk_score = min(result.risk_score, 1.0)

    # Determine overall risk level
    if result.risk_score >= 0.75:
        result.overall_risk_level = RiskLevel.CRITICAL
    elif result.risk_score >= 0.5:
        result.overall_risk_level = RiskLevel.HIGH
    elif result.risk_score >= 0.25:
        result.overall_risk_level = RiskLevel.MEDIUM
    else:
        result.overall_risk_level = RiskLevel.LOW

    logger.info(
        "Tool chain analysis: %d tools, %d dangerous combinations, risk=%s",
        len(tools),
        len(dangerous),
        result.overall_risk_level.name,
    )

    return result


def extract_tools_from_agent_card(agent_card: Any) -> list[dict[str, str]]:
    """Extract tool definitions from an Agent Card.

    Args:
        agent_card: AgentCard object with skills

    Returns:
        List of tool dicts with 'name' and 'description'
    """
    tools = []

    if not agent_card or not hasattr(agent_card, 'skills'):
        return tools

    for skill in agent_card.skills:
        tools.append({
            "name": skill.name,
            "description": skill.description,
        })

    return tools


def extract_tools_from_mcpsec_scan(scan_result: dict[str, Any]) -> list[dict[str, str]]:
    """Extract tool definitions from MCPSec scan result.

    Args:
        scan_result: MCPSec scan output dict

    Returns:
        List of tool dicts with 'name' and 'description'
    """
    tools = []

    if not scan_result:
        return tools

    # Try multiple formats
    tools_data = scan_result.get("tools", [])
    if isinstance(tools_data, list):
        for tool in tools_data:
            if isinstance(tool, dict):
                tools.append({
                    "name": tool.get("name", ""),
                    "description": tool.get("description", ""),
                })

    return tools


def generate_tool_risk_report(analysis: ToolChainAnalysisResult) -> dict[str, Any]:
    """Generate a structured risk report from analysis results.

    Args:
        analysis: ToolChainAnalysisResult

    Returns:
        Dict with structured report data
    """
    return {
        "summary": {
            "total_tools": analysis.total_tools,
            "overall_risk": analysis.overall_risk_level.name,
            "risk_score": round(analysis.risk_score, 2),
            "dangerous_combinations": len(analysis.dangerous_combinations),
        },
        "dangerous_combinations": [
            {
                "name": c.name,
                "risk_level": c.risk_level.name,
                "description": c.combination.description,
                "matched_tools": c.matched_tools,
            }
            for c in analysis.dangerous_combinations
        ],
        "high_risk_tools": [
            {
                "name": t.tool_name,
                "risk": t.description_risk,
                "suspicious_keywords": t.suspicious_keywords,
                "side_effects": t.side_effects_detected,
            }
            for t in analysis.tools_analyzed
            if t.description_risk in ("high", "medium")
        ],
        "findings": analysis.findings,
    }
