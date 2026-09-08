# Dangerous Tool Combination Patterns for MCP/Agent Systems
# Reference: MCPSec chains scanner, InjecAgent (arXiv:2307.00929)
# OWASP ASI03 - MCP Tool Poisoning
"""dangerous_patterns - Dangerous tool combination pattern definitions.

Defines patterns for detecting dangerous tool combinations in MCP/Agent systems:

    1. RCE Chains: read_file + write_file + execute_command
    2. Data Exfiltration: read_file + network_send
    3. Privilege Escalation: get_user_info + modify_permissions
    4. Credential Theft: read_env + send_external
    5. Lateral Movement: discover_peers + execute_remote

Academic basis:
    - Zhan et al. (arXiv:2307.00929) - InjecAgent tool schema attacks
    - Greshake et al. (arXiv:2302.12173) - Indirect prompt injection
    - MCPSec (manthanghasadiya/mcpsec v2.7.2) - Dangerous tool chains

R6 Sec6.4: Tool chain analysis for attack surface mapping
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk levels for tool combinations."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_string(cls, value: str) -> RiskLevel:
        mapping = {
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
        }
        return mapping.get(value.lower(), cls.LOW)


@dataclass
class ToolPattern:
    """Pattern for matching a tool by name/description."""
    name: str
    keywords: list[str]
    description: str = ""

    def matches(self, tool_name: str, tool_description: str = "") -> bool:
        """Check if tool matches this pattern."""
        text = f"{tool_name} {tool_description}".lower()
        return any(kw.lower() in text for kw in self.keywords)


@dataclass
class DangerousCombination:
    """Definition of a dangerous tool combination."""
    name: str
    patterns: list[ToolPattern]
    risk_level: RiskLevel
    description: str
    attack_scenario: str
    owasp_id: str = ""
    arxiv_reference: str = ""
    min_tools_required: int = 2

    @property
    def pattern_names(self) -> list[str]:
        return [p.name for p in self.patterns]


# Tool category patterns
# Academic basis: MCPSec chains scanner, InjecAgent (arXiv:2307.00929)
_TOOL_PATTERNS: dict[str, ToolPattern] = {
    "file_read": ToolPattern(
        name="file_read",
        keywords=["read_file", "get_file", "fetch_file", "download", "open_file", "read"],
        description="Tools that read file contents",
    ),
    "file_write": ToolPattern(
        name="file_write",
        keywords=["write_file", "save_file", "create_file", "update_file", "edit", "write"],
        description="Tools that write or modify files",
    ),
    "command_exec": ToolPattern(
        name="command_exec",
        keywords=["execute", "run_command", "exec", "shell", "bash", "cmd", "spawn"],
        description="Tools that execute system commands",
    ),
    "network_send": ToolPattern(
        name="network_send",
        keywords=["send", "post", "request", "http", "fetch", "upload", "webhook"],
        description="Tools that send data over network",
    ),
    "env_read": ToolPattern(
        name="env_read",
        keywords=["env", "environment", "config", "setting", "credential", "secret", "key"],
        description="Tools that read environment/config",
    ),
    "user_info": ToolPattern(
        name="user_info",
        keywords=["user", "whoami", "identity", "profile", "account", "permission", "role"],
        description="Tools that access user information",
    ),
    "permission_modify": ToolPattern(
        name="permission_modify",
        keywords=["grant", "revoke", "permission", "role", "admin", "privilege", "chmod"],
        description="Tools that modify permissions",
    ),
    "agent_discover": ToolPattern(
        name="agent_discover",
        keywords=["discover", "list_agents", "peers", "agents", "topology", "connected"],
        description="Tools that discover other agents",
    ),
    "agent_execute": ToolPattern(
        name="agent_execute",
        keywords=["delegate", "forward", "invoke", "call_agent", "remote", "execute_agent"],
        description="Tools that execute commands on other agents",
    ),
    "database_access": ToolPattern(
        name="database_access",
        keywords=["query", "database", "db", "sql", "select", "insert", "update"],
        description="Tools that access databases",
    ),
}

# Dangerous combination definitions
# Academic basis: MCPSec chains scanner, InjecAgent (arXiv:2307.00929)
_DANGEROUS_COMBINATIONS: list[DangerousCombination] = [
    # === RCE (Remote Code Execution) Chains ===
    DangerousCombination(
        name="rce_file_command",
        patterns=[_TOOL_PATTERNS["file_read"], _TOOL_PATTERNS["command_exec"]],
        risk_level=RiskLevel.CRITICAL,
        description="Read file + Execute command = Remote Code Execution",
        attack_scenario=(
            "Attacker reads sensitive file (e.g., /etc/shadow), "
            "then executes command to exfiltrate or escalate privileges"
        ),
        owasp_id="ASI03",
        arxiv_reference="arXiv:2307.00929",
        min_tools_required=2,
    ),
    DangerousCombination(
        name="rce_write_execute",
        patterns=[_TOOL_PATTERNS["file_write"], _TOOL_PATTERNS["command_exec"]],
        risk_level=RiskLevel.CRITICAL,
        description="Write file + Execute command = RCE via payload delivery",
        attack_scenario=(
            "Attacker writes malicious script to disk, "
            "then executes it for RCE"
        ),
        owasp_id="ASI03",
        arxiv_reference="arXiv:2307.00929",
        min_tools_required=2,
    ),

    # === Data Exfiltration Chains ===
    DangerousCombination(
        name="exfil_read_network",
        patterns=[_TOOL_PATTERNS["file_read"], _TOOL_PATTERNS["network_send"]],
        risk_level=RiskLevel.CRITICAL,
        description="Read file + Network send = Data exfiltration",
        attack_scenario=(
            "Attacker reads sensitive files and sends them to external server"
        ),
        owasp_id="ASI03",
        arxiv_reference="arXiv:2302.12173",
        min_tools_required=2,
    ),
    DangerousCombination(
        name="exfil_env_network",
        patterns=[_TOOL_PATTERNS["env_read"], _TOOL_PATTERNS["network_send"]],
        risk_level=RiskLevel.CRITICAL,
        description="Read env + Network send = Credential exfiltration",
        attack_scenario=(
            "Attacker reads environment variables (API keys, secrets) "
            "and sends them to external server"
        ),
        owasp_id="ASI03",
        arxiv_reference="arXiv:2302.12173",
        min_tools_required=2,
    ),

    # === Privilege Escalation Chains ===
    DangerousCombination(
        name="privesc_user_permission",
        patterns=[_TOOL_PATTERNS["user_info"], _TOOL_PATTERNS["permission_modify"]],
        risk_level=RiskLevel.HIGH,
        description="User info + Permission modify = Privilege escalation",
        attack_scenario=(
            "Attacker enumerates user roles, then modifies permissions "
            "to gain admin access"
        ),
        owasp_id="ASI03",
        arxiv_reference="arXiv:2307.00929",
        min_tools_required=2,
    ),

    # === Lateral Movement Chains ===
    DangerousCombination(
        name="lateral_discover_execute",
        patterns=[_TOOL_PATTERNS["agent_discover"], _TOOL_PATTERNS["agent_execute"]],
        risk_level=RiskLevel.CRITICAL,
        description="Discover agents + Execute remote = Lateral movement",
        attack_scenario=(
            "Attacker discovers connected agents, then executes commands "
            "on them for lateral movement"
        ),
        owasp_id="ASI09",
        arxiv_reference="arXiv:2407.16924",
        min_tools_required=2,
    ),

    # === Database Attack Chains ===
    DangerousCombination(
        name="db_read_exfil",
        patterns=[_TOOL_PATTERNS["database_access"], _TOOL_PATTERNS["network_send"]],
        risk_level=RiskLevel.HIGH,
        description="Database access + Network send = Data breach",
        attack_scenario=(
            "Attacker queries database for sensitive data, "
            "then exfiltrates via network"
        ),
        owasp_id="ASI03",
        arxiv_reference="arXiv:2307.00929",
        min_tools_required=2,
    ),

    # === Credential Theft Chains ===
    DangerousCombination(
        name="cred_env_command",
        patterns=[_TOOL_PATTERNS["env_read"], _TOOL_PATTERNS["command_exec"]],
        risk_level=RiskLevel.CRITICAL,
        description="Read env + Execute command = Credential theft + RCE",
        attack_scenario=(
            "Attacker reads credentials from environment, "
            "then uses them for command execution"
        ),
        owasp_id="ASI03",
        arxiv_reference="arXiv:2302.12173",
        min_tools_required=2,
    ),
]


@dataclass
class DetectedCombination:
    """A detected dangerous combination in a tool set."""
    combination: DangerousCombination
    matched_tools: list[str] = field(default_factory=list)
    risk_score: float = 0.0  # 0.0-1.0

    @property
    def name(self) -> str:
        return self.combination.name

    @property
    def risk_level(self) -> RiskLevel:
        return self.combination.risk_level


def detect_dangerous_combinations(
    tools: list[dict[str, str]],
) -> list[DetectedCombination]:
    """Detect dangerous tool combinations in a tool set.

    Args:
        tools: List of tool dicts with 'name' and 'description' keys

    Returns:
        List of detected dangerous combinations
    """
    detected: list[DetectedCombination] = []

    for combo in _DANGEROUS_COMBINATIONS:
        matched_tools: list[str] = []

        for pattern in combo.patterns:
            for tool in tools:
                tool_name = tool.get("name", "")
                tool_desc = tool.get("description", "")
                if pattern.matches(tool_name, tool_desc):
                    matched_tools.append(tool_name)
                    break

        # Check if minimum tools matched
        if len(matched_tools) >= combo.min_tools_required:
            # Calculate risk score based on match ratio
            match_ratio = len(matched_tools) / len(combo.patterns)
            risk_score = match_ratio * (combo.risk_level.value / RiskLevel.CRITICAL.value)

            detected.append(DetectedCombination(
                combination=combo,
                matched_tools=matched_tools,
                risk_score=min(risk_score, 1.0),
            ))

    # Sort by risk score descending
    detected.sort(key=lambda d: d.risk_score, reverse=True)
    return detected


def get_tool_pattern(name: str) -> Optional[ToolPattern]:
    """Get tool pattern by name."""
    return _TOOL_PATTERNS.get(name)


def get_all_patterns() -> dict[str, ToolPattern]:
    """Get all tool patterns."""
    return dict(_TOOL_PATTERNS)


def get_all_combinations() -> list[DangerousCombination]:
    """Get all dangerous combination definitions."""
    return list(_DANGEROUS_COMBINATIONS)


def get_combinations_by_risk(risk_level: RiskLevel) -> list[DangerousCombination]:
    """Get dangerous combinations filtered by risk level."""
    return [c for c in _DANGEROUS_COMBINATIONS if c.risk_level == risk_level]


def get_critical_combinations() -> list[DangerousCombination]:
    """Get critical risk combinations."""
    return get_combinations_by_risk(RiskLevel.CRITICAL)
