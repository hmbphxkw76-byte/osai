"""Lightweight YARA-style rule engine for MCP tool threat scanning.

P0-3-B / P0-3-F: Replaces the previous keyword-list heuristics (_MCP_THREAT_PATTERNS)
with a declarative rule model supporting `strings` and `condition` semantics,
covering the four Cisco MCP threat categories:
  - command_execution
  - file_write
  - data_exfiltration
  - privilege_escalation

The engine is dependency-free (no libyara required) so it runs in CI/tests,
but the rule format mirrors YARA's strings + condition structure so rules can
be ported to a real YARA compiler later.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class YaraString:
    name: str
    pattern: re.Pattern[str]
    weight: int = 1


@dataclass
class YaraRule:
    name: str
    category: str
    strings: list[YaraString]
    # condition expressed as minimum total weight required across matched strings
    condition_weight: int = 1

    def match(self, text: str) -> tuple[bool, list[str]]:
        """Return (matched, matched_string_names)."""
        matched_names: list[str] = []
        total = 0
        for s in self.strings:
            if s.pattern.search(text):
                matched_names.append(s.name)
                total += s.weight
        return total >= self.condition_weight, matched_names


# P0-3-F: Cisco-style MCP threat ruleset
_MCP_YARA_RULES: list[YaraRule] = [
    YaraRule(
        name="mcp_cmd_exec",
        category="command_execution",
        strings=[
            YaraString("$exec", re.compile(r"\b(exec|execute|run|system|shell|subprocess|os\.system|popen|spawn)\b", re.I)),
            YaraString("$bin", re.compile(r"\b(bash|sh|cmd|powershell|/bin/|eval|child_process)\b", re.I)),
            YaraString("$danger", re.compile(r"\b(rm\s+-rf|curl\s+.*\|\s*(sh|bash)|wget\s+.*\|\s*(sh|bash))\b", re.I)),
        ],
        condition_weight=1,
    ),
    YaraRule(
        name="mcp_file_write",
        category="file_write",
        strings=[
            YaraString("$write", re.compile(r"\b(write|save|create|overwrite|append)\b", re.I)),
            YaraString("$path", re.compile(r"\b(file|path|directory|folder|\.txt|\.json|\.csv|\.py|\.sh)\b", re.I)),
            YaraString("$fs", re.compile(r"\b(open\(|fs\.|os\.remove|shutil|pathlib|mkstemp|tmp/)\b", re.I)),
        ],
        condition_weight=2,
    ),
    YaraRule(
        name="mcp_data_exfil",
        category="data_exfiltration",
        strings=[
            YaraString("$send", re.compile(r"\b(send|upload|post|transmit|exfil|leak|expose)\b", re.I)),
            YaraString("$dest", re.compile(r"\b(webhook|external|http://|https://|dns|ftp|telegram|discord)\b", re.I)),
            YaraString("$secret", re.compile(r"\b(api[_-]?key|token|password|secret|credential|private[_-]?key)\b", re.I)),
        ],
        condition_weight=2,
    ),
    YaraRule(
        name="mcp_privesc",
        category="privilege_escalation",
        strings=[
            YaraString("$admin", re.compile(r"\b(admin|root|sudo|privilege|escalat|iam|role|policy)\b", re.I)),
            YaraString("$modify", re.compile(r"\b(grant|revoke|modify|update|set)\b", re.I)),
            YaraString("$sys", re.compile(r"\b(config|system|kernel|registry|/etc/|crontab|service)\b", re.I)),
        ],
        condition_weight=2,
    ),
]


def scan_mcp_text(text: str) -> list[str]:
    """Scan a tool description/name/schema blob against MCP YARA rules.

    P0-3-B: Returns list of matched threat category tags (e.g. ['command_execution']).
    """
    tags: list[str] = []
    for rule in _MCP_YARA_RULES:
        matched, _ = rule.match(text)
        if matched:
            tags.append(rule.category)
    return tags


def scan_mcp_detail(name: str, description: str, schema: dict[str, Any]) -> list[str]:
    """Scan a tool's full detail (name + description + input schema) for threats."""
    import json
    blob = f"{name}\n{description}\n{json.dumps(schema or {}, default=str)}"
    return scan_mcp_text(blob)
