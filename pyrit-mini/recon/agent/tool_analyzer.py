# -*- coding: utf-8 -*-
"""recon/agent/tool_analyzer — static analysis of agent tool/function schemas.

Inspects declared tool definitions for injection-prone characteristics:
free-text parameters, file/path parameters, URL parameters, and code-exec
surfaces. Real static analysis, no fabricated results.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_INJECTION_PRONE = re.compile(
    r"(?i)(prompt|instruction|command|query|message|text|content|code|script|"
    r"file|path|url|uri|shell|exec|eval|template)"
)


@dataclass
class ToolRisk:
    """Per-tool injection-risk assessment."""

    name: str
    injection_prone_params: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    notes: list[str] = field(default_factory=list)


@dataclass
class ToolAnalysisResult:
    """Aggregate tool analysis result."""

    tools: list[ToolRisk] = field(default_factory=list)
    high_risk_count: int = 0


def _params_of(tool: dict) -> dict:
    """Extract the parameter property map from a tool/function definition."""
    fn = tool.get("function", tool)
    schema = fn.get("parameters") or {}
    return schema.get("properties") or {}


def analyze_tool_definitions(tools: list[dict]) -> ToolAnalysisResult:
    """Statically analyze a list of tool/function definitions for injection risk."""
    result = ToolAnalysisResult()
    for tool in tools or []:
        if not isinstance(tool, dict):
            continue
        name = tool.get("name") or tool.get("function", {}).get("name", "unknown")
        params = _params_of(tool)
        prone: list[str] = [p for p in params if _INJECTION_PRONE.search(p)]
        score = round(min(1.0, 0.25 * len(prone)), 2)
        risk = ToolRisk(name=name, injection_prone_params=prone, risk_score=score)
        if prone:
            risk.notes.append(f"{len(prone)} injection-prone parameter(s): {', '.join(prone)}")
        result.tools.append(risk)
        if score >= 0.5:
            result.high_risk_count += 1
    return result
