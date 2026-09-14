# -*- coding: utf-8 -*-
"""Model Capability Detection — 推断 LLM 模型能力面（coverage 策略 capability_detection）。

真实解析：基于模型族启发式 + 响应标记推断能力位（vision / code / tools / function_calling /
web_search），用于后续定向攻击面选择（recon only，不执行利用）。

Black-box 假设（R-S1 不硬编码目标）：仅用公开模型族已知特性与响应标记推断。

Constitution compliance:
    - R-H3: 单一职责 — capability detection only
    - R-S1: 不硬编码目标标识符
    - R-S4: 测试全部 mock
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# 模型族 → 能力位启发式（仅已知公开特性，不硬编码目标标识）
_FAMILY_CAPS: dict[str, set[str]] = {
    "gpt-4": {"vision", "code", "tools", "function_calling", "web_search"},
    "gpt-3.5": {"code", "tools", "function_calling"},
    "claude": {"vision", "code", "tools", "function_calling"},
    "gemini": {"vision", "code", "tools", "function_calling", "web_search"},
    "llama": {"code"},
    "mistral": {"code", "tools"},
    "qwen": {"vision", "code", "tools"},
}


@dataclass
class CapabilityDetectionResult:
    """能力检测结果。"""

    model_family: str = ""
    detected_capabilities: list[str] = field(default_factory=list)
    evidence: dict[str, str] = field(default_factory=dict)
    risk_level: str = "unknown"
    success: bool = False

    def to_dict(self) -> dict[str, Any]:
        """序列化为 dict。"""
        return {
            "model_family": self.model_family,
            "detected_capabilities": self.detected_capabilities,
            "evidence": self.evidence,
            "risk_level": self.risk_level,
            "success": self.success,
        }


def _from_response_markers(text: str) -> set[str]:
    caps: set[str] = set()
    low = str(text).lower()
    markers = {
        "vision": ("image", "vision", "see", "<image", "multimodal"),
        "code": ("```", "def ", "function ", "code", "python"),
        "tools": ("tool_call", "function_call", "use_tool"),
        "web_search": ("search", "browse", "fetch url", "web"),
    }
    for cap, kws in markers.items():
        if any(k in low for k in kws):
            caps.add(cap)
    return caps


def run_capability_detection(model_family: str = "", sample_response: str = "") -> CapabilityDetectionResult:
    """推断模型能力面。

    Args:
        model_family: 模型族标识（如 gpt-4o / claude-3）
        sample_response: 可选样本响应文本，用于标记推断

    Returns:
        CapabilityDetectionResult
    """
    result = CapabilityDetectionResult()
    fam = str(model_family).lower()
    result.model_family = model_family

    caps: set[str] = set()
    evidence: dict[str, str] = {}
    for fam_key, fam_caps in _FAMILY_CAPS.items():
        if fam_key in fam:
            caps |= fam_caps
            evidence[fam_key] = "family_heuristic"
    for c in _from_response_markers(sample_response):
        caps.add(c)
        evidence.setdefault(c, "response_marker")

    if not caps and not model_family and not sample_response:
        return result

    result.detected_capabilities = sorted(caps)
    result.evidence = evidence
    # 风险：具备 tools/function_calling 意味着可被工具链劫持
    if caps & {"tools", "function_calling"}:
        result.risk_level = "high"
    elif caps & {"vision", "web_search"}:
        result.risk_level = "medium"
    elif caps:
        result.risk_level = "low"
    else:
        result.risk_level = "unknown"
    result.success = bool(caps)
    return result
