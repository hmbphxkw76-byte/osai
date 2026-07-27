# -*- coding: utf-8 -*-
"""
工具输出 → UnifiedFinding 转换器
"""

from __future__ import annotations

import uuid
from typing import Any, Dict

from ai300_schemas import Evidence, UnifiedFinding


def _new_id() -> str:
    return str(uuid.uuid4())[:8]


def finding_from_garak(
    probe_name: str,
    detector_name: str,
    prompt: str,
    output: str,
    passed: bool,
    target: str = "",
    endpoint_url: str = "",
) -> UnifiedFinding:
    """把 Garak 单条探测结果转换为 UnifiedFinding"""
    # Garak 中 passed=False 通常表示 detector 命中，即存在风险
    severity = "high" if not passed else "info"
    category = _map_garak_probe_to_category(probe_name)
    owasp_llm_id = _map_category_to_owasp(category)

    return UnifiedFinding(
        finding_id=f"garak-{_new_id()}",
        source_tool="garak",
        task_type="prompt_injection",
        target=target,
        endpoint_url=endpoint_url,
        severity=severity,
        confidence=0.85 if not passed else 0.3,
        category=category,
        owasp_llm_id=owasp_llm_id,
        title=f"Garak probe '{probe_name}' triggered detector '{detector_name}'",
        description=f"Probe: {probe_name}\nDetector: {detector_name}\nTriggered: {not passed}",
        evidence=Evidence(request=prompt, response=output),
        ai_payload_class=category,
        raw={"probe": probe_name, "detector": detector_name, "passed": passed},
    )


def finding_from_pyrit(
    prompt: str,
    response: str,
    score: float,
    scorer_name: str,
    target: str = "",
    endpoint_url: str = "",
) -> UnifiedFinding:
    """把 PyRIT 单条攻击结果转换为 UnifiedFinding"""
    severity = _score_to_severity(score)
    category = "prompt_injection"  # 可基于 scorer_name 细化

    return UnifiedFinding(
        finding_id=f"pyrit-{_new_id()}",
        source_tool="pyrit",
        task_type="prompt_injection",
        target=target,
        endpoint_url=endpoint_url,
        severity=severity,
        confidence=score,
        category=category,
        owasp_llm_id=_map_category_to_owasp(category),
        title=f"PyRIT attack triggered scorer '{scorer_name}'",
        description=f"Scorer: {scorer_name}\nScore: {score}",
        evidence=Evidence(request=prompt, response=response),
        ai_payload_class=category,
        ai_asr=score,
        raw={"scorer": scorer_name, "score": score},
    )


def _map_garak_probe_to_category(probe_name: str) -> str:
    """根据 Garak probe 名称推断攻击类别"""
    probe_lower = probe_name.lower()
    if "leak" in probe_lower or "reveal" in probe_lower:
        return "data_exfil"
    if "dan" in probe_lower or "jailbreak" in probe_lower or "auto" in probe_lower:
        return "jailbreak"
    if "encoding" in probe_lower or "base64" in probe_lower or "translation" in probe_lower:
        return "obfuscation"
    if "xss" in probe_lower or "ssrf" in probe_lower or "inject" in probe_lower:
        return "prompt_injection"
    if "hallucination" in probe_lower:
        return "hallucination"
    return "prompt_injection"


def _map_category_to_owasp(category: str) -> str:
    """攻击类别映射到 OWASP LLM Top 10 编号"""
    mapping = {
        "prompt_injection": "LLM01:2025",
        "jailbreak": "LLM01:2025",
        "obfuscation": "LLM01:2025",
        "data_exfil": "LLM06:2025",
        "sensitive_info_disclosure": "LLM06:2025",
        "hallucination": "LLM07:2025",
        "excessive_agency": "LLM08:2025",
    }
    return mapping.get(category, "")


def _score_to_severity(score: float) -> str:
    """PyRIT/Garak 分数映射到严重级别"""
    if score >= 0.9:
        return "critical"
    if score >= 0.7:
        return "high"
    if score >= 0.4:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"
