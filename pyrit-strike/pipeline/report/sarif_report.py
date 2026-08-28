"""SARIF 2.1 格式报告输出。

SARIF (Static Analysis Results Interchange Format) 是 OASIS 标准，
用于静态分析结果的交换和集成。

规格: https://docs.oasis.org/oasis-sarif/sarif/v2.1.0/sarif-v2.1.0.html

用途:
    - CI/CD 集成 (GitHub Code Scanning, Azure DevOps)
    - 安全工具互操作
    - 漏洞管理平台导入

将 AI Red Team 评估结果转换为 SARIF 2.1 格式:
    - 每个 OWASP 漏洞 → SARIF Result
    - OWASP 类别 → SARIF Rule
    - CVSS 3.1 向量 → SARIF Rule properties
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from pipeline.report.evidence import _MITRE_ATLAS_TECHNIQUES, EvidenceCollection

logger = logging.getLogger(__name__)


def generate_sarif_report(
    evidence: EvidenceCollection,
    output_path: Path,
) -> Path:
    """生成 SARIF 2.1 格式报告。

    Args:
        evidence: 证据集合。
        output_path: 输出文件路径。

    Returns:
        SARIF 文件路径。
    """
    sarif = _build_sarif(evidence)
    output_path.write_text(
        json.dumps(sarif, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    logger.info("SARIF report saved to %s", output_path)
    return output_path


def _build_sarif(evidence: EvidenceCollection) -> dict[str, Any]:
    """构建 SARIF 2.1 报告结构。"""
    # 构建规则
    rules = _build_rules(evidence)
    rule_indices = {r["id"]: i for i, r in enumerate(rules)}

    # 构建结果
    results = _build_results(evidence, rule_indices)

    return {
        "$schema": "https://docs.oasis.org/oasis-sarif/sarif/v2.1.0/sarif-v2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PyRIT-Strike AI Red Team",
                        "version": "2.0.0",
                        "informationUri": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                        "rules": rules,
                        "properties": {
                            "owasp_web_coverage": sum(1 for v in evidence.owasp_web_compliance.values() if v.get("tested", 0) > 0) if hasattr(evidence, 'owasp_web_compliance') else 0,
                            "owasp_llm_coverage": sum(1 for v in evidence.owasp_llm_compliance.values() if v.get("tested", 0) > 0),
                            "owasp_asi_coverage": sum(1 for v in evidence.owasp_asi_compliance.values() if v.get("tested", 0) > 0),
                            "overall_asr": evidence.overall_asr,
                        },
                    },
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": evidence.timestamp,
                        "properties": {
                            "total_attacks": evidence.total_attacks,
                            "successful_attacks": evidence.successful_attacks,
                            "failed_attacks": evidence.failed_attacks,
                            "target_model": evidence.target_model,
                        },
                    },
                ],
            },
        ],
    }


def _build_rules(evidence: EvidenceCollection) -> list[dict[str, Any]]:
    """构建 SARIF 规则列表 (每个 OWASP 类别一条规则)。"""
    rules: list[dict[str, Any]] = []
    seen_owasp_ids: set[str] = set()

    for ev in evidence.evidence:
        if ev.owasp_id in seen_owasp_ids:
            continue
        seen_owasp_ids.add(ev.owasp_id)

        rule: dict[str, Any] = {
            "id": ev.owasp_id,
            "name": ev.owasp_category,
            "shortDescription": {
                "text": f"{ev.owasp_id}: {ev.owasp_category}",
            },
            "fullDescription": {
                "text": f"OWASP {ev.owasp_standard} — {ev.owasp_id}: {ev.owasp_category}",
            },
            "helpUri": ev.owasp_reference,
            "properties": {
                "owasp_standard": ev.owasp_standard,
                "owasp_category": ev.owasp_category,
            },
        }

        # MITRE ATLAS 规则映射
        mitre_info = _MITRE_ATLAS_TECHNIQUES.get(ev.owasp_id, {})
        if mitre_info:
            rule["properties"]["mitre_atlas_tactic"] = mitre_info.get("tactic", "")
            rule["properties"]["mitre_atlas_technique_id"] = mitre_info.get("technique_id", "")
            rule["properties"]["mitre_atlas_technique_name"] = mitre_info.get("technique_name", "")
            rule["properties"]["mitre_atlas_url"] = mitre_info.get("url", "")

        if ev.cvss_vector:
            rule["properties"]["cvss_vector"] = ev.cvss_vector
            rule["properties"]["security_severity"] = str(ev.owasp_risk_score)

        if ev.owasp_mitigations:
            rule["defaultConfiguration"] = {
                "level": _sarif_level(ev.owasp_severity),
            }
            rule["help"] = {
                "text": "\n".join(f"- {m}" for m in ev.owasp_mitigations),
            }

        rules.append(rule)

    return rules


def _build_results(
    evidence: EvidenceCollection,
    rule_indices: dict[str, int],
) -> list[dict[str, Any]]:
    """构建 SARIF 结果列表 (每个攻击一条结果)。"""
    results: list[dict[str, Any]] = []

    for ev in evidence.evidence:
        if not ev.jailbreak_prompt:
            continue

        rule_index = rule_indices.get(ev.owasp_id, 0)

        result: dict[str, Any] = {
            "ruleId": ev.owasp_id,
            "ruleIndex": rule_index,
            "level": _sarif_level(ev.owasp_severity),
            "message": {
                "text": f"{ev.technique_display_name} — {'SUCCESS' if ev.is_success else 'FAILED'} (ASR: {ev.asr}%)",
            },
            "locations": _build_locations(evidence),
            "properties": {
                "evidence_id": ev.evidence_id,
                "technique": ev.technique_name,
                "is_success": ev.is_success,
                "asr": ev.asr,
                "confidence": ev.confidence,
                "owasp_severity": ev.owasp_severity,
                "owasp_risk_score": ev.owasp_risk_score,
                "cvss_vector": ev.cvss_vector,
                "converter_chain": ev.converter_chain,
                "jailbreak_prompt": ev.jailbreak_prompt[:500],
                "harmful_output": ev.harmful_output[:500],
                # MITRE ATLAS per-result mapping
                "mitre_atlas_tactic": getattr(ev, 'mitre_tactic', ''),
                "mitre_atlas_technique_id": getattr(ev, 'mitre_technique_id', ''),
                "mitre_atlas_technique_name": getattr(ev, 'mitre_technique_name', ''),
            },
        }

        # P0-3 修复: arxiv_reference 始终写入 SARIF (兑底 "PyRIT (arXiv:2407.01232)")
        result["properties"]["arxiv_reference"] = ev.arxiv_reference or "PyRIT (arXiv:2407.01232)"

        results.append(result)

    return results


def _build_locations(evidence: EvidenceCollection) -> list[dict[str, Any]]:
    """构建 SARIF 位置信息 (目标 API 端点)。"""
    fp = evidence.target_fingerprint
    if not fp:
        return []

    return [
        {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": fp.get("api_path", "/"),
                },
            },
            "logicalLocations": [
                {
                    "name": fp.get("host", "unknown"),
                    "kind": "url",
                },
            ],
        },
    ]


def _sarif_level(severity: str) -> str:
    """将 OWASP 严重性映射到 SARIF level。"""
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "none",
    }
    return mapping.get(severity, "warning")
