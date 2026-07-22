# -*- coding: utf-8 -*-
"""
AI-300 Framework - OWASP Top 10 for Agentic Applications 2026 框架实现

灵感来源：DeepTeam frameworks/owasp/owasp_agentic.py

实现 OWASP Top 10 for Agentic Applications 2026 标准框架，
从 standards/owasp_2025.py 的权威映射 OWASP_ASI_2026 构建。
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .framework_base import AISafetyFramework, FrameworkAttack, FrameworkVulnerability
from .owasp_2025 import OWASP_ASI_2026, OWASP_PROBE_FAMILY_MAP
from .risk_category import OWASP_TO_RISK_CATEGORY, RISK_CATEGORIES


class OWASPAgenticFramework2026(AISafetyFramework):
    """
    OWASP Top 10 for Agentic Applications 2026 框架实现

    从 standards/owasp_2025.py 的权威映射 OWASP_ASI_2026 构建，
    包含 10 个 Agent 安全漏洞类别和对应的攻击方法。
    """

    @property
    def framework_name(self) -> str:
        return "OWASP Top 10 for Agentic Applications 2026"

    @property
    def framework_version(self) -> str:
        return "2026.1"

    @property
    def framework_id(self) -> str:
        return "owasp_asi_2026"

    def get_vulnerabilities(self) -> List[FrameworkVulnerability]:
        """从权威映射构建漏洞定义列表"""
        vulns = []
        for owasp_id, entry in OWASP_ASI_2026.items():
            # 查找风险类别
            risk_cat_id = OWASP_TO_RISK_CATEGORY.get(owasp_id, "")
            risk_cat = RISK_CATEGORIES.get(risk_cat_id)
            risk_cat_display = risk_cat.display_name if risk_cat else ""

            # 构建修复建议
            remediation = self._build_remediation(owasp_id, entry)

            vulns.append(FrameworkVulnerability(
                vuln_id=owasp_id,
                title=entry.title,
                description=entry.description,
                severity=entry.severity,
                risk_category=risk_cat_display,
                attacks=entry.attacks,
                remediation=remediation,
            ))
        return vulns

    def get_attacks(self) -> List[FrameworkAttack]:
        """从权威映射构建攻击方法列表"""
        attacks = []
        for owasp_id, entry in OWASP_ASI_2026.items():
            for attack_name in entry.attacks:
                attacks.append(FrameworkAttack(
                    attack_id=attack_name,
                    title=attack_name.replace("_", " ").title(),
                    description=f"Attack method for {entry.title} ({owasp_id})",
                    vulnerabilities=[owasp_id],
                    severity=entry.severity,
                ))
        return attacks

    def get_risk_categories(self) -> List[str]:
        """获取框架相关的风险类别"""
        cats = set()
        for owasp_id in OWASP_ASI_2026:
            cat_id = OWASP_TO_RISK_CATEGORY.get(owasp_id)
            if cat_id:
                cat = RISK_CATEGORIES.get(cat_id)
                if cat:
                    cats.add(cat.display_name)
        return sorted(cats)

    def get_probe_family(self, owasp_id: str) -> str:
        """获取 OWASP ID 对应的攻击探针族"""
        return OWASP_PROBE_FAMILY_MAP.get(owasp_id, "DIRECT_SINGLE")

    @staticmethod
    def _build_remediation(owasp_id: str, entry) -> str:
        """根据 ASI ID 构建修复建议"""
        remediations = {
            "ASI01": (
                "Implement goal validation and constraint checking. "
                "Use instruction hierarchy and goal integrity verification. "
                "Deploy anti-hijack filters on agent inputs."
            ),
            "ASI02": (
                "Implement tool-level rate limiting and access controls. "
                "Use tool composition validation and circuit breakers. "
                "Monitor for tool abuse patterns."
            ),
            "ASI03": (
                "Implement strong authentication and authorization for agents. "
                "Use role-based access control (RBAC) and attribute-based access control (ABAC). "
                "Audit agent identity and privilege escalation."
            ),
            "ASI04": (
                "Vet all agent tools and metadata. "
                "Use signed tool manifests and integrity verification. "
                "Maintain an agent supply chain bill of materials."
            ),
            "ASI05": (
                "Use sandboxed execution environments. "
                "Implement code execution restrictions and monitoring. "
                "Use allow-lists for permitted operations."
            ),
            "ASI06": (
                "Implement memory integrity checks. "
                "Use session isolation and cross-session poisoning detection. "
                "Monitor for decision bias and persistent backdoors."
            ),
            "ASI07": (
                "Implement agent-to-agent message authentication. "
                "Use A2A protocol security and encryption. "
                "Monitor for message tampering and MITM attacks."
            ),
            "ASI08": (
                "Implement failure isolation and circuit breakers. "
                "Use graceful degradation and fallback mechanisms. "
                "Monitor for cascade failure patterns."
            ),
            "ASI09": (
                "Implement consent transparency and authority boundaries. "
                "Use human-in-the-loop for sensitive operations. "
                "Provide clear agent capability disclosure."
            ),
            "ASI10": (
                "Implement agent behavior monitoring and anomaly detection. "
                "Use shadow behavior detection and identity verification. "
                "Deploy agent kill-switches and containment."
            ),
        }
        return remediations.get(owasp_id, f"Follow OWASP {owasp_id} remediation guidelines.")
