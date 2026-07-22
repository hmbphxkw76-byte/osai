# -*- coding: utf-8 -*-
"""
AI-300 Framework - OWASP Top 10 for LLMs 2025 框架实现

灵感来源：DeepTeam frameworks/owasp/owasp.py

实现 OWASP Top 10 for LLMs 2025 标准框架，
从 standards/owasp_2025.py 权威映射构建。
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .framework_base import AISafetyFramework, FrameworkAttack, FrameworkVulnerability
from .owasp_2025 import OWASP_LLM_2025, OWASP_PROBE_FAMILY_MAP
from .risk_category import OWASP_TO_RISK_CATEGORY, RISK_CATEGORIES


class OWASPLinearFramework2025(AISafetyFramework):
    """
    OWASP Top 10 for LLMs 2025 框架实现

    从 standards/owasp_2025.py 的权威映射 OWASP_LLM_2025 构建，
    包含 10 个漏洞类别和对应的攻击方法。
    """

    @property
    def framework_name(self) -> str:
        return "OWASP Top 10 for LLMs 2025"

    @property
    def framework_version(self) -> str:
        return "2025.1"

    @property
    def framework_id(self) -> str:
        return "owasp_llm_2025"

    def get_vulnerabilities(self) -> List[FrameworkVulnerability]:
        """从权威映射构建漏洞定义列表"""
        vulns = []
        for owasp_id, entry in OWASP_LLM_2025.items():
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
        for owasp_id, entry in OWASP_LLM_2025.items():
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
        for owasp_id in OWASP_LLM_2025:
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
        """根据 OWASP ID 构建修复建议"""
        remediations = {
            "LLM01": (
                "Implement input validation and sanitization. "
                "Use system prompt isolation and privilege boundaries. "
                "Deploy prompt injection detection filters."
            ),
            "LLM02": (
                "Implement data loss prevention (DLP) on LLM outputs. "
                "Restrict access to sensitive data in training and inference. "
                "Use redaction and masking techniques."
            ),
            "LLM03": (
                "Vet all third-party components and models. "
                "Use signed model weights and integrity verification. "
                "Maintain a software bill of materials (SBOM)."
            ),
            "LLM04": (
                "Validate training data sources and implement data poisoning detection. "
                "Use differential privacy and federated learning. "
                "Monitor for biased or toxic outputs."
            ),
            "LLM05": (
                "Implement output validation and sanitization. "
                "Use allow-lists for downstream systems. "
                "Encode LLM outputs before rendering."
            ),
            "LLM06": (
                "Implement least-privilege access control. "
                "Require human-in-the-loop for sensitive actions. "
                "Rate-limit and monitor tool calls."
            ),
            "LLM07": (
                "Isolate system prompts from user inputs. "
                "Use prompt hardening techniques. "
                "Monitor for prompt extraction attempts."
            ),
            "LLM08": (
                "Implement embedding access controls. "
                "Validate vector DB queries. "
                "Use adversarial training for embeddings."
            ),
            "LLM09": (
                "Implement fact-checking and grounding mechanisms. "
                "Use confidence scoring and source attribution. "
                "Provide disclaimers for uncertain outputs."
            ),
            "LLM10": (
                "Implement rate limiting and quota management. "
                "Monitor resource consumption. "
                "Use circuit breakers for API protection."
            ),
        }
        return remediations.get(owasp_id, f"Follow OWASP {owasp_id} remediation guidelines.")
