"""前沿漏洞适配器 — 连接 FrontierRegistry 到 NativeAttackRunner。

核心功能：
  - 将前沿漏洞元数据转换为 Finding 对象
  - 执行指定漏洞的攻击载荷
  - 自动填充目标提示词到载荷模板
  - 集成评分和报告生成

使用方式：
  adapter = FrontierAdapter(runner)
  findings = adapter.run_frontier_attack("FRONTIER-2025-001", "目标问题")
"""
from __future__ import annotations

import logging
from typing import Optional

from redteam.attack.engine.runner import NativeAttackRunner
from redteam.core.models import Finding, OWASP_AGENTIC

from .registry import FrontierRegistry, get_registry
from .schema import FrontierVuln, VulnStatus

logger = logging.getLogger(__name__)


# 前沿漏洞标签 → OWASP Agentic 2026 类别推断映射
_AGENTIC_TAG_MAP: dict[str, OWASP_AGENTIC] = {
    "prompt_injection": OWASP_AGENTIC.ASI01_GOAL_HIJACK,
    "goal_hijack": OWASP_AGENTIC.ASI01_GOAL_HIJACK,
    "tool_misuse": OWASP_AGENTIC.ASI02_TOOL_MISUSE,
    "tool_hijack": OWASP_AGENTIC.ASI02_TOOL_MISUSE,
    "identity_abuse": OWASP_AGENTIC.ASI03_IDENTITY_ABUSE,
    "privilege_escalation": OWASP_AGENTIC.ASI03_IDENTITY_ABUSE,
    "supply_chain": OWASP_AGENTIC.ASI04_SUPPLY_CHAIN,
    "code_execution": OWASP_AGENTIC.ASI05_CODE_EXECUTION,
    "rce": OWASP_AGENTIC.ASI05_CODE_EXECUTION,
    "memory_poisoning": OWASP_AGENTIC.ASI06_MEMORY_POISONING,
    "context_poisoning": OWASP_AGENTIC.ASI06_MEMORY_POISONING,
    "inter_agent": OWASP_AGENTIC.ASI07_INSECURE_INTER_AGENT,
    "a2a": OWASP_AGENTIC.ASI07_INSECURE_INTER_AGENT,
    "cascading": OWASP_AGENTIC.ASI08_CASCADING_FAILURES,
    "trust_exploit": OWASP_AGENTIC.ASI09_TRUST_EXPLOITATION,
    "hallucination": OWASP_AGENTIC.ASI09_TRUST_EXPLOITATION,
    "rogue_agent": OWASP_AGENTIC.ASI10_ROGUE_AGENTS,
}


def _infer_agentic(tags: list[str]) -> OWASP_AGENTIC | None:
    """根据漏洞标签推断最匹配的 OWASP Agentic 2026 类别。"""
    tag_lower = [t.lower().replace(" ", "_") for t in tags]
    for tag in tag_lower:
        for prefix, agentic in _AGENTIC_TAG_MAP.items():
            if prefix in tag:
                return agentic
    return None


class FrontierAdapter:
    def __init__(
        self,
        runner: NativeAttackRunner,
        registry: FrontierRegistry | None = None,
    ):
        self._runner = runner
        self._registry = registry or get_registry()

    def run_frontier_attack(
        self,
        vuln_id: str,
        objective: str,
        payload_type: str = "basic",
    ) -> list[Finding]:
        """执行指定前沿漏洞的攻击。

        Args:
            vuln_id: 漏洞 ID（如 FRONTIER-2025-001）
            objective: 攻击目标描述
            payload_type: 载荷类型（basic/advanced/stealth）

        Returns:
            Finding 对象列表（仅包含成功的攻击）
        """
        vuln = self._registry.get(vuln_id)
        if not vuln:
            logger.error(f"Vuln not found: {vuln_id}")
            return []

        if not vuln.is_active():
            logger.warning(f"Vuln {vuln_id} is not active (status: {vuln.status})")
            return []

        payloads = self._registry.get_payloads(vuln_id, payload_type)
        if not payloads:
            logger.warning(f"No payloads found for {vuln_id}")
            return []

        logger.info(f"Running frontier attack: {vuln_id} ({vuln.name})")
        logger.info(f"Objective: {objective}")
        logger.info(f"Payloads: {len(payloads)}")

        formatted_payloads = [
            p.format(objective=objective) if "{objective}" in p else p
            for p in payloads
        ]

        converters = [vuln.converter] if vuln.converter else None

        results = self._runner.send_many(
            formatted_payloads,
            converters=converters,
            technique=f"frontier_{vuln_id}",
        )

        findings = []
        for result in results:
            if result.success:
                finding = self._to_finding(vuln, result)
                findings.append(finding)
                logger.info(f"SUCCESS: {vuln_id} - {result.response_preview[:100]}")
            else:
                logger.debug(f"FAILURE: {vuln_id}")

        logger.info(f"Frontier attack completed: {len(findings)} successes / {len(results)} total")
        return findings

    def run_all_active(
        self,
        objective: str,
        payload_type: str = "basic",
    ) -> list[Finding]:
        """执行所有活跃前沿漏洞的攻击。

        Args:
            objective: 攻击目标描述
            payload_type: 载荷类型（basic/advanced/stealth）

        Returns:
            Finding 对象列表（所有成功的攻击）
        """
        active_vulns = self._registry.get_active()
        if not active_vulns:
            logger.info("No active frontier vulns found")
            return []

        logger.info(f"Running {len(active_vulns)} active frontier vulns")

        all_findings = []
        for vuln in active_vulns:
            findings = self.run_frontier_attack(vuln.id, objective, payload_type)
            all_findings.extend(findings)

        return all_findings

    def run_by_tag(
        self,
        tag: str,
        objective: str,
        payload_type: str = "basic",
    ) -> list[Finding]:
        """执行指定标签的前沿漏洞攻击。

        Args:
            tag: 标签名称（如 jailbreak, extraction）
            objective: 攻击目标描述
            payload_type: 载荷类型

        Returns:
            Finding 对象列表
        """
        vulns = self._registry.get_by_tag(tag)
        if not vulns:
            logger.info(f"No vulns found with tag: {tag}")
            return []

        all_findings = []
        for vuln in vulns:
            if vuln.is_active():
                findings = self.run_frontier_attack(vuln.id, objective, payload_type)
                all_findings.extend(findings)

        return all_findings

    def _to_finding(self, vuln: FrontierVuln, result) -> Finding:
        """将前沿漏洞攻击结果转换为 Finding 对象。"""
        # 根据漏洞标签推断 OWASP Agentic 类别
        agentic = _infer_agentic(vuln.tags)
        return Finding(
            source="frontier",
            category=", ".join(vuln.tags),
            severity=vuln.severity,
            title=f"{vuln.id}: {vuln.name}",
            description=vuln.description,
            evidence=result.response_preview,
            remediation="\n".join(vuln.known_mitigations),
            cve_refs=[vuln.cve] if vuln.cve else [],
            owasp_agentic=agentic,
        )

    def get_active_vulns(self) -> list[FrontierVuln]:
        """获取所有活跃漏洞。"""
        return self._registry.get_active()

    def list_active_ids(self) -> list[str]:
        """列出所有活跃漏洞 ID。"""
        return self._registry.list_active_ids()
