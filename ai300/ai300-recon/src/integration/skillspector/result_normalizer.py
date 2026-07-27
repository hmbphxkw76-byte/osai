# -*- coding: utf-8 -*-
"""
SkillSpector Result Normalizer
==============================

将 SkillSpector 的 JSON 或 SARIF 报告转换为统一的 `UnifiedFinding` 模型，
供 Result Layer 进行去重、关联、评分和入库。
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from src.integration.schemas.unified_finding import Evidence, UnifiedFinding


class SkillSpectorResultNormalizer:
    """SkillSpector 结果规范化器"""

    # SkillSpector severity → UnifiedFinding severity
    SEVERITY_MAP = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "info",
    }

    # SkillSpector category / rule_id → OWASP LLM Top 10 2025 映射（可扩展）
    OWASP_LLM_MAP = {
        "prompt_injection": "LLM01:2025",
        "jailbreak": "LLM01:2025",
        "system_prompt_leakage": "LLM06:2025",
        "data_exfiltration": "LLM06:2025",
        "sensitive_info_disclosure": "LLM06:2025",
        "privilege_escalation": "LLM07:2025",
        "excessive_agency": "LLM08:2025",
        "tool_misuse": "LLM08:2025",
        "mcp_least_privilege": "LLM08:2025",
        "mcp_tool_poisoning": "LLM08:2025",
        "supply_chain": "LLM05:2025",
        "memory_poisoning": "LLM03:2025",
        "output_handling": "LLM02:2025",
        "anti_refusal": "LLM01:2025",
        "rogue_agent": "LLM08:2025",
        "ssrf": "LLM08:2025",
    }

    def normalize(
        self,
        report: Dict[str, Any],
        target: str = "",
        session_id: str = "",
    ) -> List[UnifiedFinding]:
        """
        将 SkillSpector 报告转换为 UnifiedFinding 列表。

        Args:
            report: SkillSpector JSON 或 SARIF 报告
            target: 目标域名或 URL
            session_id: 可选的扫描会话 ID

        Returns:
            UnifiedFinding 列表
        """
        findings: List[UnifiedFinding] = []

        if not report or not isinstance(report, dict):
            return findings

        # 判断是 SARIF 还是 JSON 格式
        if report.get("$schema") or report.get("version") == "2.1.0":
            raw_findings = self._extract_from_sarif(report)
        else:
            raw_findings = self._extract_from_json(report)

        for item in raw_findings:
            finding = self._item_to_finding(item, target, session_id, report)
            if finding:
                findings.append(finding)

        return findings

    def _extract_from_json(self, report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """从 JSON 报告中提取 issues 列表"""
        issues = report.get("issues") or []
        if isinstance(issues, list):
            return issues
        return []

    def _extract_from_sarif(self, report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """从 SARIF 报告中提取 results 列表"""
        results: List[Dict[str, Any]] = []
        runs = report.get("runs") or []
        for run in runs:
            for result in run.get("results") or []:
                props = result.get("properties") or {}
                location = {}
                locations = result.get("locations") or []
                if locations:
                    physical = locations[0].get("physicalLocation") or {}
                    artifact = physical.get("artifactLocation") or {}
                    region = physical.get("region") or {}
                    location = {
                        "file": artifact.get("uri", ""),
                        "start_line": region.get("startLine", 1),
                        "end_line": region.get("endLine"),
                    }

                results.append({
                    "id": result.get("ruleId", ""),
                    "category": props.get("category", ""),
                    "pattern": props.get("pattern", ""),
                    "severity": props.get("severity", ""),
                    "confidence": props.get("confidence", 0.7),
                    "location": location,
                    "finding": props.get("finding", ""),
                    "explanation": result.get("message", {}).get("text", props.get("explanation", "")),
                    "remediation": props.get("remediation", ""),
                    "code_snippet": props.get("code_snippet", ""),
                    "intent": props.get("intent", ""),
                    "tags": props.get("tags", []),
                })
        return results

    def _item_to_finding(
        self,
        item: Dict[str, Any],
        target: str,
        session_id: str,
        raw_report: Dict[str, Any],
    ) -> Optional[UnifiedFinding]:
        """将单条 SkillSpector issue 映射为 UnifiedFinding"""
        if not item or not isinstance(item, dict):
            return None

        rule_id = item.get("id") or item.get("rule_id", "")
        category = item.get("category", "")
        pattern = item.get("pattern", "")
        severity = self._map_severity(item.get("severity", ""))
        confidence = self._extract_confidence(item)

        location = item.get("location") or {}
        file_path = location.get("file", "")
        start_line = location.get("start_line", 1)
        end_line = location.get("end_line")

        title = item.get("finding") or f"{rule_id}: {pattern or 'unknown pattern'}"
        if title == f"{rule_id}: unknown pattern":
            title = f"SkillSpector finding {rule_id}"
        description = item.get("explanation") or item.get("message", "")
        remediation = item.get("remediation", "")

        evidence = Evidence(
            request=f"{file_path}:{start_line}",
            response=item.get("code_snippet", ""),
            extra={
                "file": file_path,
                "start_line": start_line,
                "end_line": end_line,
                "pattern": pattern,
                "intent": item.get("intent", ""),
                "tags": item.get("tags", []),
            },
        )

        return UnifiedFinding(
            finding_id=str(uuid.uuid4()),
            source_tool="skillspector",
            task_type="skill_scan",
            target=target,
            endpoint_url=file_path,
            parameter=rule_id,
            severity=severity,
            confidence=confidence,
            category=category,
            owasp_llm_id=self._map_owasp(category, rule_id, pattern),
            title=title,
            description=description,
            remediation=remediation,
            ai_payload_class=self._infer_payload_class(category, rule_id),
            evidence=evidence,
            session_id=session_id,
            raw={"issue": item, "report_summary": self._report_summary(raw_report)},
        )

    def _map_severity(self, value: Any) -> str:
        """映射严重级别"""
        if not value:
            return "info"
        return self.SEVERITY_MAP.get(str(value).upper().strip(), "info")

    def _extract_confidence(self, item: Dict[str, Any]) -> float:
        """提取置信度"""
        confidence = item.get("confidence")
        if isinstance(confidence, (int, float)):
            return float(confidence)
        return 0.7

    def _map_owasp(self, category: str, rule_id: str, pattern: str) -> str:
        """根据 category / rule_id / pattern 推断 OWASP LLM ID"""
        combined = f"{category} {rule_id} {pattern}".lower().replace("_", " ")
        for key, owasp_id in self.OWASP_LLM_MAP.items():
            if key in combined:
                return owasp_id
        return ""

    def _infer_payload_class(self, category: str, rule_id: str) -> str:
        """推断 AI 攻击载荷类别"""
        combined = f"{category} {rule_id}".lower()
        if "prompt_injection" in combined or "jailbreak" in combined or "anti_refusal" in combined:
            return "prompt_injection"
        if "data_exfil" in combined or "sensitive_info" in combined:
            return "data_exfil"
        if "mcp" in combined:
            return "mcp_abuse"
        if "supply_chain" in combined:
            return "supply_chain"
        if "excessive_agency" in combined or "tool_misuse" in combined or "privilege" in combined:
            return "excessive_agency"
        if "memory_poisoning" in combined:
            return "memory_poisoning"
        return ""

    def _report_summary(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """提取报告摘要信息"""
        summary: Dict[str, Any] = {}
        risk = report.get("risk_assessment") or {}
        if risk:
            summary["risk_score"] = risk.get("score")
            summary["risk_severity"] = risk.get("severity")
            summary["recommendation"] = risk.get("recommendation")
        skill = report.get("skill") or {}
        if skill:
            summary["skill_name"] = skill.get("name")
            summary["skill_source"] = skill.get("source")
        return summary
