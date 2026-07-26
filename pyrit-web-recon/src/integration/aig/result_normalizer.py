# -*- coding: utf-8 -*-
"""
AI-Infra-Guard Result Normalizer
================================

将 AI-Infra-Guard 的任务结果转换为统一的 `UnifiedFinding` 模型，
供 Result Layer 进行去重、关联、评分和入库。
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from src.integration.schemas.unified_finding import Evidence, UnifiedFinding


class AIGResultNormalizer:
    """AIG 结果规范化器"""

    # AIG 内部风险级别 → UnifiedFinding 风险级别映射
    SEVERITY_MAP = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
    }

    # AIG 常见 category → OWASP LLM Top 10 2025 映射（可扩展）
    OWASP_LLM_MAP = {
        "prompt_injection": "LLM01:2025",
        "jailbreak": "LLM01:2025",
        "insecure_output": "LLM02:2025",
        "training_data_poisoning": "LLM03:2025",
        "model_dos": "LLM04:2025",
        "supply_chain": "LLM05:2025",
        "sensitive_info_disclosure": "LLM06:2025",
        "permission": "LLM07:2025",
        "excessive_agency": "LLM08:2025",
        "overreliance": "LLM09:2025",
        "model_theft": "LLM10:2025",
        "mcp": "LLM08:2025",  # MCP 过度授权归入 Excessive Agency
    }

    def normalize(
        self,
        task_type: str,
        session_id: str,
        result: Dict[str, Any],
        target: str = "",
    ) -> List[UnifiedFinding]:
        """
        将 AIG 任务结果转换为 UnifiedFinding 列表。

        Args:
            task_type: AIG 任务类型，如 ai_infra_scan / agent_scan 等
            session_id: AIG 任务会话 ID
            result: AIG 返回的 result 字段内容
            target: 目标域名或 URL

        Returns:
            UnifiedFinding 列表
        """
        findings: List[UnifiedFinding] = []

        # 防御性处理：如果 result 为空或非字典
        if not result or not isinstance(result, dict):
            return findings

        # AIG 的结果通常嵌套在 "result" 或 "data" 字段中
        payload = result.get("result") or result.get("data") or result
        if not isinstance(payload, dict):
            payload = result

        # 有些任务直接返回 findings 数组
        raw_findings = payload.get("findings") or payload.get("vulnerabilities") or []
        if isinstance(raw_findings, list):
            for item in raw_findings:
                finding = self._item_to_finding(task_type, session_id, item, target)
                if finding:
                    findings.append(finding)

        # 如果没有任何 findings，但至少任务完成了，生成一条 info 级汇总发现
        if not findings:
            findings.append(self._summary_finding(task_type, session_id, payload, target))

        return findings

    def _item_to_finding(
        self,
        task_type: str,
        session_id: str,
        item: Dict[str, Any],
        target: str,
    ) -> Optional[UnifiedFinding]:
        """将单条 AIG finding 映射为 UnifiedFinding"""
        if not item or not isinstance(item, dict):
            return None

        # 提取字段，兼容多种可能的键名
        title = self._first_of(item, "title", "name", "vulnerability", "issue", "description") or "AIG finding"
        description = self._first_of(item, "description", "detail", "summary", "message") or ""
        severity = self._map_severity(self._first_of(item, "severity", "risk", "level"))
        category = self._first_of(item, "category", "type", "vuln_type", "issue_type") or ""
        endpoint_url = self._first_of(item, "url", "endpoint", "target", "path") or ""
        method = self._first_of(item, "method", "http_method") or ""
        parameter = self._first_of(item, "parameter", "param", "field") or ""
        remediation = self._first_of(item, "remediation", "fix", "solution", "recommendation") or ""
        confidence = self._extract_confidence(item)
        asr = self._extract_asr(item)
        trials = self._extract_trials(item)
        payload_class = self._extract_payload_class(item, category)

        evidence = Evidence(
            request=self._first_of(item, "request", "payload", "prompt"),
            response=self._first_of(item, "response", "output", "answer"),
            extra=item,
        )

        return UnifiedFinding(
            finding_id=str(uuid.uuid4()),
            source_tool="ai-infra-guard",
            task_type=task_type,
            target=target,
            endpoint_url=endpoint_url,
            method=method,
            parameter=parameter,
            severity=severity,
            confidence=confidence,
            category=category,
            owasp_llm_id=self._map_owasp(category),
            title=title,
            description=description,
            remediation=remediation,
            ai_asr=asr,
            ai_trials=trials,
            ai_payload_class=payload_class,
            evidence=evidence,
            session_id=session_id,
            raw=item,
        )

    def _summary_finding(
        self,
        task_type: str,
        session_id: str,
        payload: Dict[str, Any],
        target: str,
    ) -> UnifiedFinding:
        """当 AIG 未返回具体 finding 时，生成一条汇总发现"""
        status = payload.get("status", "completed")
        return UnifiedFinding(
            finding_id=str(uuid.uuid4()),
            source_tool="ai-infra-guard",
            task_type=task_type,
            target=target,
            severity="info",
            confidence=0.5,
            title=f"AIG {task_type} 任务完成",
            description=f"任务 {session_id} 状态为 {status}，未解析出具体风险项。",
            session_id=session_id,
            raw=payload,
        )

    # ------------------- 辅助方法 -------------------

    def _first_of(self, item: Dict[str, Any], *keys: str) -> str:
        """从字典中按优先级取第一个非空字符串值"""
        for key in keys:
            value = item.get(key)
            if value is not None and str(value).strip():
                return str(value).strip()
        return ""

    def _map_severity(self, value: Any) -> str:
        """将 AIG 风险级别映射为统一风险级别"""
        if not value:
            return "info"
        return self.SEVERITY_MAP.get(str(value).lower().strip(), "info")

    def _map_owasp(self, category: str) -> str:
        """根据 category 推断 OWASP LLM ID"""
        if not category:
            return ""
        cat_lower = category.lower().replace(" ", "_")
        return self.OWASP_LLM_MAP.get(cat_lower, "")

    def _extract_confidence(self, item: Dict[str, Any]) -> float:
        """提取置信度，默认 0.7"""
        confidence = item.get("confidence")
        if isinstance(confidence, (int, float)):
            return float(confidence)
        # 有些结果用 score 表示
        score = item.get("score")
        if isinstance(score, (int, float)):
            return min(float(score), 1.0)
        return 0.7

    def _extract_asr(self, item: Dict[str, Any]) -> Optional[float]:
        """提取 Attack Success Rate"""
        for key in ("asr", "attack_success_rate", "success_rate", "pwned_rate"):
            value = item.get(key)
            if isinstance(value, (int, float)):
                return float(value)
        return None

    def _extract_trials(self, item: Dict[str, Any]) -> Optional[int]:
        """提取试验次数"""
        for key in ("trials", "total", "count", "samples"):
            value = item.get(key)
            if isinstance(value, int):
                return value
        return None

    def _extract_payload_class(self, item: Dict[str, Any], category: str) -> str:
        """提取 AI 攻击载荷类别"""
        for key in ("payload_class", "attack_type", "prompt_type", "jailbreak_type"):
            value = item.get(key)
            if value:
                return str(value)
        # 从 category 推断
        cat_lower = category.lower()
        if "jailbreak" in cat_lower:
            return "jailbreak"
        if "prompt_injection" in cat_lower or "injection" in cat_lower:
            return "prompt_injection"
        if "data_exfil" in cat_lower or "exfil" in cat_lower:
            return "data_exfil"
        if "mcp" in cat_lower:
            return "mcp_abuse"
        return ""
