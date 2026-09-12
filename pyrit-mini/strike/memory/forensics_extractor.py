# -*- coding: utf-8 -*-
"""forensics_extractor.py — Agent Memory 取证数据收集器

从 agent memory 攻击中提取结构化取证证据, 用于后续报告生成:
- 泄露数据样本 (脱敏)
- 攻击路径记录
- 时间线重建
- 影响范围评估
- 修复建议

Academic basis:
    - OWASP ASI09:2025 — Trust Boundary Violation
    - NIST SP 800-86: Guide to Integrating Forensic Techniques
    - RFC 3227: Evidence Collection and Archiving

使用示例:
    extractor = ForensicsExtractor()
    evidence = extractor.extract_from_memory_result(memory_result)
    # → evidence.severity = "critical"
    # → evidence.affected_sessions = 5

Constitution compliance:
    - R-SIZE: < 800 行
    - R-H3: 单一职责 — 仅取证, 不执行攻击
    - C1: 不使用 PyRIT (纯分析逻辑)
    - C2: 不添加攻击端过滤
    - R-S3: 敏感数据自动脱敏
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class EvidenceType(str, Enum):
    """证据类型"""

    DATA_LEAK = "data_leak"  # 数据泄露
    IDOR_PROOF = "idor_proof"  # IDOR 利用证明
    PRIV_ESCALATION = "priv_escalation"  # 权限提升
    INJECTION_CONFIRMED = "injection_confirmed"  # 注入确认
    CONFIG_EXPOSURE = "config_exposure"  # 配置泄露


@dataclass
class ForensicsConfig:
    """取证配置"""

    max_sample_length: int = 500  # 证据样本最大长度
    include_timestamps: bool = True  # 包含时间戳
    redact_secrets: bool = True  # 自动脱敏密钥
    hash_evidence: bool = True  # 计算证据哈希 (完整性)
    extract_affected_users: bool = True  # 提取受影响用户数


@dataclass
class ForensicEvidence:
    """取证证据"""

    evidence_id: str = ""
    evidence_type: EvidenceType = EvidenceType.DATA_LEAK
    severity: str = "medium"  # critical/high/medium/low/info
    title: str = ""
    description: str = ""
    affected_sessions: int = 0
    injections_made: int = 0
    data_sample: str = ""  # 脱敏后的数据样本
    data_hash: str = ""  # SHA-256 hash (完整性验证)
    verification: str = ""  # 验证状态
    attack_path: list[str] = field(default_factory=list)
    timeline: list[dict[str, str]] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    collected_at: str = ""

    def __post_init__(self):
        if not self.evidence_id:
            self.evidence_id = hashlib.sha256(f"{self.title}{time.time()}".encode()).hexdigest()[:16]
        if not self.collected_at:
            self.collected_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type.value,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "affected_sessions": self.affected_sessions,
            "data_sample_length": len(self.data_sample),
            "data_hash": self.data_hash,
            "attack_path": self.attack_path,
            "timeline": self.timeline,
            "recommendations": self.recommendations,
            "collected_at": self.collected_at,
        }


class ForensicsExtractor:
    """Agent Memory 取证数据收集器

    从攻击结果中提取结构化取证证据, 自动脱敏敏感数据,
    生成完整攻击路径和时间线。
    """

    # 敏感数据模式 (用于自动脱敏)
    SENSITIVE_PATTERNS: list[tuple[str, str]] = [
        (r"sk-[a-zA-Z0-9]{32,}", "[REDACTED_OPENAI_KEY]"),
        (r"Bearer\s+[^\s]+", "Bearer [REDACTED_TOKEN]"),
        (r"ghp_[a-zA-Z0-9]{36}", "[REDACTED_GITHUB_PAT]"),
        (r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]"),
        (r"[a-zA-Z0-9_\-]{40}", "[REDACTED_SUSPECTED_SECRET]"),
    ]

    def __init__(self, config: ForensicsConfig | None = None):
        self.config = config or ForensicsConfig()

    def extract_from_memory_result(
        self,
        memory_result: Any,  # MemoryReadResult
    ) -> list[ForensicEvidence]:
        """从内存读取结果提取取证证据"""
        evidences: list[ForensicEvidence] = []

        sessions_data = getattr(memory_result, "sessions_data", {})
        if not sessions_data:
            return evidences

        total_sessions = len(sessions_data)
        total_items = 0

        for session_id, session_data in sessions_data.items():
            # 分析每个会话
            evidence = self._extract_single_session(session_id, session_data, total_sessions)
            if evidence:
                evidences.append(evidence)
                total_items += 1

        # 聚合证据
        if total_items > 1:
            aggregate = self._create_aggregate_evidence(evidences)
            if aggregate:
                evidences.append(aggregate)

        return evidences

    def extract_from_idor_result(
        self,
        idor_result: Any,  # IdorResult
    ) -> ForensicEvidence | None:
        """从 IDOR 测试结果提取证据"""
        if not getattr(idor_result, "success", False):
            return None

        severity_map: dict[str, str] = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
        }

        evidence = ForensicEvidence(
            evidence_type=EvidenceType.IDOR_PROOF,
            severity=severity_map.get(
                getattr(idor_result, "severity", "medium"),
                "medium",
            ),
            title=f"IDOR via Session ID - {getattr(idor_result, 'access_type', 'unknown').value if hasattr(getattr(idor_result, 'access_type', None), 'value') else 'unknown'}",
            description=getattr(idor_result, "description", ""),
            affected_sessions=1,
            data_sample=getattr(idor_result, "data_sample", "")[: self.config.max_sample_length],
            attack_path=getattr(idor_result, "reproduction_steps", []),
            recommendations=[
                "使用加密随机 session ID (UUID v4)",
                "实施 session ownership 验证",
                "添加 rate limiting 防止暴力枚举",
                "对 session 访问进行 audit logging",
            ],
        )

        # 脱敏处理
        if self.config.redact_secrets:
            evidence.data_sample = self._redact_sensitive(evidence.data_sample)

        # 计算完整性 hash
        if self.config.hash_evidence:
            evidence.data_hash = hashlib.sha256(evidence.data_sample.encode()).hexdigest()[:16]

        return evidence

    def extract_from_injection_result(
        self,
        injection_result: Any,  # InjectionResult
    ) -> ForensicEvidence | None:
        """从注入结果提取证据"""
        if not getattr(injection_result, "success", False):
            return None

        return ForensicEvidence(
            evidence_type=EvidenceType.INJECTION_CONFIRMED,
            severity="critical",
            title=f"Memory Injection Confirmed - {getattr(injection_result, 'target_type', 'unknown').value if hasattr(getattr(injection_result, 'target_type', None), 'value') else 'unknown'}",
            description=f"Successfully injected payload into {getattr(injection_result, 'target_type', 'unknown')} storage",
            injections_made=getattr(injection_result, "injections_made", 0),
            data_sample=getattr(injection_result, "payload_delivered", "")[: self.config.max_sample_length],
            verification=getattr(injection_result, "verification_result", ""),
            recommendations=[
                "实施 input sanitization",
                "实施 content validation",
                "使用 write-once 存储",
                "添加 injection pattern detection",
            ],
        )

    def extract_session_enumeration_evidence(
        self,
        enumeration_result: Any,  # EnumerationResult
    ) -> ForensicEvidence | None:
        """从枚举结果提取证据"""
        valid_sessions = getattr(enumeration_result, "valid_sessions", [])
        total_attempts = getattr(enumeration_result, "total_attempts", 0)

        if not valid_sessions:
            return None

        success_rate = len(valid_sessions) / total_attempts if total_attempts > 0 else 0

        return ForensicEvidence(
            evidence_type=EvidenceType.DATA_LEAK,
            severity="critical" if success_rate > 0.5 else "high",
            title="Predictable Session ID Enumeration",
            description=(
                f"Successfully enumerated {len(valid_sessions)} valid sessions "
                f"out of {total_attempts} attempts "
                f"(success rate: {success_rate:.1%})"
            ),
            affected_sessions=len(valid_sessions),
            data_sample=f"Valid sessions (first 5): {valid_sessions[:5]}",
            recommendations=[
                "Replace sequential/counter-based session IDs",
                "Use cryptographically random session IDs (UUID v4)",
                "Implement rate limiting on session creation",
                "Add session ownership verification",
            ],
            metadata={
                "total_attempts": total_attempts,
                "success_rate": f"{success_rate:.4f}",
                "enumeration_strategy": "predictive" if hasattr(enumeration_result, "strategy_used") else "unknown",
            },
        )

    def _extract_single_session(
        self,
        session_id: str,
        session_data: Any,
        total_sessions: int,
    ) -> ForensicEvidence | None:
        """从单个会话数据提取"""
        notes = getattr(session_data, "notes", [])
        history_count = len(getattr(session_data, "history", []))
        secrets_found = getattr(session_data, "secrets_found", [])

        if not notes and not secrets_found:
            return None

        # 确定严重级别
        if secrets_found:
            severity = "critical"
        elif notes:
            severity = "high"
        else:
            severity = "medium"

        evidence = ForensicEvidence(
            evidence_type=EvidenceType.DATA_LEAK,
            severity=severity,
            title=f"Cross-Session Data Access: {session_id[:20]}...",
            description=(
                f"Found {len(notes)} notes, {history_count} history items, "
                f"{len(secrets_found)} secrets in another user's session"
            ),
            affected_sessions=total_sessions,
            attack_path=[
                f"1. Predicted/guessed session ID: {session_id[:10]}...",
                "2. Sent API request with stolen session ID",
                "3. Successfully accessed private session data",
            ],
            recommendations=[
                "Implement session ownership validation",
                "Use unpredictable session identifiers",
                "Add access control for session-scoped resources",
            ],
        )

        # 构造数据样本 (脱敏)
        if notes:
            sample_text = "\n".join(notes[:3])
            evidence.data_sample = sample_text[: self.config.max_sample_length]

        if secrets_found:
            evidence.data_sample += f"\n\n[{len(secrets_found)} secrets redacted]"

        # 脱敏
        if self.config.redact_secrets:
            evidence.data_sample = self._redact_sensitive(evidence.data_sample)

        return evidence

    def _create_aggregate_evidence(
        self,
        evidences: list[ForensicEvidence],
    ) -> ForensicEvidence | None:
        """创建聚合证据"""
        if len(evidences) < 2:
            return None

        total_affected = sum(e.affected_sessions for e in evidences)
        max_severity = max(evidences, key=lambda e: self._severity_rank(e.severity)).severity

        return ForensicEvidence(
            evidence_type=EvidenceType.DATA_LEAK,
            severity=max_severity,
            title="Aggregate: Agent Memory Attack Campaign",
            description=(
                f"Total campaign: {len(evidences)} unique data leak vulnerabilities affecting {total_affected} sessions"
            ),
            affected_sessions=total_affected,
            recommendations=[
                "Urgent: Audit all session management mechanisms",
                "Implement defense-in-depth for memory storage",
                "Review all data with session-scoped access",
            ],
        )

    def _redact_sensitive(self, text: str) -> str:
        """脱敏敏感数据"""
        import re

        redacted = text
        for pattern, replacement in self.SENSITIVE_PATTERNS:
            redacted = re.sub(pattern, replacement, redacted)
        return redacted

    @staticmethod
    def _severity_rank(severity: str) -> int:
        """严重级别排序"""
        ranks = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        return ranks.get(severity.lower(), 2)


def generate_forensics_summary(
    evidences: list[ForensicEvidence],
) -> dict[str, Any]:
    """生成取证摘要"""
    if not evidences:
        return {"status": "no_evidence"}

    severities = [e.severity for e in evidences]
    affected = sum(e.affected_sessions for e in evidences)

    return {
        "total_evidence_items": len(evidences),
        "max_severity": max(severities, key=ForensicsExtractor._severity_rank),
        "total_affected_sessions": affected,
        "evidence_types": list(set(e.evidence_type.value for e in evidences)),
        "all_evidence_ids": [e.evidence_id for e in evidences],
        "recommendations": list({rec for e in evidences for rec in e.recommendations}),
    }
