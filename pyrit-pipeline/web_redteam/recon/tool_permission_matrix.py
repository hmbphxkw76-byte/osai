# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Agent 工具权限矩阵 — 量化评估 Agent 工具的过度代理风险 (LLM06).

分析 Agent 工具端点和面板, 构建工具权限矩阵:
  - 工具名称 × 操作类型 × 作用域 × 风险等级

风险等级评估维度:
  1. 数据访问范围: 读取/写入/删除
  2. 系统影响: 文件系统/网络/数据库/代码执行
  3. 可逆性: 可逆/不可逆
  4. 外部副作用: 内部/外部 API 调用

OWASP 2025 映射:
  - LLM06: Excessive Agency — 高权限工具可能被间接注入操控执行未授权操作

学术依据:
  - OWASP Top 10 for LLM Applications 2025: LLM06 Excessive Agency
  - MITRE ATT&CK T1059: Command and Scripting Interpreter
  - Anthropic Tool Use 安全指南 (2024)

> **日期**: 2026-8-2
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from web_redteam.recon.recon_result import DiscoveredEndpoint, EndpointType

logger = logging.getLogger(__name__)


class ToolRiskLevel(str, Enum):
    """工具风险等级。."""

    CRITICAL = "critical"  # 代码执行/系统命令/数据删除
    HIGH = "high"          # 文件写入/外部 API 调用/数据库修改
    MEDIUM = "medium"      # 文件读取/数据库查询/网络请求
    LOW = "low"            # 纯文本输出/无副作用查询


class ToolActionType(str, Enum):
    """工具操作类型。."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    NETWORK = "network"
    QUERY = "query"
    UNKNOWN = "unknown"


@dataclass
class ToolPermission:
    """单个工具的权限描述.

    Attributes:
        name: 工具名称。
        endpoint_url: 关联的 API 端点 URL。
        action_type: 操作类型。
        risk_level: 风险等级。
        data_scope: 数据访问范围描述。
        reversible: 是否可逆。
        external_impact: 外部影响描述。
        evidence: 评估证据列表。
    """

    name: str = ""
    endpoint_url: str = ""
    action_type: ToolActionType = ToolActionType.UNKNOWN
    risk_level: ToolRiskLevel = ToolRiskLevel.LOW
    data_scope: str = ""
    reversible: bool = True
    external_impact: str = ""
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """序列化为字典。."""
        return {
            "name": self.name,
            "endpoint_url": self.endpoint_url,
            "action_type": self.action_type.value,
            "risk_level": self.risk_level.value,
            "data_scope": self.data_scope,
            "reversible": self.reversible,
            "external_impact": self.external_impact,
            "evidence": self.evidence,
        }


@dataclass
class ToolPermissionMatrix:
    """Agent 工具权限矩阵.

    汇总所有工具的权限评估结果。

    Attributes:
        tools: 工具权限列表。
        critical_count: CRITICAL 风险工具数。
        high_count: HIGH 风险工具数。
        over Agency_score: 过度代理风险评分 (0-100, 越高越危险)。
    """

    tools: list[ToolPermission] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        """CRITICAL 风险工具数。."""
        return sum(1 for t in self.tools if t.risk_level == ToolRiskLevel.CRITICAL)

    @property
    def high_count(self) -> int:
        """HIGH 风险工具数。."""
        return sum(1 for t in self.tools if t.risk_level == ToolRiskLevel.HIGH)

    @property
    def over_agency_score(self) -> int:
        """过度代理风险评分 (0-100, 越高越危险).

        计算: CRITICAL×30 + HIGH×15 + MEDIUM×5 + LOW×1, 上限 100。
        """
        score = sum(
            1 * 30 if t.risk_level == ToolRiskLevel.CRITICAL
            else 15 if t.risk_level == ToolRiskLevel.HIGH
            else 5 if t.risk_level == ToolRiskLevel.MEDIUM
            else 1
            for t in self.tools
        )
        return min(score, 100)

    def get_tools_by_risk(self, level: ToolRiskLevel) -> list[ToolPermission]:
        """按风险等级过滤工具。."""
        return [t for t in self.tools if t.risk_level == level]

    def summary(self) -> str:
        """人类可读摘要。."""
        lines = [
            "ToolPermissionMatrix Summary:",
            f"  Total tools: {len(self.tools)}",
            f"  CRITICAL: {self.critical_count}",
            f"  HIGH: {self.high_count}",
            f"  Over-Agency Score: {self.over_agency_score}/100",
        ]
        for t in self.tools:
            lines.append(f"  [{t.risk_level.value.upper():>8}] {t.name} ({t.action_type.value}) — {t.data_scope}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """序列化为字典。."""
        return {
            "tools": [t.to_dict() for t in self.tools],
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "over_agency_score": self.over_agency_score,
        }


# ── 工具风险评估规则 ──
# (URL/名称关键词, 操作类型, 风险等级, 数据范围, 可逆, 外部影响)
_RISK_RULES: list[tuple[re.Pattern[str], ToolActionType, ToolRiskLevel, str, bool, str]] = [
    # CRITICAL: 代码执行/系统命令
    (re.compile(r"exec|execute|run|system|shell|subprocess|eval|command", re.IGNORECASE),
     ToolActionType.EXECUTE, ToolRiskLevel.CRITICAL, "代码执行", False, "可执行任意系统命令"),
    (re.compile(r"delete|remove|drop|purge|wipe|destroy", re.IGNORECASE),
     ToolActionType.DELETE, ToolRiskLevel.CRITICAL, "数据删除", False, "不可恢复的数据删除"),

    # HIGH: 文件写入/外部 API 调用/数据库修改
    (re.compile(r"write|upload|create|insert|update|modify|patch|put", re.IGNORECASE),
     ToolActionType.WRITE, ToolRiskLevel.HIGH, "数据写入", True, "修改目标系统数据"),
    (re.compile(r"send|email|notify|publish|broadcast|post", re.IGNORECASE),
     ToolActionType.NETWORK, ToolRiskLevel.HIGH, "外部通信", True, "向外部系统发送数据"),
    (re.compile(r"fetch|browse|navigate|crawl|scrape|download", re.IGNORECASE),
     ToolActionType.NETWORK, ToolRiskLevel.HIGH, "网络请求", True, "访问外部 URL (XPIA 注入面)"),

    # MEDIUM: 文件读取/数据库查询
    (re.compile(r"read|get|list|search|query|retrieve|fetch_data", re.IGNORECASE),
     ToolActionType.READ, ToolRiskLevel.MEDIUM, "数据读取", True, "读取敏感数据"),
    (re.compile(r"database|sql|db|collection|index|vector", re.IGNORECASE),
     ToolActionType.QUERY, ToolRiskLevel.MEDIUM, "数据库查询", True, "查询数据库内容"),

    # LOW: 纯文本/无副作用
    (re.compile(r"chat|respond|answer|reply|echo|format|translate", re.IGNORECASE),
     ToolActionType.READ, ToolRiskLevel.LOW, "文本输出", True, "无副作用"),
]


class ToolPermissionAnalyzer:
    """Agent 工具权限分析器.

    分析 Agent 工具端点和面板, 构建工具权限矩阵。

    用法::
        analyzer = ToolPermissionAnalyzer()
        matrix = analyzer.analyze(endpoints)
        print(matrix.summary())
    """

    def analyze(
        self,
        endpoints: list[DiscoveredEndpoint],
    ) -> ToolPermissionMatrix:
        """分析 Agent 工具端点, 构建权限矩阵.

        Args:
            endpoints: NetworkInterceptor 发现的端点列表。

        Returns:
            ToolPermissionMatrix 实例。
        """
        matrix = ToolPermissionMatrix()

        for endpoint in endpoints:
            # 只分析 Agent Tool API 端点
            if endpoint.endpoint_type != EndpointType.AGENT_TOOL_API:
                continue

            tool = self._analyze_single(endpoint)
            if tool:
                matrix.tools.append(tool)

        logger.info(
            f"ToolPermissionAnalyzer: analyzed {len(matrix.tools)} tools, "
            f"{matrix.critical_count} critical, {matrix.high_count} high, "
            f"score={matrix.over_agency_score}"
        )
        return matrix

    def _analyze_single(
        self, endpoint: DiscoveredEndpoint
    ) -> ToolPermission | None:
        """分析单个 Agent 工具端点。."""
        url = endpoint.url
        # 从 URL 提取工具名称
        tool_name = self._extract_tool_name(url)

        evidence: list[str] = []

        # 匹配风险规则
        for pattern, action_type, risk_level, data_scope, reversible, external_impact in _RISK_RULES:
            if pattern.search(url):
                evidence.append(f"URL matches risk pattern: {pattern.pattern}")

                # 检查响应体是否包含额外线索
                body = endpoint.response_body_preview or ""
                if body and pattern.search(body):
                    evidence.append(f"Response body also matches: {pattern.pattern}")

                return ToolPermission(
                    name=tool_name,
                    endpoint_url=url,
                    action_type=action_type,
                    risk_level=risk_level,
                    data_scope=data_scope,
                    reversible=reversible,
                    external_impact=external_impact,
                    evidence=evidence,
                )

        # 未匹配任何规则 → 默认 MEDIUM 风险
        return ToolPermission(
            name=tool_name,
            endpoint_url=url,
            action_type=ToolActionType.UNKNOWN,
            risk_level=ToolRiskLevel.MEDIUM,
            data_scope="未知 (需手动评估)",
            reversible=True,
            external_impact="未知",
            evidence=["No specific risk pattern matched"],
        )

    @staticmethod
    def _extract_tool_name(url: str) -> str:
        """从 URL 提取工具名称。."""
        from urllib.parse import urlparse

        path = urlparse(url).path
        # 取最后一段路径作为工具名
        segments = [s for s in path.split("/") if s]
        if segments:
            return segments[-1]
        return url

    @staticmethod
    def get_owasp_mapping(risk_level: ToolRiskLevel) -> list[str]:
        """将风险等级映射到 OWASP LLM 类别。."""
        if risk_level in (ToolRiskLevel.CRITICAL, ToolRiskLevel.HIGH):
            return ["LLM06", "LLM01"]
        return ["LLM06"]
