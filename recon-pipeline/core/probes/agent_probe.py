# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""AgentProbe: Agent 工具侦察探针。.

职责:
  1. 从 NetworkInterceptor 结果中筛选 AGENT_TOOL_API 端点
  2. 委托 ToolPermissionAnalyzer 构建工具权限矩阵
  3. 评估过度代理风险 (LLM06 Excessive Agency)

对齐 DESIGN.md 六类探针架构:
  - 输入: auth_state + browser_page
  - 产出: endpoints (AGENT_TOOL_API) + tool_permission_matrix
  - 浏览器需求: True

学术依据:
  - OWASP LLM06: Excessive Agency
  - OWASP LLM01: 间接注入操控 Agent 工具
  - MITRE ATT&CK T1059: Command and Scripting Interpreter

> **日期**: 2026-8-3
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from core.models.recon_report import DiscoveredEndpoint, EndpointType
from core.probes.base import ReconProbe
from core.probes.tool_permission_matrix import ToolPermissionAnalyzer

if TYPE_CHECKING:
    from core.session import ReconSession

logger = logging.getLogger(__name__)


class AgentProbe(ReconProbe):
    """Agent 工具侦察探针。.

    从已发现的端点中筛选 Agent 工具端点,
    构建工具权限矩阵并评估过度代理风险。

    用法::
        probe = AgentProbe()
        result = await probe.probe(session)
        # result["endpoints"] → Agent Tool API 端点列表
        # result["tool_permission_matrix"] → 工具权限矩阵
    """

    def __init__(self) -> None:
        self._analyzer = ToolPermissionAnalyzer()

    @property
    def name(self) -> str:
        return "AgentProbe"

    @property
    def requires_browser(self) -> bool:
        return True

    async def probe(self, session: ReconSession) -> dict[str, Any]:
        """执行 Agent 探针。.

        Args:
            session: 侦察会话。

        Returns:
            包含 agent_endpoints 和 tool_permission_matrix 的结果字典。
        """
        agent_endpoints = [
            e for e in session.report.endpoints
            if e.endpoint_type == EndpointType.AGENT_TOOL_API
        ]

        matrix = None
        if agent_endpoints:
            matrix = self._analyzer.analyze(agent_endpoints)

        logger.info(
            f"AgentProbe: {len(agent_endpoints)} agent tool endpoints, "
            f"over-agency score: {matrix.over_agency_score if matrix else 0}"
        )

        return {
            "endpoints": agent_endpoints,
            "tool_permission_matrix": matrix.to_dict() if matrix else {},
        }
