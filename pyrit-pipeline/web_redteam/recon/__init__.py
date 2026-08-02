# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""目标侦察模块 — 浏览器驱动的攻击面发现。.

将 web_redteam 从纯攻击框架扩展为 Recon → Attack 两层架构:
  - Recon 层 (本模块): 发现目标攻击面 (API 端点、注入面、Agent 工具调用)
  - Attack 层 (现有): 使用 PyRIT 原生攻击执行

设计原则 (R-010: PyRIT 原生优先):
  - 侦察使用 Playwright 原生 API (page.on("response"), page.query_selector)
  - 攻击推荐映射到 PyRIT 原生 Target / Workflow / Scenario
  - 不修改任何 PyRIT 原生代码

学术依据:
  - Greshake et al. (arXiv:2302.12173): 间接注入需发现 Agent 工具调用端点
  - OWASP Top 10 for LLM Applications 2025: LLM01/LLM06/LLM08 攻击面发现
  - MITRE ATT&CK: Reconnaissance (TA0043) → Initial Access (TA0001)

> **日期**: 2026-8-2
"""

from __future__ import annotations

from web_redteam.recon.attack_recommender import AttackRecommender
from web_redteam.recon.dom_analyzer import DOMAnalyzer
from web_redteam.recon.endpoint_classifier import EndpointClassifier
from web_redteam.recon.network_interceptor import NetworkInterceptor
from web_redteam.recon.recon_result import (
    AttackRecommendation,
    DiscoveredEndpoint,
    InjectionSurface,
    ReconResult,
)
from web_redteam.recon.tool_permission_matrix import (
    ToolPermission,
    ToolPermissionAnalyzer,
    ToolPermissionMatrix,
    ToolRiskLevel,
)
from web_redteam.recon.vector_db_fingerprinter import (
    VectorDBFingerprint,
    VectorDBFingerprinter,
    VectorDBType,
)

__all__ = [
    "AttackRecommendation",
    "DiscoveredEndpoint",
    "InjectionSurface",
    "ReconResult",
    "NetworkInterceptor",
    "DOMAnalyzer",
    "EndpointClassifier",
    "AttackRecommender",
    "VectorDBFingerprint",
    "VectorDBFingerprinter",
    "VectorDBType",
    "ToolPermission",
    "ToolPermissionAnalyzer",
    "ToolPermissionMatrix",
    "ToolRiskLevel",
]
