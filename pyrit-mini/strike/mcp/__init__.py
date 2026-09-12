# -*- coding: utf-8 -*-
"""strike/mcp - MCP (Model Context Protocol) Attack Framework

对 MCP (Model Context Protocol) 服务器执行安全测试:
- 恶意 MCP 服务器 (Malicious Server)
- MCP 安全编排 (MCPSec Orchestrator)
- RAG 投毒攻击 (RAG Attack)
- 动态种子生成 (Dynamic Seeds)
- Schema 操纵 (Schema Manipulation)
- Side-Channel 数据渗出 (Side-Channel Exfiltration)
- 工具 Prompt 注入 (Prompt Injection via Tool)

模块清单:
    - malicious_server    : 恶意 MCP 服务器实现
    - orchestrator        : MCP 安全编排器
    - rag_attack          : MCP RAG 投毒攻击
    - dynamic_seeds       : 动态 MCP 种子生成
    - schema_manipulator  : MCP Schema 操纵器

Academic basis:
    - Greshake et al. (arXiv:2302.12173) — schema_manipulation via MCP
    - Zou et al. (arXiv:2406.04245) — side_channel_exfiltration via tools
    - OWASP ASI Top 10 2025 — prompt_injection_via_tool

Constitution compliance:
    - R-SIZE: 每模块 < 800 行
    - R-H3: 单一职责, 无双重实现
    - R-S1: 不硬编码目标标识符
    - R-S4: 测试全部 mock
"""

# MCP 攻击模块 — 按需导入
from strike.mcp.schema_manipulator import (
    MCPSchemaManipulator,
    SchemaManipPayload,
    SchemaManipResult,
    schema_manipulation_attack,
)

__all__ = [
    # schema_manipulator
    "MCPSchemaManipulator",
    "SchemaManipPayload",
    "SchemaManipResult",
    "schema_manipulation_attack",
]
