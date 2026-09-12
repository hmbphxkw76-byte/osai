# -*- coding: utf-8 -*-
"""recon/mcp - MCP (Model Context Protocol) 侦察模块

对 MCP (Model Context Protocol) 服务器执行侦察:
- MCP Schema 提取 (Schema Extraction)
- 端点枚举 (Endpoint Enumeration)
- 工具清单扫描 (Tool Inventory)
- 安全表面扫描 (Security Surface Scan)
- 能力探测 (Capability Probe)
- 版本指纹 (Version Fingerprinting)

模块清单:
    - schema_extractor      : MCP Schema 提取器
    - endpoint_enumerator   : MCP 端点枚举器
    - tool_inventory        : 工具清单扫描器
    - surface_scanner       : 安全表面扫描仪
    - capability_probe      : 能力探测器
    - version_fingerprint   : 版本指纹器

Academic basis:
    - Greshake et al. (arXiv:2302.12173) — Indirect Prompt Injection
    - Zhan et al. (arXiv:2307.00929) — Tool schema attack surface
    - OWASP ASI Top 10 2025 — MCP Security

Constitution compliance:
    - R-SIZE: 每模块 < 800 行
    - R-H3: 单一职责, 无双重实现
    - R-S1: 不硬编码目标标识符
    - R-S4: 测试全部 mock
"""

from recon.mcp.capability_probe import (
    MCPCapabilityInfo,
    MCPCapabilityProbe,
    probe_mcp_capabilities,
)
from recon.mcp.endpoint_enumerator import (
    EndpointEnumerationResult,
    MCPEndpointEnumerator,
    MCPEndpointInfo,
    enumerate_mcp_endpoints,
)
from recon.mcp.schema_extractor import (
    MCPSchemaExtractor,
    MCPServerInfo,
    MCPToolDefinition,
    extract_mcp_schema,
)
from recon.mcp.surface_scanner import (
    MCPSecuritySurfaceScanner,
    SecuritySurfaceFinding,
    SurfaceScanResult,
    scan_mcp_security_surface,
)
from recon.mcp.tool_inventory import (
    MCPToolInventoryScanner,
    MCPToolRisk,
    ToolInventoryResult,
    scan_mcp_tool_inventory,
)
from recon.mcp.version_fingerprint import (
    MCPVersionFingerprinter,
    VersionFingerprintResult,
    fingerprint_mcp_version,
)

__all__ = [
    # Schema Extractor
    "MCPSchemaExtractor",
    "MCPServerInfo",
    "MCPToolDefinition",
    "extract_mcp_schema",
    # Endpoint Enumerator
    "MCPEndpointEnumerator",
    "MCPEndpointInfo",
    "EndpointEnumerationResult",
    "enumerate_mcp_endpoints",
    # Tool Inventory
    "MCPToolInventoryScanner",
    "MCPToolRisk",
    "ToolInventoryResult",
    "scan_mcp_tool_inventory",
    # Surface Scanner
    "MCPSecuritySurfaceScanner",
    "SecuritySurfaceFinding",
    "SurfaceScanResult",
    "scan_mcp_security_surface",
    # Capability Probe
    "MCPCapabilityProbe",
    "MCPCapabilityInfo",
    "probe_mcp_capabilities",
    # Version Fingerprint
    "MCPVersionFingerprinter",
    "VersionFingerprintResult",
    "fingerprint_mcp_version",
]
