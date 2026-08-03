# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""侦察结果数据模型 — 向后兼容重导出层。.

所有数据模型定义已统一到 core.models.recon_report。
此文件保留为兼容性 shim, 新代码应直接从 core.models 导入。

> **日期**: 2026-8-3
> **变更**: 统一数据模型, 消除 probes/recon_result.py 与 models/recon_report.py 的重复。
"""

from core.models.recon_report import (
    AttackRecommendation,
    DiscoveredEndpoint,
    EndpointType,
    InjectionSurface,
    InjectionSurfaceType,
    LLMFingerprint,
    MCPToolInfo,
    ReconReport,
)

# ReconResult 别名 — 向后兼容 stage_recon.py 和 pyrit-pipeline 中的旧引用
ReconResult = ReconReport

__all__ = [
    "AttackRecommendation",
    "DiscoveredEndpoint",
    "EndpointType",
    "InjectionSurface",
    "InjectionSurfaceType",
    "LLMFingerprint",
    "MCPToolInfo",
    "ReconReport",
    "ReconResult",
]