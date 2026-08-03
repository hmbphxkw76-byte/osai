# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""recon-pipeline: Shared AI reconnaissance module.

Architecture:
    ReconSession (auth state + browser context)
        → ReconPipeline (orchestrates probes)
            → LLMProbe / RAGProbe / AgentProbe / MCPProbe / EmbeddingProbe / DOMProbe
        → ReconReport (unified result)
            → PyRITExporter / GarakExporter / JSONExporter
"""

from core.models.auth_state import AuthState
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
from core.orchestration import ReconOrchestrator
from core.pipeline import ReconPipeline
from core.session import ReconSession
from core.task_runtime import GuardrailPolicy, ReconTask, TaskRuntime

__version__ = "0.3.0"

__all__ = [
    "AttackRecommendation",
    "AuthState",
    "DiscoveredEndpoint",
    "EndpointType",
    "InjectionSurface",
    "InjectionSurfaceType",
    "LLMFingerprint",
    "MCPToolInfo",
    "GuardrailPolicy",
    "ReconOrchestrator",
    "ReconPipeline",
    "ReconReport",
    "ReconSession",
    "ReconTask",
    "TaskRuntime",
]
