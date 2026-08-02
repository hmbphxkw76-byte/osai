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

__version__ = "0.1.0"
