# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""PyRITExporter: 将 ReconReport 导出为 PyRIT pipeline 可消费的格式。"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from core.exporters.base import ReconExporter

if TYPE_CHECKING:
    from core.models.recon_report import ReconReport

logger = logging.getLogger(__name__)


class PyRITExporter(ReconExporter):
    """PyRIT pipeline 导出器。"""

    def export(self, report: ReconReport, pipeline_ctx: Any = None, **kwargs: Any) -> ReconReport | None:
        if pipeline_ctx is None:
            return report

        if not hasattr(pipeline_ctx, "metadata"):
            pipeline_ctx.metadata = {}

        pipeline_ctx.metadata["recon_result"] = report
        pipeline_ctx.metadata["recon_summary"] = report.to_summary_dict()

        if report.llm_fingerprints:
            fp = report.llm_fingerprints[0]
            pipeline_ctx.metadata["llm_fingerprint"] = fp.to_dict()
            pipeline_ctx.metadata["model_family"] = fp.model_family
            pipeline_ctx.metadata["model_name"] = fp.model_name

        if report.mcp_tools:
            pipeline_ctx.metadata["mcp_tools"] = [t.to_dict() for t in report.mcp_tools]

        logger.info(
            f"ReconReport exported to PyRIT: "
            f"{len(report.endpoints)} endpoints, "
            f"{len(report.llm_fingerprints)} fingerprints, "
            f"{len(report.mcp_tools)} MCP tools, "
            f"{len(report.recommendations)} recommendations"
        )
        return report
