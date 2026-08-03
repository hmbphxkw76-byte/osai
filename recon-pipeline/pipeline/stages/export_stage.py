# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""阶段4: 标准报告导出。

职责 (对应需求):
  输出对应的标准格式报告, 供后续下游消费。

  支持格式 (通过 context.export_formats 配置):
    - json:  通用 JSON (ReconReport.to_dict)
    - pyrit: PyRIT pipeline 可消费 (ReconReport 写入 pipeline_ctx.metadata)
    - garak: garak-pipeline 可消费 (target_profile / connectivity / probe_candidates)

  所有产物写入 context.output_dir, 返回各格式输出路径字典。
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from pipeline.stages.base import PipelineStage

logger = logging.getLogger(__name__)


class ExportStage(PipelineStage):
    name = "export"

    def __init__(self, output_dir: str | None = None) -> None:
        self._output_dir = output_dir

    async def run(self, context: object) -> dict[str, object]:
        from core.exporters import JSONExporter, PyRITExporter, GarakExporter

        ctx = context  # type: ignore[assignment]
        report = getattr(ctx, "_last_report", None)
        if report is None:
            # 尝试从 context 上挂载的 recon 产物读取
            report = getattr(context, "report", None)
        if report is None:
            raise RuntimeError("ExportStage requires ReconReport from ReconStage (set ctx.report)")

        output_dir = Path(self._output_dir or ctx.output_dir or "outputs/reports")
        output_dir.mkdir(parents=True, exist_ok=True)
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        results: dict[str, object] = {}

        for fmt in ctx.export_formats:
            fmt = fmt.lower().strip()
            try:
                if fmt == "json":
                    path = output_dir / f"recon_report_{run_id}.json"
                    JSONExporter().export(report, output_path=path)
                    results["json"] = str(path)
                elif fmt == "pyrit":
                    # PyRIT 消费: 需要一个带 .metadata 属性的上下文对象
                    import types

                    pyrit_ctx = types.SimpleNamespace(metadata={})
                    PyRITExporter().export(report, pipeline_ctx=pyrit_ctx)
                    path = output_dir / f"pyrit_metadata_{run_id}.json"
                    import json
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump(pyrit_ctx.metadata, f, indent=2, ensure_ascii=False, default=str)
                    results["pyrit"] = str(path)
                elif fmt == "garak":
                    out = GarakExporter().export(report, output_dir=str(output_dir), run_id=run_id)
                    results["garak"] = {k: str(v) for k, v in out.items()}
                else:
                    logger.warning(f"export: unknown format '{fmt}' skipped")
            except Exception as e:  # noqa: BLE001
                logger.error(f"export: format '{fmt}' failed: {e}")
                results[fmt] = {"error": str(e)}

        logger.info(f"[export] wrote {len(results)} format(s) to {output_dir}")
        return results
