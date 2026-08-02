# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""GarakExporter: 将 ReconReport 导出为 garak-pipeline 可消费的格式。"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from core.exporters.base import ReconExporter

if TYPE_CHECKING:
    from core.models.recon_report import ReconReport

logger = logging.getLogger(__name__)


class GarakExporter(ReconExporter):
    """Garak pipeline 导出器。"""

    def export(
        self,
        report: ReconReport,
        output_dir: str | Path = "outputs/01_recon",
        run_id: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Path]:
        if run_id is None:
            run_id = datetime.now().strftime("%Y%m%d_%H%M")

        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        target_profile = {
            "run_id": run_id,
            "target_url": report.target_url,
            "auth_type": report.auth_type,
            "endpoints": [e.to_dict() for e in report.endpoints],
            "llm_fingerprints": [f.to_dict() for f in report.llm_fingerprints],
            "mcp_tools": [t.to_dict() for t in report.mcp_tools],
            "injection_surfaces": [s.to_dict() for s in report.injection_surfaces],
            "domain_transitions": report.domain_transitions,
        }
        profile_path = out_dir / f"target_profile_{run_id}.json"
        with open(profile_path, "w", encoding="utf-8") as f:
            json.dump(target_profile, f, indent=2, ensure_ascii=False, default=str)

        connectivity = {
            "run_id": run_id,
            "target_url": report.target_url,
            "ok": report.has_model_api,
            "latency_ms": int(report.recon_duration_seconds * 1000),
            "auth_type": report.auth_type,
            "endpoints_found": len(report.endpoints),
            "model_api_detected": report.has_model_api,
            "rag_api_detected": report.has_rag_api,
            "agent_tools_detected": report.has_agent_tools,
            "mcp_server_detected": report.has_mcp_server,
            "embedding_api_detected": report.has_embedding_api,
        }
        conn_path = out_dir / f"connectivity_test_{run_id}.json"
        with open(conn_path, "w", encoding="utf-8") as f:
            json.dump(connectivity, f, indent=2, ensure_ascii=False, default=str)

        candidates = []
        for rec in report.recommendations:
            candidates.append({
                "owasp_id": rec.owasp_id,
                "attack_strategy": rec.attack_strategy,
                "target_type": rec.target_type,
                "priority": rec.priority,
                "rationale": rec.rationale,
            })
        for fp in report.llm_fingerprints:
            candidates.append({
                "owasp_id": "LLM01",
                "attack_strategy": "garak_probes",
                "target_type": "model_api",
                "priority": 1,
                "rationale": f"Model fingerprinted: {fp.model_family}/{fp.model_name}",
            })
        cand_path = out_dir / f"probe_candidates_{run_id}.json"
        with open(cand_path, "w", encoding="utf-8") as f:
            json.dump(candidates, f, indent=2, ensure_ascii=False, default=str)

        logger.info(f"ReconReport exported to Garak: {profile_path.name}, {conn_path.name}, {cand_path.name}")
        return {"target_profile": profile_path, "connectivity_test": conn_path, "probe_candidates": cand_path}
