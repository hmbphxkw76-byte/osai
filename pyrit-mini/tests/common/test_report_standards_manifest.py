"""Tests for REQ-166 (AITG/PTES/AI-SSCV mapping) and REQ-165 (evidence SHA-256 manifest)."""

from __future__ import annotations

import json

from report.evidence_manifest import (
    build_evidence_manifest,
    sha256_bytes,
    sha256_file,
    verify_evidence_manifest,
    write_evidence_manifest,
)
from report.standards import (
    AITG_LAYERS,
    PTES_PHASES,
    ai_sscv_from_asr,
    build_standards_section,
    compute_ai_sscv,
    map_finding_to_standards,
    severity_band,
)


class TestStandards:
    def test_aitg_four_layers(self) -> None:
        assert set(AITG_LAYERS) == {"Model", "Implementation", "System", "Runtime"}

    def test_ptes_seven_phases(self) -> None:
        assert len(PTES_PHASES) == 7
        assert PTES_PHASES[0] == "Pre-engagement" and PTES_PHASES[-1] == "Reporting"

    def test_map_by_component(self) -> None:
        m = map_finding_to_standards(component_key="mcp_tool_poisoning")
        assert m["aitg_layer"] == "Implementation"
        assert m["ptes_phase"] == "Exploitation"

    def test_map_fallback_by_owasp(self) -> None:
        m = map_finding_to_standards(owasp_id="LLM01")
        assert m["aitg_layer"] == "Model"
        m2 = map_finding_to_standards(owasp_id="A01")
        assert m2["aitg_layer"] == "System"

    def test_severity_bands(self) -> None:
        assert severity_band(9.5) == "Critical"
        assert severity_band(7.2) == "High"
        assert severity_band(5.0) == "Medium"
        assert severity_band(1.0) == "Low"
        assert severity_band(0.0) == "Info"

    def test_compute_ai_sscv_bounds(self) -> None:
        result = compute_ai_sscv(exploitability=1.0, impact=1.0, autonomy=1.0, data_sensitivity=1.0)
        assert result["score"] == 10.0 and result["severity"] == "Critical"
        clamped = compute_ai_sscv(exploitability=5.0, impact=-1.0, autonomy=0.5, data_sensitivity=0.5)
        assert 0.0 <= clamped["score"] <= 10.0

    def test_ai_sscv_from_asr_exfil_raises_impact(self) -> None:
        low = ai_sscv_from_asr(asr_percent=10, component_key="model_behavior_shift")
        high = ai_sscv_from_asr(asr_percent=90, component_key="session_memory", exfil_confirmed=True)
        assert high["score"] > low["score"]

    def test_build_section_contains_tables(self) -> None:
        section = build_standards_section(
            [{"title": "F-1", "owasp_id": "LLM01", "component_key": "mcp_tool_poisoning", "asr_percent": 80}]
        )
        assert "OWASP AI Testing Guide" in section
        assert "PTES" in section
        assert "AI-SSCV" in section
        assert "F-1" in section

    def test_build_section_without_findings(self) -> None:
        section = build_standards_section(None)
        assert "Layer Coverage" in section


class TestEvidenceManifest:
    def test_sha256_helpers(self, tmp_path) -> None:
        f = tmp_path / "a.txt"
        f.write_bytes(b"hello")
        assert sha256_file(f) == sha256_bytes(b"hello")

    def test_manifest_lists_files(self, tmp_path) -> None:
        (tmp_path / "e1.json").write_text("{}", encoding="utf-8")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "e2.txt").write_text("x", encoding="utf-8")
        manifest = build_evidence_manifest(tmp_path)
        paths = [e["path"] for e in manifest["files"]]
        assert paths == ["e1.json", "sub/e2.txt"]
        assert manifest["count"] == 2 and manifest["root_hash"]

    def test_write_and_verify_ok(self, tmp_path) -> None:
        (tmp_path / "e.json").write_text("{}", encoding="utf-8")
        write_evidence_manifest(tmp_path)
        assert (tmp_path / "evidence_manifest.json").is_file()
        assert (tmp_path / "evidence_manifest.sha256").is_file()
        result = verify_evidence_manifest(tmp_path)
        assert result["valid"] is True and result["checked"] == 1

    def test_manifest_excludes_itself(self, tmp_path) -> None:
        (tmp_path / "e.json").write_text("{}", encoding="utf-8")
        manifest = write_evidence_manifest(tmp_path)
        # 再生成一次，清单文件不自我收录（幂等）
        manifest2 = write_evidence_manifest(tmp_path)
        assert manifest["root_hash"] == manifest2["root_hash"]
        assert all("evidence_manifest" not in e["path"] for e in manifest2["files"])

    def test_tamper_detected(self, tmp_path) -> None:
        f = tmp_path / "e.json"
        f.write_text("{}", encoding="utf-8")
        write_evidence_manifest(tmp_path)
        f.write_text('{"tampered": true}', encoding="utf-8")
        result = verify_evidence_manifest(tmp_path)
        assert result["valid"] is False
        assert "e.json" in result["mismatched"]

    def test_missing_file_detected(self, tmp_path) -> None:
        f = tmp_path / "gone.json"
        f.write_text("{}", encoding="utf-8")
        write_evidence_manifest(tmp_path)
        f.unlink()
        result = verify_evidence_manifest(tmp_path)
        assert result["valid"] is False and "gone.json" in result["missing"]

    def test_verify_without_manifest(self, tmp_path) -> None:
        result = verify_evidence_manifest(tmp_path)
        assert result["valid"] is False and result["reason"] == "manifest_not_found"

    def test_manifest_json_structure(self, tmp_path) -> None:
        (tmp_path / "e.json").write_text("{}", encoding="utf-8")
        write_evidence_manifest(tmp_path)
        data = json.loads((tmp_path / "evidence_manifest.json").read_text(encoding="utf-8"))
        assert data["schema_version"] == "1.0"
        assert data["files"][0]["sha256"]
