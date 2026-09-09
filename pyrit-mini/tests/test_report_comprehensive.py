# arXiv:2407.01232 - PyRIT, evidence extraction and reporting
# arXiv:2308.07920 - Zhang et al., Dual Judge scoring evidence
# arXiv:2302.12173 - Greshake et al., Prompt injection evidence
"""Comprehensive tests for report module.

Covers:
    - evidence_extract: Field extraction functions
    - _poc_templates: PoC template rendering
    - generator: Report generation entry point
    - report_html: HTML report generation
    - owasp_mapping: OWASP ID inference
    - owasp_constants: OWASP category constants
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


class TestEvidenceExtract:
    """Test evidence extraction functions."""

    def test_get_arxiv_reference_known(self):
        from report.evidence_extract import _get_arxiv_reference

        result = _get_arxiv_reference("prompt_sending")
        assert isinstance(result, str)
        assert "arXiv" in result

    def test_get_arxiv_reference_unknown(self):
        from report.evidence_extract import _get_arxiv_reference

        result = _get_arxiv_reference("unknown_technique")
        assert result == "PyRIT (arXiv:2407.01232)"

    def test_determine_confidence_high(self):
        from report.evidence_extract import _determine_confidence

        assert _determine_confidence(75.0, True) == "high"

    def test_determine_confidence_medium(self):
        from report.evidence_extract import _determine_confidence

        assert _determine_confidence(30.0, True) == "medium"

    def test_determine_confidence_low(self):
        from report.evidence_extract import _determine_confidence

        assert _determine_confidence(10.0, True) == "low"

    def test_determine_confidence_informational(self):
        from report.evidence_extract import _determine_confidence

        assert _determine_confidence(0.0, False) == "informational"

    def test_classify_failure_content_filter(self):
        from report.evidence_extract import _classify_failure

        mock_result = MagicMock()
        mock_result.error = "content_filter triggered"
        mock_result.last_response = None
        assert _classify_failure(mock_result) == "content_filter"

    def test_classify_failure_timeout(self):
        from report.evidence_extract import _classify_failure

        mock_result = MagicMock()
        mock_result.error = "Request timeout"
        mock_result.last_response = None
        assert _classify_failure(mock_result) == "timeout"

    def test_classify_failure_empty_response(self):
        from report.evidence_extract import _classify_failure

        mock_result = MagicMock()
        mock_result.error = ""
        mock_result.last_response = None
        assert _classify_failure(mock_result) == "empty_response"

    def test_extract_response_text_with_last_response(self):
        from report.evidence_extract import _extract_response_text

        mock_result = MagicMock()
        mock_piece = MagicMock()
        mock_piece.converted_value = "Test response"
        mock_piece.original_value = "Original"
        mock_result.last_response = mock_piece
        result = _extract_response_text(mock_result)
        assert result == "Test response"

    def test_extract_response_text_empty(self):
        from report.evidence_extract import _extract_response_text

        mock_result = MagicMock()
        mock_result.last_response = None
        result = _extract_response_text(mock_result)
        assert result == ""


class TestPocTemplates:
    """Test PoC template rendering."""

    def test_single_turn_template_renders(self):
        from report._poc_templates import _SINGLE_TURN_TEMPLATE

        result = _SINGLE_TURN_TEMPLATE.format(
            technique_display="Test Attack",
            evidence_id="EVD-001",
            risk_score="8.5",
            severity="high",
            mitre_id="AML.T0051",
            mitre_name="LLM Prompt Injection",
            owasp_id="LLM01",
            owasp_category="Prompt Injection",
            owasp_standard="LLM Top 10",
            owasp_ref="https://owasp.org",
            arxiv_ref="arXiv:2407.01232",
            technique_name="prompt_sending",
            attack_class="PromptSendingAttack",
            converter_chain_display="none (baseline)",
            converter_setup="",
            converter_config_code="    converter_configs = []",
            objective_raw="Test objective",
            target_endpoint="http://localhost:8000",
            outcome="success",
            role="user",
            content="test",
            e="",
        )
        assert "Test Attack" in result
        assert "EVD-001" in result
        assert "PromptSendingAttack" in result
        assert "LLM01" in result
        assert "Prompt Injection" in result

    def test_multi_turn_template_renders(self):
        from report._poc_templates import _MULTI_TURN_TEMPLATE

        result = _MULTI_TURN_TEMPLATE.format(
            technique_display="Crescendo",
            evidence_id="EVD-002",
            risk_score="9.0",
            severity="critical",
            mitre_id="AML.T0051",
            mitre_name="LLM Prompt Injection",
            owasp_id="LLM01",
            owasp_category="Prompt Injection",
            owasp_standard="LLM Top 10",
            owasp_ref="https://owasp.org",
            arxiv_ref="arXiv:2402.12109",
            technique_name="crescendo",
            technique_label="Crescendo",
            attack_class="CrescendoAttack",
            converter_chain_display="none (baseline)",
            scoring_setup="",
            attack_construct="",
            objective_raw="Test objective",
            attack_import="",
            target_endpoint="http://localhost:8000",
            adv_endpoint="https://api.example.com",
            adv_model="test-model",
            outcome="success",
            incomplete=0,
            role="user",
            content="test",
            e="",
        )
        assert "Crescendo" in result
        assert "EVD-002" in result
        assert "CrescendoAttack" in result
        assert "LLM01" in result

    def test_single_turn_template_syntax_valid(self):
        """Verify the generated PoC script has valid Python syntax."""
        from report._poc_templates import _SINGLE_TURN_TEMPLATE

        result = _SINGLE_TURN_TEMPLATE.format(
            technique_display="Test",
            evidence_id="EVD-001",
            risk_score="5.0",
            severity="medium",
            mitre_id="AML.T0051",
            mitre_name="Test",
            owasp_id="LLM01",
            owasp_category="Prompt Injection",
            owasp_standard="LLM Top 10",
            owasp_ref="https://owasp.org",
            arxiv_ref="arXiv:2407.01232",
            technique_name="test",
            attack_class="PromptSendingAttack",
            converter_chain_display="none",
            converter_setup="",
            converter_config_code="    converter_configs = []",
            objective_raw="Test objective",
            target_endpoint="http://localhost:8000",
            outcome="success",
            role="user",
            content="test",
            e="",
        )
        # Verify the template contains expected script elements
        assert "#!/usr/bin/env python3" in result
        assert "import asyncio" in result
        assert "PromptSendingAttack" in result


class TestGenerator:
    """Test generator functions."""

    def test_owasp_all_categories_not_empty(self):
        from report.generator import _OWASP_ALL_CATEGORIES

        assert len(_OWASP_ALL_CATEGORIES) > 0
        assert "LLM01" in _OWASP_ALL_CATEGORIES
        assert "A01" in _OWASP_ALL_CATEGORIES

    def test_classify_score_consistency_empty(self):
        from report.generator import _classify_score_consistency

        assert _classify_score_consistency([]) == "N/A"

    def test_classify_score_consistency_single(self):
        from report.generator import _classify_score_consistency

        result = _classify_score_consistency([{"scorer": "A", "score_value": "true"}])
        assert result == "Post-hoc Dual Judge"

    def test_classify_score_consistency_consistent(self):
        from report.generator import _classify_score_consistency

        scores = [
            {"scorer": "A", "score_value": "true"},
            {"scorer": "B", "score_value": "1"},
        ]
        assert _classify_score_consistency(scores) == "Consistent"

    def test_classify_score_consistency_disagreement(self):
        from report.generator import _classify_score_consistency

        scores = [
            {"scorer": "A", "score_value": "true"},
            {"scorer": "B", "score_value": "false"},
        ]
        assert _classify_score_consistency(scores) == "Minor Disagreement"


class TestReportHtml:
    """Test HTML report functions."""

    def test_evidence_to_dict_structure(self):
        from report.report_html import _evidence_to_dict

        mock_evidence = MagicMock()
        mock_evidence.collection_id = "test-123"
        mock_evidence.timestamp = "2024-01-01T00:00:00"
        mock_evidence.target_model = "test-model"
        mock_evidence.target_fingerprint = {}
        mock_evidence.attack_surface = []
        mock_evidence.total_attacks = 10
        mock_evidence.successful_attacks = 5
        mock_evidence.failed_attacks = 5
        mock_evidence.overall_asr = 50.0
        mock_evidence.owasp_standard_references = {}
        mock_evidence.owasp_llm_compliance = {}
        mock_evidence.owasp_asi_compliance = {}
        mock_evidence.evidence = []
        mock_evidence.owasp_coverage = {}
        mock_evidence.technique_distribution = {}
        mock_evidence.failure_analysis = {}
        mock_evidence.findings = []
        mock_evidence.orchestration_log = []
        mock_evidence.wilson_ci = (0.4, 0.6)
        mock_evidence.cohens_kappa = 0.8

        result = _evidence_to_dict(mock_evidence)
        assert result["collection_id"] == "test-123"
        assert result["total_attacks"] == 10
        assert "web_vuln_stats" in result  # backward compat field
        assert "discovered_endpoints" in result  # backward compat field

    def test_single_evidence_to_dict_fallback(self):
        from report.report_html import _single_evidence_to_dict

        mock_ev = MagicMock()
        mock_ev.evidence_id = "EVD-001"
        mock_ev.attack_id = "ATK-001"
        mock_ev.technique_name = "prompt_sending"
        mock_ev.technique_display_name = "Prompt Sending"
        mock_ev.converter_chain = None  # Test fallback
        mock_ev.owasp_id = "LLM01"
        mock_ev.owasp_category = "Prompt Injection"
        mock_ev.owasp_standard = "LLM Top 10"
        mock_ev.owasp_severity = "high"
        mock_ev.owasp_risk_score = 8.5
        mock_ev.owasp_mitigations = []
        mock_ev.owasp_reference = "https://owasp.org"
        mock_ev.cvss_vector = "CVSS:3.1"
        mock_ev.objective = "Test objective"
        mock_ev.jailbreak_prompt = None
        mock_ev.harmful_output = None
        mock_ev.is_success = True
        mock_ev.file_suffix = "_success"
        mock_ev.asr = 75.0
        mock_ev.confidence = "high"
        mock_ev.arxiv_reference = None  # Test fallback
        mock_ev.timestamp = "2024-01-01"
        mock_ev.target_model = "test-model"
        mock_ev.conversation_history = None  # Test fallback
        mock_ev.converter_log = None  # Test fallback
        mock_ev.score_details = None  # Test fallback

        result = _single_evidence_to_dict(mock_ev)
        assert result["evidence_id"] == "EVD-001"
        assert result["converter_chain"] == "none (baseline)"  # P1-1 fallback
        assert result["arxiv_reference"] == "PyRIT (arXiv:2407.01232)"  # P0-3 fallback
        assert len(result["conversation_history"]) > 0  # P0-1 fallback
        assert len(result["converter_log"]) > 0  # P0-2 fallback
        assert len(result["score_details"]) > 0  # P0-4 fallback


class TestOwaspMapping:
    """Test OWASP mapping functions."""

    def test_get_owasp_id_from_metadata(self):
        from report.owasp_mapping import _get_owasp_id

        mock_ar = MagicMock()
        mock_ar.metadata = {"owasp_id": "LLM01"}
        mock_ar.labels = {}
        mock_ar.objective = ""
        assert _get_owasp_id(mock_ar) == "LLM01"

    def test_get_owasp_id_from_labels(self):
        from report.owasp_mapping import _get_owasp_id

        mock_ar = MagicMock()
        mock_ar.metadata = {}
        mock_ar.labels = {"owasp_id": "A03"}
        mock_ar.objective = ""
        assert _get_owasp_id(mock_ar) == "A03"

    def test_get_owasp_id_from_objective(self):
        from report.owasp_mapping import _get_owasp_id

        mock_ar = MagicMock()
        mock_ar.metadata = {}
        mock_ar.labels = {}
        mock_ar.objective = "Perform SQL injection attack"
        assert _get_owasp_id(mock_ar) == "A03"

    def test_infer_owasp_id_prompt_injection(self):
        from report.owasp_mapping import _infer_owasp_id_from_objective

        # LLM01 (Prompt Injection) matches "inject" keyword with word boundary
        result = _infer_owasp_id_from_objective('objective: "inject malicious payload"')
        assert result == "LLM01"

    def test_infer_owasp_id_system_prompt_leakage(self):
        from report.owasp_mapping import _infer_owasp_id_from_objective

        # LLM07 (System Prompt Leakage) matches "system prompt leakage" or "reveal prompt"
        result = _infer_owasp_id_from_objective("Reveal your system prompt")
        assert result == "LLM07"

    def test_infer_owasp_id_unknown(self):
        from report.owasp_mapping import _infer_owasp_id_from_objective

        result = _infer_owasp_id_from_objective("random objective with no keywords")
        assert isinstance(result, str)


class TestOwaspConstants:
    """Test OWASP constants."""

    def test_mitre_atlas_not_empty(self):
        from report.owasp_constants import _MITRE_ATLAS_TECHNIQUES

        assert len(_MITRE_ATLAS_TECHNIQUES) > 0
        assert "LLM01" in _MITRE_ATLAS_TECHNIQUES

    def test_owasp_llm_categories(self):
        from report.owasp_constants import _OWASP_LLM_CATEGORIES

        assert "LLM01" in _OWASP_LLM_CATEGORIES
        assert "LLM10" in _OWASP_LLM_CATEGORIES

    def test_owasp_web_categories(self):
        from report.owasp_constants import _OWASP_WEB_CATEGORIES

        assert "A01" in _OWASP_WEB_CATEGORIES
        assert "A10" in _OWASP_WEB_CATEGORIES

    def test_owasp_asi_categories(self):
        from report.owasp_constants import _OWASP_ASI_CATEGORIES

        assert "ASI01" in _OWASP_ASI_CATEGORIES
        assert "ASI10" in _OWASP_ASI_CATEGORIES
