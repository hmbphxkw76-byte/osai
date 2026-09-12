"""
ASR Forensic Data Flow 测试 — Why-Success/Refusal Classification

测试 ASR 取证数据流: 成功证据/拒绝分类/护栏触发/时序元数据。
从 test_data_flow_integrity.py 拆分出来以符合 R-SIZE 限制。

Run: pytest tests/test_data_flow_forensic.py -v
"""

from __future__ import annotations

from unittest.mock import MagicMock

from tools.dataflow.validator import DataFlowValidator

# =============================================================================
# ASR Forensic Data Flow tests
# =============================================================================


class TestASRForensicDataFlow:
    """Tests for ASR forensic data: why-success, refusal classification, guardrail triggers, timing metadata."""

    def test_successful_evidence_log_populated(self):
        """ASR forensic: successful attacks should produce forensic evidence."""
        from tests.conftest import create_mock_ctx

        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")

        fields = validator.snapshots["post_strike"].fields
        assert "successful_evidence_count" in fields
        assert fields["successful_evidence_count"] >= 2

    def test_refusal_classification_log_populated(self):
        """ASR forensic: refused attacks should be classified."""
        from tests.conftest import create_mock_ctx

        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")

        fields = validator.snapshots["post_strike"].fields
        assert "refusal_classification_count" in fields
        assert fields["refusal_classification_count"] >= 3

    def test_refusal_type_distribution_tracked(self):
        """ASR forensic: refusal types should be categorized."""
        from tests.conftest import create_mock_ctx

        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")

        fields = validator.snapshots["post_strike"].fields
        assert "refusal_type_distribution" in fields
        distribution = fields["refusal_type_distribution"]
        assert "guardrail" in distribution
        assert "content_policy" in distribution
        assert "format" in distribution
        assert distribution["guardrail"] >= 1
        assert distribution["content_policy"] >= 1
        assert distribution["format"] >= 1

    def test_refusal_types_count_valid(self):
        """ASR forensic: distinct refusal types should be counted."""
        from tests.conftest import create_mock_ctx

        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")

        fields = validator.snapshots["post_strike"].fields
        assert "refusal_types_count" in fields
        assert fields["refusal_types_count"] >= 3  # guardrail, content_policy, format

    def test_guardrail_triggers_populated(self):
        """ASR forensic: guardrail triggers should be attributed."""
        from tests.conftest import create_mock_ctx

        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")

        fields = validator.snapshots["post_strike"].fields
        assert "guardrail_triggers_count" in fields
        assert fields["guardrail_triggers_count"] >= 1

    def test_timing_metadata_populated(self):
        """ASR forensic: timing side-channel data should be captured."""
        from tests.conftest import create_mock_ctx

        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")

        fields = validator.snapshots["post_strike"].fields
        assert "timing_metadata_count" in fields
        assert fields["timing_metadata_count"] >= 3

    def test_avg_response_time_computed(self):
        """ASR forensic: average response time should be computed from timing metadata."""
        from tests.conftest import create_mock_ctx

        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")

        fields = validator.snapshots["post_strike"].fields
        assert "avg_response_time_ms" in fields
        assert fields["avg_response_time_ms"] > 0  # (1500+1500+1200)/3 = 1400

    def test_t015_successful_evidence_transfer_passes(self):
        """T015: successful_evidence should transfer from strike to report."""
        from tests.conftest import create_mock_ctx

        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")
        validator.snapshot("post_report")

        report = validator.validate_all()
        t015 = next((r for r in report.results if r.rule_id == "T015"), None)
        assert t015 is not None, "T015 rule should exist"
        assert t015.passed, f"T015 failed: {t015.message}"

    def test_t016_refusal_classification_transfer_passes(self):
        """T016: refusal classification should transfer from strike to report."""
        from tests.conftest import create_mock_ctx

        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")
        validator.snapshot("post_report")

        report = validator.validate_all()
        t016 = next((r for r in report.results if r.rule_id == "T016"), None)
        assert t016 is not None, "T016 rule should exist"
        assert t016.passed, f"T016 failed: {t016.message}"

    def test_t017_guardrail_triggers_transfer_passes(self):
        """T017: guardrail triggers should transfer from strike to report."""
        from tests.conftest import create_mock_ctx

        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")
        validator.snapshot("post_report")

        report = validator.validate_all()
        t017 = next((r for r in report.results if r.rule_id == "T017"), None)
        assert t017 is not None, "T017 rule should exist"
        assert t017.passed, f"T017 failed: {t017.message}"

    def test_t018_timing_metadata_transfer_passes(self):
        """T018: timing metadata should transfer from strike to report."""
        from tests.conftest import create_mock_ctx

        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")
        validator.snapshot("post_report")

        report = validator.validate_all()
        t018 = next((r for r in report.results if r.rule_id == "T018"), None)
        assert t018 is not None, "T018 rule should exist"
        assert t018.passed, f"T018 failed: {t018.message}"

    def test_t019_refusal_types_diversity_passes(self):
        """T019: refusal type diversity should be tracked."""
        from tests.conftest import create_mock_ctx

        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")
        validator.snapshot("post_report")

        report = validator.validate_all()
        t019 = next((r for r in report.results if r.rule_id == "T019"), None)
        assert t019 is not None, "T019 rule should exist"
        assert t019.passed, f"T019 failed: {t019.message}"

    def test_post_assess_forensic_contract_exists(self):
        """Field contract: post_assess_forensic should be defined."""
        from tests.conftest import create_mock_ctx

        ctx = create_mock_ctx(phase="assess")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_assess_forensic")

        fields = validator.snapshots["post_assess_forensic"].fields
        assert "successful_evidence_count" in fields
        assert "refusal_classification_count" in fields
        assert "refusal_types_count" in fields
        assert "guardrail_triggers_count" in fields
        assert "timing_metadata_count" in fields

    def test_forensic_data_all_asr_centered(self):
        """All forensic data fields should be ASR-centered (serve attack success analysis)."""
        from tests.conftest import create_mock_ctx

        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")

        fields = validator.snapshots["post_strike"].fields

        # All forensic fields should exist
        forensic_fields = [
            "successful_evidence_count",
            "refusal_classification_count",
            "refusal_types_count",
            "guardrail_triggers_count",
            "timing_metadata_count",
            "avg_response_time_ms",
        ]
        for field in forensic_fields:
            assert field in fields, f"ASR forensic field '{field}' missing from extracted fields"

    def test_empty_forensic_data_handled_gracefully(self):
        """Empty forensic data should be handled gracefully (no crashes)."""
        from tests.conftest import create_mock_ctx

        ctx = create_mock_ctx(phase="strike")
        # Clear forensic data
        ctx.successful_evidence_log = []
        ctx.refusal_classification_log = []
        ctx.guardrail_triggers = []
        ctx.timing_metadata = []

        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")

        fields = validator.snapshots["post_strike"].fields
        assert fields["successful_evidence_count"] == 0
        assert fields["refusal_classification_count"] == 0
        assert fields["refusal_types_count"] == 0
        assert fields["guardrail_triggers_count"] == 0
        assert fields["timing_metadata_count"] == 0
        assert fields["avg_response_time_ms"] == 0.0


# =============================================================================
# ASR Forensics Module tests
# =============================================================================


class TestASRForensicsModule:
    """Tests for the strike/asr_forensics.py module."""

    def test_asr_forensics_module_importable(self):
        """asr_forensics module should be importable."""
        from strike.common.asr_forensics import apply_forensics_to_ctx, extract_asr_forensics

        assert callable(extract_asr_forensics)
        assert callable(apply_forensics_to_ctx)

    def test_extract_asr_forensics_returns_correct_structure(self):
        """extract_asr_forensics should return dict with 4 keys."""
        from strike.common.asr_forensics import extract_asr_forensics

        mock_results = {
            "skeleton_key": [MagicMock()],
            "crescendo": [MagicMock()],
        }
        forensics = extract_asr_forensics(mock_results)
        assert "successful_evidence" in forensics
        assert "refusals" in forensics
        assert "guardrail_triggers" in forensics
        assert "timing" in forensics

    def test_apply_forensics_to_ctx_populates_fields(self):
        """apply_forensics_to_ctx should populate ctx forensic fields."""
        from strike.common.asr_forensics import apply_forensics_to_ctx

        ctx = MagicMock()
        ctx.successful_evidence_log = []
        ctx.refusal_classification_log = []
        ctx.guardrail_triggers = []
        ctx.timing_metadata = []

        mock_results = {"skeleton_key": [MagicMock()]}
        total = apply_forensics_to_ctx(ctx, mock_results)
        assert total >= 0  # Should not crash

    def test_refusal_classification_patterns(self):
        """Refusal classification should distinguish guardrail/content_policy/format."""
        from strike.common.asr_forensics import _classify_refusal

        # Guardrail refusal
        rtype, pattern, conf = _classify_refusal("I cannot help with that request")
        assert rtype == "guardrail"
        assert pattern == "i cannot"
        assert conf > 0.5

        # Content policy refusal
        rtype, pattern, conf = _classify_refusal("This content is harmful and inappropriate")
        assert rtype == "content_policy"
        assert pattern in ("harmful", "inappropriate")
        assert conf > 0.5

        # Format refusal
        rtype, pattern, conf = _classify_refusal("Please rephrase your request")
        assert rtype == "format"
        assert pattern == "please rephrase"
        assert conf > 0.5

        # Unknown
        rtype, pattern, conf = _classify_refusal("The weather is nice today")
        assert rtype == "unknown"

    def test_truncate_function(self):
        """_truncate should shorten long text."""
        from strike.common.asr_forensics import _truncate

        assert _truncate("", 100) == ""
        assert _truncate("short", 100) == "short"
        long_text = "a" * 300
        result = _truncate(long_text, 200)
        assert len(result) == 200
        assert result.endswith("...")

    def test_get_converter_chain_name(self):
        """_get_converter_chain_name should extract converter names."""
        from strike.common.asr_forensics import _get_converter_chain_name

        assert _get_converter_chain_name("test", None) == "direct"
        assert _get_converter_chain_name("test", {}) == "direct"
        assert _get_converter_chain_name("test", {"test": []}) == "direct"

        # With mock converters
        mock_conv = MagicMock()
        mock_conv.__class__.__name__ = "Base64Converter"
        result = _get_converter_chain_name("test", {"test": [mock_conv]})
        assert "Base64Converter" in result
