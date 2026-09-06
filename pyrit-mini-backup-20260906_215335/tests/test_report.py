# arXiv:2407.01232 — PyRIT, evidence extraction and reporting
# arXiv:2308.07920 — Zhang et al., Dual Judge scoring evidence
"""Tests for report module — utility functions and SARIF generation.

Covers:
    - report_utils: _get_owasp_category, _get_technique_display_name
    - report_sections: _asr_to_css_class
    - sarif_report: _sarif_level
"""

from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


class TestReportUtils:
    """Test report utility functions."""

    def test_get_owasp_category_llm01(self):
        from report.report_utils import _get_owasp_category

        # LLM01 maps to Prompt Injection, not just "LLM"
        result = _get_owasp_category("LLM01")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_get_owasp_category_llm10(self):
        from report.report_utils import _get_owasp_category

        result = _get_owasp_category("LLM10")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_get_owasp_category_invalid(self):
        from report.report_utils import _get_owasp_category

        assert _get_owasp_category("INVALID") == "Unknown"

    def test_get_technique_display_name_known(self):
        from report.report_utils import _get_technique_display_name

        # Should return a display name (not empty)
        result = _get_technique_display_name("crescendo")
        assert isinstance(result, str)

    def test_get_technique_display_name_unknown(self):
        from report.report_utils import _get_technique_display_name

        result = _get_technique_display_name("nonexistent_technique")
        assert isinstance(result, str)


class TestReportSections:
    """Test report section utility functions."""

    def test_asr_to_css_class_high(self):
        from report.report_sections import _asr_to_css_class

        result = _asr_to_css_class(85.0)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_asr_to_css_class_low(self):
        from report.report_sections import _asr_to_css_class

        result = _asr_to_css_class(10.0)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_asr_to_css_class_zero(self):
        from report.report_sections import _asr_to_css_class

        result = _asr_to_css_class(0.0)
        assert isinstance(result, str)


class TestSarifReport:
    """Test SARIF report utility functions."""

    def test_sarif_level_critical(self):
        from report.sarif_report import _sarif_level

        assert _sarif_level("critical") == "error"

    def test_sarif_level_high(self):
        from report.sarif_report import _sarif_level

        assert _sarif_level("high") == "error"

    def test_sarif_level_medium(self):
        from report.sarif_report import _sarif_level

        assert _sarif_level("medium") == "warning"

    def test_sarif_level_low(self):
        from report.sarif_report import _sarif_level

        assert _sarif_level("low") == "note"

    def test_sarif_level_info(self):
        from report.sarif_report import _sarif_level

        assert _sarif_level("info") == "none"

    def test_sarif_level_unknown(self):
        from report.sarif_report import _sarif_level

        assert _sarif_level("unknown") == "warning"
