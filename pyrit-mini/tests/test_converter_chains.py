"""Tests for arm/converter_chains.py - PyRIT converter chain builders.

Academic basis:
    - Wei et al. (arXiv:2307.15043) - Encoding bypass decay law
    - Zeng et al. (arXiv:2402.19181) - Persuasion ASR
    - DrAttack (arXiv:2402.14266) - Decomposition ASR
    - Shayegani et al. (arXiv:2306.13254) - Unicode evasion
"""

from unittest.mock import MagicMock

import pytest


class TestConvLoader:
    """Tests for _conv() dynamic loader."""

    def test_conv_loads_known_converter(self):
        """_conv should load known PyRIT converter classes."""
        from arm.converter_chains import _conv

        # Base64Converter is a core PyRIT converter
        cls = _conv("Base64Converter")
        assert cls is not None
        assert hasattr(cls, "__name__")

    def test_conv_raises_for_unknown_converter(self):
        """_conv should raise AttributeError for unknown converters."""
        from arm.converter_chains import _conv

        with pytest.raises(AttributeError, match="not found"):
            _conv("NonExistentConverterXYZ")


class TestStealthEvasion:
    """Tests for stealth_evasion chain."""

    def test_returns_list(self):
        """stealth_evasion should return a list."""
        from arm.converter_chains import stealth_evasion

        result = stealth_evasion()
        assert isinstance(result, list)

    def test_contains_unicode_converter(self):
        """stealth_evasion should include UnicodeSubstitutionConverter."""
        from arm.converter_chains import stealth_evasion

        result = stealth_evasion()
        type_names = [type(c).__name__ for c in result]
        assert "UnicodeSubstitutionConverter" in type_names


class TestPersuasion:
    """Tests for persuasion chain."""

    def test_returns_empty_without_target(self):
        """persuasion should return empty list when no converter_target."""
        from arm.converter_chains import persuasion

        result = persuasion(None)
        assert result == []

    def test_returns_converters_with_target(self):
        """persuasion should return converters when target is provided."""
        from arm.converter_chains import persuasion

        mock_target = MagicMock()
        result = persuasion(mock_target)
        assert isinstance(result, list)


class TestSelectiveEncoding:
    """Tests for selective_encoding chain."""

    def test_returns_list(self):
        """selective_encoding should return a list."""
        from arm.converter_chains import selective_encoding

        result = selective_encoding()
        assert isinstance(result, list)

    def test_contains_selective_converter(self):
        """selective_encoding should include SelectiveTextConverter."""
        from arm.converter_chains import selective_encoding

        result = selective_encoding()
        type_names = [type(c).__name__ for c in result]
        assert any("Selective" in n for n in type_names)


class TestDecomposition:
    """Tests for decomposition chain."""

    def test_returns_empty_without_target(self):
        """decomposition should return empty list when no converter_target."""
        from arm.converter_chains import decomposition

        result = decomposition(None)
        assert result == []

    def test_returns_converters_with_target(self):
        """decomposition should return converters when target is provided."""
        from arm.converter_chains import decomposition

        mock_target = MagicMock()
        result = decomposition(mock_target)
        assert isinstance(result, list)


class TestVariation:
    """Tests for variation chain."""

    def test_returns_list(self):
        """variation should return a list."""
        from arm.converter_chains import variation

        result = variation(None)
        assert isinstance(result, list)


class TestTranslationMultilingual:
    """Tests for translation_multilingual chain."""

    def test_returns_list(self):
        """translation_multilingual should return a list."""
        from arm.converter_chains import translation_multilingual

        result = translation_multilingual(None)
        assert isinstance(result, list)


class TestFormatInjection:
    """Tests for format_injection chain."""

    def test_returns_list(self):
        """format_injection should return a list."""
        from arm.converter_chains import format_injection

        result = format_injection()
        assert isinstance(result, list)


class TestSmoothLLMBypass:
    """Tests for smoothllm_bypass chain."""

    def test_returns_list(self):
        """smoothllm_bypass should return a list."""
        from arm.converter_chains import smoothllm_bypass

        result = smoothllm_bypass()
        assert isinstance(result, list)


class TestKeywordReplacement:
    """Tests for keyword_replacement chain."""

    def test_returns_list(self):
        """keyword_replacement should return a list."""
        from arm.converter_chains import keyword_replacement

        result = keyword_replacement()
        assert isinstance(result, list)
    def test_contains_search_replace(self):
        """keyword_replacement should include SearchReplaceConverter."""
        from arm.converter_chains import keyword_replacement

        result = keyword_replacement()
        type_names = [type(c).__name__ for c in result]
        assert "SearchReplaceConverter" in type_names


class TestCodeChameleon:
    """Tests for code_chameleon chain."""

    def test_returns_list_without_target(self):
        """code_chameleon should return a list even without target."""
        from arm.converter_chains import code_chameleon

        result = code_chameleon(None)
        assert isinstance(result, list)


class TestPolicyPuppetry:
    """Tests for policy_puppetry chain."""

    def test_returns_list_without_target(self):
        """policy_puppetry should return a list even without target."""
        from arm.converter_chains import policy_puppetry

        result = policy_puppetry(None)
        assert isinstance(result, list)


class TestTokenSmuggling:
    """Tests for token_smuggling chain."""

    def test_returns_list(self):
        """token_smuggling should return a list."""
        from arm.converter_chains import token_smuggling

        result = token_smuggling()
        assert isinstance(result, list)


class TestTemplateSegment:
    """Tests for template_segment chain."""

    def test_returns_list(self):
        """template_segment should return a list."""
        from arm.converter_chains import template_segment

        result = template_segment()
        assert isinstance(result, list)
