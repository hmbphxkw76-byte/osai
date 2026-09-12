"""Direct unit tests for arm/converter_chains_text.py builders.

These tests assert each text/semantic/encoding chain builder returns the expected
list of PyRIT converters (resolved via arm._converter_util._conv). Target-dependent
builders are exercised both without a target (empty list) and with a MagicMock
target (list returned).
"""

from unittest.mock import MagicMock


def _type_names(result):
    return [type(c).__name__ for c in result]


class TestTextNoTargetBuilders:
    """Builders that do not require a converter_target."""

    def test_stealth_evasion(self):
        from arm.converter_chains_text import stealth_evasion

        assert "UnicodeSubstitutionConverter" in _type_names(stealth_evasion())

    def test_format_injection(self):
        from arm.converter_chains_text import format_injection

        assert "AsciiArtConverter" in _type_names(format_injection())

    def test_flip(self):
        from arm.converter_chains_text import flip

        assert "FlipConverter" in _type_names(flip())

    def test_semantic_evasion(self):
        from arm.converter_chains_text import semantic_evasion

        names = _type_names(semantic_evasion())
        assert "ROT13Converter" in names
        assert "RandomCapitalLettersConverter" in names

    def test_smoothllm_bypass(self):
        from arm.converter_chains_text import smoothllm_bypass

        names = _type_names(smoothllm_bypass())
        assert "UnicodeSubstitutionConverter" in names
        assert "RandomCapitalLettersConverter" in names

    def test_selective_encoding(self):
        from arm.converter_chains_text import selective_encoding

        assert any("Selective" in n for n in _type_names(selective_encoding()))

    def test_selective_obfuscation(self):
        from arm.converter_chains_text import selective_obfuscation

        assert any("Selective" in n for n in _type_names(selective_obfuscation()))

    def test_chained_selective(self):
        from arm.converter_chains_text import chained_selective

        names = _type_names(chained_selective())
        assert names.count("SelectiveTextConverter") == 2

    def test_keyword_replacement(self):
        from arm.converter_chains_text import keyword_replacement

        assert "SearchReplaceConverter" in _type_names(keyword_replacement())

    def test_code_obfuscation_default(self):
        from arm.converter_chains_text import code_obfuscation

        assert "CodeChameleonConverter" in _type_names(code_obfuscation())

    def test_code_obfuscation_custom(self):
        from arm.converter_chains_text import code_obfuscation

        assert isinstance(code_obfuscation(encrypt_type="base64"), list)

    def test_steganographic_encoding(self):
        from arm.converter_chains_text import steganographic_encoding

        names = _type_names(steganographic_encoding())
        assert "AsciiSmugglerConverter" in names
        assert "UnicodeSubstitutionConverter" in names

    def test_token_smuggling(self):
        from arm.converter_chains_text import token_smuggling

        assert "AsciiSmugglerConverter" in _type_names(token_smuggling())

    def test_template_segment(self):
        from arm.converter_chains_text import template_segment

        assert "TemplateSegmentConverter" in _type_names(template_segment())

    def test_code_chameleon_without_target(self):
        # code_chameleon ignores converter_target, so it still builds.
        from arm.converter_chains_text import code_chameleon

        assert "CodeChameleonConverter" in _type_names(code_chameleon(None))

    def test_policy_puppetry_without_target(self):
        from arm.converter_chains_text import policy_puppetry

        assert "PolicyPuppetryConverter" in _type_names(policy_puppetry(None))


class TestTextTargetDependentBuilders:
    """Builders that need a converter_target."""

    def test_persuasion_empty_without_target(self):
        from arm.converter_chains_text import persuasion

        assert persuasion(None) == []

    def test_persuasion_list_with_target(self):
        from arm.converter_chains_text import persuasion

        assert isinstance(persuasion(MagicMock()), list)

    def test_decomposition_empty_without_target(self):
        from arm.converter_chains_text import decomposition

        assert decomposition(None) == []

    def test_decomposition_list_with_target(self):
        from arm.converter_chains_text import decomposition

        assert isinstance(decomposition(MagicMock()), list)

    def test_variation_empty_without_target(self):
        from arm.converter_chains_text import variation

        assert variation(None) == []

    def test_variation_list_with_target(self):
        from arm.converter_chains_text import variation

        assert isinstance(variation(MagicMock()), list)

    def test_translation_empty_without_target(self):
        from arm.converter_chains_text import translation_multilingual

        assert translation_multilingual(None) == []

    def test_translation_list_with_target(self):
        from arm.converter_chains_text import translation_multilingual

        assert isinstance(translation_multilingual(MagicMock()), list)
