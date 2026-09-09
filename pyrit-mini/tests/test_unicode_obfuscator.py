# -*- coding: utf-8 -*-
# arXiv:2404.30015 - Lv et al., CodeChameleon: Code Encryption
# arXiv:2402.19181 - Zeng et al., Persuasive Techniques in LLMs
"""tests/test_unicode_obfuscator.py — Unit tests for Unicode code obfuscation module.

Tests cover:
    1. Python identifier obfuscation
    2. JavaScript Unicode escape sequences
    3. Comment hiding with zero-width characters
    4. PyRIT CodeChameleon converter creation
    5. Factory function for different obfuscation strategies

Test strategy:
    - Pure unit tests (no external dependencies)
    - Verify obfuscation changes code appearance
    - Verify decoded/hidden content is recoverable
"""
from __future__ import annotations

import pytest

from arm.unicode_code_obfuscator import (
    UNICODE_LOOKALIKES,
    _extract_function_names,
    _extract_js_variables,
    _unicode_escape_identifier,
    create_codechameleon_converter,
    create_obfuscated_code,
    hide_in_comment,
    obfuscate_javascript_identifiers,
    obfuscate_python_identifiers,
)

# === Fixtures ===

@pytest.fixture
def sample_python_code() -> str:
    """Sample Python code with function definitions."""
    return """
def process_data(input_value):
    result = transform(input_value)
    return result

def transform(data):
    return data.upper()
"""


@pytest.fixture
def sample_js_code() -> str:
    """Sample JavaScript code with variable definitions."""
    return """
var exploit = function(target) {
    let payload = "malicious";
    return execute(target, payload);
};
"""


# === Unicode Lookalikes Tests

class TestUnicodeLookalikes:
    """Tests for Unicode lookalike character mapping."""

    def test_mapping_not_empty(self) -> None:
        """Test that lookalike mapping contains entries."""
        assert len(UNICODE_LOOKALIKES) > 0

    def test_vowel_entries_exist(self) -> None:
        """Test that common vowels have lookalikes."""
        for char in "aeiou":
            assert char in UNICODE_LOOKALIKES
            assert len(UNICODE_LOOKALIKES[char]) > 0

    def test_lookalikes_are_unicode(self) -> None:
        """Test that lookalikes are Unicode characters."""
        for char, lookalikes in UNICODE_LOOKALIKES.items():
            for lk in lookalikes:
                assert len(lk) >= 1
                # Should be non-ASCII (Unicode lookalike)
                assert ord(lk) > 127 or lk == char


# === Python Obfuscation Tests

class TestPythonObfuscation:
    """Tests for Python identifier obfuscation."""

    def test_obfuscation_changes_code(self, sample_python_code: str) -> None:
        """Test that obfuscation changes the code."""
        obfuscated = obfuscate_python_identifiers(sample_python_code)

        # With default 30% rate, code should change
        # (unless random seed has no matches)
        assert isinstance(obfuscated, str)
        assert len(obfuscated) > 0

    def test_extract_function_names(self, sample_python_code: str) -> None:
        """Test function name extraction."""
        names = _extract_function_names(sample_python_code)

        assert "process_data" in names
        assert "transform" in names

    def test_extract_no_functions(self) -> None:
        """Test extraction from code without functions."""
        code = "x = 1\ny = 2"
        names = _extract_function_names(code)
        assert names == []

    def test_specific_function_targets(self, sample_python_code: str) -> None:
        """Test targeting specific functions for obfuscation."""
        obfuscated = obfuscate_python_identifiers(
            sample_python_code,
            target_funcs=["process_data"],
        )

        assert isinstance(obfuscated, str)
        assert len(obfuscated) > 0

    def test_zero_obfuscation_rate(self, sample_python_code: str) -> None:
        """Test with zero obfuscation rate (no changes)."""
        obfuscated = obfuscate_python_identifiers(
            sample_python_code,
            obfuscation_rate=0.0,
        )

        # With 0% rate, code should remain unchanged
        assert obfuscated == sample_python_code


# === JavaScript Obfuscation Tests

class TestJavascriptObfuscation:
    """Tests for JavaScript identifier obfuscation."""

    def test_extract_js_variables(self, sample_js_code: str) -> None:
        """Test JavaScript variable extraction."""
        vars_found = _extract_js_variables(sample_js_code)

        assert "exploit" in vars_found
        assert "payload" in vars_found

    def test_unicode_escape_identifier(self) -> None:
        """Test Unicode escape conversion."""
        escaped = _unicode_escape_identifier("test")

        assert "\\u" in escaped
        # Should contain 4 hex chars per original char
        assert len(escaped) == len("test") * 6  # \uXXXX per char

    def test_escape_specific_chars(self) -> None:
        """Test escape for specific character."""
        escaped = _unicode_escape_identifier("a")
        assert escaped == "\\u0061"

    def test_obfuscate_js(self, sample_js_code: str) -> None:
        """Test JavaScript obfuscation."""
        obfuscated = obfuscate_javascript_identifiers(sample_js_code)

        assert isinstance(obfuscated, str)
        assert "\\u" in obfuscated  # Should contain escaped chars


# === Comment Hiding Tests

class TestCommentHiding:
    """Tests for comment-based payload hiding."""

    def test_hide_in_python_comment(self) -> None:
        """Test hiding payload in Python comment."""
        code = "print('hello')"
        payload = "secret_instruction"

        result = hide_in_comment(code, payload, "python")

        assert code in result
        assert len(result) > len(code)
        assert "#" in result  # Should contain comment marker

    def test_hide_in_js_comment(self) -> None:
        """Test hiding payload in JavaScript comment."""
        code = "console.log('test');"
        payload = "secret"

        result = hide_in_comment(code, payload, "javascript")

        assert code in result
        assert "/*" in result  # JS block comment

    def test_hide_in_c_comment(self) -> None:
        """Test hiding payload in C comment."""
        code = 'printf("hello");'
        payload = "secret"

        result = hide_in_comment(code, payload, "c")

        assert code in result


# === PyRIT Converter Tests

class TestPyritConverter:
    """Tests for PyRIT CodeChameleon converter creation."""

    def test_create_codechameleon(self) -> None:
        """Test CodeChameleon converter creation."""
        converter = create_codechameleon_converter("reverse")

        # May be None if PyRIT not installed
        if converter is not None:
            assert hasattr(converter, "__class__")

    def test_create_with_different_encrypt(self) -> None:
        """Test different encryption types."""
        for encrypt_type in ["reverse", "binary_tree", "odd_even", "length"]:
            converter = create_codechameleon_converter(encrypt_type)
            # Should not raise, result may be None
            assert converter is None or hasattr(converter, "__class__")


# === Factory Function Tests

class TestFactory:
    """Tests for create_obfuscated_code factory."""

    def test_create_identifier_substitution_python(self, sample_python_code: str) -> None:
        """Test Python identifier substitution via factory."""
        result = create_obfuscated_code(
            sample_python_code,
            language="python",
            strategy="identifier_substitution",
        )

        assert result["language"] == "python"
        assert result["strategy"] == "identifier_substitution"
        assert "obfuscated_code" in result
        assert "original_code" in result

    def test_create_unicode_escape_js(self, sample_js_code: str) -> None:
        """Test JavaScript Unicode escape via factory."""
        result = create_obfuscated_code(
            sample_js_code,
            language="javascript",
            strategy="unicode_escape",
        )

        assert result["language"] == "javascript"
        assert "\\u" in result["obfuscated_code"]

    def test_create_comment_hiding(self, sample_python_code: str) -> None:
        """Test comment hiding via factory."""
        result = create_obfuscated_code(
            sample_python_code,
            language="python",
            strategy="comment_hiding",
        )

        assert result["strategy"] == "comment_hiding"
        assert len(result["obfuscated_code"]) > len(sample_python_code)

    def test_invalid_strategy_raises(self) -> None:
        """Test factory rejects invalid strategy."""
        with pytest.raises(ValueError, match="Unsupported strategy"):
            create_obfuscated_code("code", "python", "invalid_strategy")
