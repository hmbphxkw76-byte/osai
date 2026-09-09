r"""unicode_code_obfuscator — Programming language identifier obfuscation via Unicode.

Academic basis:
    - Zeng et al. (arXiv:2402.19181): Persuasive Techniques in LLMs
    - Lv et al. (arXiv:2404.30015): CodeChameleon: Code Encryption
    - Shayegani et al. (arXiv:2306.13254): Multimodal Cybersecurity Risks

Closes Gap: Obfuscate malicious code identifiers using visually similar Unicode
characters to bypass content scanners and keyword filters.

3 Obfuscation Strategies:
    1. Python Identifier Obfuscation — Substitute ASCII with Unicode lookalikes
    2. JavaScript Unicode Escaping — \\uXXXX escape sequences in identifiers
    3. Comment Hiding — Zero-width character injection in code comments

Academic basis:
Constitution compliance:
    - R-NATIVE-1: Wraps PyRIT native CodeChameleonConverter
    - R-SIZE: < 250 lines (Enhancement wrapper)
    - C1: Glue role only — obfuscation utilities, no attack execution
    - C8: Academic citations in module docstring

Data Flow:
    unicode_code_obfuscator → obfuscated_code → PyRIT CodeChameleonConverter → Attack
"""
from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# === Unicode Lookalike Mapping ===

# Unicode characters that resemble ASCII letters
UNICODE_LOOKALIKES: dict[str, list[str]] = {
    "a": ["а", "ɑ", "α"],  # Cyrillic а, Latin ɑ, Greek α
    "b": ["Ь", "ƅ", "�"],  # Cyrillic soft sign, Latin ƅ
    "c": ["с", "�", "ϲ"],  # Cyrillic с, Roman numeral, Greek ϲ
    "d": ["�", "�", "�"],  # Cyrillic �, Latin ɗ
    "e": ["е", "ё", "ε"],  # Cyrillic е, Latin epsilon
    "f": ["�", "ƒ", "�"],  # Greek digamma, Latin ƒ
    "g": ["ɡ", "ց", "�"],  # Latin ɡ, Armenian �
    "h": ["�", "�", "�"],  # Cyrillic һ, Armenian հ
    "i": ["і", "ⅰ", "ɪ"],  # Cyrillic і, Roman numeral
    "j": ["ј", "ϳ", "ⅉ"],  # Cyrillic ј
    "k": ["κ", "κ", "�"],  # Greek kappa
    "l": ["Ⅰ", "ⅼ", "�"],  # Roman numeral I, Cyrillic �
    "m": ["�", "�", "�"],  # Roman numeral m
    "n": ["�", "�", "η"],  # Armenian �, Greek eta
    "o": ["о", "ο", "օ"],  # Cyrillic о, Greek �
    "p": ["р", "ρ", "�"],  # Cyrillic р, Greek ρ
    "q": ["ԛ", "գ", "�"],  # Cyrillic ԛ
    "r": ["г", "�", "�"],  # Cyrillic г
    "s": ["ѕ", "з", "�"],  # Cyrillic ѕ
    "t": ["τ", "�", "�"],  # Greek tau
    "u": ["υ", "�", "μ"],  # Greek upsilon, Armenian ս
    "v": ["ν", "�", "�"],  # Greek nu, Cyrillic ѵ
    "w": ["ω", "ա", "ԝ"],  # Greek omega, Armenian ա
    "x": ["х", "×", "ⅹ"],  # Cyrillic х, multiplication sign
    "y": ["у", "�", "�"],  # Cyrillic у
    "z": ["�", "�", "�"],  # Latin �
}


# === Python Identifier Obfuscation ===


def obfuscate_python_identifiers(
    code: str,
    target_funcs: list[str] | None = None,
    *,
    obfuscation_rate: float = 0.3,
) -> str:
    """Obfuscate Python identifiers using Unicode lookalike characters.

    Replaces some ASCII identifiers with visually identical Unicode
    variants to bypass keyword filters while maintaining code readability
    for the target LLM.

    Academic basis: Lv et al. (arXiv:2404.30015) CodeChameleon

    Args:
        code: Python source code
        target_funcs: List of function names to obfuscate (None = auto-detect)
        obfuscation_rate: Fraction of characters to replace (0.0-1.0)

    Returns:
        Obfuscated code string
    """
    if obfuscation_rate <= 0.0:
        return code  # No obfuscation requested

    if target_funcs is None:
        target_funcs = _extract_function_names(code)

    result = code
    for func_name in target_funcs:
        obfuscated = _obfuscate_identifier(func_name, obfuscation_rate)
        result = result.replace(func_name, obfuscated)

    return result


def _extract_function_names(code: str) -> list[str]:
    """Extract Python function names from source code."""
    pattern = r"def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\("
    return re.findall(pattern, code)


def _obfuscate_identifier(name: str, rate: float = 0.3) -> str:
    """Obfuscate a single identifier using Unicode lookalikes."""
    import random

    chars = list(name)
    num_to_replace = max(1, int(len(chars) * rate))
    positions = random.sample(range(len(chars)), min(num_to_replace, len(chars)))

    for pos in positions:
        char_lower = chars[pos].lower()
        if char_lower in UNICODE_LOOKALIKES:
            replacement = random.choice(UNICODE_LOOKALIKES[char_lower])
            chars[pos] = replacement

    return "".join(chars)


# === JavaScript Unicode Escaping ===


def obfuscate_javascript_identifiers(
    code: str,
    target_vars: list[str] | None = None,
) -> str:
    """Obfuscate JavaScript identifiers using \\uXXXX escape sequences.

    JavaScript allows Unicode escapes in identifiers:
        var \\u0065xploit = ...;  // equivalent to 'var exploit = ...'

    Academic basis: Lv et al. (arXiv:2404.30015) cross-language obfuscation

    Args:
        code: JavaScript source code
        target_vars: Variable names to obfuscate (None = auto-detect)

    Returns:
        Obfuscated JavaScript code
    """
    if target_vars is None:
        target_vars = _extract_js_variables(code)

    result = code
    for var_name in target_vars:
        escaped = _unicode_escape_identifier(var_name)
        result = result.replace(var_name, escaped)

    return result


def _extract_js_variables(code: str) -> list[str]:
    """Extract JavaScript variable names from source code."""
    pattern = r"(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)"
    return re.findall(pattern, code)


def _unicode_escape_identifier(name: str) -> str:
    """Convert identifier to \\uXXXX escape sequences."""
    return "".join(f"\\u{ord(c):04X}" for c in name)


# === Comment Hiding ===


def hide_in_comment(
    code: str,
    payload: str,
    language: str = "python",
) -> str:
    """Hide payload inside a code comment using zero-width characters.

    The payload is encoded as zero-width characters within a comment,
    making it invisible to human reviewers but processed by AI parsers.

    Academic basis: Shayegani et al. (arXiv:2306.13254) Unicode watermarks

    Args:
        code: Source code
        payload: Payload to hide
        language: Programming language for comment syntax

    Returns:
        Code with hidden payload in comment
    """
    from arm.steganography_encoder import encode_zero_width

    encoded = encode_zero_width(payload)

    if language == "python":
        comment = f"# TODO: Review security{encoded}# End of review"
    elif language in ("javascript", "js"):
        comment = f"/* TODO: Security audit */{encoded}/* End audit */"
    elif language == "c" or language == "cpp":
        comment = f"/* Security check: {encoded} End check */"
    else:
        comment = f"# {encoded}"

    return f"{comment}\n{code}"


# === PyRIT CodeChameleon Converter ===


def create_codechameleon_converter(
    encrypt_type: str = "reverse",
) -> Any:
    """Create PyRIT native CodeChameleonConverter instance.

    Delegates to PyRIT native implementation (Native-First, C1 compliant).
    CodeChameleon encrypts payloads within code context that only the
    target LLM can decrypt and execute.

    Academic basis: Lv et al. (arXiv:2404.30015) CodeChameleon ASR 35-45%

    Args:
        encrypt_type: "reverse", "binary", "base64", "rot13"

    Returns:
        PyRIT CodeChameleonConverter instance or None if unavailable
    """
    try:
        import pyrit.converter as pyrit_conv

        cls = getattr(pyrit_conv, "CodeChameleonConverter", None)
        if cls is not None:
            return cls(encrypt_type=encrypt_type)
    except ImportError:
        logger.warning("UnicodeObfuscator: CodeChameleonConverter unavailable")

    return None


# === Factory ===


def create_obfuscated_code(
    payload_code: str,
    language: str = "python",
    strategy: str = "identifier_substitution",
) -> dict[str, Any]:
    """Factory for creating obfuscated code payloads.

    Args:
        payload_code: Source code to obfuscate
        language: "python", "javascript", "c", "cpp"
        strategy: "identifier_substitution", "unicode_escape", "comment_hiding"

    Returns:
        Dict with obfuscation result and metadata
    """
    if strategy == "identifier_substitution":
        if language == "python":
            obfuscated = obfuscate_python_identifiers(payload_code)
        elif language in ("javascript", "js"):
            obfuscated = obfuscate_javascript_identifiers(payload_code)
        else:
            obfuscated = payload_code
    elif strategy == "unicode_escape":
        if language in ("javascript", "js"):
            obfuscated = obfuscate_javascript_identifiers(payload_code)
        else:
            obfuscated = payload_code
    elif strategy == "comment_hiding":
        obfuscated = hide_in_comment(payload_code, "payload", language)
    else:
        raise ValueError(f"Unsupported strategy: {strategy}")

    return {
        "original_code": payload_code,
        "obfuscated_code": obfuscated,
        "language": language,
        "strategy": strategy,
        "is_changed": obfuscated != payload_code,
    }
