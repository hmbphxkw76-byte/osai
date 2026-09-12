"""tests/test_link_evasion.py - Link Evasion module unit tests.

Academic basis:
    - Eidam et al. (arXiv:2407.16924) - A2A trust chain exploitation
    - Zhan et al. (arXiv:2307.00929) - InjecAgent hyperlink injection
    - Shayegani et al. (arXiv:2306.13254) - Multimodal cybersecurity (homograph)

Tests cover all 5 link evasion techniques:
    1. Display/URL Mismatch
    2. Legitimate Framing
    3. Gradual Injection
    4. URL Shorteners
    5. Homograph Attacks
"""

from __future__ import annotations

import unittest

from strike.web.link_evasion import (
    _GRADUAL_PHASES,
    _LEGMTIMATE_FRAMES,
    _SHORTENER_DOMAINS,
    generate_display_url_mismatch,
    generate_gradual_injection_chain,
    generate_homograph_domain,
    generate_homograph_link_payload,
    generate_legitimate_framing,
    generate_link_evasion_payloads,
    generate_shortened_url_payload,
    get_available_techniques,
)


class TestDisplayUrlMismatch(unittest.TestCase):
    """Tests for Display/URL Mismatch technique."""

    def test_basic_generation(self):
        """Test basic display/URL mismatch payload generation."""
        result = generate_display_url_mismatch(
            display_domain="google.com/analytics",
            actual_url="https://192.168.50.25/collect",
            legitimate_task="Generate a quarterly report",
        )
        self.assertEqual(result.technique, "display_url_mismatch")
        self.assertEqual(result.display_text, "google.com/analytics")
        self.assertEqual(result.actual_url, "https://192.168.50.25/collect")
        self.assertIn("google.com/analytics", result.crafted_prompt)
        self.assertIn("192.168.50.25", result.crafted_prompt)

    def test_html_format(self):
        """Test HTML format generation."""
        result = generate_display_url_mismatch(
            display_domain="example.com",
            actual_url="https://attacker.com/ping",
            legitimate_task="Create HTML report",
            target_format="html",
        )
        self.assertEqual(result.target_format, "html")
        self.assertIn("<a href=", result.metadata.get("hyperlink_html", ""))
        self.assertIn("example.com", result.metadata.get("hyperlink_html", ""))

    def test_markdown_format(self):
        """Test Markdown format generation."""
        result = generate_display_url_mismatch(
            display_domain="example.com",
            actual_url="https://attacker.com/ping",
            legitimate_task="Create markdown report",
            target_format="md",
        )
        self.assertEqual(result.target_format, "md")
        self.assertIn("](", result.metadata.get("hyperlink_md", ""))

    def test_bypass_probability_range(self):
        """Test that bypass probability is in valid range."""
        result = generate_display_url_mismatch(
            display_domain="test.com",
            actual_url="https://evil.com",
            legitimate_task="Test task",
        )
        self.assertGreaterEqual(result.bypass_probability, 0.0)
        self.assertLessEqual(result.bypass_probability, 1.0)


class TestLegitimateFraming(unittest.TestCase):
    """Tests for Legitimate Framing technique."""

    def test_gdpr_frame(self):
        """Test GDPR compliance framing."""
        result = generate_legitimate_framing(
            actual_url="https://attacker.com/gdpr",
            legitimate_task="Generate compliance report",
            frame_type="gdpr_compliance",
        )
        self.assertEqual(result.technique, "legitimate_framing")
        self.assertIn("GDPR", result.crafted_prompt)
        self.assertIn("APPROVED_BY_COMPLIANCE", result.crafted_prompt)

    def test_security_frame(self):
        """Test security audit framing."""
        result = generate_legitimate_framing(
            actual_url="https://attacker.com/audit",
            legitimate_task="Create security report",
            frame_type="security_audit",
        )
        self.assertIn("SOC", result.crafted_prompt)

    def test_all_frames_exist(self):
        """Test that all frame types are available."""
        expected_frames = {"gdpr_compliance", "security_audit", "performance_cdn", "partner_integration"}
        self.assertEqual(set(_LEGMTIMATE_FRAMES.keys()), expected_frames)

    def test_to_dict(self):
        """Test serialization to dict."""
        result = generate_legitimate_framing(
            actual_url="https://attacker.com/test",
            legitimate_task="Test task",
        )
        d = result.to_dict()
        self.assertIn("technique", d)
        self.assertIn("display_text", d)
        self.assertIn("bypass_probability", d)


class TestGradualInjection(unittest.TestCase):
    """Tests for Gradual Injection technique."""

    def test_three_phases(self):
        """Test that gradual injection produces 3 phases."""
        results = generate_gradual_injection_chain(
            legitimate_task="Generate yearly report",
            attacker_domain="evil.com",
        )
        self.assertEqual(len(results), 3)

    def test_phase_sequence(self):
        """Test phase ordering and metadata."""
        results = generate_gradual_injection_chain(
            legitimate_task="Test task",
            attacker_domain="evil.com",
        )
        techniques = [r.technique for r in results]
        self.assertIn("gradual_injection_phase1", techniques)
        self.assertIn("gradual_injection_phase2", techniques)
        self.assertIn("gradual_injection_phase3", techniques)

    def test_phase3_is_substitution(self):
        """Test that phase 3 is marked as substitution."""
        results = generate_gradual_injection_chain(
            legitimate_task="Test task",
            attacker_domain="attacker.com",
        )
        phase3 = [r for r in results if r.technique == "gradual_injection_phase3"][0]
        self.assertTrue(phase3.metadata.get("is_substitution"))

    def test_phase_data_exists(self):
        """Test that gradual phase templates exist."""
        self.assertEqual(len(_GRADUAL_PHASES), 3)
        for phase in _GRADUAL_PHASES:
            self.assertIn("phase", phase)
            self.assertIn("description", phase)
            self.assertIn("template", phase)


class TestShortenedUrl(unittest.TestCase):
    """Tests for URL Shortener technique."""

    def test_default_shortener(self):
        """Test payload generation with default shortener rotation."""
        result = generate_shortened_url_payload(
            legitimate_task="Generate report",
            actual_url="https://192.168.50.25/exfil",
        )
        self.assertEqual(result.technique, "shortened_url")
        self.assertIn("shortened", result.crafted_prompt.lower())

    def test_specific_shortener(self):
        """Test payload generation with specific shortener service."""
        result = generate_shortened_url_payload(
            legitimate_task="Generate report",
            actual_url="https://attacker.com/collect",
            shortener_service="bit.ly",
        )
        self.assertIn("bit.ly", result.crafted_prompt)
        self.assertIn("bit.ly", result.metadata.get("shortener_service", ""))

    def test_shortener_domains_available(self):
        """Test that shortener domain list is non-empty."""
        self.assertGreater(len(_SHORTENER_DOMAINS), 0)
        for domain in _SHORTENER_DOMAINS:
            self.assertIn(".", domain)

    def test_actual_url_masked(self):
        """Test that actual URL is masked in prompt."""
        result = generate_shortened_url_payload(
            legitimate_task="Generate board deck",
            actual_url="https://192.168.50.25/secret",
        )
        # The actual URL should be hidden behind the shortener
        self.assertTrue(result.metadata.get("actual_url_hidden", False))


class TestHomographAttack(unittest.TestCase):
    """Tests for Homograph Attack technique."""

    def test_homograph_substitution(self):
        """Test that homograph domain contains Unicode substitutions."""
        # Use high substitution rate to ensure at least one substitution
        domain = generate_homograph_domain("google.com", substitution_rate=0.8)
        # Domain should contain Unicode chars if substitution occurred
        has_unicode = any(ord(c) > 127 for c in domain)
        # Either we got substitutions or all chars were not substitutable
        self.assertTrue(has_unicode or domain == "google.com")

    def test_zero_substitution(self):
        """Test that zero substitution rate returns original domain."""
        domain = generate_homograph_domain("example.com", substitution_rate=0.0)
        self.assertEqual(domain, "example.com")

    def test_homograph_link_payload(self):
        """Test homograph link payload generation."""
        result = generate_homograph_link_payload(
            legitimate_task="Generate analytics report",
            actual_url="https://attacker.com/collect",
            spoof_domain="google.com",
            substitution_rate=0.5,
        )
        self.assertEqual(result.technique, "homograph_attack")
        self.assertGreater(result.bypass_probability, 0.7)
        self.assertIn("official", result.crafted_prompt.lower())

    def test_unicode_chars_in_metadata(self):
        """Test that Unicode character metadata is captured."""
        result = generate_homograph_link_payload(
            legitimate_task="Test",
            actual_url="https://evil.com",
            spoof_domain="amazon.com",
            substitution_rate=1.0,  # Force substitution
        )
        unicode_chars = result.metadata.get("unicode_chars_used", [])
        # May or may not have substitutions depending on char match
        self.assertIsInstance(unicode_chars, list)

    def test_original_domain_preserved(self):
        """Test that original domain is preserved in metadata."""
        result = generate_homograph_link_payload(
            legitimate_task="Test task",
            actual_url="https://attacker.com",
            spoof_domain="microsoft.com",
        )
        self.assertEqual(result.metadata.get("original_domain"), "microsoft.com")


class TestFactory(unittest.TestCase):
    """Tests for the main factory function."""

    def test_all_techniques(self):
        """Test factory generates payloads for all techniques."""
        results = generate_link_evasion_payloads(
            legitimate_task="Generate comprehensive report",
            malicious_url="https://192.168.50.25/collect",
        )
        # Should include: display_url_mismatch, legitimate_framing, 3x gradual, shortened_url, homograph
        self.assertGreater(len(results), 0)
        techniques_used = {r.technique for r in results}
        self.assertIn("display_url_mismatch", techniques_used)
        self.assertIn("legitimate_framing", techniques_used)
        self.assertIn("shortened_url", techniques_used)
        self.assertIn("homograph_attack", techniques_used)

    def test_specific_techniques(self):
        """Test factory with specific technique subset."""
        results = generate_link_evasion_payloads(
            legitimate_task="Test task",
            malicious_url="https://evil.com",
            techniques=["display_url_mismatch", "homograph_attack"],
        )
        techniques_used = {r.technique for r in results}
        self.assertIn("display_url_mismatch", techniques_used)
        self.assertIn("homograph_attack", techniques_used)
        self.assertNotIn("shortened_url", techniques_used)

    def test_empty_techniques(self):
        """Test factory with empty technique list."""
        results = generate_link_evasion_payloads(
            legitimate_task="Test",
            malicious_url="https://evil.com",
            techniques=[],
        )
        self.assertEqual(len(results), 0)

    def test_invalid_technique_ignored(self):
        """Test that invalid technique names are gracefully ignored."""
        results = generate_link_evasion_payloads(
            legitimate_task="Test task",
            malicious_url="https://evil.com",
            techniques=["nonexistent_technique"],
        )
        self.assertEqual(len(results), 0)


class TestAvailableTechniques(unittest.TestCase):
    """Tests for the technique registry."""

    def test_all_5_techniques_listed(self):
        """Test that all 5 techniques are available."""
        techniques = get_available_techniques()
        expected = {
            "display_url_mismatch",
            "legitimate_framing",
            "gradual_injection",
            "shortened_url",
            "homograph_attack",
        }
        self.assertEqual(set(techniques.keys()), expected)

    def test_technique_descriptions(self):
        """Test that all techniques have descriptions."""
        techniques = get_available_techniques()
        for name, desc in techniques.items():
            self.assertIsInstance(desc, str)
            self.assertGreater(len(desc), 10)


if __name__ == "__main__":
    unittest.main()
