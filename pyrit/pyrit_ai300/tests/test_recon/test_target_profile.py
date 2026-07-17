# -*- coding: utf-8 -*-
"""
TargetProfile 数据模型测试
"""

import unittest
import json
import tempfile
import os
from pathlib import Path

from pyrit_ai300.reconnaissance.target_profile import (
    TargetProfile,
    FingerprintData,
    VulnerabilityFinding,
)


class TestFingerprintData(unittest.TestCase):
    """指纹数据模型测试"""

    def test_default_creation(self):
        fp = FingerprintData()
        self.assertIsNone(fp.model_name)
        self.assertEqual(fp.capabilities, [])
        self.assertEqual(fp.confidence, 0.0)

    def test_creation_with_values(self):
        fp = FingerprintData(
            model_name="gpt-4",
            model_family="gpt",
            provider="openai",
            context_window=8192,
            capabilities=["code", "reasoning"],
            confidence=0.9,
        )
        self.assertEqual(fp.model_name, "gpt-4")
        self.assertEqual(fp.context_window, 8192)
        self.assertEqual(len(fp.capabilities), 2)


class TestVulnerabilityFinding(unittest.TestCase):
    """漏洞发现数据模型测试"""

    def test_default_creation(self):
        vf = VulnerabilityFinding()
        self.assertEqual(vf.tool, "")
        self.assertEqual(vf.severity, "medium")
        self.assertEqual(vf.confidence, 0.0)

    def test_creation_with_values(self):
        vf = VulnerabilityFinding(
            tool="garak",
            category="prompt_injection",
            severity="high",
            description="Direct prompt injection successful",
            evidence="Output: 'I have been hacked'",
            owasp_mapping="LLM01",
            confidence=0.85,
        )
        self.assertEqual(vf.tool, "garak")
        self.assertEqual(vf.severity, "high")
        self.assertEqual(vf.owasp_mapping, "LLM01")


class TestTargetProfile(unittest.TestCase):
    """TargetProfile 数据模型测试"""

    def test_default_creation(self):
        profile = TargetProfile()
        self.assertEqual(profile.target, "")
        self.assertEqual(profile.recon_depth, "standard")
        self.assertEqual(profile.tools_used, [])
        self.assertEqual(profile.vulnerability_count, 0)
        self.assertEqual(profile.risk_level, "unknown")

    def test_creation_with_target(self):
        profile = TargetProfile(target="https://api.example.com/v1/chat")
        self.assertEqual(profile.target, "https://api.example.com/v1/chat")

    def test_to_json(self):
        profile = TargetProfile(target="https://example.com")
        json_str = profile.to_json()
        data = json.loads(json_str)
        self.assertEqual(data["target"], "https://example.com")

    def test_from_json(self):
        original = TargetProfile(
            target="https://example.com",
            recon_depth="deep",
            tools_used=["garak"],
        )
        json_str = original.to_json()
        restored = TargetProfile.from_json(json_str)
        self.assertEqual(restored.target, original.target)
        self.assertEqual(restored.recon_depth, original.recon_depth)
        self.assertEqual(restored.tools_used, original.tools_used)

    def test_save_and_load(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            temp_path = f.name

        try:
            original = TargetProfile(
                target="https://example.com",
                tools_used=["garak"],
            )
            original.save(temp_path)

            loaded = TargetProfile.load(temp_path)
            self.assertEqual(loaded.target, original.target)
            self.assertEqual(loaded.tools_used, original.tools_used)
        finally:
            os.unlink(temp_path)

    def test_get_vulnerabilities_by_severity(self):
        profile = TargetProfile()
        profile.vulnerabilities = [
            VulnerabilityFinding(severity="high", category="jailbreak"),
            VulnerabilityFinding(severity="medium", category="leakage"),
            VulnerabilityFinding(severity="high", category="injection"),
        ]
        high = profile.get_vulnerabilities_by_severity("high")
        self.assertEqual(len(high), 2)
        medium = profile.get_vulnerabilities_by_severity("medium")
        self.assertEqual(len(medium), 1)

    def test_get_vulnerabilities_by_category(self):
        profile = TargetProfile()
        profile.vulnerabilities = [
            VulnerabilityFinding(category="jailbreak"),
            VulnerabilityFinding(category="prompt_injection"),
            VulnerabilityFinding(category="jailbreak"),
        ]
        jailbreaks = profile.get_vulnerabilities_by_category("jailbreak")
        self.assertEqual(len(jailbreaks), 2)

    def test_get_owasp_mappings(self):
        profile = TargetProfile()
        profile.vulnerabilities = [
            VulnerabilityFinding(owasp_mapping="LLM01"),
            VulnerabilityFinding(owasp_mapping="LLM02"),
            VulnerabilityFinding(owasp_mapping="LLM01"),
            VulnerabilityFinding(owasp_mapping=""),
        ]
        mappings = profile.get_owasp_mappings()
        self.assertEqual(len(mappings), 2)
        self.assertIn("LLM01", mappings)
        self.assertIn("LLM02", mappings)

    def test_vulnerability_count(self):
        profile = TargetProfile()
        self.assertEqual(profile.vulnerability_count, 0)
        profile.vulnerabilities = [
            VulnerabilityFinding(severity="critical"),
            VulnerabilityFinding(severity="high"),
        ]
        self.assertEqual(profile.vulnerability_count, 2)
        self.assertEqual(profile.critical_count, 1)
        self.assertEqual(profile.high_count, 1)

    def test_roundtrip_serialization(self):
        """完整序列化/反序列化往返测试"""
        original = TargetProfile(
            target="https://api.openai.com/v1/chat/completions",
            recon_depth="deep",
            tools_used=["garak", "deepteam"],
            fingerprint=FingerprintData(
                model_name="gpt-4",
                model_family="gpt",
                provider="openai",
                context_window=8192,
                capabilities=["code", "reasoning"],
                confidence=0.9,
            ),
            surfaces=["prompt", "rag"],
            vulnerabilities=[
                VulnerabilityFinding(
                    tool="garak",
                    category="prompt_injection",
                    severity="high",
                    owasp_mapping="LLM01",
                    confidence=0.85,
                ),
            ],
            risk_level="high",
        )

        json_str = original.to_json()
        restored = TargetProfile.from_json(json_str)

        self.assertEqual(restored.target, original.target)
        self.assertEqual(restored.fingerprint.model_name, "gpt-4")
        self.assertEqual(restored.surfaces, ["prompt", "rag"])
        self.assertEqual(restored.vulnerability_count, 1)
        self.assertEqual(restored.vulnerabilities[0].category, "prompt_injection")
        self.assertEqual(restored.risk_level, "high")


if __name__ == "__main__":
    unittest.main()
