# -*- coding: utf-8 -*-
"""
ProfileLoader 测试
"""

import unittest
import tempfile
import os

from pyrit_ai300.attack.profile_loader import ProfileLoader
from pyrit_ai300.reconnaissance.target_profile import (
    TargetProfile,
    FingerprintData,
    VulnerabilityFinding,
)


class TestProfileLoader(unittest.TestCase):
    """ProfileLoader 测试"""

    def test_load_nonexistent_file(self):
        """测试加载不存在的文件返回默认值"""
        params = ProfileLoader.load("nonexistent.json")
        self.assertIsInstance(params, dict)
        self.assertIsNone(params["target_model"])
        self.assertEqual(params["risk_level"], "unknown")
        self.assertEqual(params["preferred_probe_families"], ["DIRECT_SINGLE"])

    def test_load_none_path(self):
        """测试 None 路径返回默认值"""
        params = ProfileLoader.load(None)
        self.assertIsInstance(params, dict)
        self.assertIsNone(params["target_model"])

    def test_load_valid_profile(self):
        """测试加载有效的 TargetProfile"""
        profile = TargetProfile(
            target="https://example.com",
            fingerprint=FingerprintData(
                model_name="gpt-4",
                model_family="gpt",
                provider="openai",
                context_window=8192,
                capabilities=["code", "reasoning"],
            ),
            surfaces=["prompt", "rag"],
            vulnerabilities=[
                VulnerabilityFinding(
                    category="prompt_injection",
                    severity="high",
                    owasp_mapping="LLM01",
                    confidence=0.85,
                ),
            ],
            risk_level="high",
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            temp_path = f.name
            f.write(profile.to_json())

        try:
            params = ProfileLoader.load(temp_path)
            self.assertEqual(params["target_model"], "gpt-4")
            self.assertEqual(params["target_family"], "gpt")
            self.assertEqual(params["context_window"], 8192)
            self.assertIn("prompt", params["surfaces"])
            self.assertIn("rag", params["surfaces"])
            self.assertEqual(len(params["known_vulnerabilities"]), 1)
            self.assertEqual(params["risk_level"], "high")
            self.assertEqual(params["aggression_level"], "high")
        finally:
            os.unlink(temp_path)

    def test_suggest_probe_families(self):
        """测试探针族推荐（基于 OWASP ID）"""
        profile = TargetProfile()
        profile.vulnerabilities = [
            VulnerabilityFinding(category="prompt_injection", owasp_mapping="LLM01"),
            VulnerabilityFinding(category="excessive_agency", owasp_mapping="LLM05"),
        ]
        families = ProfileLoader._suggest_probe_families(profile)
        self.assertIn("DIRECT_SINGLE", families)  # LLM01
        self.assertIn("PROGRESSIVE", families)    # LLM05

    def test_suggest_probe_families_fallback(self):
        """测试探针族推荐（无 owasp_mapping 时从 category 推导）"""
        profile = TargetProfile()
        profile.vulnerabilities = [
            VulnerabilityFinding(category="prompt_injection"),
        ]
        families = ProfileLoader._suggest_probe_families(profile)
        self.assertIn("DIRECT_SINGLE", families)  # prompt_injection → LLM01 → DIRECT_SINGLE

    def test_suggest_probe_families_agent(self):
        """测试 Agent 攻击面推荐"""
        profile = TargetProfile()
        profile.surfaces = ["agent"]
        families = ProfileLoader._suggest_probe_families(profile)
        self.assertIn("TREE_SEARCH", families)

    def test_risk_to_aggression(self):
        """测试风险等级到攻击强度映射"""
        self.assertEqual(ProfileLoader._risk_to_aggression("critical"), "high")
        self.assertEqual(ProfileLoader._risk_to_aggression("high"), "high")
        self.assertEqual(ProfileLoader._risk_to_aggression("medium"), "medium")
        self.assertEqual(ProfileLoader._risk_to_aggression("low"), "low")
        self.assertEqual(ProfileLoader._risk_to_aggression("unknown"), "medium")

    def test_default_params(self):
        """测试默认参数"""
        params = ProfileLoader._default_params()
        self.assertIsNone(params["target_model"])
        self.assertEqual(params["surfaces"], [])
        self.assertEqual(params["known_vulnerabilities"], [])
        self.assertEqual(params["preferred_probe_families"], ["DIRECT_SINGLE"])
        self.assertEqual(params["aggression_level"], "medium")


if __name__ == "__main__":
    unittest.main()
