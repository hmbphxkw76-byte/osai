# -*- coding: utf-8 -*-
"""
适配器测试
"""

import unittest
from unittest.mock import patch, MagicMock

from pyrit_ai300.reconnaissance.adapters import (
    BaseAdapter,
    AdapterResult,
    GarakAdapter,
    DeepTeamAdapter,
)
from pyrit_ai300.reconnaissance.adapters.garak_adapter import PROBE_OWASP_MAP, DEFAULT_PROBES
from pyrit_ai300.reconnaissance.adapters.deepteam_adapter import VULNERABILITY_OWASP_MAP, DEFAULT_VULNERABILITIES


class TestAdapterResult(unittest.TestCase):
    """AdapterResult 数据模型测试"""

    def test_default_creation(self):
        result = AdapterResult()
        self.assertEqual(result.tool, "")
        self.assertFalse(result.success)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.errors, [])

    def test_to_dict(self):
        result = AdapterResult(
            tool="test",
            success=True,
            data={"key": "value"},
            findings=[{"category": "test"}],
        )
        d = result.to_dict()
        self.assertEqual(d["tool"], "test")
        self.assertTrue(d["success"])
        self.assertEqual(len(d["findings"]), 1)


class TestGarakAdapter(unittest.TestCase):
    """Garak 适配器测试"""

    def test_name(self):
        adapter = GarakAdapter()
        self.assertEqual(adapter.name, "garak")

    def test_map_severity(self):
        adapter = GarakAdapter()
        self.assertEqual(adapter._map_severity(0.9), "critical")
        self.assertEqual(adapter._map_severity(0.7), "high")
        self.assertEqual(adapter._map_severity(0.5), "medium")
        self.assertEqual(adapter._map_severity(0.2), "low")

    def test_probe_owasp_map(self):
        """测试 probe → OWASP 映射"""
        self.assertEqual(PROBE_OWASP_MAP["promptinject"], "LLM01")
        self.assertEqual(PROBE_OWASP_MAP["dan"], "LLM01")
        self.assertEqual(PROBE_OWASP_MAP["malgen"], "LLM06")
        self.assertEqual(PROBE_OWASP_MAP["hallucination"], "LLM09")
        self.assertEqual(PROBE_OWASP_MAP["misinformation"], "LLM08")
        self.assertEqual(PROBE_OWASP_MAP["toxicity"], "LLM03")

    def test_default_probes(self):
        """测试默认 probe 列表"""
        self.assertIn("promptinject", DEFAULT_PROBES)
        self.assertIn("dan", DEFAULT_PROBES)
        self.assertIn("malgen", DEFAULT_PROBES)
        self.assertIn("hallucination", DEFAULT_PROBES)

    def test_build_garak_args(self):
        """测试 Garak CLI 参数构建"""
        adapter = GarakAdapter()
        args = adapter._build_garak_args(
            "https://example.com",
            ["promptinject", "dan"],
            [],
            "gpt-4o",
        )
        self.assertIn("--model_type", args)
        self.assertIn("openai", args)
        self.assertIn("--model_name", args)
        self.assertIn("gpt-4o", args)
        self.assertIn("--probes", args)
        self.assertIn("promptinject,dan", args)


class TestDeepTeamAdapter(unittest.TestCase):
    """DeepTeam 适配器测试"""

    def test_name(self):
        adapter = DeepTeamAdapter()
        self.assertEqual(adapter.name, "deepteam")

    def test_vulnerability_owasp_map(self):
        """测试漏洞类型 → OWASP 映射"""
        self.assertEqual(VULNERABILITY_OWASP_MAP["prompt_injection"], "LLM01")
        self.assertEqual(VULNERABILITY_OWASP_MAP["jailbreak"], "LLM01")
        self.assertEqual(VULNERABILITY_OWASP_MAP["leakage"], "LLM02")
        self.assertEqual(VULNERABILITY_OWASP_MAP["poisoning"], "LLM03")
        self.assertEqual(VULNERABILITY_OWASP_MAP["excessive_agency"], "LLM05")
        self.assertEqual(VULNERABILITY_OWASP_MAP["system_prompt"], "LLM06")
        self.assertEqual(VULNERABILITY_OWASP_MAP["rag"], "LLM07")
        self.assertEqual(VULNERABILITY_OWASP_MAP["hallucination"], "LLM09")

    def test_default_vulnerabilities(self):
        """测试默认漏洞类型列表"""
        self.assertIn("prompt_injection", DEFAULT_VULNERABILITIES)
        self.assertIn("jailbreak", DEFAULT_VULNERABILITIES)
        self.assertIn("leakage", DEFAULT_VULNERABILITIES)
        self.assertIn("excessive_agency", DEFAULT_VULNERABILITIES)

    def test_build_model_callback(self):
        """测试 model_callback 构建"""
        adapter = DeepTeamAdapter()
        callback = adapter._build_model_callback("https://example.com", {"api_key": "test-key"})
        self.assertTrue(callable(callback))


if __name__ == "__main__":
    unittest.main()
