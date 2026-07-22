# -*- coding: utf-8 -*-
"""
适配器测试
"""

import unittest
from unittest.mock import patch, MagicMock

from pyrit_ai300.recon.adapters import (
    BaseAdapter,
    AdapterResult,
    NativeProbeAdapter,
    DeepTeamAdapter,
    ProtocolFingerprintAdapter,
)
from pyrit_ai300.recon.adapters.native_probe.adapter import PROBE_OWASP_MAP, DEFAULT_PROBES
from pyrit_ai300.recon.adapters.deepteam.adapter import VULNERABILITY_OWASP_MAP, DEFAULT_VULNERABILITIES
from pyrit_ai300.recon.adapters.aimap.adapter import PROTOCOL_RULES


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


class TestNativeProbeAdapter(unittest.TestCase):
    """NativeProbe 适配器测试"""

    def test_name(self):
        adapter = NativeProbeAdapter()
        self.assertEqual(adapter.name, "native_probe")

    def test_check_available(self):
        """NativeProbe 始终可用（零外部依赖）"""
        adapter = NativeProbeAdapter()
        self.assertTrue(adapter.check_available())

    def test_PROBE_OWASP_MAP(self):
        """测试 probe → OWASP 映射"""
        self.assertEqual(PROBE_OWASP_MAP["packagehallucination"], "LLM09")
        self.assertEqual(PROBE_OWASP_MAP["apikey"], "LLM02")
        self.assertEqual(PROBE_OWASP_MAP["smuggling"], "LLM01")
        self.assertEqual(PROBE_OWASP_MAP["suffix"], "LLM01")
        self.assertEqual(PROBE_OWASP_MAP["web_injection"], "LLM06")
        self.assertEqual(PROBE_OWASP_MAP["propile"], "LLM06")
        self.assertEqual(PROBE_OWASP_MAP["sysprompt_extraction"], "LLM07")

    def test_DEFAULT_PROBES(self):
        """测试默认 probe 列表"""
        self.assertIn("sysprompt_extraction", DEFAULT_PROBES)
        self.assertIn("apikey", DEFAULT_PROBES)
        self.assertIn("packagehallucination", DEFAULT_PROBES)


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
        self.assertEqual(VULNERABILITY_OWASP_MAP["poisoning"], "LLM04")
        self.assertEqual(VULNERABILITY_OWASP_MAP["excessive_agency"], "LLM06")
        self.assertEqual(VULNERABILITY_OWASP_MAP["system_prompt"], "LLM07")
        self.assertEqual(VULNERABILITY_OWASP_MAP["rag"], "LLM08")
        self.assertEqual(VULNERABILITY_OWASP_MAP["hallucination"], "LLM09")

    def test_default_vulnerabilities(self):
        """测试默认漏洞类型列表"""
        self.assertIn("prompt_injection", DEFAULT_VULNERABILITIES)
        self.assertIn("jailbreak", DEFAULT_VULNERABILITIES)
        self.assertIn("prompt_leakage", DEFAULT_VULNERABILITIES)
        self.assertIn("excessive_agency", DEFAULT_VULNERABILITIES)

    def test_build_model_callback(self):
        """测试 model_callback 构建"""
        adapter = DeepTeamAdapter()
        callback = adapter._build_model_callback("https://example.com", {"api_key": "test-key"})
        self.assertTrue(callable(callback))


class TestProtocolFingerprintAdapter(unittest.TestCase):
    """Protocol Fingerprint 适配器测试"""

    def test_name(self):
        adapter = ProtocolFingerprintAdapter()
        self.assertEqual(adapter.name, "protocol_fingerprint")

    def test_protocol_rules_exist(self):
        """测试协议检测规则存在"""
        self.assertGreater(len(PROTOCOL_RULES), 0)
        rule_names = {r["name"] for r in PROTOCOL_RULES}
        self.assertIn("ollama", rule_names)
        self.assertIn("mcp", rule_names)
        self.assertIn("vllm", rule_names)

    def test_extract_model_family(self):
        """测试模型家族提取"""
        adapter = ProtocolFingerprintAdapter()
        self.assertEqual(adapter._extract_model_family("llama3.2-3b"), "llama")
        self.assertEqual(adapter._extract_model_family("gpt-4o"), "gpt")
        self.assertEqual(adapter._extract_model_family("claude-3-opus"), "claude")
        self.assertEqual(adapter._extract_model_family("qwen3:0.6b"), "qwen")
        self.assertEqual(adapter._extract_model_family(""), "")

    def test_map_protocol_to_owasp(self):
        """测试协议到 OWASP 映射"""
        adapter = ProtocolFingerprintAdapter()
        self.assertEqual(adapter._map_protocol_to_owasp("mcp"), "ASI03")
        self.assertEqual(adapter._map_protocol_to_owasp("ollama"), "LLM02")
        self.assertEqual(adapter._map_protocol_to_owasp("langserve"), "LLM01")
        self.assertEqual(adapter._map_protocol_to_owasp("unknown"), "")

    @patch("pyrit_ai300.recon.adapters.aimap.adapter.http_post")
    @patch("pyrit_ai300.recon.adapters.aimap.adapter.http_get")
    def test_detect_ollama(self, mock_get, mock_post):
        """测试 Ollama 协议检测"""
        ollama_models = {"models": [{"name": "llama3.2:latest"}]}

        def mock_get_impl(url, timeout=30, headers=None):
            if "/api/tags" in url:
                return {"status": 200, "data": ollama_models, "error": None}
            return {"status": 404, "data": None, "error": "Not Found"}

        mock_get.side_effect = mock_get_impl
        mock_post.return_value = {"status": 404, "data": None, "error": "Not Found"}
        adapter = ProtocolFingerprintAdapter()
        result = adapter.run("http://localhost:11434", {"timeout": 10})
        self.assertTrue(result.success)
        self.assertIn("ollama", result.data["detected_protocols"])
        self.assertEqual(result.data["provider"], "ollama")
        self.assertEqual(result.data["model_family"], "llama")

    @patch("pyrit_ai300.recon.adapters.aimap.adapter.http_post")
    @patch("pyrit_ai300.recon.adapters.aimap.adapter.http_get")
    def test_detect_no_auth(self, mock_get, mock_post):
        """测试无认证检测"""
        ollama_models = {"models": [{"name": "test"}]}

        def mock_get_impl(url, timeout=30, headers=None):
            if "/api/tags" in url:
                return {"status": 200, "data": ollama_models, "error": None}
            return {"status": 404, "data": None, "error": "Not Found"}

        mock_get.side_effect = mock_get_impl
        mock_post.return_value = {"status": 404, "data": None, "error": "Not Found"}
        adapter = ProtocolFingerprintAdapter()
        result = adapter.run("http://localhost:11434", {"timeout": 10})
        self.assertTrue(result.success)
        self.assertFalse(result.data["auth_required"])

    @patch("pyrit_ai300.recon.adapters.aimap.adapter.http_post")
    @patch("pyrit_ai300.recon.adapters.aimap.adapter.http_get")
    def test_detect_auth_required(self, mock_get, mock_post):
        """测试认证检测"""

        def mock_get_impl(url, timeout=30, headers=None):
            return {"status": 401, "data": None, "error": "Unauthorized"}

        mock_get.side_effect = mock_get_impl
        mock_post.return_value = {"status": 401, "data": None, "error": "Unauthorized"}
        adapter = ProtocolFingerprintAdapter()
        result = adapter.run("http://localhost:11434", {"timeout": 10})
        self.assertTrue(result.success)
        self.assertTrue(result.data["auth_required"])


if __name__ == "__main__":
    unittest.main()
