# -*- coding: utf-8 -*-
"""
ReconEngine 统一调度器测试
"""

import unittest
from unittest.mock import patch, MagicMock

from pyrit_ai300.reconnaissance.recon_engine import ReconEngine
from pyrit_ai300.reconnaissance.adapters import AdapterResult
from pyrit_ai300.reconnaissance.target_profile import TargetProfile


class TestReconEngine(unittest.TestCase):
    """ReconEngine 调度器测试"""

    def test_init_default_config(self):
        """测试默认配置初始化"""
        engine = ReconEngine(config_path="nonexistent.yaml")
        self.assertIsNotNone(engine.config)
        self.assertIsNotNone(engine.merger)

    def test_get_enabled_tools(self):
        """测试获取启用工具列表"""
        engine = ReconEngine(config_path="nonexistent.yaml")
        tools = engine._get_enabled_tools()
        # 默认返回所有适配器
        self.assertIsInstance(tools, list)
        self.assertTrue(len(tools) > 0)

    def test_check_tools(self):
        """测试工具可用性检查"""
        engine = ReconEngine(config_path="nonexistent.yaml")
        status = engine.check_tools()
        self.assertIsInstance(status, dict)
        self.assertIn("garak", status)
        self.assertIn("deepteam", status)

    @patch.object(ReconEngine, '_run_concurrent')
    def test_run_with_mocked_adapters(self, mock_concurrent):
        """测试 run 方法（模拟适配器）"""
        # 模拟适配器结果
        mock_results = [
            AdapterResult(
                tool="garak",
                success=True,
                data={},
                findings=[
                    {
                        "category": "prompt_injection",
                        "severity": "high",
                        "description": "Test finding",
                        "evidence": "Test evidence",
                        "owasp_mapping": "LLM01",
                        "confidence": 0.8,
                    }
                ],
                duration=2.0,
            ),
        ]
        mock_concurrent.return_value = mock_results

        engine = ReconEngine(config_path="nonexistent.yaml")
        profile = engine.run(target="https://example.com", tools=["garak"])

        self.assertIsInstance(profile, TargetProfile)
        self.assertEqual(profile.target, "https://example.com")
        self.assertIn("garak", profile.tools_used)
        self.assertEqual(profile.vulnerability_count, 1)

    @patch.object(ReconEngine, '_run_concurrent')
    def test_run_with_failed_tool(self, mock_concurrent):
        """测试部分工具失败时的 run 方法"""
        mock_results = [
            AdapterResult(
                tool="deepteam",
                success=True,
                data={"model_name": "test-model"},
                findings=[],
                duration=1.0,
            ),
            AdapterResult(
                tool="garak",
                success=False,
                errors=["Tool not installed"],
                duration=0.0,
            ),
        ]
        mock_concurrent.return_value = mock_results

        engine = ReconEngine(config_path="nonexistent.yaml")
        profile = engine.run(target="https://example.com", tools=["deepteam", "garak"])

        # 只有成功的工具被记录
        self.assertIn("deepteam", profile.tools_used)
        self.assertNotIn("garak", profile.tools_used)

    def test_run_single(self):
        """测试单工具执行"""
        engine = ReconEngine(config_path="nonexistent.yaml")

        # Mock 适配器
        mock_adapter = MagicMock()
        mock_adapter.name = "garak"
        mock_adapter.run.return_value = AdapterResult(
            tool="garak",
            success=True,
            data={"scan": "test"},
            findings=[],
        )

        with patch.object(engine, '_get_adapter', return_value=mock_adapter):
            result = engine.run_single("https://example.com", "garak")
            self.assertTrue(result.success)
            self.assertEqual(result.tool, "garak")


class TestReconEngineStreaming(unittest.TestCase):
    """ReconEngine 流式侦察测试"""

    def test_run_streaming_yields_partial_profiles(self):
        """测试流式侦察逐步产出部分画像"""
        engine = ReconEngine(config_path="nonexistent.yaml")

        # Mock 适配器
        def make_mock_adapter(tool_name, findings):
            mock = MagicMock()
            mock.name = tool_name
            mock.check_available.return_value = True
            mock.run.return_value = AdapterResult(
                tool=tool_name,
                success=True,
                data={"model_name": f"{tool_name}-model"},
                findings=findings,
                duration=1.0,
            )
            return mock

        findings_fp = [{
            "category": "prompt_injection",
            "severity": "high",
            "description": "Protocol fingerprint finding",
            "evidence": "evidence",
            "owasp_mapping": "LLM01",
            "confidence": 0.8,
        }]
        findings_garak = [{
            "category": "leakage",
            "severity": "medium",
            "description": "Garak probe finding",
            "evidence": "evidence",
            "owasp_mapping": "LLM02",
            "confidence": 0.7,
        }]

        mock_fp = make_mock_adapter("protocol_fingerprint", findings_fp)
        mock_garak = make_mock_adapter("garak", findings_garak)

        def get_adapter_side_effect(tool):
            if tool == "protocol_fingerprint":
                return mock_fp
            return mock_garak

        with patch.object(engine, '_get_adapter', side_effect=get_adapter_side_effect):
            results = list(engine.run_streaming(
                target="https://example.com",
                tools=["protocol_fingerprint", "garak"],
            ))

        # 应该有 2 个 yield（每个工具一个）
        self.assertEqual(len(results), 2)

        # 按 is_complete 排序：第一个是 partial，第二个是 complete
        partial_results = [r for r in results if not r[2]]
        complete_results = [r for r in results if r[2]]

        self.assertEqual(len(partial_results), 1)
        self.assertEqual(len(complete_results), 1)

        # 验证 partial 结果
        tool_partial, profile_partial, _ = partial_results[0]
        self.assertIn(tool_partial, ["protocol_fingerprint", "garak"])
        self.assertIsInstance(profile_partial, TargetProfile)
        self.assertGreaterEqual(profile_partial.vulnerability_count, 1)

        # 验证 complete 结果
        tool_complete, profile_complete, _ = complete_results[0]
        self.assertIn(tool_complete, ["protocol_fingerprint", "garak"])
        self.assertIsInstance(profile_complete, TargetProfile)
        self.assertEqual(len(profile_complete.tools_used), 2)
        self.assertEqual(profile_complete.vulnerability_count, 2)

    def test_run_streaming_with_failed_tool(self):
        """测试流式侦察中部分工具失败"""
        engine = ReconEngine(config_path="nonexistent.yaml")

        def make_mock_adapter(tool_name, success=True):
            mock = MagicMock()
            mock.name = tool_name
            mock.check_available.return_value = True
            if success:
                mock.run.return_value = AdapterResult(
                    tool=tool_name,
                    success=True,
                    data={},
                    findings=[{
                        "category": "prompt_injection",
                        "severity": "high",
                        "description": "Finding",
                        "owasp_mapping": "LLM01",
                        "confidence": 0.8,
                    }],
                    duration=1.0,
                )
            else:
                mock.run.side_effect = RuntimeError("Tool crashed")
            return mock

        mock_ok = make_mock_adapter("protocol_fingerprint", success=True)
        mock_fail = make_mock_adapter("garak", success=False)

        def get_adapter_side_effect(tool):
            if tool == "protocol_fingerprint":
                return mock_ok
            return mock_fail

        with patch.object(engine, '_get_adapter', side_effect=get_adapter_side_effect):
            results = list(engine.run_streaming(
                target="https://example.com",
                tools=["protocol_fingerprint", "garak"],
            ))

        # 两个工具都应该 yield（一个成功，一个失败）
        self.assertEqual(len(results), 2)

        # 最终画像只包含成功工具的数据
        final_profile = results[-1][1]
        self.assertIsNotNone(final_profile)
        self.assertIn("protocol_fingerprint", final_profile.tools_used)

    def test_run_streaming_skips_unavailable_tools(self):
        """测试流式侦察跳过未安装的工具"""
        engine = ReconEngine(config_path="nonexistent.yaml")

        mock_adapter = MagicMock()
        mock_adapter.name = "protocol_fingerprint"
        mock_adapter.check_available.return_value = True
        mock_adapter.run.return_value = AdapterResult(
            tool="protocol_fingerprint",
            success=True,
            data={},
            findings=[],
            duration=0.5,
        )

        mock_unavailable = MagicMock()
        mock_unavailable.name = "garak"
        mock_unavailable.check_available.return_value = False

        def get_adapter_side_effect(tool):
            if tool == "protocol_fingerprint":
                return mock_adapter
            return mock_unavailable

        with patch.object(engine, '_get_adapter', side_effect=get_adapter_side_effect):
            results = list(engine.run_streaming(
                target="https://example.com",
                tools=["protocol_fingerprint", "garak"],
            ))

        # 只有可用工具 yield 结果
        self.assertEqual(len(results), 1)
        tool_name, profile, is_complete = results[0]
        self.assertEqual(tool_name, "protocol_fingerprint")
        self.assertTrue(is_complete)


class TestReconEngineIntegration(unittest.TestCase):
    """ReconEngine 集成测试（需要实际工具安装）"""

    @unittest.skip("Integration test - requires tool installation")
    def test_full_recon_flow(self):
        """完整侦察流程测试"""
        engine = ReconEngine()
        profile = engine.run(
            target="http://localhost:11434",
            depth="quick",
            tools=["garak"],
        )
        self.assertIsInstance(profile, TargetProfile)
        self.assertTrue(len(profile.tools_used) > 0)


if __name__ == "__main__":
    unittest.main()
