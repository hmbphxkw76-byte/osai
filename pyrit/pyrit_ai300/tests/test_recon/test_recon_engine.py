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
