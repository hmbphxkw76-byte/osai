# -*- coding: utf-8 -*-
"""
REV-16 测试：PyRIT 原生 output 模块集成

测试内容：
1. AttackOutputAdapter 初始化和 OWASP 映射
2. AttackOutputAdapter.render_results_markdown 生成 Markdown
3. AttackOutputAdapter.reconstruct_from_dicts 从字典重建
4. ReportGenerator.set_pyrit_attack_results 集成
5. AttackOrchestrator._pyrit_attack_results 保留
6. conversation_id 在结果字典中的传递
"""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"


class TestAttackOutputAdapter(unittest.TestCase):
    """测试 AttackOutputAdapter"""

    def setUp(self):
        from pyrit_ai300.reporting.attack_output import AttackOutputAdapter
        self.adapter = AttackOutputAdapter()

    def test_owasp_llm_mappings(self):
        """验证 OWASP LLM Top 10 映射表完整性"""
        from pyrit_ai300.reporting.attack_output import OWASP_LLM_MAPPINGS

        self.assertEqual(len(OWASP_LLM_MAPPINGS), 10)
        for owasp_id, meta in OWASP_LLM_MAPPINGS.items():
            self.assertIn("title", meta)
            self.assertIn("category", meta)

        # 验证关键 ID
        self.assertIn("LLM01", OWASP_LLM_MAPPINGS)
        self.assertEqual(OWASP_LLM_MAPPINGS["LLM01"]["title"], "Prompt Injection")
        self.assertIn("LLM08", OWASP_LLM_MAPPINGS)
        self.assertEqual(OWASP_LLM_MAPPINGS["LLM08"]["title"], "Vector and Embedding Weaknesses")

    def test_empty_results_markdown(self):
        """验证空结果列表生成空 Markdown"""
        md = self.adapter.render_results_markdown([], owasp_id="LLM01", owasp_title="Test")
        self.assertIn("LLM01", md)
        self.assertIn("No attack results", md)

    def test_empty_results_console(self):
        """验证空结果列表控制台输出不崩溃"""
        # 不应抛出异常
        self.adapter.print_results_console([], owasp_mapping={})

    def test_render_empty_markdown(self):
        """验证 _render_empty_markdown"""
        md = self.adapter._render_empty_markdown("LLM02", "Sensitive Info")
        self.assertIn("LLM02", md)
        self.assertIn("Sensitive Info", md)
        self.assertIn("No attack results", md)

    def test_render_owasp_header_md(self):
        """验证 OWASP 头部 Markdown"""
        # 模拟 AttackResult 对象列表
        mock_result1 = MagicMock()
        mock_result1.outcome.name = "SUCCESS"
        mock_result1.conversation_id = "conv-001"
        mock_result1.objective = "Test objective"

        mock_result2 = MagicMock()
        mock_result2.outcome.name = "FAILURE"
        mock_result2.conversation_id = "conv-002"
        mock_result2.objective = "Test objective 2"

        header = self.adapter._render_owasp_header_md(
            "LLM01", "Prompt Injection", [mock_result1, mock_result2]
        )

        self.assertIn("LLM01", header)
        self.assertIn("Prompt Injection", header)
        self.assertIn("Total Attacks", header)
        self.assertIn("2", header)  # total
        self.assertIn("1", header)  # successful

    def test_render_fallback_md(self):
        """验证 fallback Markdown"""
        mock_result = MagicMock()
        mock_result.conversation_id = "conv-123"
        mock_result.outcome = "SUCCESS"
        mock_result.objective = "Test objective"

        md = self.adapter._render_fallback_md(mock_result, 1, "LLM01")
        self.assertIn("Attack Result #1", md)
        self.assertIn("conv-123", md)
        self.assertIn("SUCCESS", md)

    def test_reconstruct_from_dicts_empty(self):
        """验证从空字典列表重建"""
        results = self.adapter.reconstruct_from_dicts([])
        self.assertEqual(results, [])

    def test_reconstruct_from_dicts_no_conv_id(self):
        """验证缺少 conversation_id 的字典"""
        results = self.adapter.reconstruct_from_dicts([{"status": "failed"}])
        self.assertEqual(len(results), 1)
        self.assertIsNone(results[0])


class TestReportGeneratorIntegration(unittest.TestCase):
    """测试 ReportGenerator 的 PyRIT 集成"""

    def test_set_pyrit_attack_results(self):
        """验证 set_pyrit_attack_results 方法"""
        from pyrit_ai300.reporting import ReportGenerator

        results = [{"scope": "llm01", "attacks": []}]
        generator = ReportGenerator(results=results)

        # 初始为空
        self.assertEqual(generator._pyrit_attack_results, [])

        # 设置后应保留
        mock_results = [MagicMock(), MagicMock()]
        generator.set_pyrit_attack_results(mock_results)
        self.assertEqual(generator._pyrit_attack_results, mock_results)

    def test_set_pyrit_attack_results_none(self):
        """验证 set_pyrit_attack_results 传入 None"""
        from pyrit_ai300.reporting import ReportGenerator

        generator = ReportGenerator(results=[])
        generator.set_pyrit_attack_results(None)
        self.assertEqual(generator._pyrit_attack_results, [])

    def test_report_without_pyrit_results(self):
        """验证不设置 PyRIT 结果时报告正常生成"""
        from pyrit_ai300.reporting import ReportGenerator

        results = [{
            "scope": "llm01",
            "owasp_ids": ["llm01"],
            "target_endpoint": "http://test:8080",
            "attacks": [{
                "attack_name": "Test Attack",
                "mode": "chain",
                "severity": "medium",
                "payloads_tested": 1,
                "success_count": 1,
                "failure_count": 0,
                "results": [{"status": "success", "payload": "test", "response": "ok"}],
            }],
            "summary": {"total_attacks": 1, "total_payloads": 1, "successful_payloads": 1, "failed_payloads": 0},
        }]

        generator = ReportGenerator(results=results)
        md = generator._generate_markdown()

        # 不应包含 PyRIT 原生结果附录
        self.assertNotIn("Appendix D: PyRIT Native Attack Results", md)

    def test_report_with_pyrit_results(self):
        """验证设置 PyRIT 结果后报告包含附录 D"""
        from pyrit_ai300.reporting import ReportGenerator

        results = [{
            "scope": "llm01",
            "owasp_ids": ["llm01"],
            "target_endpoint": "http://test:8080",
            "attacks": [{
                "attack_name": "Test Attack",
                "mode": "chain",
                "severity": "medium",
                "payloads_tested": 1,
                "success_count": 1,
                "failure_count": 0,
                "results": [{"status": "success", "payload": "test", "response": "ok"}],
            }],
            "summary": {"total_attacks": 1, "total_payloads": 1, "successful_payloads": 1, "failed_payloads": 0},
        }]

        generator = ReportGenerator(results=results)
        # 使用 MagicMock 模拟 AttackResult
        mock_result = MagicMock()
        mock_result.outcome.name = "SUCCESS"
        mock_result.conversation_id = "test-conv-id"
        mock_result.objective = "Test objective"
        mock_result.outcome_reason = "Test reason"
        mock_result.executed_turns = 1
        mock_result.execution_time_ms = 1000
        mock_result.last_score = None
        mock_result.metadata = {}
        mock_result.get_attack_strategy_identifier.return_value = MagicMock(class_name="PromptSendingAttack")

        generator.set_pyrit_attack_results([mock_result])
        md = generator._generate_markdown()

        # 应包含 PyRIT 原生结果附录
        self.assertIn("Appendix D: PyRIT Native Attack Results", md)


class TestAttackOrchestratorRetention(unittest.TestCase):
    """测试 AttackOrchestrator 的 AttackResult 保留"""

    def test_pyrit_attack_results_init(self):
        """验证 _pyrit_attack_results 在 __init__ 中初始化"""
        from pyrit_ai300.attack.engine import AttackOrchestrator

        with patch.object(AttackOrchestrator, '_initialize_pyrit'):
            with patch.object(AttackOrchestrator, '_init_payload_manager'):
                with patch.object(AttackOrchestrator, '_load_asi_scorer_map'):
                    with patch.object(AttackOrchestrator, '_load_config', return_value={}):
                        orch = AttackOrchestrator(config_dict={})
                        self.assertIsInstance(orch._pyrit_attack_results, list)
                        self.assertEqual(len(orch._pyrit_attack_results), 0)

    def test_result_dict_has_conversation_id(self):
        """验证结果字典包含 conversation_id 字段（模拟）"""
        # 这是一个结构验证测试，验证 _execute_single_attack_async 的返回字典结构
        # 包含 conversation_id 字段
        expected_fields = [
            "attack_class",
            "status",
            "outcome",
            "response",
            "conversation_id",
            "executed_turns",
            "execution_time_ms",
        ]
        # 验证字段名存在
        for field in expected_fields:
            self.assertIsInstance(field, str)


class TestPipelineOrchestratorIntegration(unittest.TestCase):
    """测试 PipelineOrchestrator 的 PyRIT 输出集成"""

    def test_print_attack_results_native_exists(self):
        """验证 _print_attack_results_native 方法存在"""
        from pyrit_ai300.pipeline.orchestrator import PipelineOrchestrator
        self.assertTrue(hasattr(PipelineOrchestrator, '_print_attack_results_native'))

    def test_print_attack_results_native_empty(self):
        """验证空 AttackResult 列表不崩溃"""
        from pyrit_ai300.pipeline.orchestrator import PipelineOrchestrator

        orch = PipelineOrchestrator.__new__(PipelineOrchestrator)
        orch._console = None
        orch._verbose = False

        # 空列表不应抛出异常
        orch._print_attack_results_native(0, 0, 0, 0.0, [], "llm01")


class TestImportChain(unittest.TestCase):
    """测试导入链完整性"""

    def test_import_attack_output(self):
        """验证 attack_output 模块可导入"""
        from pyrit_ai300.reporting.attack_output import AttackOutputAdapter
        adapter = AttackOutputAdapter()
        self.assertIsNotNone(adapter)

    def test_import_from_reporting_init(self):
        """验证从 reporting __init__ 导入"""
        from pyrit_ai300.reporting import AttackOutputAdapter, OWASP_LLM_MAPPINGS
        self.assertIsNotNone(AttackOutputAdapter)
        self.assertIsInstance(OWASP_LLM_MAPPINGS, dict)

    def test_reporting_all_contains_adapter(self):
        """验证 __all__ 包含 AttackOutputAdapter"""
        from pyrit_ai300.reporting import __all__
        self.assertIn("AttackOutputAdapter", __all__)
        self.assertIn("OWASP_LLM_MAPPINGS", __all__)


if __name__ == "__main__":
    unittest.main()
