# -*- coding: utf-8 -*-
"""
AI-300 Framework - Core Library Tests
验证核心共享库的独立性和正确性

测试覆盖：
1. core 模块无业务模块依赖（无循环依赖）
2. detect_target_type 正确性
3. extract_spa_llm_endpoint / extract_spa_model_name 正确性
4. build_aimap_data_from_spa_profile 正确性
5. inject_credentials_to_recon / inject_credentials_to_attack 正确性
6. StageInput / StageOutput / PipelineResult 协议正确性
7. PipelineStage 协议结构验证
8. ProfileContract / FingerprintContract 模型验证
"""

from __future__ import annotations

import unittest
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch


class TestCoreIndependence(unittest.TestCase):
    """验证 core 模块无业务模块依赖"""

    def test_core_no_business_imports(self):
        """core 包不应导入任何业务模块"""
        import importlib
        import pkgutil
        import pyrit_ai300.core as core_pkg

        business_prefixes = (
            "reconnaissance",
            "pipeline",
            "orchestrators",
            "reporting",
            "standards",
            "scenarios",
            "payloads",
            "attack",
        )

        for importer, modname, ispkg in pkgutil.walk_packages(
            core_pkg.__path__, prefix="pyrit_ai300.core."
        ):
            try:
                mod = importlib.import_module(modname)
            except Exception:
                continue

            # 检查模块的 __dict__ 中是否有对业务模块的导入
            source = getattr(mod, "__file__", "")
            if not source or not source.endswith(".py"):
                continue

            with open(source, "r", encoding="utf-8") as f:
                content = f.read()

            for prefix in business_prefixes:
                # 允许在注释/文档字符串中出现，但不在实际 import 语句中
                lines = content.split("\n")
                for line in lines:
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    if stripped.startswith('"""') or stripped.startswith("'''"):
                        continue
                    if "import" in stripped and f"..{prefix}" in stripped:
                        self.fail(
                            f"core module {modname} imports from business module "
                            f"({prefix}): {stripped}"
                        )

    def test_core_imports_succeed(self):
        """core 包导入不报错"""
        from pyrit_ai300.core import (
            detect_target_type,
            extract_spa_llm_endpoint,
            extract_spa_model_name,
            build_aimap_data_from_spa_profile,
            inject_credentials_to_recon,
            inject_credentials_to_attack,
            StageInput,
            StageOutput,
            PipelineResult,
            PipelineStage,
            PHASE_CREDENTIAL,
            PHASE_RECON,
            PHASE_ATTACK,
            PHASE_REPORT,
            ALL_PHASES,
            EndpointInfo,
            FingerprintContract,
            ProfileContract,
        )
        # 验证常量值
        self.assertEqual(PHASE_CREDENTIAL, "credential")
        self.assertEqual(PHASE_RECON, "recon")
        self.assertEqual(PHASE_ATTACK, "attack")
        self.assertEqual(PHASE_REPORT, "report")
        self.assertEqual(len(ALL_PHASES), 4)


class TestDetectTargetType(unittest.TestCase):
    """detect_target_type 测试"""

    def test_spa_with_config(self):
        """有 spa_config 时检测为 spa"""
        from pyrit_ai300.core.utils import detect_target_type
        result = detect_target_type("https://example.com/#/home", "config/targets/spa_target.yaml")
        self.assertEqual(result, "spa")

    def test_spa_hash_url(self):
        """URL 含 #/ 检测为 spa"""
        from pyrit_ai300.core.utils import detect_target_type
        result = detect_target_type("https://app.example.com/#/chat", None)
        self.assertEqual(result, "spa")

    def test_api_localhost(self):
        """localhost 检测为 api"""
        from pyrit_ai300.core.utils import detect_target_type
        result = detect_target_type("http://localhost:11434/v1", None)
        self.assertEqual(result, "api")

    def test_api_known_port(self):
        """已知 LLM 端口检测为 api"""
        from pyrit_ai300.core.utils import detect_target_type
        result = detect_target_type("http://example.com:8080", None)
        self.assertEqual(result, "api")

    def test_api_v1_path(self):
        """v1/ 路径检测为 api"""
        from pyrit_ai300.core.utils import detect_target_type
        result = detect_target_type("https://example.com/v1/models", None)
        self.assertEqual(result, "api")

    def test_api_subdomain(self):
        """api. 子域名检测为 api"""
        from pyrit_ai300.core.utils import detect_target_type
        result = detect_target_type("https://api.example.com/data", None)
        self.assertEqual(result, "api")

    def test_empty_url(self):
        """空 URL 检测为 api"""
        from pyrit_ai300.core.utils import detect_target_type
        result = detect_target_type("", None)
        self.assertEqual(result, "api")

    def test_web_app_path_chat(self):
        """Web 应用 /chat 路径检测为 spa"""
        from pyrit_ai300.core.utils import detect_target_type
        result = detect_target_type("https://app.example.com/chat", None)
        self.assertEqual(result, "spa")

    def test_web_app_path_dashboard(self):
        """Web 应用 /dashboard 路径检测为 spa"""
        from pyrit_ai300.core.utils import detect_target_type
        result = detect_target_type("https://app.example.com/dashboard", None)
        self.assertEqual(result, "spa")

    def test_default_spa(self):
        """公网域名 + 非 API 路径默认为 spa"""
        from pyrit_ai300.core.utils import detect_target_type
        result = detect_target_type("https://www.example.com", None)
        self.assertEqual(result, "spa")


class TestExtractSpaMethods(unittest.TestCase):
    """extract_spa_llm_endpoint / extract_spa_model_name 测试"""

    def test_extract_endpoint_from_entry_points(self):
        """从 entry_points 提取 LLM 端点"""
        from pyrit_ai300.core.utils import extract_spa_llm_endpoint
        mock_profile = MagicMock()
        mock_profile.entry_points = [{"url": "https://api.example.com/v1/chat"}]
        result = extract_spa_llm_endpoint(mock_profile)
        self.assertEqual(result, "https://api.example.com/v1/chat")

    def test_extract_endpoint_from_fingerprint(self):
        """从 fingerprint 提取 LLM 端点"""
        from pyrit_ai300.core.utils import extract_spa_llm_endpoint
        mock_profile = MagicMock()
        mock_profile.entry_points = []
        mock_profile.fingerprint = MagicMock()
        mock_profile.fingerprint.endpoint = "https://api.example.com/v1/chat"
        result = extract_spa_llm_endpoint(mock_profile)
        self.assertEqual(result, "https://api.example.com/v1/chat")

    def test_extract_endpoint_none(self):
        """无端点时返回 None"""
        from pyrit_ai300.core.utils import extract_spa_llm_endpoint
        mock_profile = MagicMock()
        mock_profile.entry_points = []
        mock_profile.fingerprint = None
        mock_profile.raw_data = {}
        result = extract_spa_llm_endpoint(mock_profile)
        self.assertIsNone(result)

    def test_extract_model_from_fingerprint(self):
        """从 fingerprint 提取模型名"""
        from pyrit_ai300.core.utils import extract_spa_model_name
        mock_profile = MagicMock()
        mock_profile.fingerprint = MagicMock()
        mock_profile.fingerprint.model_name = "gpt-4o"
        result = extract_spa_model_name(mock_profile)
        self.assertEqual(result, "gpt-4o")

    def test_extract_model_none(self):
        """无模型时返回 None"""
        from pyrit_ai300.core.utils import extract_spa_model_name
        mock_profile = MagicMock()
        mock_profile.fingerprint = None
        mock_profile.raw_data = {}
        result = extract_spa_model_name(mock_profile)
        self.assertIsNone(result)


class TestBuildAimapData(unittest.TestCase):
    """build_aimap_data_from_spa_profile 测试"""

    def test_none_profile(self):
        """None profile 返回默认 surfaces"""
        from pyrit_ai300.core.utils import build_aimap_data_from_spa_profile
        result = build_aimap_data_from_spa_profile(None)
        self.assertIn("prompt", result["surfaces"])

    def test_with_surfaces(self):
        """有 surfaces 时正确提取"""
        from pyrit_ai300.core.utils import build_aimap_data_from_spa_profile
        mock_profile = MagicMock()
        mock_profile.surfaces = ["prompt", "rag"]
        mock_profile.fingerprint = MagicMock()
        mock_profile.fingerprint.capabilities = ["chat", "vision"]
        mock_profile.fingerprint.model_family = "openai"
        mock_profile.raw_results = None
        result = build_aimap_data_from_spa_profile(mock_profile)
        self.assertIn("prompt", result["surfaces"])
        self.assertIn("rag", result["surfaces"])
        self.assertIn("chat", result["capabilities"])
        self.assertEqual(result["model_family"], "openai")


class TestCredentialInjection(unittest.TestCase):
    """inject_credentials_to_recon / inject_credentials_to_attack 测试"""

    def test_recon_no_credentials(self):
        """无凭据时返回空配置"""
        from pyrit_ai300.core.utils import inject_credentials_to_recon
        result = inject_credentials_to_recon(None)
        self.assertEqual(result, {})

    def test_recon_with_credentials(self):
        """有凭据时注入 Bearer Token"""
        from pyrit_ai300.core.utils import inject_credentials_to_recon
        mock_resolution = MagicMock()
        mock_resolution.has_credentials = True
        mock_resolution.profile = MagicMock()
        mock_resolution.profile.headers = {"Authorization": "Bearer test-token-123"}
        mock_resolution.profile.raw_cookies = "session=abc123"
        result = inject_credentials_to_recon(mock_resolution)
        self.assertIn("native_probe", result)
        self.assertEqual(result["native_probe"]["credential_bearer"], "test-token-123")
        self.assertIn("deepteam", result)

    def test_attack_no_credentials(self):
        """无凭据时不注入"""
        from pyrit_ai300.core.utils import inject_credentials_to_attack

        class FakeEngine:
            pass

        engine = FakeEngine()
        inject_credentials_to_attack(None, engine)
        # 验证引擎未被修改（不应有凭据属性）
        self.assertFalse(hasattr(engine, '_credential_api_key'))

    def test_attack_with_credentials(self):
        """有凭据时注入到引擎"""
        from pyrit_ai300.core.utils import inject_credentials_to_attack
        mock_resolution = MagicMock()
        mock_resolution.has_credentials = True
        mock_resolution.profile = MagicMock()
        mock_resolution.profile.headers = {"Authorization": "Bearer test-key-456"}
        mock_engine = MagicMock()
        inject_credentials_to_attack(mock_resolution, mock_engine)
        self.assertEqual(mock_engine._credential_api_key, "test-key-456")


class TestStageProtocols(unittest.TestCase):
    """StageInput / StageOutput / PipelineResult 协议测试"""

    def test_stage_input_defaults(self):
        """StageInput 默认值正确"""
        from pyrit_ai300.core.protocols import StageInput
        si = StageInput()
        self.assertEqual(si.target_url, "")
        self.assertEqual(si.depth, "standard")
        self.assertEqual(si.scope, "quick")
        self.assertIsNone(si.target_file)
        self.assertEqual(si.extra, {})

    def test_stage_output_defaults(self):
        """StageOutput 默认值正确"""
        from pyrit_ai300.core.protocols import StageOutput
        so = StageOutput(phase="test", success=True)
        self.assertEqual(so.phase, "test")
        self.assertTrue(so.success)
        self.assertEqual(so.duration_ms, 0.0)
        self.assertEqual(so.data, {})
        self.assertEqual(so.errors, [])
        self.assertFalse(so.has_errors)

    def test_stage_output_has_errors(self):
        """StageOutput.has_errors 正确"""
        from pyrit_ai300.core.protocols import StageOutput
        so = StageOutput(phase="test", success=False, errors=["error1"])
        self.assertTrue(so.has_errors)

    def test_pipeline_result_defaults(self):
        """PipelineResult 默认值正确"""
        from pyrit_ai300.core.protocols import PipelineResult
        pr = PipelineResult()
        self.assertEqual(pr.target, "")
        self.assertEqual(pr.phases, [])
        self.assertFalse(pr.overall_success)

    def test_pipeline_result_recon_success(self):
        """PipelineResult.recon_success 正确"""
        from pyrit_ai300.core.protocols import PipelineResult, StageOutput, PHASE_RECON
        pr = PipelineResult()
        pr.phases.append(StageOutput(phase=PHASE_RECON, success=True))
        self.assertTrue(pr.recon_success)
        self.assertFalse(pr.attack_success)

    def test_pipeline_result_get_phase(self):
        """PipelineResult.get_phase 正确"""
        from pyrit_ai300.core.protocols import PipelineResult, StageOutput, PHASE_ATTACK
        pr = PipelineResult()
        pr.phases.append(StageOutput(phase=PHASE_ATTACK, success=True))
        result = pr.get_phase(PHASE_ATTACK)
        self.assertIsNotNone(result)
        self.assertTrue(result.success)
        self.assertIsNone(pr.get_phase("nonexistent"))

    def test_pipeline_result_summary_table(self):
        """PipelineResult.summary_table 正确"""
        from pyrit_ai300.core.protocols import PipelineResult, StageOutput, PHASE_RECON
        pr = PipelineResult(target="https://example.com")
        pr.phases.append(StageOutput(phase=PHASE_RECON, success=True, duration_ms=1000, summary="OK"))
        table = pr.summary_table()
        self.assertIn("AI Red Team", table)
        self.assertIn("example.com", table)
        self.assertIn("recon", table)


class TestPipelineStageProtocol(unittest.TestCase):
    """PipelineStage 协议验证"""

    def test_pipeline_stage_is_protocol(self):
        """PipelineStage 是 runtime_checkable Protocol"""
        from pyrit_ai300.core.protocols import PipelineStage
        from typing import Protocol
        # Protocol 是可检查的
        self.assertTrue(hasattr(PipelineStage, '_is_protocol'))

    def test_stage_implementation_matches_protocol(self):
        """实现 PipelineStage 接口的类可以被 runtime check 通过"""
        from pyrit_ai300.core.protocols import PipelineStage, StageInput, StageOutput

        class MyStage:
            def execute(self, stage_input: StageInput) -> StageOutput:
                return StageOutput(phase="custom", success=True)

        stage = MyStage()
        # PipelineStage 是 runtime_checkable，应该匹配
        self.assertTrue(isinstance(stage, PipelineStage))


class TestDataModels(unittest.TestCase):
    """数据模型测试"""

    def test_endpoint_info_defaults(self):
        """EndpointInfo 默认值正确"""
        from pyrit_ai300.core.models import EndpointInfo
        ei = EndpointInfo()
        self.assertEqual(ei.url, "")
        self.assertEqual(ei.method, "POST")
        self.assertEqual(ei.protocols, [])

    def test_fingerprint_contract_defaults(self):
        """FingerprintContract 默认值正确"""
        from pyrit_ai300.core.models import FingerprintContract
        fc = FingerprintContract()
        self.assertEqual(fc.model_name, "")
        self.assertEqual(fc.capabilities, [])

    def test_profile_contract_is_protocol(self):
        """ProfileContract 是 Protocol"""
        from pyrit_ai300.core.models import ProfileContract
        from typing import Protocol
        self.assertTrue(hasattr(ProfileContract, '_is_protocol'))


if __name__ == "__main__":
    unittest.main()
