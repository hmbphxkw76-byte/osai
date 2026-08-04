# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""测试 Recon → Target 桥接模块 (R-T1/T2/T3) + 认证状态桥接 + 策略桥接 + MCP 攻击。

测试覆盖:
  - test_recon_target_bridge: 端点提取 / HTTPTarget 构建 / Burp 增强 / RateLimitedTarget 包装
  - test_auth_state_bridge: 认证状态导出/导入/复用/JSON 文件加载
  - test_recon_strategy_bridge: 能力提取 / Converter 链选择 / Payload 定制 / 攻击序列
  - test_mcp_attack: MCP 攻击载荷结构 / 报告生成

> **日期**: 2026-8-4
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

# ============================================================
# R-T1/T2/T3: recon_target_bridge 测试
# ============================================================


class TestExtractEndpoints:
    """R-T1: 从 ReconReport 中提取端点。"""

    def test_extract_from_dict_endpoints(self):
        """从 dict 格式的端点列表提取。"""
        from pipeline.integrations.recon_target_bridge import extract_endpoints_from_recon

        recon = SimpleNamespace(
            endpoints=[
                {
                    "url": "https://api.example.com/v1/chat/completions",
                    "method": "POST",
                    "headers": {"Authorization": "Bearer token123"},
                    "body": '{"messages": [{"role": "user", "content": "hello"}]}',
                    "content_type": "application/json",
                },
                {
                    "url": "https://api.example.com/v1/models",
                    "method": "GET",
                    "headers": {},
                    "body": "",
                    "content_type": "application/json",
                },
            ]
        )

        endpoints = extract_endpoints_from_recon(recon)

        # GET 端点应被过滤
        assert len(endpoints) == 1
        assert endpoints[0].method == "POST"
        assert endpoints[0].is_llm_endpoint is True
        assert endpoints[0].has_auth is True
        assert "Authorization" in endpoints[0].auth_headers

    def test_extract_from_object_endpoints(self):
        """从对象格式的端点列表提取。"""
        from pipeline.integrations.recon_target_bridge import extract_endpoints_from_recon

        ep = SimpleNamespace(
            url="https://chat.app.com/api/chat",
            method="POST",
            headers={"X-API-Key": "key123"},
            body='{"prompt": "test"}',
            content_type="application/json",
        )
        recon = SimpleNamespace(endpoints=[ep])

        endpoints = extract_endpoints_from_recon(recon)
        assert len(endpoints) == 1
        assert endpoints[0].url == "https://chat.app.com/api/chat"
        assert endpoints[0].has_auth is True
        assert "{PROMPT}" in endpoints[0].body_template

    def test_extract_empty_endpoints(self):
        """空端点列表返回空列表。"""
        from pipeline.integrations.recon_target_bridge import extract_endpoints_from_recon

        recon = SimpleNamespace(endpoints=[])
        assert extract_endpoints_from_recon(recon) == []

    def test_llm_endpoint_priority(self):
        """LLM 端点应排在前面。"""
        from pipeline.integrations.recon_target_bridge import extract_endpoints_from_recon

        recon = SimpleNamespace(
            endpoints=[
                {
                    "url": "https://api.example.com/upload",
                    "method": "POST",
                    "headers": {},
                    "body": "",
                    "content_type": "multipart/form-data",
                },
                {
                    "url": "https://api.example.com/v1/chat/completions",
                    "method": "POST",
                    "headers": {},
                    "body": "",
                    "content_type": "application/json",
                },
            ]
        )

        endpoints = extract_endpoints_from_recon(recon)
        assert endpoints[0].is_llm_endpoint is True


class TestPromptPlaceholderInjection:
    """R-T2: {PROMPT} 占位符注入。"""

    def test_inject_into_openai_format(self):
        """OpenAI messages 格式注入。"""
        from pipeline.integrations.recon_target_bridge import _inject_prompt_placeholder

        body = '{"messages": [{"role": "user", "content": "hello"}]}'
        result = _inject_prompt_placeholder(body, "application/json")
        assert "{PROMPT}" in result

    def test_inject_into_simple_format(self):
        """简单 prompt 格式注入。"""
        from pipeline.integrations.recon_target_bridge import _inject_prompt_placeholder

        body = '{"prompt": "hello"}'
        result = _inject_prompt_placeholder(body, "application/json")
        assert "{PROMPT}" in result

    def test_inject_non_json(self):
        """非 JSON 格式追加。"""
        from pipeline.integrations.recon_target_bridge import _inject_prompt_placeholder

        body = "plain text body"
        result = _inject_prompt_placeholder(body, "text/plain")
        assert "{PROMPT}" in result

    def test_existing_placeholder_preserved(self):
        """已有占位符不重复注入。"""
        from pipeline.integrations.recon_target_bridge import _inject_prompt_placeholder

        body = '{"prompt": "{PROMPT}"}'
        result = _inject_prompt_placeholder(body, "application/json")
        assert result.count("{PROMPT}") == 1


class TestEnhanceBurpRequest:
    """R-T2: Burp 请求增强。"""

    def test_enhance_with_auth_headers(self):
        """注入认证 header。"""
        from pipeline.integrations.recon_target_bridge import enhance_burp_request

        raw = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            "{\"prompt\": \"test\"}"
        )
        result = enhance_burp_request(
            raw,
            auth_headers={"Authorization": "Bearer token123"},
        )

        assert "Authorization: Bearer token123" in result
        assert "{PROMPT}" in result

    def test_enhance_no_duplicate_headers(self):
        """不重复添加已存在的 header。"""
        from pipeline.integrations.recon_target_bridge import enhance_burp_request

        raw = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Authorization: Bearer existing\r\n"
            "\r\n"
            "{\"prompt\": \"test\"}"
        )
        result = enhance_burp_request(
            raw,
            auth_headers={"Authorization": "Bearer new"},
        )

        # 应保留原有 header, 不添加新的
        assert result.count("Authorization:") == 1


class TestBuildTargetFromRecon:
    """R-T1/T2/T3: 完整桥接流程。"""

    def test_build_target_no_recon(self, pipeline_ctx):
        """无侦察结果时返回 skipped。"""
        import asyncio

        from pipeline.integrations.recon_target_bridge import build_target_from_recon

        async def _run() -> Any:
            return await build_target_from_recon(pipeline_ctx)

        result = asyncio.run(_run())
        assert not result.success
        assert "recon_result not found" in result.skipped_reason

    def test_build_target_with_recon(self, pipeline_ctx):
        """有侦察结果时构建 HTTPTarget。"""
        import asyncio

        from pipeline.integrations.recon_target_bridge import build_target_from_recon

        pipeline_ctx.metadata["recon_result"] = SimpleNamespace(
            endpoints=[
                {
                    "url": "https://api.example.com/v1/chat/completions",
                    "method": "POST",
                    "headers": {"Authorization": "Bearer token123"},
                    "body": '{"messages": [{"role": "user", "content": "hello"}]}',
                    "content_type": "application/json",
                }
            ]
        )

        async def _run() -> Any:
            return await build_target_from_recon(
                pipeline_ctx,
                max_concurrency=1,
                requests_per_minute=None,
            )

        # mock PyRIT CentralMemory (HTTPTarget 构造时需要)
        with patch("pyrit.memory.central_memory.CentralMemory.get_memory_instance") as mock_mem:
            mock_mem.return_value = MagicMock()
            result = asyncio.run(_run())

        assert result.success
        assert result.endpoint_info is not None
        assert result.endpoint_info.is_llm_endpoint is True


# ============================================================
# 认证状态桥接测试
# ============================================================


class TestAuthState:
    """认证状态数据结构测试。"""

    def test_auth_state_creation(self):
        """创建 AuthState。"""
        from pipeline.integrations.auth_state_bridge import AuthState

        state = AuthState(
            auth_type="same_domain",
            target_url="https://app.example.com",
            login_url="https://app.example.com/login",
            headers={"Authorization": "Bearer token123"},
        )
        assert state.auth_type == "same_domain"
        assert state.is_valid() is True

    def test_auth_state_none_type_valid(self):
        """none 类型的认证状态总是有效。"""
        from pipeline.integrations.auth_state_bridge import AuthState

        state = AuthState(auth_type="none")
        assert state.is_valid() is True

    def test_auth_state_empty_invalid(self):
        """空认证状态无效。"""
        from pipeline.integrations.auth_state_bridge import AuthState

        state = AuthState(auth_type="same_domain")
        assert state.is_valid() is False

    def test_to_auth_headers_with_token(self):
        """从 tokens 自动构建 Authorization header。"""
        from pipeline.integrations.auth_state_bridge import AuthState

        state = AuthState(
            auth_type="cross_domain",
            tokens={"access_token": "my_token"},
        )
        headers = state.to_auth_headers()
        assert headers["Authorization"] == "Bearer my_token"

    def test_serialization_roundtrip(self):
        """序列化/反序列化往返。"""
        from pipeline.integrations.auth_state_bridge import AuthState

        original = AuthState(
            auth_type="same_domain",
            target_url="https://app.example.com",
            headers={"Authorization": "Bearer token"},
            mfa_required=True,
            mfa_types=["otp", "sms"],
        )
        data = original.to_dict()
        restored = AuthState.from_dict(data)

        assert restored.auth_type == "same_domain"
        assert restored.target_url == "https://app.example.com"
        assert restored.mfa_types == ["otp", "sms"]


class TestAuthStateExportImport:
    """认证状态导出/导入测试。"""

    def test_export_import_roundtrip(self, tmp_path):
        """导出再导入应得到相同数据。"""
        from pipeline.integrations.auth_state_bridge import AuthState, export_auth_state, import_auth_state

        state = AuthState(
            auth_type="cross_domain",
            target_url="https://app.example.com",
            headers={"Authorization": "Bearer token123"},
            source="pyrit",
        )

        file_path = export_auth_state(state, output_dir=tmp_path)
        assert file_path.exists()

        imported = import_auth_state(file_path)
        assert imported is not None
        assert imported.auth_type == "cross_domain"
        assert imported.headers["Authorization"] == "Bearer token123"

    def test_import_nonexistent_file(self, tmp_path):
        """导入不存在的文件返回 None。"""
        from pipeline.integrations.auth_state_bridge import import_auth_state

        result = import_auth_state(tmp_path / "nonexistent.json")
        assert result is None


class TestReconResultFromFile:
    """从 JSON 文件加载侦察结果测试。"""

    def test_load_recon_json(self, tmp_path):
        """从 JSON 文件加载侦察结果。"""
        from pipeline.integrations.auth_state_bridge import load_recon_result_from_file

        recon_data = {
            "endpoints": [
                {"url": "https://api.example.com/v1/chat", "method": "POST"}
            ],
            "has_agent_tools": True,
            "has_rag_endpoints": False,
        }
        json_file = tmp_path / "recon.json"
        json_file.write_text(json.dumps(recon_data), encoding="utf-8")

        report = load_recon_result_from_file(json_file)
        assert report is not None
        assert report.has_agent_tools is True
        assert len(report.endpoints) == 1

    def test_load_nonexistent_file(self, tmp_path):
        """加载不存在的文件返回 None。"""
        from pipeline.integrations.auth_state_bridge import load_recon_result_from_file

        assert load_recon_result_from_file(tmp_path / "missing.json") is None


# ============================================================
# R-S1/S2/S3: recon_strategy_bridge 测试
# ============================================================


class TestExtractCapability:
    """R-S1: 能力标志提取。"""

    def test_extract_from_object(self):
        """从对象提取能力标志。"""
        from pipeline.integrations.recon_strategy_bridge import extract_capability

        recon = SimpleNamespace(
            has_agent_tools=True,
            has_rag_endpoints=False,
            has_mcp=True,
            has_embedding=False,
            endpoints=[
                SimpleNamespace(url="https://api.example.com/tool/list", method="POST"),
                SimpleNamespace(url="https://api.example.com/rag/search", method="POST"),
            ],
            injection_surfaces=[],
            recommendations=[],
        )

        cap = extract_capability(recon)
        assert cap.has_agent_tools is True
        assert cap.has_mcp is True
        assert len(cap.agent_tool_names) == 1
        assert len(cap.rag_endpoints) == 1

    def test_extract_from_dict(self):
        """从 dict 提取能力标志。"""
        from pipeline.integrations.recon_strategy_bridge import extract_capability

        recon = {
            "has_agent_tools": False,
            "has_rag_endpoints": True,
            "endpoints": [],
            "injection_surfaces": [],
            "recommendations": [],
        }

        cap = extract_capability(recon)
        assert cap.has_rag_endpoints is True
        assert cap.has_agent_tools is False


class TestSelectConverterChains:
    """R-S1: Converter 链选择。"""

    def test_agent_tools_chain(self):
        """Agent 工具能力 → stealth_evasion + encoding_bypass。"""
        from pipeline.integrations.recon_strategy_bridge import ReconCapability, select_converter_chains

        cap = ReconCapability(has_agent_tools=True)
        chains = select_converter_chains(cap)

        assert "agent_tools" in chains
        assert "stealth_evasion" in chains["agent_tools"]
        assert "encoding_bypass" in chains["agent_tools"]

    def test_all_capabilities(self):
        """全部能力都有对应链。"""
        from pipeline.integrations.recon_strategy_bridge import ReconCapability, select_converter_chains

        cap = ReconCapability(
            has_agent_tools=True,
            has_rag_endpoints=True,
            has_mcp=True,
            has_embedding=True,
            has_file_upload=True,
            has_multimodal_input=True,
        )
        chains = select_converter_chains(cap)
        assert len(chains) == 6

    def test_no_capabilities(self):
        """无能力时返回空映射。"""
        from pipeline.integrations.recon_strategy_bridge import ReconCapability, select_converter_chains

        cap = ReconCapability()
        chains = select_converter_chains(cap)
        assert len(chains) == 0


class TestCustomizePayloads:
    """R-S2: Payload 定制。"""

    def test_custom_payloads_with_rag(self):
        """RAG 能力 → rag_document payload。"""
        from pipeline.integrations.recon_strategy_bridge import ReconCapability, customize_payloads

        cap = ReconCapability(has_rag_endpoints=True)
        payloads = customize_payloads(cap)

        assert "rag_document" in payloads
        assert "original_payload" not in payloads["rag_document"]  # 模板已填充

    def test_custom_payloads_with_agent(self):
        """Agent 能力 → tool_output payload。"""
        from pipeline.integrations.recon_strategy_bridge import ReconCapability, customize_payloads

        cap = ReconCapability(has_agent_tools=True)
        payloads = customize_payloads(cap)

        assert "tool_output" in payloads

    def test_custom_payloads_with_mcp(self):
        """MCP 能力 → mcp_resource payload。"""
        from pipeline.integrations.recon_strategy_bridge import ReconCapability, customize_payloads

        cap = ReconCapability(has_mcp=True)
        payloads = customize_payloads(cap)

        assert "mcp_resource" in payloads


class TestBuildAttackSequence:
    """R-S3: 攻击序列编排。"""

    def test_sequence_from_recommendations(self):
        """从推荐中生成序列。"""
        from pipeline.integrations.recon_strategy_bridge import ReconCapability, build_attack_sequence

        cap = ReconCapability(
            recommendations=[
                SimpleNamespace(owasp_id="LLM01", attack_strategy="prompt_injection", priority=1),
                SimpleNamespace(owasp_id="LLM06", attack_strategy="tool_hijack", priority=2),
            ]
        )
        seq = build_attack_sequence(cap)

        assert "many_shot" in seq  # LLM01 → many_shot
        assert "tool_hijack" in seq  # LLM06 → tool_hijack

    def test_sequence_default_fallback(self):
        """无推荐时的默认序列。"""
        from pipeline.integrations.recon_strategy_bridge import ReconCapability, build_attack_sequence

        cap = ReconCapability(has_agent_tools=True)
        seq = build_attack_sequence(cap)

        assert "tool_hijack" in seq
        assert len(seq) > 0


class TestBridgeReconToStrategy:
    """完整策略桥接测试。"""

    def test_bridge_no_recon(self, pipeline_ctx):
        """无侦察结果时返回 skipped。"""
        from pipeline.integrations.recon_strategy_bridge import bridge_recon_to_strategy

        result = bridge_recon_to_strategy(pipeline_ctx)
        assert "No recon result" in result.skipped_reason

    def test_bridge_with_recon(self, pipeline_ctx):
        """有侦察结果时完整桥接。"""
        from pipeline.integrations.recon_strategy_bridge import bridge_recon_to_strategy

        pipeline_ctx.metadata["recon_result"] = SimpleNamespace(
            has_agent_tools=True,
            has_rag_endpoints=True,
            has_mcp=False,
            has_embedding=False,
            endpoints=[],
            injection_surfaces=[],
            recommendations=[],
        )

        result = bridge_recon_to_strategy(pipeline_ctx)
        assert result.capability is not None
        assert result.capability.has_agent_tools is True
        assert "agent_tools" in result.converter_chains
        assert "rag" in result.converter_chains


# ============================================================
# R-M1: MCP 攻击模块测试
# ============================================================


class TestMCPAttackProbes:
    """MCP 攻击载荷结构测试。"""

    def test_probe_count(self):
        """应有 8 个 MCP 攻击探针。"""
        from pipeline.scenarios.mcp_attack import _MCP_ATTACK_PROBES

        assert len(_MCP_ATTACK_PROBES) == 8

    def test_probe_structure(self):
        """每个探针应有 5 个字段。"""
        from pipeline.scenarios.mcp_attack import _MCP_ATTACK_PROBES

        for probe in _MCP_ATTACK_PROBES:
            assert len(probe) == 5
            attack_type, surface, payload, keywords, severity = probe
            assert isinstance(attack_type, str)
            assert isinstance(surface, str)
            assert isinstance(payload, str)
            assert isinstance(keywords, list)
            assert severity in ("critical", "high", "medium", "low")

    def test_all_surfaces_covered(self):
        """覆盖所有 MCP 原语。"""
        from pipeline.scenarios.mcp_attack import _MCP_ATTACK_PROBES

        surfaces = {probe[1] for probe in _MCP_ATTACK_PROBES}
        assert "resource" in surfaces
        assert "tool" in surfaces
        assert "prompt" in surfaces
        assert "sampling" in surfaces


class TestMCPAttackReport:
    """MCP 攻击报告测试。"""

    def test_report_creation(self):
        """创建报告。"""
        from pipeline.scenarios.mcp_attack import MCPAttackReport, MCPAttackResult

        report = MCPAttackReport(
            results=[
                MCPAttackResult(
                    attack_type="resource_injection",
                    target_surface="resource",
                    is_successful=True,
                    severity="critical",
                ),
                MCPAttackResult(
                    attack_type="tool_description_injection",
                    target_surface="tool",
                    is_successful=False,
                    severity="critical",
                ),
            ]
        )

        assert report.success_count == 1
        assert report.critical_count == 1
        assert report.risk_score > 0

    def test_report_serialization(self):
        """报告序列化。"""
        from pipeline.scenarios.mcp_attack import MCPAttackReport, MCPAttackResult

        report = MCPAttackReport(
            results=[
                MCPAttackResult(
                    attack_type="sampling_injection",
                    target_surface="sampling",
                    is_successful=True,
                    severity="critical",
                )
            ]
        )

        data = report.to_dict()
        assert data["success_count"] == 1
        assert data["critical_count"] == 1
        assert len(data["results"]) == 1


class TestMCPAttackRun:
    """MCP 攻击执行测试。"""

    def test_run_no_target(self, pipeline_ctx):
        """无 Target 时返回空报告。"""
        import asyncio

        from pipeline.scenarios.mcp_attack import run_mcp_attack

        async def _run() -> Any:
            return await run_mcp_attack(pipeline_ctx)

        # mock TargetRegistry 返回空
        with patch("pyrit.registry.TargetRegistry") as mock_registry:
            mock_registry.get_registry_singleton.return_value.instances.get_all_instances.return_value = []
            report = asyncio.run(_run())

        assert len(report.results) == 0
