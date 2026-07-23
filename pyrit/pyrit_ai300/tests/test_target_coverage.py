# -*- coding: utf-8 -*-
"""
AI-300 Framework - 靶机全覆盖测试
验证 OWASP DonkAI 和 AIVP (AI-Vulnerabilities) 两个靶机
在侦察、分析、攻击、报告全阶段的覆盖能力。

测试范围：
1. ResponseParser — JSON / SSE / 纯文本响应解析
2. ApiTargetBuilder — REST API / SSE Chat 目标构建
3. LabCatalog — Lab/挑战目录加载和查询
4. PayloadFilter — 靶机类型攻击面推断和过滤
5. TargetBuilder — 新目标类型 (rest_api / sse_chat) 集成
6. InfraScanAdapter — DonkAI/AIVP 端点检测规则
7. Target Config — YAML 配置文件加载验证
8. 端到端覆盖 — 侦察→分析→攻击→报告全链路覆盖验证
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
import yaml

# 确保项目根目录在 sys.path
_PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ════════════════════════════════════════════════════════════════
# 1. ResponseParser 测试
# ════════════════════════════════════════════════════════════════

class TestResponseParser:
    """响应解析器测试"""

    def test_json_response_parser_basic(self):
        """JSON 响应解析 — 基本字段提取"""
        from pyrit_ai300.attack.interactions.response_parser import ResponseParser

        parser = ResponseParser.create("json", field="response")
        raw = json.dumps({"response": "Hello world", "session_id": 1})
        assert parser.parse(raw) == "Hello world"

    def test_json_response_parser_nested(self):
        """JSON 响应解析 — 嵌套字段"""
        from pyrit_ai300.attack.interactions.response_parser import ResponseParser

        parser = ResponseParser.create("json", field="data.message")
        raw = json.dumps({"data": {"message": "nested value"}})
        assert parser.parse(raw) == "nested value"

    def test_json_response_parser_field_not_found(self):
        """JSON 响应解析 — 字段不存在时返回原始文本"""
        from pyrit_ai300.attack.interactions.response_parser import ResponseParser

        parser = ResponseParser.create("json", field="nonexistent")
        raw = json.dumps({"response": "Hello"})
        result = parser.parse(raw)
        assert "response" in result  # 返回原始 JSON 文本

    def test_json_response_parser_invalid_json(self):
        """JSON 响应解析 — 无效 JSON 返回原始文本"""
        from pyrit_ai300.attack.interactions.response_parser import ResponseParser

        parser = ResponseParser.create("json", field="response")
        assert parser.parse("not json at all") == "not json at all"

    def test_sse_response_parser_basic(self):
        """SSE 响应解析 — 基本内容提取"""
        from pyrit_ai300.attack.interactions.response_parser import ResponseParser

        parser = ResponseParser.create("sse")
        raw = 'data: {"content": "Hello "}\n\ndata: {"content": "world"}\n\n'
        assert parser.parse(raw) == "Hello world"

    def test_sse_response_parser_with_meta_event(self):
        """SSE 响应解析 — 跳过 meta 事件"""
        from pyrit_ai300.attack.interactions.response_parser import ResponseParser

        parser = ResponseParser.create("sse")
        raw = (
            'event: meta\ndata: {"request_id": "abc"}\n\n'
            'data: {"content": "actual content"}\n\n'
        )
        assert parser.parse(raw) == "actual content"

    def test_sse_response_parser_ollama_format(self):
        """SSE 响应解析 — Ollama 格式 (message.content)"""
        from pyrit_ai300.attack.interactions.response_parser import ResponseParser

        parser = ResponseParser.create("sse")
        raw = (
            'data: {"message": {"content": "chunk1"}}\n\n'
            'data: {"message": {"content": "chunk2"}}\n\n'
        )
        assert parser.parse(raw) == "chunk1chunk2"

    def test_sse_response_parser_openai_format(self):
        """SSE 响应解析 — OpenAI 流式格式 (choices[0].delta.content)"""
        from pyrit_ai300.attack.interactions.response_parser import ResponseParser

        parser = ResponseParser.create("sse")
        raw = (
            'data: {"choices": [{"delta": {"content": "Hi"}}]}\n\n'
            'data: {"choices": [{"delta": {"content": " there"}}]}\n\n'
            'data: [DONE]\n\n'
        )
        assert parser.parse(raw) == "Hi there"

    def test_sse_response_parser_plain_text(self):
        """SSE 响应解析 — 纯文本 data 行"""
        from pyrit_ai300.attack.interactions.response_parser import ResponseParser

        parser = ResponseParser.create("sse")
        raw = "data: plain text content\n\n"
        assert parser.parse(raw) == "plain text content"

    def test_sse_response_parser_empty(self):
        """SSE 响应解析 — 空响应"""
        from pyrit_ai300.attack.interactions.response_parser import ResponseParser

        parser = ResponseParser.create("sse")
        assert parser.parse("") == ""

    def test_sse_response_parser_mcp_result_event(self):
        """SSE 响应解析 — 跳过 mcp_result 事件"""
        from pyrit_ai300.attack.interactions.response_parser import ResponseParser

        parser = ResponseParser.create("sse")
        raw = (
            'data: {"content": "model response"}\n\n'
            'event: mcp_result\ndata: {"tool_result": "tool output"}\n\n'
        )
        assert parser.parse(raw) == "model response"

    def test_text_response_parser(self):
        """纯文本响应解析 — 直通模式"""
        from pyrit_ai300.attack.interactions.response_parser import ResponseParser

        parser = ResponseParser.create("text")
        assert parser.parse("raw text") == "raw text"


# ════════════════════════════════════════════════════════════════
# 2. ApiTargetBuilder 测试
# ════════════════════════════════════════════════════════════════

class TestApiTargetBuilder:
    """API 目标构建器测试"""

    def test_api_target_config_resolve_endpoint(self):
        """ApiTargetConfig — URL 路径参数解析"""
        from pyrit_ai300.attack.pyrit.api_target_builder import ApiTargetConfig

        config = ApiTargetConfig(
            base_url="http://localhost:8000",
            endpoint_path="/api/labs/{lab_id}/chat",
            url_params={"lab_id": "PI_01"},
        )
        url = config.resolve_endpoint()
        assert url == "http://localhost:8000/api/labs/PI_01/chat"

    def test_api_target_config_resolve_endpoint_override(self):
        """ApiTargetConfig — URL 参数覆盖"""
        from pyrit_ai300.attack.pyrit.api_target_builder import ApiTargetConfig

        config = ApiTargetConfig(
            base_url="http://localhost:8000",
            endpoint_path="/api/labs/{lab_id}/chat",
            url_params={"lab_id": "PI_01"},
        )
        url = config.resolve_endpoint({"lab_id": "DE_10"})
        assert url == "http://localhost:8000/api/labs/DE_10/chat"

    def test_api_target_config_build_headers_with_auth(self):
        """ApiTargetConfig — 认证头构建"""
        from pyrit_ai300.attack.pyrit.api_target_builder import ApiTargetConfig

        config = ApiTargetConfig(
            base_url="http://localhost:8000",
            endpoint_path="/chat",
            auth_token="user_1_token",
        )
        headers = config.build_headers()
        assert headers["Authorization"] == "Bearer user_1_token"
        assert headers["Content-Type"] == "application/json"

    def test_api_target_config_build_body_with_prompt(self):
        """ApiTargetConfig — 请求体构建（含 {PROMPT} 替换）"""
        from pyrit_ai300.attack.pyrit.api_target_builder import ApiTargetConfig

        config = ApiTargetConfig(
            base_url="http://localhost:8000",
            endpoint_path="/chat",
            request_body_template='{"message": "{PROMPT}", "user_id": 1}',
        )
        body = config.build_body("Ignore previous instructions")
        data = json.loads(body)
        assert data["message"] == "Ignore previous instructions"
        assert data["user_id"] == 1

    def test_api_target_config_build_body_with_special_chars(self):
        """ApiTargetConfig — 请求体构建（特殊字符 JSON 转义）"""
        from pyrit_ai300.attack.pyrit.api_target_builder import ApiTargetConfig

        config = ApiTargetConfig(
            base_url="http://localhost:8000",
            endpoint_path="/chat",
            request_body_template='{"message": "{PROMPT}"}',
        )
        body = config.build_body('Hello "world" \n newline')
        data = json.loads(body)
        assert data["message"] == 'Hello "world" \n newline'

    def test_api_target_config_response_parser_json(self):
        """ApiTargetConfig — JSON 响应解析器"""
        from pyrit_ai300.attack.pyrit.api_target_builder import ApiTargetConfig

        config = ApiTargetConfig(
            base_url="http://localhost:8000",
            endpoint_path="/chat",
            response_format="json",
            response_field="response",
        )
        parser = config.get_response_parser()
        result = parser.parse('{"response": "test output"}')
        assert result == "test output"

    def test_api_target_config_response_parser_sse(self):
        """ApiTargetConfig — SSE 响应解析器"""
        from pyrit_ai300.attack.pyrit.api_target_builder import ApiTargetConfig

        config = ApiTargetConfig(
            base_url="http://localhost:8000",
            endpoint_path="/api/labs/PI_01/chat",
            response_format="sse",
        )
        parser = config.get_response_parser()
        result = parser.parse('data: {"content": "streamed"}\n\n')
        assert result == "streamed"

    def test_build_api_target_from_config_donkai(self):
        """build_api_target — DonkAI 配置构建"""
        from pyrit_ai300.attack.pyrit.api_target_builder import build_api_target

        config = {
            "type": "rest_api",
            "connection": {
                "base_url": "http://localhost:8000",
                "endpoint_path": "/chat",
                "method": "POST",
                "request_body": '{"message": "{PROMPT}", "user_id": 1}',
                "response": {"format": "json", "field": "response"},
                "auth": {"type": "none"},
            },
        }
        adapter = build_api_target(config)
        assert adapter.config.base_url == "http://localhost:8000"
        assert adapter.config.endpoint_path == "/chat"
        assert adapter.config.response_format == "json"

    def test_build_api_target_from_config_aivp(self):
        """build_api_target — AIVP 配置构建"""
        from pyrit_ai300.attack.pyrit.api_target_builder import build_api_target

        config = {
            "type": "sse_chat",
            "connection": {
                "base_url": "http://localhost:8000",
                "endpoint_path": "/api/labs/{lab_id}/chat",
                "method": "POST",
                "request_body": '{"prompt": "{PROMPT}"}',
                "response": {"format": "sse"},
                "url_params": {"lab_id": "PI_01"},
                "auth": {"type": "none"},
            },
        }
        adapter = build_api_target(config)
        assert adapter.config.base_url == "http://localhost:8000"
        assert adapter.config.endpoint_path == "/api/labs/{lab_id}/chat"
        assert adapter.config.response_format == "sse"
        assert adapter.config.url_params.get("lab_id") == "PI_01"


# ════════════════════════════════════════════════════════════════
# 3. LabCatalog 测试
# ════════════════════════════════════════════════════════════════

class TestLabCatalog:
    """Lab 目录加载器测试"""

    def test_load_aivp_labs_catalog(self):
        """加载 AIVP lab 目录"""
        from pyrit_ai300.payloads.lab_catalog import LabCatalog

        catalog = LabCatalog.load("config/targets/aivp_labs.yaml")
        assert catalog.target_name == "AIVP"
        assert catalog.target_type == "sse_chat"
        assert len(catalog.labs) >= 55  # 55 labs

    def test_aivp_labs_by_phase(self):
        """AIVP — 按阶段查询 labs"""
        from pyrit_ai300.payloads.lab_catalog import LabCatalog

        catalog = LabCatalog.load("config/targets/aivp_labs.yaml")
        phase1 = catalog.get_labs_by_phase(1)
        phase2 = catalog.get_labs_by_phase(2)
        phase3 = catalog.get_labs_by_phase(3)
        phase4 = catalog.get_labs_by_phase(4)
        assert len(phase1) == 10  # PI_01..PI_10
        assert len(phase2) == 15  # DE_01..DE_15
        assert len(phase3) == 15  # MM_01..MM_15
        assert len(phase4) == 15  # MCP_01..MCP_15

    def test_aivp_labs_by_owasp(self):
        """AIVP — 按 OWASP 分类查询 labs"""
        from pyrit_ai300.payloads.lab_catalog import LabCatalog

        catalog = LabCatalog.load("config/targets/aivp_labs.yaml")
        llm01_labs = catalog.get_labs_by_owasp("LLM01")
        assert len(llm01_labs) >= 10  # At least PI_01..PI_10

    def test_aivp_lab_info(self):
        """AIVP — 单个 lab 信息查询"""
        from pyrit_ai300.payloads.lab_catalog import LabCatalog

        catalog = LabCatalog.load("config/targets/aivp_labs.yaml")
        lab = catalog.get_lab("PI_01")
        assert lab is not None
        assert lab.phase == 1
        assert lab.owasp == "LLM01"
        assert lab.name == "Direct Prompt Injection"

    def test_aivp_find_labs_for_scope_all(self):
        """AIVP — scope=all 返回所有 labs"""
        from pyrit_ai300.payloads.lab_catalog import LabCatalog

        catalog = LabCatalog.load("config/targets/aivp_labs.yaml")
        labs = catalog.find_labs_for_scope("all")
        assert len(labs) >= 55

    def test_aivp_find_labs_for_scope_llm(self):
        """AIVP — scope=llm 返回 LLM 分类 labs"""
        from pyrit_ai300.payloads.lab_catalog import LabCatalog

        catalog = LabCatalog.load("config/targets/aivp_labs.yaml")
        labs = catalog.find_labs_for_scope("llm")
        assert all(lab.owasp.upper().startswith("LLM") for lab in labs)

    def test_aivp_find_labs_for_scope_asi(self):
        """AIVP — scope=asi 返回 ASI 分类 labs"""
        from pyrit_ai300.payloads.lab_catalog import LabCatalog

        catalog = LabCatalog.load("config/targets/aivp_labs.yaml")
        labs = catalog.find_labs_for_scope("asi")
        assert all(lab.owasp.upper().startswith("ASI") for lab in labs)

    def test_load_donkai_challenges_catalog(self):
        """加载 DonkAI 挑战目录"""
        from pyrit_ai300.payloads.lab_catalog import LabCatalog

        catalog = LabCatalog.load("config/targets/donkai_challenges.yaml")
        assert catalog.target_name == "OWASP DonkAI"
        assert catalog.target_type == "rest_api"

    def test_donkai_sensitive_targets(self):
        """DonkAI — 敏感信息目标"""
        from pyrit_ai300.payloads.lab_catalog import LabCatalog

        catalog = LabCatalog.load("config/targets/donkai_challenges.yaml")
        patterns = catalog.get_sensitive_patterns()
        assert len(patterns) >= 4
        # 检查关键敏感信息
        pattern_names = [p.get("name", "") for p in patterns]
        assert "API_KEY" in pattern_names
        assert "ADMIN_PASSWORD" in pattern_names

    def test_donkai_categories(self):
        """DonkAI — 10 个 OWASP LLM 类别"""
        from pyrit_ai300.payloads.lab_catalog import LabCatalog

        catalog = LabCatalog.load("config/targets/donkai_challenges.yaml")
        categories = catalog.get_owasp_categories()
        # DonkAI 有 LLM01-LLM10
        for i in range(1, 11):
            assert f"LLM{i:02d}" in categories

    def test_lab_catalog_nonexistent_file(self):
        """Lab 目录 — 文件不存在返回空目录"""
        from pyrit_ai300.payloads.lab_catalog import LabCatalog

        catalog = LabCatalog.load("config/targets/nonexistent.yaml")
        assert len(catalog.labs) == 0


# ════════════════════════════════════════════════════════════════
# 4. PayloadFilter 靶机适配测试
# ════════════════════════════════════════════════════════════════

class TestPayloadFilterTargetAdaptation:
    """PayloadFilter 靶机适配测试"""

    def test_infer_surfaces_rest_api(self):
        """从 rest_api 类型推断攻击面"""
        from pyrit_ai300.payloads.payload_filter import infer_surfaces_from_target_type

        surfaces = infer_surfaces_from_target_type("rest_api")
        assert "prompt" in surfaces
        assert "api" in surfaces

    def test_infer_surfaces_sse_chat(self):
        """从 sse_chat 类型推断攻击面"""
        from pyrit_ai300.payloads.payload_filter import infer_surfaces_from_target_type

        surfaces = infer_surfaces_from_target_type("sse_chat")
        assert "prompt" in surfaces
        assert "agent" in surfaces
        assert "mcp" in surfaces

    def test_infer_surfaces_ollama(self):
        """从 ollama 类型推断攻击面"""
        from pyrit_ai300.payloads.payload_filter import infer_surfaces_from_target_type

        surfaces = infer_surfaces_from_target_type("ollama")
        assert "prompt" in surfaces

    def test_infer_surfaces_unknown_type(self):
        """未知类型返回空列表"""
        from pyrit_ai300.payloads.payload_filter import infer_surfaces_from_target_type

        surfaces = infer_surfaces_from_target_type("unknown_type")
        assert surfaces == []

    def test_payload_filter_donkai_surfaces(self):
        """PayloadFilter — DonkAI 攻击面过滤"""
        from pyrit_ai300.payloads.payload_filter import PayloadFilter, infer_surfaces_from_target_type

        surfaces = infer_surfaces_from_target_type("rest_api")
        pf = PayloadFilter()

        # DonkAI 有 prompt + api 攻击面
        # LLM01 (Prompt Injection) 需要 prompt → 不跳过
        assert pf.should_skip_attack("LLM01", surfaces) == False
        # LLM04 (RAG Poison) 需要 rag → 跳过（DonkAI 无 RAG）
        assert pf.should_skip_attack("LLM04", surfaces) == True
        # LLM06 (Excessive Agency) 需要 agent/mcp → 跳过（DonkAI 无 Agent）
        assert pf.should_skip_attack("LLM06", surfaces) == True
        # LLM08 (Vector) 需要 rag/vector → 跳过
        assert pf.should_skip_attack("LLM08", surfaces) == True

    def test_payload_filter_aivp_surfaces(self):
        """PayloadFilter — AIVP 攻击面过滤"""
        from pyrit_ai300.payloads.payload_filter import PayloadFilter, infer_surfaces_from_target_type

        surfaces = infer_surfaces_from_target_type("sse_chat")
        pf = PayloadFilter()

        # AIVP 有 prompt + agent + rag + mcp 攻击面
        # LLM01 (Prompt Injection) → 不跳过
        assert pf.should_skip_attack("LLM01", surfaces) == False
        # LLM04 (RAG Poison) 需要 rag → 不跳过（AIVP 有 RAG）
        assert pf.should_skip_attack("LLM04", surfaces) == False
        # LLM06 (Excessive Agency) 需要 agent/mcp → 不跳过（AIVP 有 Agent/MCP）
        assert pf.should_skip_attack("LLM06", surfaces) == False
        # ASI01 (Agent Goal Hijack) 需要 agent → 不跳过
        assert pf.should_skip_attack("ASI01", surfaces) == False


# ════════════════════════════════════════════════════════════════
# 5. TargetBuilder 新类型集成测试
# ════════════════════════════════════════════════════════════════

class TestTargetBuilderNewTypes:
    """TargetBuilder 新目标类型集成测试"""

    def test_target_builder_supports_rest_api(self):
        """TargetBuilder — 支持 rest_api 类型"""
        from pyrit_ai300.attack.pyrit.target_builder import TargetBuilder

        builder = TargetBuilder()
        config = {
            "type": "rest_api",
            "connection": {
                "base_url": "http://localhost:8000",
                "endpoint_path": "/chat",
                "method": "POST",
                "request_body": '{"message": "{PROMPT}", "user_id": 1}',
                "response": {"format": "json", "field": "response"},
                "auth": {"type": "none"},
            },
        }
        target = builder.build(config)
        assert target is not None
        assert hasattr(target, "config")
        assert target.config.base_url == "http://localhost:8000"

    def test_target_builder_supports_sse_chat(self):
        """TargetBuilder — 支持 sse_chat 类型"""
        from pyrit_ai300.attack.pyrit.target_builder import TargetBuilder

        builder = TargetBuilder()
        config = {
            "type": "sse_chat",
            "connection": {
                "base_url": "http://localhost:8000",
                "endpoint_path": "/api/labs/PI_01/chat",
                "method": "POST",
                "request_body": '{"prompt": "{PROMPT}"}',
                "response": {"format": "sse"},
                "auth": {"type": "none"},
            },
        }
        target = builder.build(config)
        assert target is not None
        assert hasattr(target, "config")
        assert target.config.response_format == "sse"

    def test_target_builder_rate_controller_for_rest_api(self):
        """TargetBuilder — rest_api 速率控制器"""
        from pyrit_ai300.attack.pyrit.target_builder import TargetBuilder

        builder = TargetBuilder()
        config = {
            "type": "rest_api",
            "connection": {
                "base_url": "http://localhost:8000",
                "endpoint_path": "/chat",
                "request_body": '{"message": "{PROMPT}"}',
                "auth": {"type": "none"},
            },
        }
        builder.build(config)
        assert builder.rate_controller is not None


# ════════════════════════════════════════════════════════════════
# 6. InfraScanAdapter DonkAI/AIVP 检测规则测试
# ════════════════════════════════════════════════════════════════

class TestInfraScanDonkaiAivpRules:
    """InfraScanAdapter DonkAI/AIVP 检测规则测试"""

    def test_donkai_detection_rules_exist(self):
        """DonkAI 检测规则存在"""
        from pyrit_ai300.recon.adapters.infra_scan.adapter import INFRA_VULN_CHECKS

        donkai_rules = [r for r in INFRA_VULN_CHECKS if "donkai" in r["id"]]
        assert len(donkai_rules) >= 3  # chat, auth, challenge

    def test_donkai_chat_endpoint_rule(self):
        """DonkAI Chat 端点检测规则"""
        from pyrit_ai300.recon.adapters.infra_scan.adapter import INFRA_VULN_CHECKS

        rule = next(r for r in INFRA_VULN_CHECKS if r["id"] == "donkai_chat_endpoint")
        assert "/chat" in rule["paths"]
        assert rule["severity"] == "high"

    def test_aivp_detection_rules_exist(self):
        """AIVP 检测规则存在"""
        from pyrit_ai300.recon.adapters.infra_scan.adapter import INFRA_VULN_CHECKS

        aivp_rules = [r for r in INFRA_VULN_CHECKS if "aivp" in r["id"]]
        assert len(aivp_rules) >= 3  # sse_chat, secret_validation, run_tracking

    def test_aivp_sse_chat_endpoint_rule(self):
        """AIVP SSE Chat 端点检测规则"""
        from pyrit_ai300.recon.adapters.infra_scan.adapter import INFRA_VULN_CHECKS

        rule = next(r for r in INFRA_VULN_CHECKS if r["id"] == "aivp_sse_chat_endpoint")
        assert "/api/labs" in rule["paths"]
        assert rule["severity"] == "high"


# ════════════════════════════════════════════════════════════════
# 7. Target Config YAML 加载验证测试
# ════════════════════════════════════════════════════════════════

class TestTargetConfigYaml:
    """目标配置 YAML 文件加载验证"""

    def test_donkai_target_yaml_exists(self):
        """DonkAI 目标配置文件存在"""
        assert Path("config/targets/donkai_target.yaml").exists()

    def test_donkai_target_yaml_loads(self):
        """DonkAI 目标配置 YAML 可加载"""
        with open("config/targets/donkai_target.yaml", "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
        target = config["target"]
        assert target["type"] == "rest_api"
        assert target["connection"]["endpoint_path"] == "/chat"
        assert target["connection"]["response"]["format"] == "json"
        assert target["connection"]["response"]["field"] == "response"

    def test_donkai_target_yaml_auth(self):
        """DonkAI 目标配置 — 认证配置"""
        with open("config/targets/donkai_target.yaml", "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
        auth = config["target"]["connection"]["auth"]
        assert auth["type"] == "login"
        assert auth["login_path"] == "/auth/login"

    def test_aivp_target_yaml_exists(self):
        """AIVP 目标配置文件存在"""
        assert Path("config/targets/aivp_target.yaml").exists()

    def test_aivp_target_yaml_loads(self):
        """AIVP 目标配置 YAML 可加载"""
        with open("config/targets/aivp_target.yaml", "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
        target = config["target"]
        assert target["type"] == "sse_chat"
        assert target["connection"]["endpoint_path"] == "/api/labs/{lab_id}/chat"
        assert target["connection"]["response"]["format"] == "sse"

    def test_aivp_target_yaml_url_params(self):
        """AIVP 目标配置 — URL 参数"""
        with open("config/targets/aivp_target.yaml", "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
        url_params = config["target"]["connection"]["url_params"]
        assert "lab_id" in url_params

    def test_aivp_target_yaml_secret_validation(self):
        """AIVP 目标配置 — Secret 验证端点"""
        with open("config/targets/aivp_target.yaml", "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
        assert "secret_validation" in config
        assert config["secret_validation"]["endpoint"] == "/api/secrets/validate"

    def test_donkai_challenges_yaml_exists(self):
        """DonkAI 挑战目录文件存在"""
        assert Path("config/targets/donkai_challenges.yaml").exists()

    def test_aivp_labs_yaml_exists(self):
        """AIVP lab 目录文件存在"""
        assert Path("config/targets/aivp_labs.yaml").exists()


# ════════════════════════════════════════════════════════════════
# 8. 端到端覆盖验证测试
# ════════════════════════════════════════════════════════════════

class TestEndToEndCoverage:
    """端到端覆盖验证 — 侦察→分析→攻击→报告全链路"""

    def test_donkai_full_coverage(self):
        """
        DonkAI 全阶段覆盖验证：
        - 侦察: InfraScan 检测 DonkAI 端点
        - 分析: LabCatalog 加载 10 个 OWASP 类别
        - 攻击: ApiTargetAdapter 支持 /chat 端点
        - 报告: 敏感信息模式可用于评分器验证
        """
        # 侦察: InfraScan 有 DonkAI 检测规则
        from pyrit_ai300.recon.adapters.infra_scan.adapter import INFRA_VULN_CHECKS
        donkai_rules = [r for r in INFRA_VULN_CHECKS if "donkai" in r["id"]]
        assert len(donkai_rules) >= 3

        # 分析: LabCatalog 加载挑战目录
        from pyrit_ai300.payloads.lab_catalog import LabCatalog
        catalog = LabCatalog.load("config/targets/donkai_challenges.yaml")
        assert catalog.target_type == "rest_api"
        assert len(catalog.get_owasp_categories()) >= 10

        # 攻击: ApiTargetAdapter 配置
        from pyrit_ai300.attack.pyrit.api_target_builder import ApiTargetConfig
        config = ApiTargetConfig(
            base_url="http://localhost:8000",
            endpoint_path="/chat",
            request_body_template='{"message": "{PROMPT}", "user_id": 1}',
            response_format="json",
            response_field="response",
        )
        adapter_config = config
        assert adapter_config.resolve_endpoint() == "http://localhost:8000/chat"

        # 报告: 敏感信息模式
        patterns = catalog.get_sensitive_patterns()
        assert len(patterns) >= 4
        assert any(p["name"] == "API_KEY" for p in patterns)

    def test_aivp_full_coverage(self):
        """
        AIVP 全阶段覆盖验证：
        - 侦察: InfraScan 检测 AIVP 端点
        - 分析: LabCatalog 加载 55 个 labs
        - 攻击: ApiTargetAdapter 支持 SSE 端点 + URL 参数化
        - 报告: OWASP 映射汇总覆盖所有分类
        """
        # 侦察: InfraScan 有 AIVP 检测规则
        from pyrit_ai300.recon.adapters.infra_scan.adapter import INFRA_VULN_CHECKS
        aivp_rules = [r for r in INFRA_VULN_CHECKS if "aivp" in r["id"]]
        assert len(aivp_rules) >= 3

        # 分析: LabCatalog 加载 lab 目录
        from pyrit_ai300.payloads.lab_catalog import LabCatalog
        catalog = LabCatalog.load("config/targets/aivp_labs.yaml")
        assert catalog.target_type == "sse_chat"
        assert len(catalog.labs) >= 55

        # 攻击: ApiTargetAdapter 配置 + URL 参数化
        from pyrit_ai300.attack.pyrit.api_target_builder import ApiTargetConfig
        config = ApiTargetConfig(
            base_url="http://localhost:8000",
            endpoint_path="/api/labs/{lab_id}/chat",
            request_body_template='{"prompt": "{PROMPT}"}',
            response_format="sse",
            url_params={"lab_id": "PI_01"},
        )
        # URL 参数化 — 默认 lab_id
        assert config.resolve_endpoint() == "http://localhost:8000/api/labs/PI_01/chat"
        # URL 参数化 — 覆盖 lab_id
        assert config.resolve_endpoint({"lab_id": "DE_10"}) == "http://localhost:8000/api/labs/DE_10/chat"
        # URL 参数化 — MCP lab
        assert config.resolve_endpoint({"lab_id": "MCP_01"}) == "http://localhost:8000/api/labs/MCP_01/chat"

        # 报告: OWASP 映射汇总
        owasp_cats = catalog.get_owasp_categories()
        assert "LLM01" in owasp_cats
        assert "ASI01" in owasp_cats

    def test_aivp_phase_coverage(self):
        """AIVP — 4 个阶段全覆盖"""
        from pyrit_ai300.payloads.lab_catalog import LabCatalog

        catalog = LabCatalog.load("config/targets/aivp_labs.yaml")
        for phase in [1, 2, 3, 4]:
            labs = catalog.get_labs_by_phase(phase)
            assert len(labs) > 0, f"Phase {phase} has no labs"

    def test_aivp_owasp_coverage(self):
        """AIVP — OWASP 分类覆盖验证"""
        from pyrit_ai300.payloads.lab_catalog import LabCatalog

        catalog = LabCatalog.load("config/targets/aivp_labs.yaml")
        # AIVP 应覆盖 LLM01-LLM10 和 ASI01-ASI10
        owasp_cats = set(catalog.get_owasp_categories())
        # 至少覆盖 LLM01 (Prompt Injection)
        assert "LLM01" in owasp_cats
        # Phase 4 MCP labs 映射到 ASI 分类
        asi_labs = catalog.find_labs_for_scope("asi")
        assert len(asi_labs) > 0

    def test_donkai_attack_surface_coverage(self):
        """DonkAI — 攻击面覆盖验证"""
        from pyrit_ai300.payloads.payload_filter import PayloadFilter, infer_surfaces_from_target_type

        surfaces = infer_surfaces_from_target_type("rest_api")
        pf = PayloadFilter()

        # DonkAI 应覆盖的 OWASP 类别（有 prompt 攻击面）
        should_cover = ["LLM01", "LLM02", "LLM03", "LLM05", "LLM07", "LLM09", "LLM10"]
        for owasp in should_cover:
            assert pf.should_skip_attack(owasp, surfaces) == False, \
                f"{owasp} should not be skipped for DonkAI"

        # DonkAI 不应覆盖的 OWASP 类别（需要 rag/agent/mcp）
        should_skip = ["LLM04", "LLM06", "LLM08", "ASI01", "ASI02"]
        for owasp in should_skip:
            assert pf.should_skip_attack(owasp, surfaces) == True, \
                f"{owasp} should be skipped for DonkAI"

    def test_aivp_attack_surface_coverage(self):
        """AIVP — 攻击面覆盖验证"""
        from pyrit_ai300.payloads.payload_filter import PayloadFilter, infer_surfaces_from_target_type

        surfaces = infer_surfaces_from_target_type("sse_chat")
        pf = PayloadFilter()

        # AIVP 应覆盖所有 OWASP 类别（有 prompt + agent + rag + mcp）
        all_owasp = [f"LLM{i:02d}" for i in range(1, 11)] + [f"ASI{i:02d}" for i in range(1, 11)]
        for owasp in all_owasp:
            assert pf.should_skip_attack(owasp, surfaces) == False, \
                f"{owasp} should not be skipped for AIVP"

    def test_pipeline_orchestrator_target_file_support(self):
        """PipelineOrchestrator — 支持 --target-file 参数"""
        from pyrit_ai300 import PipelineOrchestrator

        orchestrator = PipelineOrchestrator()
        # 验证 orchestrator 可以接受 target_file 参数
        # （不实际执行，只验证接口兼容性）
        assert hasattr(orchestrator, "run")
        import inspect
        sig = inspect.signature(orchestrator.run)
        assert "target_file" in sig.parameters
        assert "spa_config" in sig.parameters
